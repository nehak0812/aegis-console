"""Preventive checks — pure functions, no network and no database.

Everything here turns an already-fetched public record into a decision:
RDAP registration data, RPKI validation state, Certificate Transparency entries and
lookalike-domain candidates. The network calls live in `collectors/surface.py`;
keeping the logic here is what makes it testable the way the rest of the rules are.

Nothing in this module contacts a monitored organisation. Lookalike candidates are
generated locally and resolved through public resolvers only.
"""
import re
from datetime import datetime, timezone

# --- domain lifecycle (RDAP) --------------------------------------------------------------------
# RDAP normalises EPP status codes to lower-case words, so the wire format is
# "client transfer prohibited", never "clientTransferProhibited". Verified against rdap.verisign.com.
TRANSFER_LOCKS = ("client transfer prohibited", "server transfer prohibited")


def rdap_summary(js: dict | None) -> dict | None:
    """RDAP domain response -> {registrar, expires, statuses, locked}. None if unusable."""
    if not isinstance(js, dict):
        return None
    statuses = [str(s).strip().lower() for s in (js.get("status") or []) if s]
    expires = None
    for e in js.get("events") or []:
        if str(e.get("eventAction", "")).strip().lower() == "expiration":
            expires = (e.get("eventDate") or "")[:19] or None
            break
    registrar = None
    for ent in js.get("entities") or []:
        if "registrar" in [r.lower() for r in (ent.get("roles") or [])]:
            card = ent.get("vcardArray")
            if isinstance(card, list) and len(card) > 1:
                for field in card[1]:
                    if isinstance(field, list) and field and field[0] == "fn":
                        registrar = str(field[-1])[:120]
                        break
            break
    if not statuses and not expires:
        return None
    return {"registrar": registrar, "expires": expires, "statuses": statuses[:12],
            "locked": any(l in statuses for l in TRANSFER_LOCKS)}


def days_until(iso: str | None, now: datetime | None = None) -> int | None:
    """Whole days from now until an ISO-8601 instant. Negative once it has passed."""
    if not iso:
        return None
    txt = str(iso).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(txt)
    except ValueError:
        try:
            dt = datetime.strptime(txt[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int((dt - (now or datetime.now(timezone.utc))).total_seconds() // 86400)


def expiry_rule(days: int | None) -> str | None:
    """Domain expiry -> rule id. Already-expired domains still read as the 30-day case."""
    if days is None:
        return None
    if days <= 30:
        return "DOM-EXPIRY-30"
    if days <= 90:
        return "DOM-EXPIRY-90"
    return None


# --- routing integrity (RPKI) -------------------------------------------------------------------
def rpki_rule(state: str | None) -> str | None:
    """RIPEstat rpki-validation state -> rule id. 'valid' is the good case and raises nothing."""
    s = (state or "").strip().lower()
    if s == "invalid":
        return "BGP-RPKI-INVALID"
    if s == "unknown":          # announced, but no ROA covers it
        return "BGP-RPKI-NONE"
    return None


# --- certificates ------------------------------------------------------------------------------
# CAA records name a CA by domain; CT logs name it by its certificate subject. This maps the
# common issuers between the two. Deliberately incomplete: an issuer that is not listed here is
# never reported as a violation, because a false "possible mis-issuance" is worse than a miss.
# A certificate authority may publish several CAA identifiers, and brands it has acquired keep
# issuing under their own names. Micron authorises "www.digicert.com"; a DigiCert certificate
# whose CN reads "GeoTrust TLS RSA CA G1" is issued under that same authorisation. Matching a CA
# to one domain only produced false "possible mis-issuance" findings against both.
# Sources: each CA's published CAA identifier, per CCADB's "CAA Identifiers" field.
# A brand maps to its parent's full identifier set, so GeoTrust resolves to DigiCert's.
_DIGICERT = ("digicert.com", "www.digicert.com", "geotrust.com", "rapidssl.com", "thawte.com",
             "symantec.com", "digicert.ne.jp", "cybertrust.ne.jp")
_SECTIGO = ("sectigo.com", "comodo.com", "comodoca.com", "usertrust.com", "trust-provider.com")
CA_DOMAINS: dict[str, tuple[str, ...]] = {
    "let's encrypt": ("letsencrypt.org",),
    "digicert": _DIGICERT, "geotrust": _DIGICERT, "rapidssl": _DIGICERT, "thawte": _DIGICERT,
    "symantec": _DIGICERT, "cybertrust": _DIGICERT,
    "sectigo": _SECTIGO, "comodo": _SECTIGO, "usertrust": _SECTIGO,
    "amazon": ("amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"),
    "globalsign": ("globalsign.com",),
    "godaddy": ("godaddy.com", "starfieldtech.com"),
    "starfield": ("starfieldtech.com", "godaddy.com"),
    "entrust": ("entrust.net", "affirmtrust.com"),
    "google trust services": ("pki.goog", "google.com"),
    "microsoft": ("microsoft.com",),
    "apple": ("apple.com",),
    "buypass": ("buypass.com",),
    "zerossl": ("sectigo.com", "zerossl.com"),
    "actalis": ("actalis.it",),
    "ssl.com": ("ssl.com",),
    "identrust": ("identrust.com",),
    "certum": ("certum.pl", "certum.eu"),
    "quovadis": ("quovadisglobal.com",) + _DIGICERT,
    "swisssign": ("swisssign.com",),
    "harica": ("harica.gr",),
    "trustasia": ("trustasia.com",),
    "e-tugra": ("e-tugra.com.tr",),
    "telia": ("telia.com", "telia.fi"),
    "trustwave": ("trustwave.com", "securetrust.com"),
    "firmaprofesional": ("firmaprofesional.com",),
    "camerfirma": ("camerfirma.com",),
    "chunghwa telecom": ("cht.com.tw", "publicca.hinet.net"),
}
_CAA_ISSUE = re.compile(r'(?i)\bissue(wild)?\s+"?([^";\s]*)')


def caa_allowed(caa_records: list[str] | None) -> set[str] | None:
    """CAA records -> the set of CA domains permitted to issue.

    None means "no usable issue policy", which is HYG-CAA's business, not ours.
    An empty set means the domain published `issue ";"` — issuance denied outright.
    """
    if not caa_records:
        return None
    allowed, saw_issue = set(), False
    for rec in caa_records:
        for m in _CAA_ISSUE.finditer(str(rec)):
            saw_issue = True
            val = (m.group(2) or "").strip().lower()
            if val and val != ";":
                allowed.add(val.split(";")[0].strip())
    return allowed if saw_issue else None


def issuer_domains(issuer_name: str | None) -> tuple[str, ...]:
    """Certificate issuer subject -> the CAA domains that CA issues under, or () if unrecognised."""
    text = (issuer_name or "").lower()
    for needle, domains in CA_DOMAINS.items():
        if needle in text:
            return domains
    return ()


def covered_by(name: str | None, domain: str) -> bool:
    """Is this certificate name inside the domain whose CAA policy we hold?

    Certificate Transparency returns a certificate whenever *any* of its names match, so a
    query for micron.com also returns certificates covering micron.cn. Those are a different
    registrable domain with their own — possibly absent — CAA policy, and judging them against
    this domain's policy is how the rule produced false findings.
    """
    n = (name or "").strip().lower().lstrip("*.")
    d = (domain or "").strip().lower()
    return bool(n) and bool(d) and (n == d or n.endswith("." + d))


def caa_violation(issuer_name: str | None, allowed: set[str] | None,
                  issued: str | None = None, policy_seen: str | None = None) -> bool:
    """True only when a known CA issued a certificate this domain's CAA policy excludes.

    `issued` is the certificate's not_before and `policy_seen` is when this exact CAA set was
    first observed. CAA is evaluated by the CA at issuance time (RFC 8659), so a certificate
    issued before the current policy existed proves nothing about it. Without both timestamps
    the case is not evaluable and produces no finding.
    """
    if allowed is None:            # no policy published -> nothing to violate
        return False
    domains = issuer_domains(issuer_name)
    if not domains:                # unrecognised CA -> stay quiet rather than guess
        return False
    if not any(d in allowed for d in domains):
        return issued is not None and policy_seen is not None and issued >= policy_seen
    return False


def caa_key(caa_records: list[str] | None) -> str:
    """A stable identity for a CAA policy, so a change resets when it was first observed."""
    allowed = caa_allowed(caa_records)
    return "" if allowed is None else "|".join(sorted(allowed))


# --- lookalike domains --------------------------------------------------------------------------
# Characters a person plausibly mistypes or misreads for another, on a QWERTY keyboard.
_NEIGHBOURS = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr", "f": "drtgvc", "g": "ftyhbv",
    "h": "gyujnb", "i": "ujko", "j": "huikmn", "k": "jiolm", "l": "kop", "m": "njk", "n": "bhjm",
    "o": "iklp0", "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy", "u": "yhji",
    "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu", "z": "asx",
    "0": "o", "1": "l", "3": "e", "5": "s",
}
_SWAP_TLDS = ("com", "net", "org", "co", "io", "info", "online", "site", "shop", "app")
_PREFIXES = ("secure", "login", "my", "portal", "mail", "support")


def lookalikes(domain: str, limit: int = 60) -> list[str]:
    """Plausible confusable variants of a domain, generated locally.

    Covers omission, transposition, keyboard-adjacent substitution, character repetition,
    hyphenation, TLD swap and a common-prefix pattern. The original is never returned.
    """
    d = (domain or "").strip().lower().strip(".")
    if "." not in d or len(d) < 4:
        return []
    label, _, tld = d.partition(".")
    if len(label) < 2:
        return []
    out: list[str] = []

    def add(name: str) -> None:
        if name != d and name not in out and len(name.partition(".")[0]) >= 2:
            out.append(name)

    for i in range(len(label)):                                    # omission
        add(label[:i] + label[i + 1:] + "." + tld)
    for i in range(len(label) - 1):                                # transposition
        add(label[:i] + label[i + 1] + label[i] + label[i + 2:] + "." + tld)
    for i, ch in enumerate(label):                                 # keyboard neighbour
        for sub in _NEIGHBOURS.get(ch, ""):
            add(label[:i] + sub + label[i + 1:] + "." + tld)
    for i, ch in enumerate(label):                                 # doubled character
        add(label[:i] + ch + ch + label[i:] + "." + tld)
    for i in range(1, len(label)):                                 # hyphenation
        add(label[:i] + "-" + label[i:] + "." + tld)
    for t in _SWAP_TLDS:                                           # same name, different TLD
        add(label + "." + t)
    for p in _PREFIXES:                                            # brand-prefix pattern
        add(p + "-" + label + "." + tld)
    return out[:limit]


def lookalike_rule(has_mx: bool, resolves: bool) -> str | None:
    """A registered lookalike only matters once it can receive mail or serve traffic.

    Mail first: an MX record is the direct enabler of invoice fraud and credential phishing.
    """
    if has_mx:
        return "LOOK-MX"
    if resolves:
        return "LOOK-LIVE"
    return None


# --- email and DNS hygiene already collected but never rated -------------------------------------
SPF_LOOKUP_LIMIT = 10          # RFC 7208 §4.6.4


def spf_lookup_excess(spf: dict | None) -> bool:
    """True when an SPF record needs more DNS lookups than receivers will perform.

    Past the limit a receiver returns permerror and the record stops protecting the
    domain, while every by-eye check still looks correct.
    """
    if not spf:
        return False
    return int(spf.get("lookups") or 0) > SPF_LOOKUP_LIMIT


def ns_single_provider(ns: list[str] | None) -> bool:
    """True when every authoritative nameserver sits under one registrable domain."""
    hosts = [h.strip().lower().rstrip(".") for h in (ns or []) if h and h.strip()]
    if len(hosts) < 2:
        return False
    bases = {".".join(h.split(".")[-2:]) for h in hosts if h.count(".") >= 1}
    return len(bases) == 1
