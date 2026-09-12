"""Indicators of compromise from published threat reports, and brand-impersonation matching.

Deterministic and explainable:
- `extract()` refangs report text ("ms365-live[.]com" → ms365-live.com) and pulls domains, IPs, URLs and hashes,
  with hygiene rules learned from live reports (file names are not domains, publisher hosts are not IOCs, …).
- `BrandIndex` matches a domain to a monitored organisation's brand tokens. Short or dictionary-word brands
  ("delta", "apple", "aws") only match as a whole label *and* next to a lure word ("login", "365", "us-east"),
  so `deltaclient.xyz` is not Delta Air Lines while `aws-us-east-3.com` is Amazon.
Every match records the token and the reason, which the UI shows next to the finding.
"""
import ipaddress
import re

from aegis.intel.entities import AMBIGUOUS, norm, reg_domain

# ------------------------------------------------------------------ refang + extract
_REFANG = [
    (re.compile(r"h(?:xx|XX|\*\*)p(s?)(?=\[?:|://)"), r"http\1"),
    (re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}", re.I), "."),
    (re.compile(r"\s+\[dot\]\s+|\s+\(dot\)\s+", re.I), "."),
    (re.compile(r"\[://\]|\[:\]//"), "://"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*@\s*\]|\[at\]|\(at\)", re.I), "@"),
]
_DEFANG_MARK = re.compile(r"\[\s*(?:\.|dot|:)\s*\]|\(\s*(?:\.|dot)\s*\)|h(?:xx|XX)ps?", re.I)
RX = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s\"'<>()\[\]{}]{4,2000}", re.I),
    "domain": re.compile(r"\b(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})\b", re.I),
    "ipv4": re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
    "ipv6": re.compile(r"(?<![0-9a-f:])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?)(?![0-9a-f:])", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
}
# pseudo-TLDs that are really file extensions or code identifiers
FILE_EXT = {"exe", "dll", "apk", "md", "js", "png", "jpg", "jpeg", "gif", "svg", "zip", "rar", "7z", "txt", "pdf", "doc", "docx",
            "xls", "xlsx", "ps1", "bat", "cmd", "vbs", "py", "sh", "json", "xml", "html", "htm", "php", "aspx", "jsp", "lnk", "iso",
            "msi", "bin", "dat", "log", "tmp", "cfg", "ini", "yaml", "yml", "csv", "db", "sys", "so", "dylib", "jar", "class", "go",
            "rs", "ts", "tsx", "css", "map", "hta", "wsf", "img", "vhd", "one", "ico", "woff", "ttf", "plist", "app", "dmg", "pkg",
            "deb", "rpm", "service", "conf", "local", "internal", "lan", "corp", "home", "onion"}
# hosts that appear in reports as platforms or references, not as indicators
BENIGN = {"microsoft.com", "google.com", "github.com", "githubusercontent.com", "t.me", "telegram.org", "telegram.me", "anthropic.com",
          "claude.ai", "claude.com", "openai.com", "virustotal.com", "twitter.com", "x.com", "linkedin.com", "youtube.com", "apple.com",
          "amazonaws.com", "amazon.com", "cloudflare.com", "windows.net", "office.com", "live.com", "microsoftonline.com", "mozilla.org",
          "wikipedia.org", "gstatic.com", "googleapis.com", "w3.org", "schema.org", "mitre.org", "cisa.gov", "nist.gov", "example.com",
          "example.org", "example.net", "localhost", "bit.ly", "archive.org", "facebook.com", "instagram.com", "whatsapp.com",
          "discord.com", "slack.com", "zoom.us", "dropbox.com", "gitlab.com", "pypi.org", "npmjs.com", "docker.com", "docker.io",
          "huggingface.co", "abuse.ch", "urlscan.io", "shodan.io", "censys.io", "any.run", "hybrid-analysis.com", "joesandbox.com",
          "misp-project.org", "circl.lu", "botvrij.eu", "talosintelligence.com", "paloaltonetworks.com", "eset.com", "welivesecurity.com",
          "volexity.com", "sekoia.io", "crowdstrike.com", "mandiant.com", "cloud.google.com", "withgoogle.com", "blogspot.com",
          "medium.com", "reddit.com", "ycombinator.com", "digicert.com", "letsencrypt.org", "sectigo.com", "godaddy.com", "namecheap.com",
          "captive.apple.com", "connectivitycheck.android.com", "msftconnecttest.com", "ipify.org", "ifconfig.me", "icanhazip.com",
          "sharepoint.com", "onedrive.com", "azure.com", "azurewebsites.net", "cloudfront.net", "akamai.net", "akamaiedge.net",
          "fastly.net", "wordpress.com", "wordpress.org", "wp.com", "gravatar.com", "jquery.com", "cdnjs.cloudflare.com", "jsdelivr.net",
          "unpkg.com", "bing.com", "yahoo.com", "baidu.com", "yandex.ru", "live.net", "skype.com", "adobe.com", "oracle.com", "ibm.com"}
# domains whose sub-hosts are abused as free hosting: a listing there is not a compromise of the platform owner
PLATFORM = BENIGN | {"r2.dev", "pages.dev", "workers.dev", "netlify.app", "vercel.app", "github.io", "herokuapp.com", "firebaseapp.com",
                     "web.app", "appspot.com", "googleusercontent.com", "blob.core.windows.net", "s3.amazonaws.com", "ngrok.io",
                     "ngrok-free.app", "trycloudflare.com", "glitch.me", "replit.dev", "repl.co", "weebly.com", "wixsite.com",
                     "squarespace.com", "webflow.io", "000webhostapp.com", "mediafire.com", "4shared.com", "box.com", "sites.google.com",
                     "docs.google.com", "drive.google.com", "forms.gle", "goo.gl", "tinyurl.com", "is.gd", "linktr.ee", "notion.site",
                     "canva.site", "godaddysites.com", "myshopify.com", "hubspotpagebuilder.com", "sendgrid.net", "mailchimp.com",
                     "surge.sh", "onrender.com", "fly.dev", "railway.app", "up.railway.app", "azureedge.net", "azurefd.net", "ipfs.io",
                     "dweb.link", "cloudflare-ipfs.com", "telegra.ph", "pastebin.com", "paste.ee", "discordapp.com", "cdn.discordapp.com"}


def refang(text: str) -> str:
    for rx, rep in _REFANG:
        text = rx.sub(rep, text or "")
    return text


def _ip_ok(v: str) -> bool:
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        return False
    return not (a.is_private or a.is_reserved or a.is_loopback or a.is_multicast or a.is_link_local or a.is_unspecified)


def _domain_ok(d: str, publisher_host: str = "") -> bool:
    d = d.lower().strip(".")
    tld = d.rsplit(".", 1)[-1]
    if tld in FILE_EXT or tld.isdigit() or len(d) > 253 or "." not in d:
        return False
    if re.fullmatch(r"(com|org|net|io|app)\.[a-z0-9_]+\.[a-z0-9_.]+", d):  # Android package names: com.app.safeguard
        return False
    rd = reg_domain(d)
    if rd in BENIGN or d in BENIGN or (publisher_host and rd == reg_domain(publisher_host)):
        return False
    return True


def extract(text: str, *, defanged_only: bool = False, publisher_host: str = "") -> list[dict]:
    """-> [{"type", "value", "context"}]. `defanged_only`: in prose (HTML reports) only tokens the author defanged are indicators;
    plain domains in prose are references ("see microsoft.com") and are dropped."""
    out, seen = [], set()
    # pages built by JS frameworks embed their text as JSON: "\n" / "<" escapes would glue onto the next token
    raw = re.sub(r"\\u[0-9a-fA-F]{4}|\\[nrt\"/]", " ", text or "")
    # remember which spans were defanged in the original
    defanged_vals = set()
    for m in re.finditer(r"[\w\-\[\]().:/@]{4,300}", raw):
        tok = m.group(0)
        if _DEFANG_MARK.search(tok):
            defanged_vals.add(refang(tok).strip("()[]{}.,;:").lower())
    t = refang(raw)

    def add(typ, val, pos):
        key = (typ, val)
        if key in seen:
            return
        seen.add(key)
        out.append({"type": typ, "value": val, "context": t[max(0, pos - 90): pos + len(val) + 90].replace("\n", " ").strip()[:200]})

    def was_defanged(v: str) -> bool:
        return any(v in dv for dv in defanged_vals)

    for m in RX["url"].finditer(t):
        u = m.group(0).rstrip(".,;:)'\"]")
        host = re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/")[0].split(":")[0].lower()
        if not host or (not _ip_ok(host) and not _domain_ok(host, publisher_host)):
            continue
        if defanged_only and not was_defanged(u.lower()) and not was_defanged(host):
            continue
        add("url", u, m.start())
    for m in RX["domain"].finditer(t):
        d = m.group(0).lower().strip(".")
        if "@" in t[max(0, m.start() - 1): m.start()]:  # part of an email address
            continue
        if not _domain_ok(d, publisher_host):
            continue
        if defanged_only and not was_defanged(d):
            continue
        add("domain", d, m.start())
    for m in RX["ipv4"].finditer(t):
        v = m.group(0)
        if _ip_ok(v) and (not defanged_only or was_defanged(v)):
            add("ip", v, m.start())
    for m in RX["ipv6"].finditer(t):
        v = m.group(0).lower()
        if v.count(":") >= 3 and _ip_ok(v) and (not defanged_only or was_defanged(v)):
            add("ip", v, m.start())
    # in prose, a hex string is a hash indicator only when the text around it says so (build ids and asset hashes are not)
    hash_ctx = (lambda pos: bool(re.search(r"sha-?256|sha256|md5|hash|sample|payload|file", t[max(0, pos - 160): pos], re.I))) if defanged_only else (lambda pos: True)
    sha = set()
    for m in RX["sha256"].finditer(t):
        if hash_ctx(m.start()):
            sha.add(m.group(0).lower())
            add("sha256", m.group(0).lower(), m.start())
    for m in RX["md5"].finditer(t):
        v = m.group(0).lower()
        if not any(v in s for s in sha) and hash_ctx(m.start()) and not re.search(r"[a-f0-9]{33,}", t[max(0, m.start() - 1): m.end() + 1], re.I):
            add("md5", v, m.start())
    return out


# ------------------------------------------------------------------ brand matching
LURES = {"login", "logon", "signin", "sign", "sso", "secure", "security", "verify", "verification", "account", "accounts", "auth",
         "mfa", "2fa", "otp", "support", "helpdesk", "help", "portal", "owa", "365", "o365", "teams", "wallet", "claim", "refund",
         "pay", "payment", "payments", "invoice", "billing", "update", "device", "devices", "id", "live", "cdn", "api", "east", "west",
         "north", "south", "central", "region", "cloud", "console", "store", "key", "keys", "cheap", "proxy", "credits", "reseller",
         "mail", "webmail", "online", "service", "services", "official", "reset", "recovery", "unlock", "alert", "notice", "access",
         "admin", "office", "share", "docs", "drive", "file", "files", "download", "app", "apps", "gift", "prize", "bonus", "promo",
         "rewards", "kyc", "confirm", "validate", "session", "token", "connect", "sync", "backup", "vpn", "remote", "desk", "hr",
         "benefits", "payroll", "careers", "jobs", "delivery", "track", "tracking", "parcel", "customs", "tax", "bank", "banking",
         "card", "cards", "loan", "crypto", "exchange", "trade", "trading", "invest", "us", "eu", "uk", "global", "web", "my",
         "rebate", "reward", "giftcard", "prize", "notice", "members", "member", "verify"}
# lure words that count when glued inside a longer label ("costcorebate", "dardengiftcardaccess", "fiservglobalcareers").
# Deliberately excludes generic words ("service", "online", "global") that ordinary businesses use in names.
SUB_LURES = {"login", "signin", "secure", "verify", "account", "support", "helpdesk", "portal", "wallet", "claim", "refund", "payment",
             "invoice", "billing", "update", "reset", "recovery", "unlock", "rebate", "reward", "gift", "bonus", "prize", "promo", "kyc",
             "confirm", "validate", "careers", "payroll", "benefits", "tracking", "delivery", "parcel", "customs", "office365", "teams",
             "access", "webmail", "password", "passwd", "auth"}
DICTIONARY = {"delta", "apple", "target", "shell", "next", "total", "visa", "ford", "gap", "ball", "match", "fox", "news", "general",
              "united", "american", "national", "equity", "global", "first", "energy", "cardinal", "key", "regions", "citizens",
              "principal", "hub", "arm", "sage", "intel", "zoom", "snap", "unity", "pool", "chase", "booking", "orange", "amazon",
              "meta", "block", "oracle", "discover", "progressive", "southern", "state", "street", "public", "storage", "tapestry",
              "corning", "dover", "eaton", "linde", "aptiv", "centene", "humana", "cigna", "aon", "chubb", "travelers", "allstate",
              "hartford", "loews", "assurant", "bunzl", "informa", "pearson", "reckitt", "legal", "admiral", "aviva", "halma",
              "howden", "croda", "smith", "smiths", "ashtead", "rightmove", "entain", "flutter", "games", "workshop", "segro",
              "severn", "trent", "united", "utilities", "whitbread", "wise", "prudential", "phoenix", "schroders", "barratt",
              "berkeley", "persimmon", "vodafone", "compass", "diageo", "experian", "relx", "sse", "bt", "bp", "axa", "ing", "kering",
              "engie", "orange", "safran", "thales", "vinci", "renault", "stellantis", "bayer", "basf", "siemens", "allianz", "adidas",
              "puma", "merck", "linde", "henkel", "beiersdorf", "continental", "infineon", "porsche", "symrise", "zalando", "brenntag",
              "capital", "one", "best", "buy", "home", "depot", "general", "mills", "dollar", "tree", "ross", "stores", "coach",
              "micron", "lumen", "vistra", "constellation", "republic", "waste", "management", "nvent", "keysight", "copart",
              "fortive", "ametek", "textron", "paccar", "halliburton", "baker", "hughes", "marathon", "valero", "phillips", "hess",
              "apa", "devon", "diamondback", "ecolab", "nucor", "steel", "dynamics", "mosaic", "clorox", "kroger", "sysco", "tyson",
              "hormel", "kenvue", "moderna", "illumina", "insulet", "resmed", "stryker", "zimmer", "biomet", "boston", "scientific",
              "abbott", "amgen", "gilead", "pfizer", "viatris", "incyte", "biogen", "regeneron", "vertex", "zoetis", "cencora",
              "mckesson", "labcorp", "quest", "diagnostics", "universal", "health", "services", "molina", "elevance", "cvs",
              "walgreens", "kraft", "heinz", "hershey", "kellanova", "campbell", "conagra", "lamb", "weston", "mondelez", "pepsico",
              "church", "dwight", "colgate", "palmolive", "kimberly", "clark", "estee", "lauder", "altria", "philip", "morris"}
# curated extra brand tokens for the most-impersonated organisations (keyed by primary domain)
BRAND_ALIASES = {
    "microsoft.com": ["microsoft", "ms365", "m365", "office365", "outlook", "onedrive", "sharepoint", "azure", "xbox", "msonline", "hotmail"],
    "amazon.com": ["amazon", "aws", "amazonaws", "primevideo"],
    "abc.xyz": ["google", "gmail", "youtube", "googledocs", "gdrive"],
    "meta.com": ["facebook", "instagram", "whatsapp"],
    "apple.com": ["apple", "icloud", "appleid", "itunes"],
    "paypal.com": ["paypal"], "netflix.com": ["netflix"], "coinbase.com": ["coinbase"], "adobe.com": ["adobe", "acrobat"],
    "docusign.com": ["docusign"], "salesforce.com": ["salesforce"], "hsbc.com": ["hsbc"], "barclays.com": ["barclays"],
    "jpmorganchase.com": ["jpmorgan", "chase"], "bankofamerica.com": ["bankofamerica", "bofa"], "wellsfargo.com": ["wellsfargo"],
    "americanexpress.com": ["amex", "americanexpress"], "visa.com": ["visa"], "mastercard.com": ["mastercard"],
    "dhl.com": ["dhl"], "fedex.com": ["fedex"], "ups.com": ["ups"], "att.com": ["att"], "comcast.com": ["comcast", "xfinity"],
    "societegenerale.com": ["societegenerale", "sgcib"], "bnpparibas.fr": ["bnpparibas", "bnp"], "ing.com": ["ing"],
    "oracle.com": ["oracle"], "cisco.com": ["cisco", "webex"], "okta.com": ["okta"], "nvidia.com": ["nvidia"],
}
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})


def _labels(domain: str) -> list[str]:
    d = domain.lower().strip(".")
    try:
        d = d.encode("ascii").decode("idna") if "xn--" in d else d
    except (UnicodeError, ValueError):
        pass
    rd = reg_domain(d)
    sfx = rd.split(".", 1)[1] if "." in rd else ""
    host = d[: -len(sfx) - 1] if sfx and d.endswith("." + sfx) else d
    return [x for x in re.split(r"[.\-_]", host) if x]


class BrandIndex:
    """orgs: [{"id", "name", "domain", "domains"}]. Tokens come from the organisation's own registered domains plus BRAND_ALIASES."""

    def __init__(self, orgs: list[dict]):
        self.token_org: dict[str, str] = {}
        self.strong: set[str] = set()
        self.distinctive: set[str] = set()  # curated aliases and long tokens: match as a whole label without a lure
        self.owned: dict[str, str] = {}
        self.own_labels: set[str] = set()  # second-level labels of the organisations' own domains ("essilorluxottica")
        for o in orgs:
            doms = [d for d in [o.get("domain")] + list(o.get("domains") or []) if d]
            for d in doms:
                self.owned[reg_domain(d)] = o["id"]
                self.own_labels.add(reg_domain(d).split(".")[0])
            toks = set()
            for d in doms:
                lab = reg_domain(d).split(".")[0]
                if len(lab) >= 3:
                    toks.add(lab)
            for d in doms:
                toks |= set(BRAND_ALIASES.get(reg_domain(d), []))
            name_key = norm(o.get("name") or "")
            for t in toks:
                t = t.lower()
                if t in self.token_org and self.token_org[t] != o["id"]:
                    continue  # first organisation keeps a shared token; ambiguous tokens stay weak below
                self.token_org[t] = o["id"]
                weak = len(t) < 6 or t in DICTIONARY or t in AMBIGUOUS or name_key in AMBIGUOUS
                if not weak:
                    self.strong.add(t)
                    if len(t) >= 10 or any(t in v for v in BRAND_ALIASES.values()):
                        self.distinctive.add(t)
        # hand-checked distinctive short tokens
        short = {t for t in ("ms365", "m365", "hsbc", "dhl", "fedex", "o365") if t in self.token_org}
        self.strong |= short
        self.distinctive |= short

    def owner(self, domain: str) -> str | None:
        return self.owned.get(reg_domain(domain))

    def match(self, domain: str) -> dict | None:
        """-> {"org_id", "token", "how"} or None. The organisation's own domains never match."""
        d = (domain or "").lower().strip(".")
        if not d or self.owner(d) or reg_domain(d) in PLATFORM:
            return None
        labels = _labels(d)
        if not labels:
            return None
        is_lure = lambda l: l in LURES or l.rstrip("0123456789") in LURES or bool(re.fullmatch(r"\d{1,4}", l))
        # 1. a whole label is the brand: distinctive brands match alone; others need a lure in the adjacent label
        for i, lab in enumerate(labels):
            for cand in {lab, lab.translate(_LEET)}:
                oid = self.token_org.get(cand)
                if not oid or (cand != lab and cand not in self.strong):  # digit swaps ("delt4") only count for strong brands
                    continue
                if cand in self.distinctive:
                    if cand == reg_domain(d).split(".")[0] and cand in self.own_labels:
                        return {"org_id": oid, "token": cand, "how": f"'{reg_domain(d)}' is the organisation's own name on another domain ending "
                                                                      "— may be its own site or a lookalike; verify ownership"}
                    return {"org_id": oid, "token": cand, "how": f"label '{lab}' is the brand token '{cand}'"}
                adj = [labels[j] for j in (i - 1, i + 1) if 0 <= j < len(labels)]
                lw = next((l for l in adj if is_lure(l)), None)
                if lw:
                    return {"org_id": oid, "token": cand, "how": f"brand token '{cand}' next to lure '{lw}'"}
        # 2. glued compounds, strong brands only: need a lure glued in ("dardengiftcard…") or a lure label elsewhere
        #    ("support-carrefour…"); a one-letter typo only for distinctive brands ("googlee")
        other_lure = lambda lab: next((l for l in labels if l != lab and is_lure(l)), None)
        for lab in labels:
            flat = lab.translate(_LEET)
            # prefix / suffix set look-ups (not a scan of every brand): fast enough for tens of thousands of indicators per run
            cands = [flat[:n] for n in range(6, len(flat))] + [flat[-n:] for n in range(6, len(flat))]
            for t in (c for c in cands if c in self.strong):
                if len(flat) > len(t) and (flat.startswith(t) or flat.endswith(t)):
                    rest = flat[len(t):] if flat.startswith(t) else flat[: -len(t)]
                    glued = next((l for l in SUB_LURES if l in rest), None)
                    if glued:
                        return {"org_id": self.token_org[t], "token": t, "how": f"'{lab}' joins the brand '{t}' with the lure '{glued}'"}
                    ol = other_lure(lab)
                    # brand-first compounds ("outlooksstoragefile") are typical lures; brand-last ones need a short prefix
                    # ("web07microsoft") — "thesugarista" is a word, not Arista
                    if ol and (flat.startswith(t) or len(rest) <= 5):
                        return {"org_id": self.token_org[t], "token": t, "how": f"'{lab}' contains the brand '{t}', next to lure '{ol}'"}
                    if t in self.distinctive and len(rest) == 1 and rest != "s":
                        return {"org_id": self.token_org[t], "token": t, "how": f"'{lab}' is a one-letter variant of the brand '{t}'"}
        return None


# What the lookalike pretends to be — first match wins; shown as the "lure theme" concentration on the Impersonation page
LURE_THEMES = [
    ("Help desk & IT support", r"help-?desk|service-?desk|it-?support|support|helpline"),
    ("Microsoft 365 & collaboration", r"ms365|m365|o365|office365|outlook|owa|teams|sharepoint|onedrive|hotmail|docs|drive|meet|share|webex|zoom"),
    ("Login & account security", r"log-?in|sign-?in|sso|auth|verif|account|secure|mfa|2fa|otp|passw|reset|recover|unlock|session|identity|\bid\b"),
    ("Payments, rewards & gift cards", r"pay|invoice|billing|refund|rebate|reward|gift|prize|bonus|promo|pressie|voucher|card|claim|member"),
    ("Careers & HR", r"career|jobs?\b|recruit|hiring|payroll|benefit|\bhr\b"),
    ("Cloud & API infrastructure", r"aws|amazonaws|(us|eu|ap)-(east|west|central|north|south)|region|cloud|api|cdn|static|console|\bs3\b|storage"),
    ("Delivery & logistics", r"deliver|track|parcel|customs|shipping|courier"),
    ("Crypto & investment", r"crypto|coin|wallet|exchange|trade|invest|defi|token"),
    ("Software update & downloads", r"update|download|install|\bapp\b|apk|patch|client"),
]
_LURE_RX = [(n, re.compile(p, re.I)) for n, p in LURE_THEMES]


def lure_theme(domain: str) -> str:
    """The lure a lookalike domain uses, from its labels (TLD excluded) — explainable, first match wins."""
    text = " ".join(_labels(host_of(domain)))
    for name, rx in _LURE_RX:
        if rx.search(text):
            return name
    return "Brand name only"


def host_of(value: str) -> str:
    v = (value or "").strip().lower()
    v = re.sub(r"^[a-z]+://", "", v).split("/")[0].split("?")[0]
    return v.split(":")[0] if v.count(":") == 1 else v
