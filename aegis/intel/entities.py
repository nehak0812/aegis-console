"""Organisation matching: domain (confidence A), exact normalised name (B), text mention (C).

Short or dictionary-word names ("Target", "Shell", "Apple") only match in text when written with their
capitalisation and never as part of a longer word; a stop-list forces a legal-form match for the most
ambiguous ones.
"""
import re
import threading

from aegis import db

SUFFIXES = r"(,?\s+(inc|incorporated|corp|corporation|co|company|plc|p\.l\.c|ltd|limited|llc|lp|ag|se|sa|s\.a|nv|n\.v|bv|asa|ab|oyj|spa|s\.p\.a|holdings?|group|the|class [a-c]|/[a-z]+/))+\.?$"
AMBIGUOUS = {"target", "shell", "apple", "visa", "ford", "oracle", "amazon", "meta", "block", "gap", "ball", "match",
             "fox", "news", "discover", "progressive", "southern", "general", "united", "american", "state street",
             "national", "public storage", "equity", "global", "first", "energy", "cardinal", "key", "regions",
             "citizens", "principal", "hub", "on", "arm", "sage", "next", "tesco", "bt", "intel", "zoom", "snap",
             "unity", "pool", "chase", "booking", "salesforce", "texas instruments", "genuine parts", "corning",
             "nordson", "fastenal", "gartner", "cummins", "paychex", "leidos", "dover", "eaton", "linde", "trane",
             "moody's", "aptiv", "baxter", "hershey", "kellogg", "mattel", "tapestry", "dollar tree", "lennar",
             "iron mountain", "prologis", "welltower", "centene", "humana", "cigna", "elevance", "aon", "chubb",
             "travelers", "allstate", "hartford", "loews", "assurant", "brown & brown", "globe life"}


def norm(name: str) -> str:
    n = (name or "").lower().strip()
    n = n.replace("&", " and ").replace("’", "'")
    n = re.sub(SUFFIXES, "", n)
    n = re.sub(r"[^\w\s']", " ", n)
    return re.sub(r"\s+", " ", n).strip()


def reg_domain(host: str) -> str:
    h = (host or "").lower().strip()
    h = re.sub(r"^[a-z]+://", "", h).split("/")[0].split(":")[0]
    h = h[4:] if h.startswith("www.") else h
    parts = h.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "ac", "gov"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


# ISO-3166 alpha-2 → display name, mirroring COUNTRY in web/src/lib/format.ts.
COUNTRY_NAME = {
    "US": "United States", "GB": "United Kingdom", "DE": "Germany", "FR": "France", "NL": "Netherlands", "CH": "Switzerland",
    "ES": "Spain", "IT": "Italy", "IE": "Ireland", "SE": "Sweden", "NO": "Norway", "DK": "Denmark", "FI": "Finland",
    "BE": "Belgium", "AT": "Austria", "CA": "Canada", "AU": "Australia", "JP": "Japan", "IN": "India", "BR": "Brazil",
    "MX": "Mexico", "LU": "Luxembourg", "PT": "Portugal", "PL": "Poland", "CN": "China", "KR": "South Korea",
    "SG": "Singapore", "IL": "Israel", "AE": "UAE", "SA": "Saudi Arabia", "ZA": "South Africa", "TW": "Taiwan",
    "HK": "Hong Kong", "RU": "Russia", "IR": "Iran", "KP": "North Korea", "UA": "Ukraine", "TR": "Turkey",
    "AR": "Argentina", "CO": "Colombia", "CL": "Chile", "NZ": "New Zealand", "VN": "Vietnam", "PS": "Palestine",
    "LB": "Lebanon", "SY": "Syria", "PK": "Pakistan", "KZ": "Kazakhstan", "BY": "Belarus", "VE": "Venezuela",
    "EG": "Egypt", "GE": "Georgia", "CZ": "Czechia", "GR": "Greece", "RO": "Romania", "HU": "Hungary", "SK": "Slovakia",
    "TH": "Thailand", "MY": "Malaysia", "ID": "Indonesia", "PH": "Philippines", "NG": "Nigeria", "KE": "Kenya",
    "MA": "Morocco", "PE": "Peru", "QA": "Qatar", "KW": "Kuwait", "BH": "Bahrain", "OM": "Oman", "JO": "Jordan",
    "IQ": "Iraq", "LK": "Sri Lanka", "BD": "Bangladesh", "NP": "Nepal", "HR": "Croatia", "RS": "Serbia", "BG": "Bulgaria",
    "SI": "Slovenia", "EE": "Estonia", "LV": "Latvia", "LT": "Lithuania", "IS": "Iceland", "CY": "Cyprus", "MT": "Malta",
    "DO": "Dominican Republic", "PR": "Puerto Rico", "EC": "Ecuador", "UY": "Uruguay", "CR": "Costa Rica", "PA": "Panama",
}
_BY_NAME = {n.lower(): a for a, n in COUNTRY_NAME.items()}
_BY_NAME.update({
    "usa": "US", "u.s.": "US", "u.s.a.": "US", "united states of america": "US", "america": "US",
    "uk": "GB", "u.k.": "GB", "britain": "GB", "great britain": "GB", "england": "GB", "scotland": "GB", "wales": "GB",
    "united arab emirates": "AE", "emirates": "AE", "korea": "KR", "republic of korea": "KR", "dprk": "KP",
    "russian federation": "RU", "czech republic": "CZ", "holland": "NL", "the netherlands": "NL",
    "turkiye": "TR", "türkiye": "TR", "viet nam": "VN", "saudi": "SA", "kingdom of saudi arabia": "SA",
    "people's republic of china": "CN", "prc": "CN", "hong kong sar": "HK", "deutschland": "DE", "espana": "ES",
    "españa": "ES", "nippon": "JP", "bharat": "IN",
})


def country_code(raw):
    """Resolve free text to an ISO-3166 alpha-2 code.

    Returns (code, error). Truncating to two characters is not safe — 'Germany'
    would become 'GE', which is Georgia — so anything longer must resolve by name.
    """
    c = (raw or "").strip()
    if not c:
        return None, None
    # names and aliases first: 'UK' is a two-letter alias, but the ISO code is GB
    hit = _BY_NAME.get(c.lower())
    if hit:
        return hit, None
    # pass through any other well-formed code, since the table above is not exhaustive
    if len(c) == 2 and c.isalpha():
        return c.upper(), None
    return None, f"Country {c!r} was not recognised. Use an ISO-2 code such as IN, or a country name such as India."


class Matcher:
    def __init__(self):
        self._lock = threading.Lock()
        self._built_at = None
        self.by_domain: dict[str, str] = {}
        self.by_name: dict[str, str] = {}
        self._rx: re.Pattern | None = None
        self._rx_map: dict[str, str] = {}

    def build(self) -> None:
        orgs = db.q("SELECT id, name, legal_name, aliases, domain, domains FROM org")
        by_domain, by_name, text_terms = {}, {}, {}
        for o in orgs:
            for d in [o.get("domain")] + list(o.get("domains") or []):
                if d:
                    by_domain[reg_domain(d)] = o["id"]
            names = {o["name"], o.get("legal_name") or ""} | set(o.get("aliases") or [])
            for n in names:
                k = norm(n)
                if len(k) >= 3:
                    by_name.setdefault(k, o["id"])
                    # text-mention terms: prefer the display form; ambiguous words need legal form
                    if k in AMBIGUOUS:
                        if n and norm(n) != n.lower().strip():  # has a legal suffix, e.g. "Target Corp"
                            text_terms[n.strip()] = o["id"]
                    elif len(k) >= 4:
                        disp = re.sub(SUFFIXES, "", n.strip(), flags=re.I).strip(" ,.")
                        if len(disp) >= 4:
                            text_terms[disp] = o["id"]
        by_sub = {}
        for s in db.q("SELECT org_id, attrs FROM asset WHERE kind='subsidiary'"):
            k = norm((s.get("attrs") or {}).get("name") or "")
            if len(k) >= 5 and k not in by_name:
                by_sub.setdefault(k, s["org_id"])
        pats = sorted(text_terms, key=len, reverse=True)
        with self._lock:
            self.by_domain, self.by_name, self.by_sub = by_domain, by_name, by_sub
            self._rx_map = {p.lower(): text_terms[p] for p in pats}
            # case-sensitive for single capitalised words, insensitive for multi-word names
            alts = [re.escape(p) for p in pats]
            self._rx = re.compile(r"(?<![\w@.-])(" + "|".join(alts) + r")(?![\w-])") if alts else None
            self._built_at = db.now()

    def ensure(self) -> None:
        if self._rx is None and not self.by_domain:
            self.build()

    def domain(self, host: str) -> str | None:
        self.ensure()
        return self.by_domain.get(reg_domain(host)) if host else None

    def name(self, name: str) -> str | None:
        self.ensure()
        return self.by_name.get(norm(name)) if name else None

    def resolve(self, name: str = "", host: str = "") -> tuple[str | None, str | None]:
        """-> (org_id, match_type) where match_type is 'domain' | 'name'."""
        oid = self.domain(host)
        if oid:
            return oid, "domain"
        oid = self.name(name)
        if oid:
            return oid, "name"
        oid = getattr(self, "by_sub", {}).get(norm(name)) if name else None
        if oid:
            return oid, "subsidiary"
        # leak-site victims are often posted as a bare domain
        if name and re.fullmatch(r"[\w.-]+\.[a-z]{2,}", name.strip().lower()):
            oid = self.domain(name)
            if oid:
                return oid, "domain"
        return None, None

    def mentions(self, text: str) -> list[str]:
        self.ensure()
        if not text or self._rx is None:
            return []
        found = []
        for m in self._rx.finditer(text):
            oid = self._rx_map.get(m.group(1).lower())
            if oid and oid not in found:
                found.append(oid)
        return found


matcher = Matcher()
