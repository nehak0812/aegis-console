"""Theme taxonomy and keyword extraction — deterministic, explainable, no LLM.

Each theme is matched by readable regex patterns so an analyst can see exactly why an article was tagged.
Themes are grouped into the same families the console uses to organise the entity view.
"""
import re

# family -> theme -> patterns
THEME_TREE: dict[str, dict[str, list[str]]] = {
    "Attack types": {
        "Ransomware & extortion": [r"ransomware", r"extortion", r"leak site", r"double extortion", r"encrypt(ed|ion) (files|systems)"],
        "Data breach & leak": [r"data breach", r"breach(ed)?\b", r"data leak", r"leaked (data|database|records)", r"exposed (data|records|database)", r"stolen data"],
        "Phishing & social engineering": [r"phishing", r"smishing", r"vishing", r"social engineering", r"help ?desk (scam|impersonat)", r"clickfix", r"fake captcha"],
        "Business email compromise": [r"business email compromise", r"\bBEC\b", r"invoice fraud", r"wire fraud"],
        "DDoS": [r"\bddos\b", r"denial[- ]of[- ]service", r"botnet flood"],
        "Supply-chain compromise": [r"supply[- ]chain", r"third[- ]party (breach|vendor|provider|compromise)", r"software update (compromise|hijack)", r"malicious (package|npm|pypi|extension)", r"dependency confusion", r"typosquat"],
        "Zero-day exploitation": [r"zero[- ]day", r"0-day", r"exploited in the wild", r"actively exploited", r"under active exploitation", r"mass exploitation"],
        "Espionage": [r"espionage", r"cyber ?spy", r"state[- ](sponsored|backed)", r"\bAPT\s?\d*\b", r"nation[- ]state"],
        "Destructive / wiper": [r"\bwiper\b", r"destructive (malware|attack)", r"sabotage"],
        "Insider threat": [r"insider threat", r"rogue (employee|insider)", r"disgruntled (employee|former)", r"north korean (it )?workers?"],
        "Autonomous / agentic intrusion": [r"(ai|agent|llm)[- ]orchestrated", r"autonomous (ai )?(agents?|intrusions?|attacks?|hacking|cyber ?attacks?|operations?|malware)",
                                           r"agentic (intrusions?|attacks?|hacking|malware|operations?|threats?)", r"agent swarms?", r"vibe[- ]hack",
                                           r"ai agents? (conducted|carried out|executed|compromised|breached)"],
        "DNS hijacking": [r"dns hijack", r"dns (tampering|poisoning|redirection)", r"domain hijack", r"captive[- ]portal (hijack|attack|abuse)",
                          r"rogue (wi-?fi|access points?)", r"evil twin"],
    },
    "Access & identity": {
        "Credential theft & infostealers": [r"infostealer", r"info-stealer", r"stealer (log|malware)", r"credential (theft|stuffing|harvest)", r"stolen credentials", r"lumma", r"redline", r"vidar", r"raccoon stealer", r"stealc"],
        "Initial access brokers": [r"initial access broker", r"\bIAB\b", r"access (for sale|being sold|sale)", r"selling access"],
        "MFA & identity bypass": [r"\bmfa\b.*(bypass|fatigue)", r"mfa bypass", r"session (hijack|token|cookie)", r"token theft", r"adversary[- ]in[- ]the[- ]middle", r"\bAiTM\b", r"oauth (abuse|consent|token)", r"identity provider", r"\bSSO\b"],
        "Account takeover": [r"account takeover", r"\bATO\b", r"sim[- ]swap"],
        "Device-code & token theft": [r"device[- ]code (phishing|flow|authentication|auth)", r"token (theft|replay|hijacking)", r"stolen (session |access |refresh )?tokens",
                                      r"primary refresh token", r"\bMSAL\b", r"consent phishing", r"illicit consent", r"oauth (tokens?|apps?) (abuse|theft|stolen)"],
    },
    "Exposure & vulnerability": {
        "Edge & VPN devices": [r"\bvpn\b", r"firewall", r"fortinet|fortigate|fortios|forticlient|fortiweb", r"ivanti|pulse secure|connect secure", r"citrix|netscaler", r"palo alto|pan-os|globalprotect", r"sonicwall", r"cisco (asa|ftd|ios xe)", r"f5 big-?ip", r"juniper", r"check point"],
        "Critical vulnerabilities": [r"critical (flaw|vulnerabilit|bug)", r"remote code execution", r"\bRCE\b", r"cvss (score of )?(9|10)", r"authentication bypass", r"patch (now|immediately|urgently)"],
        "Cloud misconfiguration & exposure": [r"misconfigur", r"exposed (bucket|database|elasticsearch|s3)", r"open (bucket|database)", r"publicly accessible", r"unsecured (server|database)"],
        "Cloud & SaaS platforms": [r"\baws\b|amazon web services", r"\bazure\b|entra id|microsoft 365|office 365", r"google cloud|\bgcp\b|workspace", r"salesforce", r"snowflake", r"okta", r"servicenow", r"atlassian|confluence|jira", r"sharepoint", r"kubernetes|container"],
        "Patch Tuesday & advisories": [r"patch tuesday", r"security update", r"security advisory", r"out-of-band"],
        "OT / ICS": [r"\bICS\b", r"\bSCADA\b", r"\bOT\b (network|security|systems)", r"operational technology", r"industrial control", r"\bPLC\b"],
    },
    "Adversary & ecosystem": {
        "Hacktivism": [r"hacktivis", r"noname057", r"killnet", r"anonymous sudan", r"cyber army", r"pro-(russian|palestinian|iranian|israeli) (hackers|group)"],
        "Dark-web markets & forums": [r"dark ?web", r"breachforums|breach forums", r"\bxss\.is\b|xss forum", r"exploit\.in|exploit forum", r"underground forum", r"darknet market", r"telegram channel"],
        # named police operations are capitalised ("Operation Endgame"); the case-sensitive group and the look-behinds keep
        # "covert influence operation Doppelganger" out of this theme (it was mis-tagged before 2.2)
        "Law enforcement & takedowns": [r"takedown", r"arrest(ed)?", r"seized", r"indict(ed|ment)", r"sanction(ed|s)", r"extradit",
                                        r"(?<!nfluence )(?<!nformation )(?<!overt )(?<!yber )(?-i:Operation [A-Z][a-z]+)", r"europol|fbi|doj|nca\b"],
        "Cybercrime economy": [r"ransom (payment|paid|demand)", r"cryptocurrency (theft|laundering)", r"crypto (heist|drain)", r"money mule", r"malware[- ]as[- ]a[- ]service", r"ransomware[- ]as[- ]a[- ]service|\bRaaS\b"],
        "Influence operations & FIMI": [r"influence (operations?|campaigns?|networks?|ops)", r"\bFIMI\b", r"coordinated inauthentic", r"disinformation",
                                        r"propaganda (networks?|campaigns?)", r"fake news (sites?|networks?|outlets?)", r"doppelganger", r"storm-1516", r"copycop", r"spamouflage"],
    },
    "AI & emerging": {
        "AI-enabled attacks": [r"(ai|llm|chatgpt|gemini|claude)[- ](generated|powered|assisted|enabled) (phishing|malware|attack)", r"deepfake", r"voice clon", r"ai agents? (abuse|attack)", r"weaponi[sz]ed ai"],
        "AI system security": [r"prompt injection", r"jailbreak", r"model (theft|poisoning|extraction)", r"data poisoning", r"\bMCP\b server", r"ai agent (security|risk|vulnerab)", r"llm (vulnerab|security)"],
        "AI governance & regulation": [r"ai act", r"ai (governance|regulation|policy)", r"responsible ai", r"ai safety"],
        "Quantum & crypto-agility": [r"post-quantum", r"quantum[- ](safe|resistant|computing)", r"\bPQC\b"],
        "AI incidents & harms": [r"\bAI incident", r"ai (harm|failure|mishap)s?\b"],
        "Offensive AI frameworks": [r"pentagi", r"hexstrike", r"offensive (ai|llm) (tools?|frameworks?|agents?)",
                                    r"ai[- ](powered|driven|native) (pentest(ing)?|penetration[- ]testing|red[- ]team(ing)?|hacking) (tools?|frameworks?|agents?|platforms?)"],
        "AI supply chain & key theft": [r"(ai|llm|openai|anthropic|claude|gemini) api keys?", r"(leaked|stolen|exposed) (ai|llm|api) (keys?|credits|accounts?)", r"llmjacking",
                                        r"malicious (models?|mcp servers?|ai (packages?|extensions?|models?))", r"model (hub|repository) (malware|poisoning)",
                                        r"\b(litellm|langflow|mlflow|ollama|vllm|n8n)\b", r"slopsquat", r"pickle (exploit|malware|deserializ)"],
        "AI-enabled fraud & romance scams": [r"romance scams?", r"pig[- ]butchering", r"(ai|llm)[- ](generated|powered|driven) (scams?|fraud|personas?)",
                                             r"fake (dating|investment|trading) (apps?|platforms?)", r"synthetic identit", r"kyc (bypass|fraud|evasion)",
                                             r"deepfake (kyc|identity|video calls?)"],
        "Illicit distillation & AI resellers": [r"distillation (attacks?|campaigns?)", r"(illicit|unauthori[sz]ed) (model )?distillation",
                                                r"(ai|api|llm) (resellers?|proxy (services?|resellers?))", r"(discount|cheap) (claude|chatgpt|api) (access|credits|keys?)",
                                                r"(api|llm) routers?"],
    },
    "Governance & regulation": {
        "Disclosure & reporting": [r"8-k", r"item 1\.05", r"material cybersecurity incident", r"disclos(ed|ure) (to|with) (the )?sec", r"notif(ied|ication) (regulators|authorities)", r"breach notification"],
        "Regulation & enforcement": [r"\bnis ?2\b", r"\bdora\b", r"\bgdpr\b", r"\bcircia\b", r"\bhipaa\b", r"\bfine[ds]?\b", r"penalt(y|ies)", r"regulator", r"\bico\b|\bftc\b|\bsec charges\b", r"cyber resilience act"],
        "Resilience & outages": [r"\boutage\b", r"service disruption", r"downtime", r"systems (offline|down)", r"business continuity"],
        "Critical infrastructure": [r"critical infrastructure", r"water (utility|system|treatment)", r"power grid|electric(ity)? grid", r"pipeline", r"\bport\b (of|operations)", r"airport", r"hospital"],
        "Export-control evasion": [r"export[- ]controls?", r"sanctions? evasion", r"dual[- ]use (goods|items|technolog)", r"(chip|semiconductor|gpu)s? smuggl",
                                   r"transshipment", r"diversion of (goods|chips|technology)"],
    },
}

SECTORS: dict[str, list[str]] = {
    "Healthcare": [r"hospital", r"health ?care", r"healthcare", r"medical", r"clinic", r"pharma", r"patient data", r"\bNHS\b", r"health system"],
    "Financial services": [r"\bbank(s|ing)?\b", r"financial (services|institution)", r"insurer|insurance", r"fintech", r"credit union", r"brokerage", r"payment (processor|provider)"],
    "Government & public sector": [r"government", r"ministry", r"municipal", r"city of ", r"county", r"federal agenc", r"public sector", r"council\b"],
    "Education": [r"universit", r"school district", r"\bschools?\b", r"college", r"education"],
    "Manufacturing & industrial": [r"manufactur", r"industrial", r"factory|plant operations", r"automotive|carmaker"],
    "Energy & utilities": [r"\benergy\b", r"\boil\b|\bgas\b", r"utility|utilities", r"power (company|plant)", r"electric"],
    "Retail & consumer": [r"retail(er)?", r"e-?commerce", r"consumer", r"grocery", r"restaurant"],
    "Technology & telecom": [r"software (company|vendor|maker)", r"\bSaaS\b", r"telecom|telco", r"mobile (operator|carrier)", r"internet service provider|\bISP\b", r"cloud provider", r"managed service provider|\bMSP\b"],
    "Transport & logistics": [r"airline", r"aviation", r"shipping", r"logistics", r"railway|rail operator", r"transport"],
    "Legal & professional": [r"law firm", r"legal services", r"accounting firm", r"consult(ing|ancy) firm"],
}

_COMPILED = {fam: {t: re.compile("|".join(f"(?:{p})" for p in ps), re.I) for t, ps in themes.items()}
             for fam, themes in THEME_TREE.items()}
_SECT = {s: re.compile("|".join(f"(?:{p})" for p in ps), re.I) for s, ps in SECTORS.items()}
THEME_FAMILY = {t: fam for fam, themes in THEME_TREE.items() for t in themes}

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def themes_for(text: str) -> list[str]:
    out = []
    for fam, themes in _COMPILED.items():
        for t, rx in themes.items():
            if rx.search(text):
                out.append(t)
    return out


def sectors_for(text: str) -> list[str]:
    return [s for s, rx in _SECT.items() if rx.search(text)]


def cves_for(text: str) -> list[str]:
    return sorted({c.upper() for c in CVE_RE.findall(text or "")})


def theme_catalogue() -> list[dict]:
    return [{"family": fam, "theme": t, "patterns": ps} for fam, themes in THEME_TREE.items() for t, ps in themes.items()]
