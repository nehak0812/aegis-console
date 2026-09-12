"""Playbooks: for every organisation rule, who owns the fix, how big it is, what it prevents, the steps, and indicative control references.

The 58 playbooks in `playbooks_prod.json` are carried over verbatim from the production deployment (v2.0.1 + "Prevent"), so actions
raised there keep the same wording and owners. `EXTRA` adds the rules introduced in v2.2. Control references are labelled
"indicative" in the console; entries are left empty where a reference could not be stated with confidence.
"""
import json
import os

OWNERS = ["Email & DNS administration", "IT operations", "Security operations", "Network engineering",
          "Procurement & vendor management", "Legal & compliance"]
EFFORT = {"S": "hours", "M": "days", "L": "weeks, or a project"}

with open(os.path.join(os.path.dirname(__file__), "playbooks_prod.json"), encoding="utf-8") as fh:
    _BASE = {p["rule_id"]: p for p in json.load(fh)}

_TAKEDOWN = ["Add the domains to the mail- and web-gateway blocklists (Impersonation → blocklist export).",
             "Request takedown from the registrar and hosting provider, and report the URLs to Google Safe Browsing and Microsoft SmartScreen.",
             "Warn staff and, where customers are targeted, customers — name the lookalike and the lure.",
             "Watch for new registrations on the same pattern; AEGIS re-checks liveness daily."]

EXTRA = {
    "VUL-EPSS-SURGE": {"owner": "Security operations", "effort": "S",
                       "prevents": "Being caught unpatched when exploitation of software you run starts — the likelihood is rising before CISA confirms it.",
                       "steps": ["Confirm which of your exposed hosts run an affected version.",
                                 "Patch, or apply the vendor's mitigation, now rather than on the normal cycle.",
                                 "Add detection for exploitation attempts against the product.",
                                 "AEGIS re-checks the exposure on the next scan."],
                       "controls": ["NIST CSF 2.0 ID.RA-01"]},
    "TP-NAMED-CUSTOMER": {"owner": "Procurement & vendor management", "effort": "M",
                          "prevents": "Learning too late that a supplier's incident exposed your data or access.",
                          "steps": ["Ask the supplier five factual questions: scope, your data affected, containment, indicators, timeline.",
                                    "Identify what data and integrations you share with the supplier.",
                                    "Rotate credentials, API keys and tokens used by the integration.",
                                    "Check contractual and regulatory notification duties (for example DORA, NIS2, SEC) with Legal — do not assume one applies."],
                          "controls": ["NIST CSF 2.0 GV.SC-07"]},
    "AI-KEV-EXPOSED": {"owner": "Security operations", "effort": "M",
                       "prevents": "Takeover of an internet-facing AI service through a flaw attackers are already exploiting.",
                       "steps": ["Take the service off the internet or put it behind authentication and a VPN.",
                                 "Patch to a fixed version.",
                                 "Rotate model-provider API keys and secrets the service could read.",
                                 "Review logs for exploitation since the KEV date."],
                       "controls": ["NIST CSF 2.0 ID.RA-01"]},
    "AI-KEV-PRODUCT": {"owner": "IT operations", "effort": "S",
                       "prevents": "Running an exploited AI/ML product version on a public hostname.",
                       "steps": ["Confirm the product and version behind the hostname.", "Patch or remove public access.",
                                 "Rotate any keys the service stores."], "controls": []},
    "IOC-BRAND-LIVE": {"owner": "Security operations", "effort": "S",
                       "prevents": "Credential theft and fraud through a live lookalike of your brand named in threat reporting.",
                       "steps": _TAKEDOWN, "controls": []},
    "IOC-BRAND": {"owner": "Security operations", "effort": "S",
                  "prevents": "A lookalike of your brand named in threat reporting going live against your staff or customers.",
                  "steps": ["Pre-block the domains in mail and web gateways.", "Monitor for the domains resolving; request takedown if they go live."],
                  "controls": []},
    "IOC-OWN-DOMAIN": {"owner": "Security operations", "effort": "M",
                       "prevents": "A domain you own being used as attacker infrastructure.",
                       "steps": ["Find which system serves the named hostname and who runs it.",
                                 "Open an incident: a threat report names it as an indicator.",
                                 "Check DNS records, certificates and hosting for unauthorised changes.",
                                 "Confirm with the report author once cleaned."], "controls": ["NIST CSF 2.0 RS.MA-01"]},
    "IOC-OWN-IP": {"owner": "Security operations", "effort": "M",
                   "prevents": "An address in your own network operating as attacker infrastructure.",
                   "steps": ["Identify and isolate the host behind the address.", "Open an incident and preserve evidence before rebuilding.",
                             "Check what else the host could reach."], "controls": ["NIST CSF 2.0 RS.MA-01"]},
    "NRD-PHISH": {"owner": "Security operations", "effort": "S",
                  "prevents": "Phishing from a newly registered lookalike that is already live and on a phishing feed.", "steps": _TAKEDOWN, "controls": []},
    "NRD-LIVE": {"owner": "Security operations", "effort": "S",
                 "prevents": "Phishing or invoice fraud from a newly registered lookalike that already resolves.", "steps": _TAKEDOWN, "controls": []},
    "NRD-MATCH": {"owner": "Security operations", "effort": "S",
                  "prevents": "A newly registered lookalike being used once it goes live.",
                  "steps": ["Pre-block the domains in mail and web gateways.", "AEGIS re-checks liveness daily; request takedown if they go live."],
                  "controls": []},
    "PHISH-BRAND": {"owner": "Security operations", "effort": "S",
                    "prevents": "Customers or staff entering credentials on live phishing pages impersonating you.", "steps": _TAKEDOWN, "controls": []},
    "PHISH-TARGET": {"owner": "Security operations", "effort": "S",
                     "prevents": "Customers or staff entering credentials on verified phishing pages that target you.", "steps": _TAKEDOWN, "controls": []},
    "WEB-CLICKFIX": {"owner": "Security operations", "effort": "M",
                     "prevents": "Your own website tricking visitors into running malware (ClickFix fake-CAPTCHA lure).",
                     "steps": ["Treat the site as compromised: remove the injected script and find how it got there.",
                               "Patch the CMS and plugins; rotate admin and hosting credentials.",
                               "Check whether visitors were affected and whether notification is needed.",
                               "Ask the feed to delist the URL once clean."], "controls": ["NIST CSF 2.0 RS.MA-01"]},
    "WEB-MALWARE": {"owner": "Security operations", "effort": "M",
                    "prevents": "Your website or domain distributing malware.",
                    "steps": ["Remove the malicious content and find the entry point.", "Patch and rotate credentials.",
                              "Request delisting from the feed once clean."], "controls": []},
    "WEB-CMS-KEV": {"owner": "IT operations", "effort": "S",
                    "prevents": "Website takeover through a content-management flaw attackers already exploit.",
                    "steps": ["Confirm the CMS version.", "Patch to a fixed release, or apply a WAF virtual patch until you can.",
                              "Check for web shells and unexpected admin accounts."], "controls": ["NIST CSF 2.0 ID.RA-01"]},
    "DNS-NS-REPLACED": {"owner": "Email & DNS administration", "effort": "S",
                        "prevents": "A DNS hijack moving your web and mail traffic.",
                        "steps": ["Confirm with the registrar that the name-server change was planned.",
                                  "If not: lock the domain, reset registrar credentials and restore the name servers.",
                                  "Check certificate transparency for certificates issued since the change."], "controls": []},
    "DNS-MX-MOVED": {"owner": "Email & DNS administration", "effort": "S",
                     "prevents": "Mail being intercepted after an unauthorised change of mail provider.",
                     "steps": ["Confirm the MX change was planned.", "If not: restore the records, lock the domain and reset registrar and DNS-provider credentials."],
                     "controls": []},
    "DNS-DNSSEC-LOST": {"owner": "Email & DNS administration", "effort": "S",
                        "prevents": "DNS forgery after DNSSEC was removed — often a step before a hijack.",
                        "steps": ["Confirm the removal was intended (for example a DNS-provider migration).", "Re-sign the zone and publish the DS record again."],
                        "controls": []},
    "DNS-CAA-REMOVED": {"owner": "Email & DNS administration", "effort": "S",
                        "prevents": "Any certificate authority being able to issue certificates for your domain.",
                        "steps": ["Confirm the removal was intended.", "Publish CAA again, listing only the authorities you use."], "controls": []},
}

PLAYBOOKS = {**_BASE, **{k: {**v, "rule_id": k} for k, v in EXTRA.items()}}


def playbook(rule_id: str | None) -> dict | None:
    p = PLAYBOOKS.get(rule_id or "")
    return {**p, "effort_label": EFFORT.get(p.get("effort"), "")} if p else None


def coverage(rule_ids) -> dict:
    ids = sorted(set(rule_ids))
    missing = [r for r in ids if r not in PLAYBOOKS]
    return {"rules": len(ids), "with_playbook": len(ids) - len(missing), "missing": missing}
