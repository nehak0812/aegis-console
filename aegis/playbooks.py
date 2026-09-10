"""What to do about a finding — the step between "this is wrong" and someone fixing it.

Each entry answers the four questions a CISO asks of any finding: what does fixing this
actually prevent, who owns it, how much work is it, and what does the fix look like.

Control references are **indicative**. They point a reader at the relevant published
guidance; they are not an audit mapping and no compliance claim is made from them. Where
no reference is confidently known, the list is left empty rather than filled with a guess.
"""

# The five roles a preventive fix realistically lands on. Kept small on purpose: a longer
# list produces arguments about ownership instead of fixes.
OWNERS = ["Email & DNS administration", "IT operations", "Security operations",
          "Network engineering", "Procurement & vendor management"]
EFFORT = {"S": "hours", "M": "days", "L": "weeks, or a project"}

PLAYBOOKS: dict[str, dict] = {
    # --- email authentication ---------------------------------------------------------------
    "HYG-DMARC-NONE": {
        "owner": "Email & DNS administration", "effort": "M",
        "prevents": "Anyone sending mail that appears to come from your domain. This is the opening move in invoice fraud and credential phishing against your staff, customers and suppliers.",
        "steps": ["Publish a DMARC record at p=none with a rua address, and collect reports for two to four weeks.",
                  "Use the reports to find every legitimate sender — payroll, CRM, marketing, ticketing — and bring each under SPF or DKIM.",
                  "Move to p=quarantine, then to p=reject once the reports show no legitimate mail failing.",
                  "Set sp=reject so subdomains inherit the policy."],
        "controls": ["NIST SP 800-177 Rev. 1 §4.6", "NIST CSF 2.0 PR.DS-02"],
    },
    "HYG-SPF-MISSING": {
        "owner": "Email & DNS administration", "effort": "S",
        "prevents": "Receiving mail servers having no way to tell your mail from a forgery.",
        "steps": ["List every system that sends mail as this domain.",
                  "Publish a v=spf1 record naming those senders and ending in -all.",
                  "Confirm each sender still delivers before enforcing."],
        "controls": ["NIST SP 800-177 Rev. 1 §4.4"],
    },
    "HYG-SPF-SOFT": {
        "owner": "Email & DNS administration", "effort": "S",
        "prevents": "Forged mail being delivered anyway. ~all tells receivers to accept mail that failed the check.",
        "steps": ["Review DMARC reports to confirm every legitimate sender is already listed.",
                  "Change the record to end in -all.",
                  "Watch reports for a week for senders you missed."],
        "controls": ["NIST SP 800-177 Rev. 1 §4.4"],
    },
    "HYG-SPF-LOOKUPS": {
        "owner": "Email & DNS administration", "effort": "M",
        "prevents": "SPF failing silently. Past ten DNS lookups receivers return permerror and stop evaluating, so the record protects nothing while still looking correct.",
        "steps": ["Count the lookups: every include, a, mx, ptr, exists and redirect counts.",
                  "Remove includes for services you no longer send from — this is usually most of the excess.",
                  "Flatten or consolidate the remainder, or move senders onto a subdomain with its own record.",
                  "Re-test and confirm the record evaluates without permerror."],
        "controls": ["NIST SP 800-177 Rev. 1 §4.4", "RFC 7208 §4.6.4"],
    },
    "HYG-DKIM-NONE": {
        "owner": "Email & DNS administration", "effort": "M",
        "prevents": "Receivers being unable to prove your mail was not altered in transit, and DMARC having only SPF to rely on — which breaks whenever mail is forwarded.",
        "steps": ["Enable DKIM signing at each mail provider.",
                  "Publish the public key each provider gives you at its selector.",
                  "Confirm signatures verify, then require DKIM alignment in DMARC."],
        "controls": ["NIST SP 800-177 Rev. 1 §4.5"],
    },
    "HYG-MTASTS": {
        "owner": "Email & DNS administration", "effort": "M",
        "prevents": "An attacker downgrading inbound mail to plain text and reading it in transit. Without a policy, TLS is opportunistic and silently skippable.",
        "steps": ["Publish the policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt.",
                  "Publish the _mta-sts TXT record with a policy id.",
                  "Run in testing mode first, then move to enforce."],
        "controls": ["NIST SP 800-177 Rev. 1 §4.7", "NIST CSF 2.0 PR.DS-02"],
    },
    "HYG-TLSRPT": {
        "owner": "Email & DNS administration", "effort": "S",
        "prevents": "Failed inbound mail encryption going unnoticed. TLS-RPT is how you find out MTA-STS is misconfigured before someone else does.",
        "steps": ["Publish a _smtp._tls TXT record with a reporting address.",
                  "Route the reports to a monitored mailbox rather than an unread alias."],
        "controls": ["NIST SP 800-177 Rev. 1 §4.7"],
    },
    # --- DNS and domain ----------------------------------------------------------------------
    "HYG-DNSSEC": {
        "owner": "Email & DNS administration", "effort": "L",
        "prevents": "Forged DNS answers sending your customers and mail to an attacker's servers without touching your systems at all.",
        "steps": ["Confirm your DNS provider and registrar both support DNSSEC for this TLD.",
                  "Sign the zone and publish the DS record at the registrar.",
                  "Validate the chain resolves, and put key rollover on a schedule before you enable it.",
                  "Treat this as a change with rollback: a broken chain makes the domain unreachable."],
        "controls": ["NIST SP 800-81-2", "NIST CSF 2.0 PR.DS-02"],
    },
    "HYG-CAA": {
        "owner": "Email & DNS administration", "effort": "S",
        "prevents": "Any certificate authority in the world issuing a valid certificate for your domain. CAA restricts issuance to the ones you actually use.",
        "steps": ["List the certificate authorities your teams legitimately use, including those inside cloud services.",
                  "Publish CAA records naming only those, plus an iodef address for violation reports.",
                  "Re-check certificate transparency afterwards for issuance outside the policy."],
        "controls": ["NIST CSF 2.0 PR.DS-02", "RFC 8659"],
    },
    "HYG-NS-SINGLE": {
        "owner": "Email & DNS administration", "effort": "M",
        "prevents": "One provider outage taking your web, mail and every other service offline at once. DNS is the single dependency nothing else works without.",
        "steps": ["Decide whether single-provider DNS is an accepted risk for this domain — for many organisations it is.",
                  "If not, add a second provider and keep the zones synchronised.",
                  "Test failover before you need it."],
        "controls": ["NIST CSF 2.0 ID.AM-04"],
    },
    "DOM-LOCK": {
        "owner": "IT operations", "effort": "S",
        "prevents": "An unauthorised transfer moving the domain — and with it all your email and web traffic — to someone else. This is one of the cheapest controls available and it is usually just switched off.",
        "steps": ["Ask the registrar to apply clientTransferProhibited, clientUpdateProhibited and clientDeleteProhibited.",
                  "For a domain the business genuinely depends on, ask about registry lock, which requires manual verification for any change.",
                  "Turn on multi-factor authentication for the registrar account and confirm who has access.",
                  "Set the registrar contact to a monitored mailbox, not an individual's."],
        "controls": ["NIST CSF 2.0 ID.AM-01"],
    },
    "DOM-EXPIRY-30": {
        "owner": "IT operations", "effort": "S",
        "prevents": "The domain lapsing. Email and web stop, and once it drops the name can be registered by anyone — including someone who wants your mail.",
        "steps": ["Renew now, and renew for several years rather than one.",
                  "Enable auto-renew and confirm the payment card on file has not expired.",
                  "Put the expiry date in a calendar owned by a team, not a person."],
        "controls": ["NIST CSF 2.0 ID.AM-01"],
    },
    "DOM-EXPIRY-90": {
        "owner": "IT operations", "effort": "S",
        "prevents": "A renewal being missed while nobody is watching the date.",
        "steps": ["Confirm auto-renew is on and the payment method is valid.",
                  "Extend the registration term so this recurs less often."],
        "controls": ["NIST CSF 2.0 ID.AM-01"],
    },
    # --- certificates -------------------------------------------------------------------------
    "CRT-EXPIRY-14": {
        "owner": "IT operations", "effort": "S",
        "prevents": "A certificate expiring in production — a full outage on a live hostname, and one of the most common self-inflicted incidents there is.",
        "steps": ["Renew and deploy the certificate.",
                  "Automate renewal for this hostname so it does not recur.",
                  "Alert on certificates within 30 days of expiry, not 7."],
        "controls": ["NIST CSF 2.0 PR.DS-02"],
    },
    "CRT-CAA-VIOLATION": {
        "owner": "Security operations", "effort": "M",
        "prevents": "A certificate you did not sanction being trusted for your domain. Either a team is buying certificates outside the agreed process, or someone else obtained one.",
        "steps": ["Identify who requested the certificate — check the hostname against your own inventory first.",
                  "If it is a team of yours, bring them onto an approved certificate authority.",
                  "If nobody recognises it, treat it as possible mis-issuance and report it to the issuing authority for revocation.",
                  "Update the CAA record so the policy matches reality."],
        "controls": ["NIST CSF 2.0 PR.DS-02", "NIST CSF 2.0 DE.CM-01"],
    },
    # --- routing -------------------------------------------------------------------------------
    "BGP-RPKI-INVALID": {
        "owner": "Network engineering", "effort": "M",
        "prevents": "Traffic to your address space being diverted. An invalid announcement is either a hijack in progress or a stale authorisation — and until you check, you cannot tell which.",
        "steps": ["Check whether the announcement is yours. If it is not, this is a possible hijack: contact the announcing network and your upstreams now.",
                  "If it is yours, the ROA is wrong or stale — correct the origin AS and prefix length at your regional registry.",
                  "Re-validate and confirm the state clears.",
                  "Review every ROA you publish for the same error."],
        "controls": ["NIST SP 1800-14"],
    },
    "BGP-RPKI-NONE": {
        "owner": "Network engineering", "effort": "M",
        "prevents": "Networks that filter on RPKI being unable to tell a hijack of your prefix from a legitimate announcement — so they accept both.",
        "steps": ["Create Route Origin Authorisations at your regional internet registry for every prefix you announce.",
                  "Set the maximum prefix length deliberately; too permissive re-opens more-specific hijacks.",
                  "Validate, then ask your upstream providers to drop RPKI-invalid routes."],
        "controls": ["NIST SP 1800-14"],
    },
    # --- lookalike domains ----------------------------------------------------------------------
    "LOOK-MX": {
        "owner": "Security operations", "effort": "M",
        "prevents": "Invoice fraud and credential phishing from a domain that reads as yours. An MX record means it is set up to receive replies — that is preparation, not coincidence.",
        "steps": ["Check certificate transparency and the site itself for evidence of an active phishing page.",
                  "Block the domain at your mail gateway and web proxy, and add it to your detection rules.",
                  "Warn finance and any customer-facing team, since these domains target payment redirection.",
                  "Consider a takedown request through the registrar, and register the closest variants yourself."],
        "controls": ["NIST CSF 2.0 DE.CM-01", "NIST CSF 2.0 PR.AT-01"],
    },
    "LOOK-LIVE": {
        "owner": "Security operations", "effort": "S",
        "prevents": "A confusable domain being used against your staff or customers before you have heard of it.",
        "steps": ["Check what it currently serves — some are parked, some are yours already.",
                  "Add it to gateway blocklists if it is not yours.",
                  "Keep watching it: a parked lookalike often gains an MX record before a campaign."],
        "controls": ["NIST CSF 2.0 DE.CM-01"],
    },
    # --- exposed surface -------------------------------------------------------------------------
    "SURF-RISKY-PORT": {
        "owner": "IT operations", "effort": "M",
        "prevents": "Remote administration and database services being reachable from the whole internet. These are found by mass scanning within hours and are a standard route to ransomware.",
        "steps": ["Confirm the service should be reachable at all — usually it should not.",
                  "Put it behind the VPN or a zero-trust proxy, or restrict it to known source addresses.",
                  "If it must stay public, enforce multi-factor authentication and rate limiting, and monitor it.",
                  "Re-scan to confirm the port is closed."],
        "controls": ["NIST CSF 2.0 PR.IR-01", "CIS Controls v8 4.1", "CIS Controls v8 12.1"],
    },
    "SURF-EDGE-KEV": {
        "owner": "Security operations", "effort": "M",
        "prevents": "Exploitation of an internet-facing appliance of a type attackers are actively exploiting right now. Edge devices are the most common initial access route in ransomware.",
        "steps": ["Identify the exact product and version on each listed hostname.",
                  "Check it against the CISA KEV entry and apply the vendor fix or mitigation now.",
                  "Assume compromise if the device was unpatched while the flaw was being exploited: review logs, sessions and configuration for changes.",
                  "Rotate credentials and any VPN or session tokens the device holds."],
        "controls": ["NIST CSF 2.0 ID.RA-01", "NIST CSF 2.0 PR.PS-02", "CIS Controls v8 7.1"],
    },
    "SURF-EDGE": {
        "owner": "IT operations", "effort": "S",
        "prevents": "Edge devices going unmanaged. This is inventory rather than a fault — but you cannot patch what you have not written down.",
        "steps": ["Confirm each appliance is in your asset inventory and has a named owner.",
                  "Confirm it is in scope for patching and for log collection.",
                  "Remove anything no longer in use."],
        "controls": ["NIST CSF 2.0 ID.AM-01", "CIS Controls v8 1.1"],
    },
    "SURF-TAKEOVER": {
        "owner": "IT operations", "effort": "S",
        "prevents": "Subdomain takeover. The CNAME points at a cloud resource that no longer exists, so anyone can claim that resource and serve content from your hostname — with a valid certificate.",
        "steps": ["Remove the dangling DNS record, or re-claim the cloud resource it points to.",
                  "Check whether anyone else has already claimed it.",
                  "Add decommissioning of DNS records to your cloud teardown process — this is where they come from."],
        "controls": ["NIST CSF 2.0 ID.AM-01", "NIST CSF 2.0 PR.IR-01"],
    },
    "SURF-LARGE": {
        "owner": "IT operations", "effort": "L",
        "prevents": "An external footprint too large to govern, where forgotten hosts stay unpatched because nobody knows they exist.",
        "steps": ["Reconcile the certificate transparency hostnames against your asset inventory.",
                  "Retire what is no longer used, starting with pre-production names exposed publicly.",
                  "Give every remaining hostname a named owner."],
        "controls": ["NIST CSF 2.0 ID.AM-01", "CIS Controls v8 1.1"],
    },
    # --- vulnerabilities --------------------------------------------------------------------------
    "VUL-KEV-EXPOSED": {
        "owner": "Security operations", "effort": "M",
        "prevents": "Exploitation of a flaw that is confirmed to be exploited in the wild, on a host anyone can reach. This is the highest-value patch you can apply today.",
        "steps": ["Patch or apply the vendor mitigation on the affected host now.",
                  "Check the CISA KEV due date as an indicative deadline.",
                  "Look for signs the flaw was already used before you patched.",
                  "Confirm the fix by re-scanning the host."],
        "controls": ["NIST CSF 2.0 ID.RA-01", "NIST CSF 2.0 PR.PS-02", "CIS Controls v8 7.1"],
    },
    "VUL-EXPOSED-HIGH": {
        "owner": "Security operations", "effort": "M",
        "prevents": "Exploitation of a flaw with a public exploit or a high predicted exploitation probability, on an internet-facing host.",
        "steps": ["Patch on your normal high-priority cycle.",
                  "If you cannot patch quickly, restrict access to the service in the meantime.",
                  "Re-scan to confirm."],
        "controls": ["NIST CSF 2.0 ID.RA-01", "CIS Controls v8 7.1"],
    },
    "VUL-EXPOSED": {
        "owner": "IT operations", "effort": "M",
        "prevents": "Known vulnerable software staying exposed. Version-inferred, so confirm before acting.",
        "steps": ["Confirm the reported version is accurate — index data infers it from banners.",
                  "Bring the host into the normal patch cycle.",
                  "Reduce what the host exposes publicly."],
        "controls": ["NIST CSF 2.0 PR.PS-02", "CIS Controls v8 7.1"],
    },
    # --- compromise and exposure -------------------------------------------------------------------
    "CMP-C2": {
        "owner": "Security operations", "effort": "M",
        "prevents": "An address inside your own network operating as attacker infrastructure. Treat this as an active incident, not a hygiene item.",
        "steps": ["Identify and isolate the host behind the address.",
                  "Open an incident: this indicates compromise, not misconfiguration.",
                  "Preserve evidence before rebuilding, and check what else that host could reach.",
                  "Confirm the listing clears once remediated."],
        "controls": ["NIST CSF 2.0 DE.CM-01", "NIST CSF 2.0 RS.MA-01"],
    },
    "CMP-ABUSE": {
        "owner": "Security operations", "effort": "M",
        "prevents": "Your address space being used for attacks against others, which also damages your mail and network reputation.",
        "steps": ["Identify the host and what it is sending.",
                  "Remediate, then request delisting from the relevant blocklist.",
                  "Check whether the same weakness exists on neighbouring hosts."],
        "controls": ["NIST CSF 2.0 DE.CM-01"],
    },
    "DW-STEALER-30": {
        "owner": "Security operations", "effort": "M",
        "prevents": "An attacker logging in with valid credentials and a stolen session cookie, which bypasses multi-factor authentication entirely.",
        "steps": ["Force a password reset and revoke all active sessions and refresh tokens for affected staff.",
                  "Tighten conditional access — device compliance, not just multi-factor.",
                  "Rebuild the infected devices rather than cleaning them.",
                  "Check for logins from unusual locations in the period since infection."],
        "controls": ["NIST CSF 2.0 PR.AA-01", "NIST CSF 2.0 PR.AA-05"],
    },
    "DW-STEALER-EMP": {
        "owner": "Security operations", "effort": "M",
        "prevents": "Older credential theft still being usable because nothing was rotated at the time.",
        "steps": ["Rotate credentials for the affected accounts and revoke long-lived sessions.",
                  "Confirm those accounts have phishing-resistant multi-factor authentication.",
                  "Review whether corporate credentials are being used on personal devices."],
        "controls": ["NIST CSF 2.0 PR.AA-01"],
    },
    "BR-PUBLIC-90": {
        "owner": "Security operations", "effort": "M",
        "prevents": "Reuse of credentials exposed in a third-party breach against your own systems.",
        "steps": ["Force resets for accounts matching the breached domain.",
                  "Check the breached credentials against your own directory for reuse.",
                  "Confirm your notification obligations with legal and privacy."],
        "controls": ["NIST CSF 2.0 PR.AA-01", "NIST CSF 2.0 RS.CO-02"],
    },
    # --- third parties -----------------------------------------------------------------------------
    "TP-VENDOR-INC": {
        "owner": "Procurement & vendor management", "effort": "M",
        "prevents": "A supplier's incident becoming yours while nobody has asked them anything. Your DNS shows you depend on them.",
        "steps": ["Ask the supplier five factual questions: scope, whether your data is affected, containment status, indicators to search for, and timeline.",
                  "Search your own logs for the indicators they provide.",
                  "Review what access and data the supplier holds, and revoke what is no longer needed.",
                  "Check contractual and regulatory notification duties with legal — do not assume one applies."],
        "controls": ["NIST CSF 2.0 GV.SC-01", "NIST CSF 2.0 GV.SC-08"],
    },
    # --- active threat, where there is still something to do -------------------------------------
    "DW-ACCESS-14": {
        "owner": "Security operations", "effort": "M",
        "prevents": "A broker selling working access to your network to a ransomware crew. This is the step immediately before an intrusion, and it is the most valuable warning on this platform.",
        "steps": ["Treat as an active investigation, not a hygiene item — the claim is that access already exists.",
                  "Review remote access first: VPN, RDP, Citrix and any admin panel exposed to the internet.",
                  "Force password resets and revoke sessions for privileged and remote-access accounts.",
                  "Hunt for unfamiliar logins, new accounts and new persistence in the period covered by the claim.",
                  "Remember the claim is unverified — confirm before escalating externally."],
        "controls": ["NIST CSF 2.0 DE.CM-01", "NIST CSF 2.0 PR.AA-05", "NIST CSF 2.0 RS.MA-01"],
    },
    "DW-LEAK-30": {
        "owner": "Security operations", "effort": "L",
        "prevents": "Nothing at this stage — the listing means data is already claimed to be taken. What remains is containment, obligation and preventing a repeat.",
        "steps": ["Open a major incident and confirm whether the claim is genuine before responding publicly.",
                  "Establish what data the group actually holds, from their own sample rather than their claim.",
                  "Engage legal and privacy on notification duties, and communications on customer messaging.",
                  "Once contained, find the entry route and close it — otherwise the same group returns."],
        "controls": ["NIST CSF 2.0 RS.MA-01", "NIST CSF 2.0 RS.CO-02", "NIST CSF 2.0 RC.RP-01"],
    },
    "DW-FORUM-30": {
        "owner": "Security operations", "effort": "M",
        "prevents": "Credentials or data offered for sale being bought and used while nobody has checked whether the claim is real.",
        "steps": ["Assess whether the claim is credible — many are recycled or invented.",
                  "If it names a system, verify that system's exposure and access logs.",
                  "Rotate any credentials the claim plausibly covers.",
                  "Record the assessment either way, so a repeat claim can be compared."],
        "controls": ["NIST CSF 2.0 DE.CM-01", "NIST CSF 2.0 PR.AA-01"],
    },
    "DW-DDOS-7": {
        "owner": "Network engineering", "effort": "M",
        "prevents": "An availability outage from a hacktivist campaign that has already published you as a target — one of the few attacks you get warning of.",
        "steps": ["Confirm the named hosts are behind DDoS protection, and that it is in active rather than monitoring mode.",
                  "Check the protection covers the actual origin, not just the CDN hostname.",
                  "Confirm your provider escalation path and who can authorise mitigation out of hours.",
                  "Watch the listed hosts for the campaign window."],
        "controls": ["NIST CSF 2.0 PR.IR-04", "NIST CSF 2.0 RS.MA-01"],
    },
    "THR-SECTOR": {
        "owner": "Security operations", "effort": "M",
        "prevents": "Being unprepared for the techniques currently being used against organisations like yours. Context rather than a fault.",
        "steps": ["Review which groups are active in your sector and country, and what they are known to use.",
                  "Check your detections cover their common initial access routes — phishing, exposed edge devices, valid accounts.",
                  "Use it to prioritise this quarter's hardening, not to raise an alert."],
        "controls": ["NIST CSF 2.0 ID.RA-03", "NIST CSF 2.0 DE.CM-01"],
    },
    "TP-CONCENTRATION": {
        "owner": "Procurement & vendor management", "effort": "L",
        "prevents": "A single provider outage affecting far more of your estate than anyone realised. Inventory rather than a fault.",
        "steps": ["Record the dependency and what it would take down.",
                  "Confirm the recovery plan does not itself depend on the same provider.",
                  "Weigh a second provider against the cost for the services that matter most."],
        "controls": ["NIST CSF 2.0 GV.SC-04", "NIST CSF 2.0 ID.AM-04"],
    },
}


def playbook(rule_id: str) -> dict | None:
    """The playbook for a rule, or None where no preventive action applies."""
    p = PLAYBOOKS.get(rule_id)
    return {**p, "rule_id": rule_id, "effort_label": EFFORT.get(p["effort"], "")} if p else None


def catalogue() -> list[dict]:
    return [playbook(r) for r in PLAYBOOKS]


def coverage() -> dict:
    """Which rules have a playbook — surfaced on Sources & method so the gaps are visible."""
    from aegis.rating import RULES
    org_rules = [r for r, v in RULES.items() if v[1] == "organisation"]
    return {"rules": len(org_rules), "with_playbook": sum(1 for r in org_rules if r in PLAYBOOKS),
            "missing": [r for r in org_rules if r not in PLAYBOOKS]}
