"""Passive fingerprint tables: public DNS records → the software, SaaS and third parties an organisation uses.
Every match stores the exact record as evidence, e.g. "MX mxa-00299f02.gslb.pphosted.com"."""
import re

# (regex, vendor, category)
MX = [
    (r"\.mail\.protection\.outlook\.com\.?$", "Microsoft 365", "Email & collaboration"),
    (r"(aspmx\.l\.google\.com|googlemail\.com|smtp\.google\.com)\.?$", "Google Workspace", "Email & collaboration"),
    (r"\.pphosted\.com\.?$", "Proofpoint", "Email security"), (r"\.ppe-hosted\.com\.?$", "Proofpoint Essentials", "Email security"),
    (r"\.mimecast\.(com|co\.za)\.?$", "Mimecast", "Email security"), (r"\.iphmx\.com\.?$", "Cisco Secure Email", "Email security"),
    (r"\.barracudanetworks\.com\.?$", "Barracuda", "Email security"), (r"\.messagelabs\.com\.?$", "Broadcom Email Security", "Email security"),
    (r"\.fireeyecloud\.com\.?$", "Trellix Email", "Email security"), (r"\.trendmicro\.(com|eu)\.?$", "Trend Micro Email", "Email security"),
    (r"\.sophos\.com\.?$", "Sophos Email", "Email security"), (r"\.mailcontrol\.com\.?$|\.forcepoint\.com", "Forcepoint", "Email security"),
    (r"\.hornetsecurity\.com\.?$", "Hornetsecurity", "Email security"), (r"\.mx\.cloudflare\.net\.?$", "Cloudflare Email Security", "Email security"),
    (r"\.zoho\.(com|eu|in)\.?$", "Zoho Mail", "Email & collaboration"), (r"inbound-smtp\..*\.amazonaws\.com", "Amazon SES / WorkMail", "Email & collaboration"),
]
NS = [
    (r"\.ns\.cloudflare\.com\.?$|secondary\.cloudflare\.com", "Cloudflare", "DNS & CDN"), (r"\.akam\.net\.?$|akamaidns", "Akamai", "DNS & CDN"),
    (r"\.awsdns-\d+\.", "AWS Route 53", "Cloud platform"), (r"\.azure-dns\.(com|net|org|info)\.?$", "Azure DNS", "Cloud platform"),
    (r"ns-cloud-.*\.googledomains\.com", "Google Cloud DNS", "Cloud platform"),
    (r"\.ultradns\.(com|net|org|biz|info|co\.uk)\.?$", "Vercara UltraDNS", "DNS & CDN"), (r"\.nsone\.net\.?$", "NS1 (IBM)", "DNS & CDN"),
    (r"\.dynect\.net\.?$", "Oracle Dyn", "DNS & CDN"), (r"\.cscdns\.(net|uk)\.?$", "CSC", "Domain registrar & DNS"),
    (r"\.markmonitor\.com\.?$", "MarkMonitor", "Domain registrar & DNS"), (r"\.domaincontrol\.com\.?$", "GoDaddy", "Domain registrar & DNS"),
    (r"\.dnsmadeeasy\.com\.?$", "DNS Made Easy", "DNS & CDN"), (r"\.verisigndns\.com\.?$", "Verisign DNS", "DNS & CDN"),
    (r"\.f5cloudservices\.com\.?$", "F5 Distributed Cloud", "DNS & CDN"), (r"\.incapdns\.net\.?$", "Imperva", "DNS & CDN"),
]
TXT = [
    (r"^MS=ms\d+", "Microsoft 365", "Email & collaboration"), (r"^d365mktkey=", "Microsoft Dynamics 365", "CRM & marketing"),
    (r"^google-site-verification=", "Google", "Email & collaboration"), (r"^atlassian-domain-verification=", "Atlassian", "Developer & collaboration"),
    (r"^docusign=", "DocuSign", "Business SaaS"), (r"^adobe-sign-verification=", "Adobe Acrobat Sign", "Business SaaS"),
    (r"^adobe-idp-site-verification=", "Adobe", "Business SaaS"), (r"^facebook-domain-verification=", "Meta Business", "CRM & marketing"),
    (r"^workplace-domain-verification=", "Meta Workplace", "Email & collaboration"), (r"^apple-domain-verification=", "Apple Business", "Device management"),
    (r"ZOOM_verify_", "Zoom", "Email & collaboration"), (r"^webexdomainverification", "Cisco Webex", "Email & collaboration"),
    (r"^cisco-ci-domain-verification=", "Cisco (Duo / Umbrella / Webex)", "Security"), (r"^duo_sso_verification=", "Cisco Duo", "Identity & access"),
    (r"^_?github-challenge|^github-verification", "GitHub", "Developer & collaboration"), (r"^docker-verification=", "Docker", "Developer & collaboration"),
    (r"^linear-domain-verification=", "Linear", "Developer & collaboration"), (r"^hcp-domain-verification=", "HashiCorp", "Cloud platform"),
    (r"^mongodb-site-verification=", "MongoDB Atlas", "Cloud platform"), (r"^salesforce-|^sfdc-", "Salesforce", "CRM & marketing"),
    (r"^pardot", "Salesforce Pardot", "CRM & marketing"), (r"^stripe-verification=", "Stripe", "Payments"),
    (r"^onetrust-domain-verification=", "OneTrust", "Security"), (r"^okta-verification=", "Okta", "Identity & access"),
    (r"^citrix-verification-code=", "Citrix Cloud", "Remote access"), (r"^miro-verification=", "Miro", "Developer & collaboration"),
    (r"^slack-domain-verification=", "Slack", "Email & collaboration"), (r"^dropbox-domain-verification=", "Dropbox", "File sharing"),
    (r"^box-domain-verification=", "Box", "File sharing"), (r"^hubspot-developer-verification=|^hubspot", "HubSpot", "CRM & marketing"),
    (r"^amazonses:", "Amazon SES", "Email delivery"), (r"^mandrill_verify\.", "Mailchimp", "Email delivery"),
    (r"^zendeskverification=", "Zendesk", "Business SaaS"), (r"^servicenow-", "ServiceNow", "Business SaaS"),
    (r"^workday", "Workday", "Business SaaS"), (r"^knowbe4-site-verification=", "KnowBe4", "Security"),
    (r"^pendo-domain-verification=", "Pendo", "Business SaaS"), (r"^mixpanel-domain-verify=", "Mixpanel", "Business SaaS"),
    (r"^sitecore-domain-verification=", "Sitecore", "Business SaaS"), (r"^jamf-site-verification=", "Jamf", "Device management"),
    (r"^infoblox-domain-mastery=", "Infoblox", "DNS & CDN"), (r"^wiz-domain-verification=", "Wiz", "Security"),
    (r"^sophos-domain-verification=", "Sophos", "Security"), (r"^_?globalsign-domain-verification=", "GlobalSign", "PKI & certificates"),
    (r"^_?digicert", "DigiCert", "PKI & certificates"), (r"^sectigo", "Sectigo", "PKI & certificates"),
    (r"^teamviewer-sso-verification=", "TeamViewer", "Remote access"), (r"^logmein-verification-code=", "GoTo (LogMeIn)", "Remote access"),
    (r"^lastpass-verification-code=", "LastPass", "Identity & access"), (r"^1password-site-verification=", "1Password", "Identity & access"),
    (r"^openai-domain-verification=", "OpenAI", "AI services"), (r"^anthropic-domain-verification", "Anthropic", "AI services"),
    (r"^canva-site-verification=", "Canva", "Business SaaS"), (r"^airtable-verification=", "Airtable", "Business SaaS"),
    (r"^smartsheet-site-validation=", "Smartsheet", "Business SaaS"), (r"^h1-domain-verification=", "HackerOne", "Security"),
    (r"^bugcrowd-verification", "Bugcrowd", "Security"), (r"^dynatrace-site-verification", "Dynatrace", "Cloud platform"),
    (r"^flexera-", "Flexera", "Business SaaS"), (r"^cloudhealth=", "VMware CloudHealth", "Cloud platform"),
    (r"^sendinblue-code|^brevo-code", "Brevo", "Email delivery"), (r"^snowflake", "Snowflake", "Cloud platform"),
]
SPF = [
    (r"spf\.protection\.outlook\.com", "Microsoft 365", "Email & collaboration"), (r"_spf\.google\.com", "Google Workspace", "Email & collaboration"),
    (r"pphosted\.com", "Proofpoint", "Email security"), (r"mimecast", "Mimecast", "Email security"), (r"iphmx\.com", "Cisco Secure Email", "Email security"),
    (r"amazonses\.com", "Amazon SES", "Email delivery"), (r"sendgrid\.net", "SendGrid (Twilio)", "Email delivery"), (r"mailgun\.org", "Mailgun", "Email delivery"),
    (r"servers\.mcsv\.net|mandrillapp\.com", "Mailchimp", "Email delivery"), (r"_spf\.salesforce\.com|exacttarget\.com", "Salesforce", "CRM & marketing"),
    (r"mktomail\.com", "Marketo (Adobe)", "CRM & marketing"), (r"hubspotemail\.net", "HubSpot", "CRM & marketing"),
    (r"mail\.zendesk\.com", "Zendesk", "Business SaaS"), (r"service-now\.com", "ServiceNow", "Business SaaS"), (r"docusign\.net", "DocuSign", "Business SaaS"),
    (r"sparkpostmail\.com", "SparkPost", "Email delivery"), (r"mailjet\.com", "Mailjet", "Email delivery"), (r"mtasv\.net", "Postmark", "Email delivery"),
    (r"eloqua", "Oracle Eloqua", "CRM & marketing"), (r"rsys\d*\.net|responsys", "Oracle Responsys", "CRM & marketing"),
    (r"messagelabs\.com", "Broadcom Email Security", "Email security"), (r"zoho\.", "Zoho", "Email & collaboration"),
    (r"qualtrics", "Qualtrics", "Business SaaS"), (r"successfactors|sapsf", "SAP SuccessFactors", "Business SaaS"),
    (r"workday\.com", "Workday", "Business SaaS"), (r"freshdesk", "Freshdesk", "Business SaaS"),
]
CNAME = [
    (r"\.cloudfront\.net\.?$", "AWS", "Cloud platform"), (r"\.elb\.amazonaws\.com\.?$", "AWS", "Cloud platform"),
    (r"\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com\.?$", "AWS", "Cloud platform"), (r"\.execute-api\.[a-z0-9-]+\.amazonaws\.com", "AWS", "Cloud platform"),
    (r"\.azurewebsites\.net\.?$|\.azurefd\.net\.?$|\.azureedge\.net\.?$|\.trafficmanager\.net\.?$|\.cloudapp\.(net|azure\.com)\.?$|\.blob\.core\.windows\.net\.?$|\.azure-api\.net\.?$", "Microsoft Azure", "Cloud platform"),
    (r"\.googleusercontent\.com|ghs\.googlehosted\.com|\.appspot\.com|\.run\.app", "Google Cloud", "Cloud platform"),
    (r"\.herokuapp\.com|\.herokudns\.com", "Heroku", "Cloud platform"),
    (r"\.edgekey\.net|\.edgesuite\.net|\.akamaiedge\.net|\.akamai\.net|\.akamaized\.net", "Akamai", "DNS & CDN"),
    (r"\.fastly\.net|\.fastlylb\.net", "Fastly", "DNS & CDN"), (r"\.cdn\.cloudflare\.net", "Cloudflare", "DNS & CDN"),
    (r"\.incapdns\.net", "Imperva", "DNS & CDN"), (r"\.force\.com|\.salesforce\.com|salesforce-sites", "Salesforce", "CRM & marketing"),
    (r"\.zendesk\.com", "Zendesk", "Business SaaS"), (r"\.okta\.com|\.oktapreview\.com", "Okta", "Identity & access"),
    (r"\.service-now\.com", "ServiceNow", "Business SaaS"), (r"\.github\.io", "GitHub Pages", "Developer & collaboration"),
    (r"\.netlify\.(app|com)", "Netlify", "Cloud platform"), (r"\.vercel(-dns)?\.(app|com)", "Vercel", "Cloud platform"),
    (r"\.pages\.dev", "Cloudflare Pages", "Cloud platform"), (r"\.wpengine\.com", "WP Engine", "Cloud platform"),
    (r"\.hubspot\.net|hs-sites", "HubSpot", "CRM & marketing"), (r"\.myshopify\.com|shops\.myshopify", "Shopify", "Business SaaS"),
    (r"\.snowflakecomputing\.com", "Snowflake", "Cloud platform"), (r"\.atlassian\.net", "Atlassian", "Developer & collaboration"),
    (r"\.myworkday(site)?\.com|\.workday\.com", "Workday", "Business SaaS"), (r"\.sharepoint\.com", "Microsoft 365", "Email & collaboration"),
    (r"\.ssl\.sectigo|\.digicert", "DigiCert", "PKI & certificates"), (r"\.sfmc-content\.com|\.exacttarget\.com", "Salesforce", "CRM & marketing"),
    (r"\.onelogin\.com", "OneLogin", "Identity & access"), (r"\.pingone\.(com|eu)|\.pingidentity\.com", "Ping Identity", "Identity & access"),
    (r"\.zscaler\.(net|com)", "Zscaler", "Security"), (r"\.successfactors\.(com|eu)", "SAP SuccessFactors", "Business SaaS"),
    (r"\.openai\.azure\.com\.?$", "Azure OpenAI", "AI services"),
]
TAKEOVER_PRONE = re.compile(r"\.s3[.-]|\.azurewebsites\.net|\.cloudapp\.|\.trafficmanager\.net|\.github\.io|\.herokuapp\.com|\.blob\.core\.windows\.net|\.pages\.dev|\.netlify\.", re.I)

# Hostname keyword → edge / remote-access product (maps to CISA KEV vendorProject)
EDGE = [
    (r"fortigate|fortinet|fortivpn|\bfgt\b|forti", "Fortinet", "FortiGate / FortiOS SSL-VPN"),
    (r"globalprotect|\bgp-|panorama|paloalto", "Palo Alto Networks", "PAN-OS GlobalProtect"),
    (r"pulse|ivanti|connect-secure|\bics\b", "Ivanti", "Connect Secure"),
    (r"mobileiron|\bepmm\b|\bmdm\b", "Ivanti", "Endpoint Manager Mobile"),
    (r"citrix|netscaler|\bctx|storefront|citrix-?receiver", "Citrix", "NetScaler ADC / Gateway"),  # bare "receiver" matched github-receiver
    (r"anyconnect|\basa\b|ciscovpn", "Cisco", "ASA / Secure Client"),
    (r"sonicwall|\bsma\b|\bsra\b", "SonicWall", "SMA / SonicOS"),
    (r"bigip|big-ip|\bf5\b|\btmui\b", "F5", "BIG-IP"),
    (r"juniper|junos|dynamicvpn", "Juniper", "Junos OS"),
    (r"checkpoint|mobile-access", "Check Point", "Quantum Security Gateway"),
    (r"vcenter|vsphere|esxi|horizon|workspaceone|\bvidm\b", "VMware", "vCenter / Horizon / Workspace ONE"),
    (r"\bjira\b", "Atlassian", "Jira Server / Data Center"), (r"confluence", "Atlassian", "Confluence Server / Data Center"),
    (r"bitbucket", "Atlassian", "Bitbucket Server"),
    (r"\bowa\b|exchange|autodiscover", "Microsoft", "Exchange Server"), (r"\badfs\b|\bsts\b", "Microsoft", "AD FS"),
    (r"rdweb|rdgateway|\brds\b|remotedesktop", "Microsoft", "Remote Desktop Gateway"), (r"sharepoint", "Microsoft", "SharePoint Server"),
    (r"moveit", "Progress", "MOVEit Transfer"), (r"goanywhere", "Fortra", "GoAnywhere MFT"), (r"crushftp", "CrushFTP", "CrushFTP"),
    (r"\bcleo\b|vltrader|lexicom", "Cleo", "Harmony / VLTrader"), (r"ws_?ftp|whatsup", "Progress", "WS_FTP / WhatsUp Gold"),
    (r"netweaver|\bfiori\b", "SAP", "NetWeaver"), (r"weblogic|\bebs\b|oracleapps", "Oracle", "E-Business Suite / WebLogic"),
    (r"screenconnect|connectwise", "ConnectWise", "ScreenConnect"), (r"beyondtrust|bomgar", "BeyondTrust", "Remote Support / PRA"),
    (r"simplehelp", "SimpleHelp", "SimpleHelp"), (r"veeam", "Veeam", "Backup & Replication"),
    (r"zimbra", "Synacor", "Zimbra Collaboration"), (r"roundcube", "Roundcube", "Webmail"),
    (r"manageengine|servicedesk|desktopcentral", "Zoho", "ManageEngine"), (r"solarwinds|orion|serv-?u", "SolarWinds", "Orion / Serv-U"),
    (r"kaseya", "Kaseya", "VSA"), (r"barracuda", "Barracuda Networks", "Email Security Gateway"),
    (r"sophos|\butm\b", "Sophos", "Firewall"), (r"watchguard|firebox", "WatchGuard", "Firebox"),
    (r"gitlab", "GitLab", "GitLab CE/EE"), (r"jenkins", "Jenkins", "Jenkins"), (r"sitecore", "Sitecore", "Experience Platform"),
    (r"commvault", "Commvault", "Command Center"), (r"\bprtg\b", "Paessler", "PRTG"),
    (r"langflow", "Langflow", "Langflow"), (r"litellm", "BerriAI", "LiteLLM"),  # AI stack with CISA KEV entries (vendorProject strings)
    (r"n-?central|\bncentral\b", "N-able", "N-central"), (r"artifactory|\bjfrog\b", "JFrog", "Artifactory"),  # MSP / DevOps with KEV entries
    (r"\bvpn\b|sslvpn|remote|webvpn", None, "VPN / remote-access gateway (vendor unknown)"),
]
DKIM_SELECTORS = ["selector1", "selector2", "google", "k1", "s1", "s2", "default", "dkim", "mail", "mandrill", "pp1", "mimecast20190124", "sm", "m1"]

_C = lambda tbl: [(re.compile(p, re.I), v, c) for p, v, c in tbl]
MX_C, NS_C, TXT_C, SPF_C, CNAME_C = _C(MX), _C(NS), _C(TXT), _C(SPF), _C(CNAME)
EDGE_C = [(re.compile(p, re.I), v, prod) for p, v, prod in EDGE]


def match(tbl, value: str):
    for rx, vendor, cat in tbl:
        if rx.search(value or ""):
            return vendor, cat
    return None


def edge_product(hostname: str):
    first = hostname.split(".")[0] if hostname else ""
    labels = ".".join(hostname.split(".")[:-2]) if hostname.count(".") >= 2 else first
    for rx, vendor, prod in EDGE_C:
        if rx.search(labels):
            return vendor, prod
    return None
