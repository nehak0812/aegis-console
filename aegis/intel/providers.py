"""Provider catalogue — the third parties AEGIS can link incidents to.

Two jobs:
1. **Recognise a provider in the news.** Names and aliases ("Snowflake Data Cloud", "Salesloft Drift") map reporting to one
   canonical provider, so a provider incident is recognised even when no monitored organisation shows it in DNS.
2. **Recognise a provider in public DNS.** CNAME / TXT / SPF / MX / NS patterns, applied to the records every surface scan
   stores. A pattern added later (in the catalogue or by an analyst in the console) is applied to existing scans at the next
   pipeline run — no rescan needed.

`observable=False` marks providers that public DNS cannot reveal (e.g. Blue Yonder, CDK Global, Change Healthcare); for those,
AEGIS links organisations only when reporting names them as affected customers (link type NAMED_CUSTOMER).
Analyst-added providers are stored in the `provider` table and survive catalogue updates.
"""
import re

from aegis import db

C = lambda *p: list(p)  # noqa: E731 — readability in the table below
# name, category, aliases, {cname, txt, spf, mx, ns}, observable
CATALOGUE: list[dict] = [
    # --- data & analytics platforms
    {"name": "Snowflake", "category": "Data platform", "aliases": C("Snowflake Data Cloud", "Snowflake Inc"), "cname": C(r"\.snowflakecomputing\.(com|cn|app)$", r"\.snowflake\.app$"), "txt": C(r"^snowflake")},
    {"name": "Databricks", "category": "Data platform", "aliases": C("Databricks Inc"), "cname": C(r"\.cloud\.databricks\.(com|us|mil)$", r"\.azuredatabricks\.net$", r"\.gcp\.databricks\.com$", r"\.databricksapps\.(com|us|mil)$")},
    {"name": "MongoDB Atlas", "category": "Data platform", "aliases": C("MongoDB"), "cname": C(r"\.mongodb\.net$"), "txt": C(r"^mongodb-site-verification=")},
    {"name": "Confluent", "category": "Data platform", "aliases": C("Confluent Cloud"), "cname": C(r"\.confluent\.cloud$")},
    {"name": "Elastic Cloud", "category": "Data platform", "aliases": C("Elastic", "Elasticsearch Service"), "cname": C(r"\.elastic-cloud\.com$", r"\.found\.io$", r"\.elastic\.cloud$")},
    {"name": "Redis Cloud", "category": "Data platform", "aliases": C("Redis Labs", "Redis Enterprise Cloud"), "cname": C(r"\.redns\.redis-cloud\.com$", r"\.redislabs\.com$")},
    {"name": "Cloudera", "category": "Data platform", "aliases": C(), "cname": C(r"\.cloudera\.site$")},
    {"name": "Palantir", "category": "Data platform", "aliases": C("Palantir Foundry"), "cname": C(r"\.palantirfoundry\.(com|co\.uk)$")},
    {"name": "Teradata", "category": "Data platform", "aliases": C("Teradata VantageCloud")},
    {"name": "Fivetran", "category": "Data platform", "aliases": C()},
    {"name": "Segment", "category": "Data platform", "aliases": C("Twilio Segment")},
    {"name": "Mixpanel", "category": "Data platform", "aliases": C(), "txt": C(r"^mixpanel-domain-verify=")},
    {"name": "Amplitude", "category": "Data platform", "aliases": C()},
    {"name": "Gainsight", "category": "CRM & marketing", "aliases": C()},
    # --- observability
    {"name": "Datadog", "category": "Observability", "aliases": C(), "txt": C(r"^datadog")},
    {"name": "Splunk", "category": "Observability", "aliases": C("Splunk Cloud"), "cname": C(r"\.splunkcloud\.com$")},
    {"name": "New Relic", "category": "Observability", "aliases": C()},
    {"name": "Dynatrace", "category": "Observability", "aliases": C(), "txt": C(r"^dynatrace-site-verification")},
    {"name": "PagerDuty", "category": "Observability", "aliases": C(), "cname": C(r"\.pagerduty\.com$")},
    {"name": "Atlassian Statuspage", "category": "Observability", "aliases": C("Statuspage"), "cname": C(r"\.stspg-customer\.com$"), "spf": C(r"stspg-customer\.com"),
     "txt": C(r"^status-page-domain-verification=")},
    {"name": "Site24x7", "category": "Observability", "aliases": C(), "cname": C(r"site24x7sp\.com$")},
    # --- identity
    {"name": "Okta", "category": "Identity & access", "aliases": C("Okta Inc"), "cname": C(r"\.okta\.com$", r"\.okta-emea\.com$", r"\.oktapreview\.com$", r"okta-dnssec\.com$"), "txt": C(r"^okta-verification=")},
    {"name": "Auth0", "category": "Identity & access", "aliases": C("Okta Customer Identity"), "cname": C(r"\.auth0\.com$", r"\.auth0app\.com$")},
    {"name": "Ping Identity", "category": "Identity & access", "aliases": C("PingOne", "PingFederate"), "cname": C(r"\.pingone\.(com|eu|asia)$", r"\.pingidentity\.com$")},
    {"name": "OneLogin", "category": "Identity & access", "aliases": C(), "cname": C(r"\.onelogin\.com$")},
    {"name": "ForgeRock", "category": "Identity & access", "aliases": C("Ping ForgeRock"), "cname": C(r"\.forgerock\.io$", r"\.forgeblocks\.com$")},
    {"name": "CyberArk", "category": "Identity & access", "aliases": C("CyberArk Identity", "Idaptive"), "cname": C(r"\.cyberark\.cloud$", r"\.idaptive\.app$", r"\.my\.idaptive\.app$")},
    {"name": "SailPoint", "category": "Identity & access", "aliases": C("IdentityNow"), "cname": C(r"\.identitynow\.com$")},
    {"name": "Cisco Duo", "category": "Identity & access", "aliases": C("Duo Security"), "txt": C(r"^duo_sso_verification=")},
    {"name": "1Password", "category": "Identity & access", "aliases": C(), "txt": C(r"^1password-site-verification=")},
    {"name": "LastPass", "category": "Identity & access", "aliases": C(), "txt": C(r"^lastpass-verification-code=")},
    # --- HR, finance & ERP
    {"name": "Workday", "category": "Business SaaS", "aliases": C(), "cname": C(r"\.myworkday(site)?\.com$", r"\.workday\.com$")},
    {"name": "ServiceNow", "category": "Business SaaS", "aliases": C(), "cname": C(r"\.service-now\.com$", r"\.servicenowservices\.com$")},
    {"name": "SAP", "category": "Business SaaS", "aliases": C("SAP SuccessFactors", "SAP Concur", "SAP Ariba", "SAP NetWeaver", "SAP BTP"), "cname": C(r"\.ondemand\.com$", r"\.successfactors\.(com|eu)$", r"\.sapsf\.(com|eu|cn)$", r"\.cloud\.sap$"), "spf": C(r"successfactors|sapsf|concurcompleat|concursolutions|ariba\.com")},
    {"name": "Oracle Cloud", "category": "Cloud platform", "aliases": C("Oracle Cloud Infrastructure", "OCI", "Oracle E-Business Suite", "Oracle EBS", "Oracle Fusion"), "cname": C(r"\.oraclecloud\.com$", r"\.oraclecloudapps\.com$"), "spf": C(r"oraclecloud\.com|oracleemaildelivery\.com"), "ns": C(r"oraclecloud\.net$")},
    {"name": "Oracle Eloqua", "category": "CRM & marketing", "aliases": C("Eloqua"), "cname": C(r"\.en25\.com$", r"\.eloqua\.com$"), "spf": C(r"eloqua|en25\.com")},
    {"name": "Coupa", "category": "Business SaaS", "aliases": C(), "cname": C(r"\.coupahost\.com$")},
    {"name": "ADP", "category": "Business SaaS", "aliases": C("ADP Workforce Now"), "spf": C(r"(^|\.)adp\.com$")},
    {"name": "UKG", "category": "Business SaaS", "aliases": C("UKG Pro", "UltiPro", "Kronos"), "spf": C(r"ultipro\.com|ukg\.com")},
    {"name": "Paychex", "category": "Business SaaS", "aliases": C()},
    {"name": "Workhuman", "category": "Business SaaS", "aliases": C(), "spf": C(r"workhuman\.com")},
    {"name": "Docebo", "category": "Business SaaS", "aliases": C(), "spf": C(r"docebosaas\.com")},
    {"name": "KnowBe4", "category": "Security", "aliases": C(), "spf": C(r"knowbe4\.com"), "txt": C(r"^knowbe4-site-verification=")},
    {"name": "Qualtrics", "category": "Business SaaS", "aliases": C(), "cname": C(r"qualtrics\.com$"), "spf": C(r"qualtrics")},
    {"name": "Cvent", "category": "Business SaaS", "aliases": C(), "spf": C(r"cvent")},
    {"name": "Everbridge", "category": "Business SaaS", "aliases": C(), "spf": C(r"everbridge\.net")},
    {"name": "Yardi", "category": "Business SaaS", "aliases": C(), "spf": C(r"yardi\.com")},
    # --- CRM, sales, support, marketing, messaging
    {"name": "Salesforce", "category": "CRM & marketing", "aliases": C("Salesforce Inc", "Salesforce Sites"), "cname": C(r"\.force\.com$", r"\.salesforce\.com$", r"\.siteforce\.com$", r"salesforce-sites"), "txt": C(r"^salesforce-|^sfdc-")},
    {"name": "MuleSoft", "category": "Developer & collaboration", "aliases": C("Anypoint"), "cname": C(r"anypointdns\.net$", r"\.cloudhub\.io$")},
    {"name": "Salesforce Pardot", "category": "CRM & marketing", "aliases": C("Pardot", "Marketing Cloud Account Engagement"), "cname": C(r"go\.pardot\.com$"), "spf": C(r"pardot\.com")},
    {"name": "Salesloft", "category": "CRM & marketing", "aliases": C("Salesloft Drift", "Drift")},
    {"name": "HubSpot", "category": "CRM & marketing", "aliases": C(), "cname": C(r"\.hubspot\.net$", r"hs-sites")},
    {"name": "Zendesk", "category": "Business SaaS", "aliases": C(), "cname": C(r"\.zendesk\.com$")},
    {"name": "Freshworks", "category": "Business SaaS", "aliases": C("Freshdesk", "Freshservice"), "cname": C(r"\.freshdesk\.com$", r"\.freshservice\.com$")},
    {"name": "Intercom", "category": "Business SaaS", "aliases": C(), "cname": C(r"\.intercom\.help$", r"custom\.intercom\.help$")},
    {"name": "Twilio", "category": "Email delivery", "aliases": C("Twilio SendGrid", "SendGrid", "SendGrid (Twilio)"), "spf": C(r"sendgrid\.net")},
    {"name": "Mailchimp", "category": "Email delivery", "aliases": C("Intuit Mailchimp", "Mandrill")},
    {"name": "Marketo", "category": "CRM & marketing", "aliases": C("Adobe Marketo"), "cname": C(r"\.mktoweb\.com$", r"mktossl\.com$")},
    {"name": "Constant Contact", "category": "Email delivery", "aliases": C(), "spf": C(r"constantcontact\.com")},
    {"name": "Campaign Monitor", "category": "Email delivery", "aliases": C(), "spf": C(r"createsend\.com")},
    {"name": "Valimail", "category": "Email security", "aliases": C(), "cname": C(r"mta-vali\.email$", r"\.vali\.email$"), "spf": C(r"vali\.email")},
    {"name": "Red Sift OnDMARC", "category": "Email security", "aliases": C("OnDMARC", "Red Sift"), "spf": C(r"ondmarc\.com")},
    {"name": "Agari", "category": "Email security", "aliases": C("Fortra Agari"), "spf": C(r"agari")},
    # --- payments & commerce
    {"name": "Stripe", "category": "Payments", "aliases": C(), "cname": C(r"hosted-checkout\.stripecdn\.com$"), "txt": C(r"^_?stripe-verification=")},
    {"name": "Adyen", "category": "Payments", "aliases": C()},
    {"name": "PayPal", "category": "Payments", "aliases": C("Braintree"), "spf": C(r"(^|\.)paypal\.com$")},
    {"name": "Shopify", "category": "Business SaaS", "aliases": C(), "cname": C(r"\.myshopify\.com$", r"shops\.myshopify")},
    {"name": "SAP Commerce Cloud", "category": "Business SaaS", "aliases": C("SAP Hybris"), "cname": C(r"commerce\.ondemand\.com$")},
    # --- developer & collaboration
    {"name": "Atlassian", "category": "Developer & collaboration", "aliases": C("Jira", "Confluence", "Bitbucket", "Trello"), "cname": C(r"\.atlassian\.net$", r"saas\.atlassian\.com$"), "txt": C(r"^atlassian-domain-verification=")},
    {"name": "GitHub", "category": "Developer & collaboration", "aliases": C(), "cname": C(r"\.github\.io$"), "txt": C(r"^_?github-challenge|^github-verification")},
    {"name": "GitLab", "category": "Developer & collaboration", "aliases": C(), "cname": C(r"\.gitlab\.io$")},
    {"name": "JFrog", "category": "Developer & collaboration", "aliases": C("Artifactory", "JFrog Artifactory"), "cname": C(r"\.jfrog\.io$")},
    {"name": "Slack", "category": "Email & collaboration", "aliases": C(), "txt": C(r"^slack-domain-verification=")},
    {"name": "Zoom", "category": "Email & collaboration", "aliases": C(), "txt": C(r"zoom_verify_")},
    {"name": "Cisco Webex", "category": "Email & collaboration", "aliases": C("Webex"), "txt": C(r"^webexdomainverification")},
    {"name": "Box", "category": "File sharing", "aliases": C(), "txt": C(r"^box-domain-verification=")},
    {"name": "Dropbox", "category": "File sharing", "aliases": C(), "txt": C(r"^dropbox-domain-verification=")},
    {"name": "DocuSign", "category": "Business SaaS", "aliases": C(), "txt": C(r"^docusign="), "spf": C(r"docusign\.net")},
    {"name": "Adobe", "category": "Business SaaS", "aliases": C("Adobe Experience Manager", "AEM", "Adobe Commerce", "Magento"), "cname": C(r"adobeaemcloud\.com$", r"\.cjm\.adobe\.com$", r"\.adobe\.com$"), "txt": C(r"^adobe-(idp-)?site-verification=|^adobe-sign-verification=")},
    {"name": "Miro", "category": "Developer & collaboration", "aliases": C(), "txt": C(r"^miro-verification=")},
    {"name": "Notion", "category": "Developer & collaboration", "aliases": C(), "cname": C(r"external\.notion\.site$")},
    {"name": "Smartsheet", "category": "Business SaaS", "aliases": C(), "txt": C(r"^smartsheet-site-validation=")},
    {"name": "OneTrust", "category": "Security", "aliases": C(), "cname": C(r"my\.onetrust\.com$"), "txt": C(r"^onetrust-domain-verification=")},
    # --- web, investor-relations & careers hosting
    {"name": "Q4 Inc", "category": "Web & IR hosting", "aliases": C("Q4", "Q4 Web"), "cname": C(r"q4web\.com$", r"shareholder\.com$"), "spf": C(r"q4press\.com")},
    {"name": "Investis Digital", "category": "Web & IR hosting", "aliases": C("Investis"), "cname": C(r"investis\.com$")},
    {"name": "Optimizely", "category": "Web & IR hosting", "aliases": C("Episerver"), "cname": C(r"episerver\.net$", r"optimizely\.com$")},
    {"name": "WP Engine", "category": "Web & IR hosting", "aliases": C(), "cname": C(r"wpengine(powered)?\.com$")},
    {"name": "Squarespace", "category": "Web & IR hosting", "aliases": C(), "cname": C(r"squarespace\.com$")},
    {"name": "Webflow", "category": "Web & IR hosting", "aliases": C(), "cname": C(r"webflow\.(com|io)$")},
    {"name": "Equisolve", "category": "Web & IR hosting", "aliases": C(), "cname": C(r"equisolve\.com$")},
    # --- CDN, DNS, network & endpoint security
    {"name": "Cloudflare", "category": "DNS & CDN", "aliases": C(), "cname": C(r"\.cdn\.cloudflare\.net$", r"\.pages\.dev$"), "ns": C(r"\.ns\.cloudflare\.com$", r"foundationdns\.(com|net|org)$"),
     "mx": C(r"route\d\.mx\.cloudflare\.net$", r"mailstream-[a-z0-9]+\.mxrecord\.(io|mx)$"), "spf": C(r"_spf\.mx\.cloudflare\.net")},
    {"name": "Akamai", "category": "DNS & CDN", "aliases": C(), "cname": C(r"\.edgekey(-staging)?\.net$", r"\.edgesuite\.net$", r"\.akamaiedge\.net$", r"\.akadns\.net$", r"\.akamaized\.net$"), "ns": C(r"\.akam\.net$", r"akamaidns")},
    {"name": "Fastly", "category": "DNS & CDN", "aliases": C(), "cname": C(r"\.fastly\.net$", r"\.fastlylb\.net$", r"fastly-validations\.com$")},
    {"name": "Imperva", "category": "DNS & CDN", "aliases": C("Incapsula", "Thales Imperva"), "cname": C(r"impervadns\.net$", r"\.incapdns\.net$"), "ns": C(r"impervasecuredns\.net$", r"\.incapdns\.net$")},
    {"name": "F5 Distributed Cloud", "category": "DNS & CDN", "aliases": C("F5 XC", "Volterra"), "cname": C(r"\.ves\.io$"), "ns": C(r"f5clouddns\.com$", r"\.f5cloudservices\.com$")},
    {"name": "Radware", "category": "DNS & CDN", "aliases": C("Radware Cloud WAF"), "cname": C(r"radwarecloud\.net$")},
    {"name": "Zscaler", "category": "Security", "aliases": C("Zscaler Private Access", "ZPA"), "cname": C(r"\.zscaler\.(net|com)$", r"zpa-app\.net$")},
    {"name": "Netskope", "category": "Security", "aliases": C(), "cname": C(r"\.goskope\.com$"), "spf": C(r"_spf\.goskope\.com")},
    # endpoint agents connect outbound only — documented as not observable in the customer's public DNS
    {"name": "CrowdStrike", "category": "Security", "aliases": C("CrowdStrike Falcon"), "observable": False},
    {"name": "SentinelOne", "category": "Security", "aliases": C(), "observable": False},
    {"name": "Palo Alto Prisma Access", "category": "Security", "aliases": C("Prisma Access", "Prisma SASE"), "cname": C(r"\.proxy\.prismaaccess\.com$", r"\.gpcloudservice\.com$")},
    {"name": "Vercara UltraDNS", "category": "DNS & CDN", "aliases": C("UltraDNS", "DigiCert UltraDNS"), "ns": C(r"\.ultradns\.", r"ultradns2\.(com|org|net)$")},
    {"name": "MarkMonitor", "category": "Domain registrar & DNS", "aliases": C(), "ns": C(r"markmonitor\.(com|zone)$")},
    {"name": "Com Laude", "category": "Domain registrar & DNS", "aliases": C(), "ns": C(r"comlaude\.")},
    # --- clouds & device management
    {"name": "AWS", "category": "Cloud platform", "aliases": C("Amazon Web Services"), "cname": C(r"\.amazonaws\.com$", r"\.cloudfront\.net$", r"\.on\.aws$"), "ns": C(r"\.awsdns-\d+\.")},
    {"name": "Microsoft Azure", "category": "Cloud platform", "aliases": C("Azure"), "cname": C(r"\.azurewebsites\.net$", r"\.azurestaticapps\.net$", r"\.azurefd\.net$", r"\.trafficmanager\.net$", r"\.cloudapp\.(net|azure\.com)$")},
    {"name": "Microsoft 365", "category": "Email & collaboration", "aliases": C("Office 365", "Exchange Online", "Microsoft Teams"), "cname": C(r"autodiscover\.outlook\.com$", r"\.sharepoint\.com$", r"outlook\.office\.com$"), "mx": C(r"\.mail\.protection\.outlook\.com$", r"mx\.microsoft$"), "spf": C(r"spf\.protection\.outlook\.com|office365\.us")},
    {"name": "Google Cloud", "category": "Cloud platform", "aliases": C("GCP"), "cname": C(r"\.run\.app$", r"\.appspot\.com$", r"ghs\.googlehosted\.com$")},
    {"name": "IBM Cloud", "category": "Cloud platform", "aliases": C(), "cname": C(r"\.appdomain\.cloud$", r"\.cloud\.ibm\.com$")},
    {"name": "Jamf", "category": "Device management", "aliases": C(), "txt": C(r"^jamf-site-verification=")},
    {"name": "Microsoft Intune", "category": "Device management", "aliases": C("Intune"),
     "cname": C(r"enterpriseenrollment(-s)?\.manage\.microsoft\.(com|us)$", r"enterpriseregistration\.windows\.net$", r"enterpriseenrollment-s\.manage\.microsoftonline\.cn$")},
    {"name": "Google Workspace", "category": "Email & collaboration", "aliases": C("G Suite"), "mx": C(r"(^|\.)smtp\.google\.com$", r"aspmx\.l\.google\.com$", r"googlemail\.com$"),
     "spf": C(r"_spf\.google\.com"), "cname": C(r"domainverify\.googlehosted\.com$")},
    # --- managed file transfer & IT management (MSP / RMM)
    {"name": "Progress MOVEit", "category": "File transfer", "aliases": C("MOVEit", "MOVEit Transfer", "Progress Software")},
    {"name": "Cleo", "category": "File transfer", "aliases": C("Cleo Harmony", "VLTrader")},
    {"name": "Fortra GoAnywhere", "category": "File transfer", "aliases": C("GoAnywhere", "GoAnywhere MFT")},
    {"name": "Globalscape EFT", "category": "File transfer", "aliases": C("Globalscape", "Fortra Globalscape"), "cname": C(r"globalscape\.com$")},
    {"name": "Kiteworks", "category": "File transfer", "aliases": C("Accellion"), "cname": C(r"\.kiteworks\.com$")},
    {"name": "Kaseya", "category": "MSP / RMM", "aliases": C("Kaseya VSA")},
    {"name": "ConnectWise", "category": "MSP / RMM", "aliases": C("ScreenConnect", "ConnectWise ScreenConnect"), "cname": C(r"\.screenconnect\.com$", r"\.hostedrmm\.com$")},
    {"name": "SolarWinds", "category": "MSP / RMM", "aliases": C("SolarWinds Orion", "Serv-U", "SolarWinds Service Desk", "Samanage", "Pingdom"),
     "cname": C(r"\.samanage\.com$", r"stats\.pingdom\.com$"), "spf": C(r"_spf\.samanage\.com")},
    {"name": "N-able", "category": "MSP / RMM", "aliases": C("N-central", "N-able N-central")},
    {"name": "NinjaOne", "category": "MSP / RMM", "aliases": C()},
    # --- sector platforms (not observable in DNS)
    {"name": "Change Healthcare", "category": "Sector platform", "aliases": C("Optum Change Healthcare"), "observable": False},
    {"name": "CDK Global", "category": "Sector platform", "aliases": C(), "observable": False},
    {"name": "Blue Yonder", "category": "Sector platform", "aliases": C(), "observable": False},
    {"name": "Epic Systems", "category": "Sector platform", "aliases": C("Epic MyChart", "MyChart"), "cname": C(r"\.epichosted\.com$")},
    {"name": "Oracle Health", "category": "Sector platform", "aliases": C("Cerner"), "observable": False},
    {"name": "Collins Aerospace", "category": "Sector platform", "aliases": C("MUSE", "vMUSE"), "observable": False},
    {"name": "Sitel", "category": "Sector platform", "aliases": C("Foundever"), "observable": False},
    # --- AI providers (DNS verification already fingerprinted)
    {"name": "OpenAI", "category": "AI services", "aliases": C("ChatGPT"), "txt": C(r"^openai-domain-verification=")},
    {"name": "Anthropic", "category": "AI services", "aliases": C("Claude"), "txt": C(r"^anthropic-domain-verification")},
]
KINDS = ("cname", "txt", "spf", "mx", "ns")

# Provider status feeds tested live on 2026-09-11 (HTTP 200 with incidents). Providers already polled by the status collector's
# own list (GitHub, Cloudflare, Atlassian, Zoom, Datadog, Twilio, Snowflake, Dropbox, Box, Akamai, HubSpot, AWS, Zscaler, Slack,
# Salesforce, Google Cloud, OpenAI, Anthropic) are not repeated. kind: "statuspage" = /api/v2/incidents.json, "rss" = RSS/Atom.
STATUS_FEEDS = {
    "Databricks": ("https://status.databricks.com/pages/5cf02dde58a00904bda41926/rss", "rss"),
    "MongoDB Atlas": ("https://status.mongodb.com/api/v2/incidents.json", "statuspage"),
    "Confluent": ("https://status.confluent.cloud/api/v2/incidents.json", "statuspage"),
    "Elastic Cloud": ("https://status.elastic.co/api/v2/incidents.json", "statuspage"),
    "Cloudera": ("https://status.cloudera.com/api/v2/incidents.json", "statuspage"),
    "Segment": ("https://status.segment.com/api/v2/incidents.json", "statuspage"),
    "Mixpanel": ("https://www.mixpanelstatus.com/api/v2/incidents.json", "statuspage"),
    "Amplitude": ("https://status.amplitude.com/api/v2/incidents.json", "statuspage"),
    "Gainsight": ("https://status.gainsight.com/api/v2/incidents.json", "statuspage"),
    "Splunk": ("https://status.splunkcloud.com/api/v2/incidents.json", "statuspage"),
    "New Relic": ("https://status.newrelic.com/api/v2/incidents.json", "statuspage"),
    "Dynatrace": ("https://dynatrace.status.io/pages/546d8cb6af8407b6730000cb/rss", "rss"),
    "Okta": ("https://feeds.feedburner.com/OktaTrustRSS", "rss"),  # no entries since 2025-04 — kept so a revival is picked up
    "Ping Identity": ("https://status.pingidentity.com/api/v2/incidents.json", "statuspage"),
    "SailPoint": ("https://status.sailpoint.com/api/v2/incidents.json", "statuspage"),
    "Cisco Duo": ("https://status.duo.com/api/v2/incidents.json", "statuspage"),
    "1Password": ("https://status.1password.com/api/v2/incidents.json", "statuspage"),
    "LastPass": ("https://status.lastpass.com/history.rss", "rss"),
    "Oracle Cloud": ("https://ocistatus.oraclecloud.com/history.rss", "rss"),
    "Salesloft": ("https://status.salesloft.com/api/v2/incidents.json", "statuspage"),
    "Intercom": ("https://www.finstatus.com/api/v2/incidents.json", "statuspage"),
    "Stripe": ("https://www.stripestatus.com/api/v2/incidents.json", "statuspage"),
    "PayPal": ("https://www.paypal-status.com/feed/rss", "rss"),
    "Shopify": ("https://www.shopifystatus.com/api/v2/incidents.json", "statuspage"),
    "GitLab": ("https://status.gitlab.com/pages/5b36dc6502d06804c08349f7/rss", "rss"),
    "Cisco Webex": ("https://status.webex.com/history.rss", "rss"),
    "Miro": ("https://status.miro.com/api/v2/incidents.json", "statuspage"),
    "Notion": ("https://www.notion-status.com/api/v2/incidents.json", "statuspage"),
    "SentinelOne": ("https://status.sentinelone.com/api/v2/incidents.json", "statuspage"),
    "Palo Alto Prisma Access": ("https://status.paloaltonetworks.com/api/v2/incidents.json", "statuspage"),
    "Microsoft Azure": ("https://rssfeed.azure.status.microsoft/en-us/status/feed/", "rss"),
    "IBM Cloud": ("https://cloud.ibm.com/status/api/notifications/feed.rss", "rss"),
    "Jamf": ("https://status.jamf.com/api/v2/incidents.json", "statuspage"),
    "Progress MOVEit": ("https://status.moveitcloud.com/api/v2/incidents.json", "statuspage"),
    "Cleo": ("https://status.cleo.com/api/v2/incidents.json", "statuspage"),
    "Fortra GoAnywhere": ("https://status.fortra.com/history.rss", "rss"),
    "Kaseya": ("https://status.kaseya.com/api/v2/incidents.json", "statuspage"),
    "ConnectWise": ("https://status.connectwise.com/pages/619cf82551fec9053d612f09/rss", "rss"),
    "SolarWinds": ("https://status.cloud.solarwinds.com/api/v2/incidents.json", "statuspage"),
    "NinjaOne": ("https://status.ninjaone.com/api/v2/incidents.json", "statuspage"),
    "Change Healthcare": ("https://solution-status.optum.com/api/v2/incidents.json", "statuspage"),
}


def sync_catalogue() -> None:
    """Upsert the shipped catalogue; analyst-added rows (source='analyst') are never overwritten."""
    rows = []
    for p in CATALOGUE:
        rows.append({"name": p["name"], "category": p["category"], "aliases": p.get("aliases") or [],
                     "patterns": {k: p.get(k) or [] for k in KINDS}, "observable": 0 if p.get("observable") is False else 1,
                     "status_url": p.get("status"), "source": "catalogue", "added": db.now()})
    have = {r["name"]: r["source"] for r in db.q("SELECT name, source FROM provider")}
    db.upsert("provider", [r for r in rows if have.get(r["name"]) != "analyst"], keep=("added",))


class Catalogue:
    """Compiled view of the provider table (catalogue + analyst additions)."""

    def __init__(self, rows: list[dict] | None = None):
        rows = rows if rows is not None else db.q("SELECT * FROM provider")
        self.rows = {r["name"]: r for r in rows}
        self.rx: dict[str, list[tuple[re.Pattern, str, str]]] = {k: [] for k in KINDS}
        alias = {}
        for r in rows:
            pats = r.get("patterns") or {}
            for k in KINDS:
                for p in pats.get(k) or []:
                    try:
                        self.rx[k].append((re.compile(p, re.I), r["name"], r["category"]))
                    except re.error:
                        continue
            for a in [r["name"]] + list(r.get("aliases") or []):
                if a and len(a) >= 3:
                    alias[a.lower()] = r["name"]
        self.alias = alias
        self.terms = sorted({a for r in rows for a in [r["name"]] + list(r.get("aliases") or []) if a and len(a) >= 3}, key=len, reverse=True)
        pats = sorted(alias, key=len, reverse=True)
        self.name_rx = re.compile(r"(?<![\w-])(" + "|".join(re.escape(a) for a in pats) + r")(?![\w-])", re.I) if pats else None

    def match(self, kind: str, value: str) -> tuple[str, str] | None:
        v = (value or "").lower().rstrip(".")
        for rx, name, cat in self.rx.get(kind, []):
            if rx.search(v):
                return name, cat
        return None

    def canonical(self, name: str) -> str | None:
        return self.alias.get((name or "").strip().lower())

    def mentioned(self, text: str) -> list[str]:
        if not self.name_rx or not text:
            return []
        out = []
        for m in self.name_rx.finditer(text):
            n = self.alias.get(m.group(1).lower())
            if n and n not in out:
                out.append(n)
        return out

    def names_of(self, name: str) -> list[str]:
        r = self.rows.get(name) or {}
        return [name] + [a for a in r.get("aliases") or [] if len(a) >= 3]

    def category(self, name: str) -> str | None:
        return (self.rows.get(name) or {}).get("category")

    def observable(self, name: str) -> bool:
        return bool((self.rows.get(name) or {}).get("observable", 1))
