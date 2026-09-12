import { Fragment, ReactNode, isValidElement } from 'react'

/** Abbreviations the console uses in its own voice, with the plain-English expansion
 *  shown on hover. Vendor and product names that arrive from third-party feeds
 *  (PAN-OS, BIG-IP, EPMM…) are deliberately absent: they are not ours to define,
 *  and the source text usually spells them out already. */
export const GLOSSARY: Record<string, string> = {
  // vulnerabilities
  KEV: 'Known Exploited Vulnerabilities — CISA’s catalogue of flaws with confirmed exploitation in the wild',
  CVE: 'Common Vulnerabilities and Exposures — the public identifier for one specific security flaw',
  CVSS: 'Common Vulnerability Scoring System — the 0–10 technical severity score for a vulnerability',
  EPSS: 'Exploit Prediction Scoring System — the probability that a vulnerability will be exploited in the next 30 days',
  NVD: 'National Vulnerability Database — the US government’s enriched record of every CVE',
  CPE: 'Common Platform Enumeration — the standard name for a product and version, used to match software to vulnerabilities',
  // organisations and catalogues
  CISA: 'Cybersecurity and Infrastructure Security Agency — the US federal cyber defence agency',
  FIRST: 'Forum of Incident Response and Security Teams — the body that publishes EPSS',
  MITRE: 'MITRE Corporation — the non-profit that maintains the CVE and ATT&CK catalogues',
  'ATT&CK': 'Adversarial Tactics, Techniques and Common Knowledge — MITRE’s catalogue of observed attacker behaviour',
  MISP: 'Malware Information Sharing Platform — an open threat-intelligence sharing project',
  NCSC: 'National Cyber Security Centre — the UK (and Dutch) national cyber authority',
  CERT: 'Computer Emergency Response Team — a national or sector body that publishes security advisories',
  ENISA: 'European Union Agency for Cybersecurity',
  SANS: 'SANS Institute — a security research and training organisation',
  ISC: 'Internet Storm Center — the SANS Institute’s internet threat monitoring service',
  HIBP: 'Have I Been Pwned — a public catalogue of known data breaches',
  // adversaries
  APT: 'Advanced Persistent Threat — a state-backed or long-running intrusion group',
  C2: 'Command and Control — the infrastructure an attacker uses to control compromised machines',
  TTP: 'Tactics, Techniques and Procedures — how a particular attacker operates',
  IOC: 'Indicator of Compromise — an observable sign that a system has been attacked',
  DDoS: 'Distributed Denial of Service — flooding a service with traffic to take it offline',
  RaaS: 'Ransomware as a Service — a ransomware crew renting its malware to affiliates',
  // internet and email plumbing
  DNS: 'Domain Name System — the public directory that maps names to addresses',
  DNSSEC: 'Domain Name System Security Extensions — cryptographic signing of DNS answers, so they cannot be forged',
  SPF: 'Sender Policy Framework — a DNS record listing who is allowed to send email for a domain',
  DKIM: 'DomainKeys Identified Mail — a cryptographic signature on outgoing email',
  DMARC: 'Domain-based Message Authentication, Reporting and Conformance — the policy telling receivers what to do when SPF or DKIM fail',
  CT: 'Certificate Transparency — public append-only logs of every TLS certificate issued',
  TLS: 'Transport Layer Security — the encryption behind HTTPS',
  ASN: 'Autonomous System Number — the identifier for a block of internet addresses run by one operator',
  CIDR: 'Classless Inter-Domain Routing — the a.b.c.d/n notation for a range of IP addresses',
  MX: 'Mail Exchanger — the DNS record naming a domain’s mail servers',
  NS: 'Name Server — the DNS record naming which servers answer for a domain',
  TXT: 'Text record — free-form DNS entries, often used to prove ownership of a domain to a provider',
  CNAME: 'Canonical Name — a DNS record pointing one name at another',
  CDN: 'Content Delivery Network — distributed servers that cache a site closer to its visitors',
  CAA: 'Certification Authority Authorization — a DNS record naming which certificate authorities may issue for a domain',
  BGP: 'Border Gateway Protocol — how networks announce to the internet which IP ranges they carry',
  RPKI: 'Resource Public Key Infrastructure — cryptographic proof of which network is allowed to announce an IP range',
  ROA: 'Route Origin Authorisation — the signed statement naming the network permitted to announce a prefix',
  RDAP: 'Registration Data Access Protocol — the structured successor to WHOIS for registry records, mandatory for gTLDs since 2025',
  WHOIS: 'The legacy domain registration lookup, replaced by RDAP',
  EPP: 'Extensible Provisioning Protocol — the registry protocol whose status codes carry a domain’s transfer and deletion locks',
  IDN: 'Internationalised Domain Name — a domain using non-Latin characters, which can be used to build visually confusable lookalikes',
  // corporate identity
  LEI: 'Legal Entity Identifier — the global 20-character code for one legally distinct company',
  GLEIF: 'Global Legal Entity Identifier Foundation — publisher of the LEI register and corporate ownership data',
  SEC: 'Securities and Exchange Commission — the US markets regulator',
  EDGAR: 'Electronic Data Gathering, Analysis and Retrieval — the SEC’s public database of company filings',
  CIK: 'Central Index Key — the number the SEC uses to identify a filing company',
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\&]/g, '\\$&')
// longest first, so DNSSEC wins over DNS and ATT&CK is not split
const TERMS = Object.keys(GLOSSARY).sort((a, b) => b.length - a.length)
// The leading character is captured rather than matched with a lookbehind: lookbehind
// throws at construction on older Safari, which would take the whole console down.
// Trailing "s" is allowed so "CVEs" and "IOCs" are still recognised. A term touching
// a word character or hyphen is left alone, so CERT-EU and JPCERT stay untouched.
const RX = new RegExp(`(^|[^\\w-])(${TERMS.map(esc).join('|')})(s?)(?![\\w-])`, 'g')

/** One abbreviation with its expansion on hover. */
export function Abbr({ term, children }: { term: string; children?: ReactNode }) {
  const full = GLOSSARY[term]
  if (!full) return <>{children ?? term}</>
  return <abbr className="gloss" title={full}>{children ?? term}</abbr>
}

/** Wrap every known abbreviation in a plain string with its hover expansion.
 *  Non-string nodes pass through untouched, so callers can hand this any prop. */
export function gloss(node: ReactNode): ReactNode {
  if (typeof node !== 'string') return node
  RX.lastIndex = 0
  if (!RX.test(node)) return node
  RX.lastIndex = 0
  const out: ReactNode[] = []
  let last = 0, m: RegExpExecArray | null, i = 0
  while ((m = RX.exec(node))) {
    // m[1] is the captured character before the term, and belongs to the plain text
    const start = m.index + m[1].length
    if (start > last) out.push(node.slice(last, start))
    out.push(<Abbr key={i++} term={m[2]}>{m[2] + m[3]}</Abbr>)
    last = start + m[2].length + m[3].length
  }
  if (last < node.length) out.push(node.slice(last))
  return <>{out.map((p, n) => <Fragment key={n}>{p}</Fragment>)}</>
}

/** Component form, for prose written directly in JSX. */
export function Gloss({ children }: { children?: ReactNode }) {
  if (typeof children === 'string') return <>{gloss(children)}</>
  if (Array.isArray(children)) return <>{children.map((c, i) => <Fragment key={i}>{typeof c === 'string' ? gloss(c) : c}</Fragment>)}</>
  return <>{isValidElement(children) ? children : gloss(children)}</>
}
