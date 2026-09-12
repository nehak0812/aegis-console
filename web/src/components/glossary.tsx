import { useEffect, useRef, useState } from 'react'
import { useApi } from '../lib/api'

/** Plain-language explanations for the abbreviations used across the console. Shown on hover (or tap) anywhere on a page. */
export const GLOSSARY: Record<string, string> = {
  KEV: 'Known Exploited Vulnerabilities — CISA\'s catalogue of flaws confirmed as exploited in real attacks.',
  CISA: 'Cybersecurity and Infrastructure Security Agency (US). Publishes the KEV catalogue and remediation due dates.',
  CVE: 'Common Vulnerabilities and Exposures — the public ID of a specific software flaw (e.g. CVE-2026-19490).',
  CVSS: 'Common Vulnerability Scoring System — the vendor-neutral 0–10 severity of a flaw (not how likely it is to be exploited).',
  EPSS: 'Exploit Prediction Scoring System (FIRST) — the published probability that a CVE is exploited in the next 30 days.',
  NVD: 'National Vulnerability Database (NIST) — US reference database of CVEs.',
  CPE: 'Common Platform Enumeration — a standard name for a software product and version, used to match CVEs to hosts.',
  CNA: 'CVE Numbering Authority — usually the vendor, which publishes the CVE record and its fix references.',
  DMARC: 'Domain-based Message Authentication, Reporting & Conformance — tells receivers to reject mail that fails SPF/DKIM for your domain.',
  SPF: 'Sender Policy Framework — DNS list of servers allowed to send mail for a domain. "-all" means reject everything else.',
  DKIM: 'DomainKeys Identified Mail — a signature on outgoing mail, checked against a key published in DNS.',
  'MTA-STS': 'Mail Transfer Agent Strict Transport Security — forces encrypted delivery of inbound mail.',
  'TLS-RPT': 'TLS Reporting — asks other mail servers to report failed encrypted deliveries to you.',
  DNSSEC: 'DNS Security Extensions — cryptographically signs DNS answers so they cannot be forged.',
  CAA: 'Certification Authority Authorization — DNS record naming the certificate authorities allowed to issue for a domain.',
  RDAP: 'Registration Data Access Protocol — the modern WHOIS; gives domain expiry and transfer-lock status.',
  RPKI: 'Resource Public Key Infrastructure — lets networks verify who may announce an IP range (protects against BGP hijacks).',
  ROA: 'Route Origin Authorisation — the RPKI record stating which network may announce an IP range.',
  BGP: 'Border Gateway Protocol — how networks announce IP ranges to each other on the internet.',
  ASN: 'Autonomous System Number — the ID of a network that announces IP ranges.',
  DNS: 'Domain Name System — the internet\'s address book (names to addresses, mail servers, verification records).',
  DoH: 'DNS over HTTPS — how AEGIS queries public DNS passively (via Google and Cloudflare resolvers).',
  NS: 'Name server — the provider that hosts a domain\'s DNS.',
  MX: 'Mail exchanger — the server that receives email for a domain.',
  TXT: 'A free-text DNS record — used for SPF, DMARC and service-verification tokens.',
  CNAME: 'Canonical name — a DNS alias pointing one hostname at another (often a SaaS or CDN provider).',
  CT: 'Certificate Transparency — public logs of every TLS certificate issued.',
  NRD: 'Newly registered domain — domains registered in the last days, checked for lookalikes of monitored brands.',
  IOC: 'Indicator of compromise — a domain, IP, URL or file hash published as attacker infrastructure.',
  IOCs: 'Indicators of compromise — domains, IPs, URLs or file hashes published as attacker infrastructure.',
  C2: 'Command and control — a server attackers use to steer malware or compromised machines.',
  SLA: 'Service-level agreement — here, the number of days allowed to fix a finding at each level.',
  LEI: 'Legal Entity Identifier — the global ID of a legal entity (GLEIF).',
  GLEIF: 'Global Legal Entity Identifier Foundation — publishes LEIs and who owns whom (parent companies).',
  CSL: 'Consolidated Screening List (US trade.gov) — combines US export-control and sanctions lists.',
  OFAC: 'Office of Foreign Assets Control (US Treasury) — administers US sanctions (the SDN list).',
  BIS: 'Bureau of Industry and Security (US Commerce) — maintains the Entity List for export controls.',
  SEC: 'US Securities and Exchange Commission — its 8-K filings disclose material cyber incidents.',
  '8-K': 'SEC Form 8-K — a US public-company filing; Item 1.05 discloses a material cybersecurity incident.',
  'ATT&CK': 'MITRE ATT&CK — the public catalogue of attacker tactics and techniques.',
  ATLAS: 'MITRE ATLAS — ATT&CK\'s counterpart for attacks on AI and machine-learning systems.',
  MITRE: 'MITRE — US non-profit that maintains CVE, ATT&CK and ATLAS.',
  DDoS: 'Distributed denial of service — flooding a service so legitimate users cannot reach it.',
  DDoSia: 'The volunteer DDoS tool of the pro-Russian NoName057(16) group; its target lists are public.',
  MFA: 'Multi-factor authentication — a second check beyond the password.',
  AiTM: 'Adversary-in-the-middle — a phishing proxy that steals session cookies and bypasses MFA.',
  BEC: 'Business email compromise — fraud via a hijacked or spoofed business mailbox.',
  FIMI: 'Foreign information manipulation and interference — state-linked influence operations.',
  NIS2: 'The EU Network and Information Security Directive (2022) — security and incident-reporting duties.',
  DORA: 'The EU Digital Operational Resilience Act — ICT-risk rules for financial firms, incl. third-party registers.',
  NIST: 'US National Institute of Standards and Technology — publishes the Cybersecurity Framework (CSF).',
  CSF: 'NIST Cybersecurity Framework 2.0 — the reference for the indicative control mappings in playbooks.',
  OSV: 'Open Source Vulnerabilities — Google\'s database of flaws in open-source packages.',
  OSINT: 'Open-source intelligence — intelligence from public sources.',
  MISP: 'Malware Information Sharing Platform — open threat-sharing format; AEGIS reads public MISP feeds.',
  PoC: 'Proof of concept — public exploit code demonstrating a flaw.',
  WAF: 'Web application firewall — can block exploitation until a patch is applied.',
  CMS: 'Content management system (e.g. WordPress, Drupal).',
  VPN: 'Virtual private network — often an internet-facing edge device, a frequent exploitation target.',
  SSO: 'Single sign-on — one identity provider for many applications.',
  RaaS: 'Ransomware as a service — gangs that rent their ransomware to affiliates.',
  SBOM: 'Software bill of materials — the list of components inside a piece of software.',
  AIID: 'AI Incident Database — public register of AI system incidents and harms.',
  AIAAIC: 'AI, Algorithmic and Automation Incidents and Controversies — an independent AI incident register.',
  FTP: 'File Transfer Protocol — an old, unencrypted file-transfer service; risky when exposed.',
  RDP: 'Remote Desktop Protocol — Windows remote access; a common initial-access target when exposed.',
}
const HIGHLIGHT = 'aegis-gloss'

/** Underlines known abbreviations on the page (CSS Custom Highlight API — no DOM changes, so React stays in charge of the text)
 *  and shows their explanation on hover, or on tap on touch screens. Rule IDs (e.g. VUL-KEV-EXPOSED, DL-72H) explain themselves too. */
export function GlossaryLayer({ root = '.main' }: { root?: string }) {
  const { data: rules } = useApi<any[]>('/rules', 3600)
  const [tip, setTip] = useState<{ x: number; y: number; term: string; text: string } | null>(null)
  const dict = useRef<Record<string, string>>(GLOSSARY)
  const rx = useRef<RegExp | null>(null)

  useEffect(() => {
    const d: Record<string, string> = { ...GLOSSARY }
    for (const r of rules || []) d[r.id] = `Rule ${r.id} (${r.applies_to}, ${r.level}): ${r.rule}`
    dict.current = d
    const terms = Object.keys(d).sort((a, b) => b.length - a.length).map(t => t.replace(/[.*+?^${}()|[\]\\&]/g, m => (m === '&' ? '&' : `\\${m}`)))
    rx.current = new RegExp(`(?<![A-Za-z0-9-])(${terms.join('|')})(?![A-Za-z0-9-])`, 'g')
  }, [rules])

  // underline every occurrence — recomputed (debounced) whenever the page's text changes
  useEffect(() => {
    const CSSx = (window as any).CSS
    if (!CSSx?.highlights || typeof (window as any).Highlight !== 'function') return
    let t: any
    const scan = () => {
      const el = document.querySelector(root)
      const re = rx.current
      if (!el || !re) return
      const ranges: Range[] = []
      const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, {
        acceptNode: n => (n.parentElement?.closest('input,textarea,script,style,.tip,.gloss-tip') ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT),
      })
      for (let n = walker.nextNode(); n && ranges.length < 4000; n = walker.nextNode()) {
        const s = n.nodeValue || ''
        if (s.length < 2) continue
        re.lastIndex = 0
        for (let m = re.exec(s); m; m = re.exec(s)) {
          const r = new Range()
          r.setStart(n, m.index)
          r.setEnd(n, m.index + m[0].length)
          ranges.push(r)
        }
      }
      CSSx.highlights.set(HIGHLIGHT, new (window as any).Highlight(...ranges))
    }
    const obs = new MutationObserver(() => { clearTimeout(t); t = setTimeout(scan, 450) })
    const el = document.querySelector(root)
    if (el) obs.observe(el, { subtree: true, childList: true, characterData: true })
    t = setTimeout(scan, 600)
    return () => { obs.disconnect(); clearTimeout(t); CSSx.highlights.delete(HIGHLIGHT) }
  }, [root, rules])

  // find the term under the pointer without touching the DOM
  useEffect(() => {
    const at = (x: number, y: number): { term: string } | null => {
      const re = rx.current
      if (!re) return null
      const doc: any = document
      let node: Node | null = null, off = 0
      if (doc.caretRangeFromPoint) { const r = doc.caretRangeFromPoint(x, y); if (r) { node = r.startContainer; off = r.startOffset } }
      else if (doc.caretPositionFromPoint) { const p = doc.caretPositionFromPoint(x, y); if (p) { node = p.offsetNode; off = p.offset } }
      if (!node || node.nodeType !== 3 || !(node.parentElement?.closest(root))) return null
      const s = node.nodeValue || ''
      re.lastIndex = 0
      for (let m = re.exec(s); m; m = re.exec(s)) {
        if (off >= m.index && off <= m.index + m[0].length) {
          // confirm the pointer is really over the word (caret APIs snap to the nearest character)
          const r = new Range(); r.setStart(node, m.index); r.setEnd(node, m.index + m[0].length)
          const b = r.getBoundingClientRect()
          if (x >= b.left - 2 && x <= b.right + 2 && y >= b.top - 2 && y <= b.bottom + 2) return { term: m[0] }
        }
      }
      return null
    }
    let raf = 0
    const show = (x: number, y: number) => {
      const hit = at(x, y)
      setTip(hit ? { x, y, term: hit.term, text: dict.current[hit.term] } : null)
    }
    const move = (e: MouseEvent) => { cancelAnimationFrame(raf); raf = requestAnimationFrame(() => show(e.clientX, e.clientY)) }
    const tap = (e: PointerEvent) => { if (e.pointerType !== 'mouse') show(e.clientX, e.clientY) }
    document.addEventListener('mousemove', move, { passive: true })
    document.addEventListener('pointerdown', tap, { passive: true })
    return () => { document.removeEventListener('mousemove', move); document.removeEventListener('pointerdown', tap); cancelAnimationFrame(raf) }
  }, [root])

  if (!tip) return null
  const left = Math.min(tip.x + 14, window.innerWidth - 300)
  return (
    <div className="tip gloss-tip" role="tooltip" style={{ position: 'fixed', left: Math.max(8, left), top: tip.y + 16, zIndex: 80, maxWidth: 300, pointerEvents: 'none' }}>
      <strong>{tip.term}</strong><div>{tip.text}</div>
    </div>
  )
}
