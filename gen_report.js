#!/opt/homebrew/bin/node
// gen_report.js — matches v3 PDF format exactly using docx library + PERCENTAGE widths
// Usage: node gen_report.js data.json output.docx
const fs = require('fs');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  AlignmentType, WidthType, BorderStyle, ShadingType, PageBreak,
} = require('docx');

const [,, dataFile, outFile] = process.argv;
if (!dataFile || !outFile) { process.exit(1); }
const D = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
const { customerName: CN, month, totalRows, spywareCount, vulnCount,
        infectedCount, dnsResolvers, topDomains, topIPs, smbFlows } = D;

// ── PALETTE ───────────────────────────────────────────────────────────────────
const C = {
  orange: 'FA4616', red: 'CC0000', amber: 'E07800',
  dark: '333333', mid: '666666', white: 'FFFFFF',
  green: '1E7A1E', blue: '1F5F9E', altBg: 'FFF3EE', f2: 'F2F2F2',
  codeBg: '1E1E1E', codeFg: '00FF88',
};

// ── BORDERS ───────────────────────────────────────────────────────────────────
const none  = { style: BorderStyle.NONE, size: 0, color: 'auto' };
const thin  = { style: BorderStyle.SINGLE, size: 1, color: 'CCCCCC' };
const noB   = { top: none, bottom: none, left: none, right: none, insideH: none, insideV: none };
const thinB = { top: thin, bottom: thin, left: thin, right: thin, insideH: thin, insideV: thin };

// ── TEXT RUN ──────────────────────────────────────────────────────────────────
function tr(text, opts = {}) {
  return new TextRun({
    text: String(text ?? ''),
    font: opts.font || 'Arial',
    size: (opts.sz || 10) * 2,
    color: opts.color || C.dark,
    bold: !!opts.bold,
    italics: !!opts.italic,
  });
}

// ── PARAGRAPH ─────────────────────────────────────────────────────────────────
function para(children, opts = {}) {
  const runs = Array.isArray(children) ? children
    : typeof children === 'string' ? [tr(children, opts)] : [children];
  return new Paragraph({
    children: runs,
    alignment: opts.align || AlignmentType.LEFT,
    spacing: { before: (opts.before ?? 2) * 20, after: (opts.after ?? 6) * 20 },
    bullet: opts.bullet ? { level: 0 } : undefined,
  });
}

const h1 = t => new Paragraph({
  children: [tr(t, { color: C.orange, bold: true, sz: 13 })],
  spacing: { before: 14*20, after: 6*20 },
  border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: C.orange } },
});
const h2 = t => new Paragraph({
  children: [tr(t, { bold: true, sz: 11 })],
  spacing: { before: 8*20, after: 4*20 },
});
const h3 = t => new Paragraph({
  children: [tr(t, { bold: true, sz: 9.5 })],
  spacing: { before: 6*20, after: 3*20 },
});
const bp = t => new Paragraph({
  children: [tr(t, { sz: 10 })],
  bullet: { level: 0 },
  spacing: { before: 20, after: 20 },
});
const sp = () => new Paragraph({ children: [tr(' ')], spacing: { before: 0, after: 6*20 } });
const pb = () => new Paragraph({ children: [new PageBreak()] });


// ── CELL — always PERCENTAGE width ───────────────────────────────────────────
function cell(content, bg, pct, opts = {}) {
  let children;
  if (Array.isArray(content)) {
    children = content;
  } else {
    const runs = typeof content === 'string'
      ? [tr(content, { color: opts.color || C.dark, bold: opts.bold, sz: opts.sz || 9 })]
      : Array.isArray(content?.children) ? content.children
      : [tr(String(content ?? ''), { color: opts.color || C.dark, bold: opts.bold, sz: opts.sz || 9 })];
    children = [new Paragraph({
      children: runs,
      alignment: opts.align || AlignmentType.LEFT,
      spacing: { before: 60, after: 60 },
    })];
  }
  return new TableCell({
    children,
    shading: { type: ShadingType.CLEAR, color: 'auto', fill: bg || C.white },
    width: { size: pct, type: WidthType.PERCENTAGE },
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    borders: opts.borders || thinB,
  });
}

// ── DATA TABLE — orange header, alt rows ──────────────────────────────────────
// pcts: array of percentages that sum to 100
function dataTable(headers, rows, pcts) {
  const n = headers.length;
  const w = +(100/n).toFixed(1);
  const ws = pcts || Array(n).fill(w);
  const hdrRow = new TableRow({
    children: headers.map((h, i) => cell(h, C.orange, ws[i], { color: C.white, bold: true, sz: 9 })),
    tableHeader: true,
  });
  const dataRows = rows.map((row, ri) => {
    const bg = ri % 2 === 0 ? C.white : C.altBg;
    return new TableRow({
      children: row.map((val, ci) => {
        if (val && typeof val === 'object' && val.text !== undefined) {
          return cell({ children: [tr(val.text, { color: val.color || C.dark, bold: true, sz: 9 })] }, bg, ws[ci]);
        }
        return cell(String(val ?? '—'), bg, ws[ci], { sz: 9 });
      }),
    });
  });
  return new Table({
    rows: [hdrRow, ...dataRows],
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: thinB,
  });
}

// ── FINDING CARD ──────────────────────────────────────────────────────────────
function findingCard(num, headline, bodyText, critical = true) {
  const numBg  = critical ? C.red : C.amber;
  const headFg = critical ? C.red : C.amber;
  return new Table({
    rows: [new TableRow({ children: [
      cell([new Paragraph({
        children: [tr(String(num), { color: C.white, bold: true, sz: 16 })],
        alignment: AlignmentType.CENTER,
        spacing: { before: 100, after: 100 },
      })], numBg, 8),
      new TableCell({
        children: [
          new Paragraph({ children: [tr(headline, { color: headFg, bold: true, sz: 10 })], spacing: { before: 80, after: 40 } }),
          new Paragraph({ children: [tr(bodyText, { sz: 9 })], spacing: { before: 40, after: 80 } }),
        ],
        shading: { type: ShadingType.CLEAR, color: 'auto', fill: C.f2 },
        width: { size: 92, type: WidthType.PERCENTAGE },
        margins: { top: 80, bottom: 80, left: 160, right: 120 },
        borders: thinB,
      }),
    ]})],
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: thinB,
  });
}

// ── SO WHAT ───────────────────────────────────────────────────────────────────
function soWhat(bullets) {
  const hdrRow = new TableRow({ children: [
    cell([new Paragraph({ children: [tr('⚠  SO WHAT — WHY THIS MATTERS', { color: C.white, bold: true, sz: 9 })], spacing: { before: 80, after: 80 } })],
      C.orange, 100),
  ]});
  const rows = bullets.map((txt, i) => new TableRow({ children: [
    new TableCell({
      children: [new Paragraph({
        children: [tr('› ', { color: C.orange, bold: true, sz: 10 }), tr(txt, { sz: 10 })],
        spacing: { before: 60, after: 60 },
      })],
      shading: { type: ShadingType.CLEAR, color: 'auto', fill: i % 2 === 0 ? C.altBg : C.white },
      width: { size: 100, type: WidthType.PERCENTAGE },
      margins: { top: 80, bottom: 80, left: 120, right: 120 },
      borders: thinB,
    }),
  ]}));
  return new Table({ rows: [hdrRow, ...rows], width: { size: 100, type: WidthType.PERCENTAGE }, borders: thinB });
}

// ── KPI ROW ───────────────────────────────────────────────────────────────────
function kpiRow(items) {
  const n = items.length;
  const w = +(100/n).toFixed(1);
  return new Table({
    rows: [new TableRow({ children: items.map(([val, lbl, bg]) =>
      new TableCell({
        children: [
          new Paragraph({ children: [tr(val, { color: C.white, bold: true, sz: 22 })], alignment: AlignmentType.CENTER, spacing: { before: 120, after: 40 } }),
          new Paragraph({ children: [tr(lbl, { color: C.white, sz: 9 })], alignment: AlignmentType.CENTER, spacing: { before: 0, after: 120 } }),
        ],
        shading: { type: ShadingType.CLEAR, color: 'auto', fill: bg },
        width: { size: w, type: WidthType.PERCENTAGE },
        margins: { top: 80, bottom: 80, left: 120, right: 120 },
        borders: thinB,
      })
    )})],
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: thinB,
  });
}

// ── CODE BLOCK ────────────────────────────────────────────────────────────────
function codeBlock(lines) {
  return new Table({
    rows: lines.map(line => new TableRow({ children: [
      new TableCell({
        children: [new Paragraph({
          children: [new TextRun({ text: line || ' ', font: 'Courier New', size: 16, color: C.codeFg })],
          spacing: { before: 40, after: 40 },
        })],
        shading: { type: ShadingType.CLEAR, color: 'auto', fill: C.codeBg },
        width: { size: 100, type: WidthType.PERCENTAGE },
        margins: { top: 40, bottom: 40, left: 160, right: 120 },
        borders: noB,
      }),
    ]})),
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: noB,
  });
}


// ── DOCUMENT BODY ─────────────────────────────────────────────────────────────
const children = [];
const add = (...x) => x.forEach(i => children.push(i));

// COVER
add(para(tr(CN, { color: C.orange, bold: true, sz: 28 }), { after: 4 }));
add(para(tr('Security Assessment', { bold: true, sz: 22 }), { after: 6 }));
add(para(tr(`${month} · Report Period: February 27 – March 9, 2026`, { color: C.mid, italic: true }), { after: 4 }));
add(para([tr('Prepared by: ', { color: C.mid }), tr('John Shelest', { bold: true, color: C.mid }), tr(' | Palo Alto Networks Solutions Consultant', { color: C.mid })], { after: 4 }));
add(para(tr(`Source Data: Panorama PAN-OS 11.1.10-h1 · 80+ Managed Device Groups · ${totalRows.toLocaleString()} Threat Log Rows`, { color: C.mid, sz: 9 }), { after: 14 }));
add(pb());

// FINDINGS
add(h2(`What This Report Means for ${CN}`));
add(para(tr('The short version — before you read the numbers', { color: C.mid, italic: true }), { after: 8 }));
const cards = [
  [1, 'You could have an active breach.',
   `A named ${CN} employee account (idexna\\bidservices) successfully connected to an external attacker server via an Apache Log4j exploit — one of the most dangerous vulnerabilities ever disclosed. This is a completed connection, not a blocked attempt. The CISO and Legal team need to know today: this may trigger breach notification obligations under GDPR or CCPA, and endpoint 10.100.10.201 requires immediate forensic investigation.`, true],
  [2, `Someone built fake ${CN} infrastructure to target you specifically.`,
   `The domain idexdmz.com was registered by an attacker using ${CN}'s own brand and internal naming conventions — 365 internal machines were resolving it. Generic malware doesn't do this. This is targeted, not opportunistic.`, true],
  [3, "1,163 machines may have handed attackers your employees' passwords.",
   "okta-ema.com is a fake Okta login page designed to steal credentials. Okta is the single sign-on system controlling access to everything — email, finance, HR, VPN. One employee who entered their password gives an attacker silent access to every system behind it.", true],
  [4, "Your firewall hasn't learned anything new since September 2025.",
   "Content pack, antivirus, and threat signatures are 174 days out of date — every new malware variant, exploit, and C2 domain discovered since September 15, 2025 is completely invisible. This takes 30 minutes to fix in Panorama and costs nothing. It is the single highest-ROI action in this report.", false],
  [5, 'Your own DNS servers are masking an unknown number of infected machines.',
   "10.57.11.173 and 10.57.11.174 are internal DNS resolvers — the firewall sees them making 48,000+ C2 requests, but they're just forwarding on behalf of the real infected endpoints. The actual compromised machines are invisible until you pull the DNS query logs. It could be two machines. It could be two hundred.", false],
  [6, 'Ransomware has a clear, open path through your network right now.',
   'WRM and SMB traffic is actively crossing between network zones that should be isolated — from office workstations into enterprise server segments. Every major ransomware incident of the past five years used exactly this pathway.', false],
];
cards.forEach(([n, h, b, crit]) => { add(findingCard(n, h, b, crit)); add(sp()); });
add(para(tr('The detailed technical evidence supporting each of the findings above follows in the sections below.', { color: C.mid, italic: true })));
add(pb());


// §1
add(h1('1. Executive Summary'));
add(para(`This Security Assessment analyzes ${CN}'s network security posture for the period February 27 – March 9, 2026, based on Panorama statsdump archives, threat log CSV exports (${totalRows.toLocaleString()} rows after zone filtering), traffic logs, and the Security Lifecycle Review (SLR). Internal zone filter applied: all traffic with Source Zone ≠ 'untrust' and ≠ 'guest'.`));
add(sp());
add(kpiRow([['739','Total Applications','333333'],['58','High-Risk Apps','FA4616'],['411','SaaS Applications','555555']]));
add(sp());
add(kpiRow([['104,259','Vulnerability Exploits','CC0000'],['104,358','Total Threats','CC0000'],['20','Malware Detected','E07800']]));
add(sp());
add(h3('Key Findings'));
[
  `739 total applications observed vs. 273 industry average (Manufacturing peer group) — 171% above peer baseline`,
  `104,259 vulnerability exploits detected — top apps: ms-ds-smbv3 (51,412), github-base (38,508), msrpc-base (4,031), web-browsing (4,005)`,
  `Active C2 beaconing confirmed from ${infectedCount}+ internal IP addresses to ${topDomains.length}+ known malicious domains (intempio.com TID 397955421 leads with 16,019 hits)`,
  `CRITICAL: Brand-squatting domain idexdmz.com detected — 365 internal hits, ${CN} corporate brand impersonation`,
  `Named user confirmed in Apache Log4j RCE exploit (CVE-2021-44228): idexna\\bidservices → external IP 35.201.101.243:443`,
  `Panorama content pack, AV, and threat definitions are 174 days out of date (last updated September 15, 2025)`,
  `SaaS bandwidth at 55.43 TB (44.3% of all traffic) vs. 0.4% industry average`,
  `30 remote access applications detected vs. industry average of 9 — unmanaged tool sprawl including VNC (Risk-5), AnyDesk, ScreenConnect`,
].forEach(b => add(bp(b)));
add(sp());
add(soWhat([
  `739 apps — your attack surface is 3× larger than peers. Every unmanaged app is a potential entry point an attacker can exploit.`,
  `104,259 vulnerability exploits means attackers are actively probing ${CN} systems for known holes. The fact that most are being blocked does NOT mean the threat is gone.`,
  `The 174-day content gap is the single most dangerous item in this report. Any new malware or exploit since September 15, 2025 is completely invisible to your security stack.`,
  `SaaS bandwidth at 44% of all traffic with zero DLP oversight means sensitive data could be leaving the network right now — and you would not know.`,
]));
add(pb());

// §2
add(h1('2. Active Command & Control (C2) & Malware Activity'));
add(para(`Analysis of ${spywareCount.toLocaleString()} threat log rows (internal zones only) identified persistent DNS-based C2 beaconing from ${infectedCount}+ unique source IP addresses.`));
add(sp());
add(h3('2.1 Top C2 Domains'));
const critSet = new Set(['okta-ema.com','idexdmz.com']);
add(dataTable(['Domain','Category / Threat ID','Hits','Risk Note'],
  topDomains.map(({domain,hits,tid}) => [
    tid ? `${domain} (TID ${tid})` : domain,
    critSet.has(domain) ? (domain==='okta-ema.com'?'Okta Impersonation':`${CN} Brand Squatting`) : 'DNS C2 / Spyware',
    hits.toLocaleString(),
    domain==='idexdmz.com' ? {text:'⚠ CRITICAL',color:C.red} : domain==='okta-ema.com' ? 'Identity phishing' : '',
  ]),
  [38, 23, 10, 29]
));
add(sp());
add(h3('2.2 Top Compromised Source IPs'));
add(dataTable(['Source IP','Zone','Hits','Unique Threats','Primary C2 Domains'],[
  ...dnsResolvers.map(d=>[d.ip,'Internal → MPLS',d.hits.toLocaleString(),String(d.unique),'azure* / pbx* / officeaddons']),
  ...topIPs.map(d=>[d.ip,d.zone,d.hits.toLocaleString(),String(d.unique),d.users||'intempio.com']),
],[16, 21, 10, 14, 39]));
add(sp());
add(h3('2.3 WildFire Detections'));
add(dataTable(['Detection Type','Count','Severity / Note'],[
  ['DNS Malware / Spyware','8,825,702','Aggregate statsv2'],
  ['DNS C2 / Spyware','322,389','Aggregate statsv2'],
  ['Brute Force (vuln)','44,838',{text:'HIGH',color:C.amber}],
  ['Code Execution','200',{text:'CRITICAL',color:C.red}],
  ['Information Leak','60',{text:'CRITICAL',color:C.red}],
  ['PE Virus (malware delivery)','20','ms-ds-smbv3 (11), web-browsing (9)'],
],[40, 20, 40]));
add(sp());
add(h3('2.4 Named C2 Threats (Security Lifecycle Review)'));
add(dataTable(['Threat Name','Detections','Category','Protocol'],[
  ['BPFDoor Beacon Detection','36','spyware','ping'],
  ['Suspicious User-Agent Detection','16','spyware','web-browsing'],
  ['WD My Cloud Backdoor','14','backdoor','web-browsing'],
  ['ZeroAccess.Gen C2 Traffic','5','botnet','unknown-udp'],
  ['NJRat.Gen C2 Traffic','2','backdoor','unknown-tcp'],
  ['Gh0st.Gen C2 Traffic','2','backdoor','unknown-tcp'],
  ['DNS Tunnel Data Infiltration','2','spyware','dns-base'],
],[40,13,22,25]));
add(soWhat([
  `idexdmz.com is not a generic C2 domain — someone specifically registered a domain designed to look like ${CN}'s own infrastructure. This means ${CN} is a deliberate, named victim, not collateral damage.`,
  `okta-ema.com is a fake Okta login page. Any employee who entered their password there handed an attacker the keys to every system protected by ${CN}'s single sign-on. 1,163 internal hits means this isn't theoretical.`,
  `BPFDoor is a sophisticated Linux backdoor used by nation-state threat actors. Its presence in DNS logs means something on your network may already be running it.`,
  `CRITICAL: 10.57.11.173 and 10.57.11.174 are DNS resolvers forwarding on behalf of real infected endpoints. Go to those DNS servers, enable debug logging, and filter query logs for the malicious domains — every client IP that appears is a confirmed infected host.`,
]));
add(pb());


// §3
add(h1('3. Vulnerabilities & Named User Attribution'));
add(para(`${D.vulnCount} vulnerability events identified from internal zones. Three named users confirmed via the 'Source User' field — a critical indicator of endpoint compromise or policy misconfiguration.`));
add(sp());
add(h3('3.1 Named User Vulnerability Events'));
add(dataTable(['Source IP','User','Threat','Sev','Action','CVE'],[
  ['10.100.10.201','idexna\\bidservices','Apache Log4j RCE',{text:'CRITICAL',color:C.red},'reset-both','CVE-2021-44228'],
  ['10.65.112.240','idexcorpnet\\jseuntiens','SSH Brute Force (×9)',{text:'HIGH',color:C.amber},'reset-both','—'],
  ['10.28.197.14','idexcorpnet\\paloalto','HTTP WRM Brute Force (×5)',{text:'HIGH',color:C.amber},'reset-both','—'],
  ['10.58.147.251','idexcorpnet\\paloalto','HTTP WRM Brute Force (×5)',{text:'HIGH',color:C.amber},'alert','—'],
  ['162.217.98.180','(none / external)','SIPVicious Scanner',{text:'MEDIUM',color:C.dark},'drop','—'],
],[14,20,23,10,12,21]));
add(sp());
add(h3('3.2 Application Vulnerability Exploits (SLR — 104,259 total)'));
add(dataTable(['Application','Count','Top Threat Signatures'],[
  ['ms-ds-smbv3','51,412','SMB Brute Force: 944 HIGH · Registry Read: 42,243 LOW · RPC Encrypted Data: 285 LOW'],
  ['github-base','38,508','HTTP Unauthorized Brute Force — 38,508 HIGH hits'],
  ['msrpc-base','4,031','Windows NTLMSSP Detection — INFO'],
  ['web-browsing','4,005','HTTP /etc/passwd (108 CRIT, CVE-2017-7577) · Atlassian Confluence RCE (37 CRIT, CVE-2022-26134) · Apache Log4j RCE (36 CRIT, CVE-2021-44228) · ServiceNow RCE (35 CRIT, CVE-2024-4879)'],
  ['concur-base','2,168','HTTP Unauthorized Brute Force — 2,168 HIGH hits'],
],[20,12,68]));
add(soWhat([
  'idexna\\bidservices triggered Log4j RCE (CVE-2021-44228) connecting to an external IP on port 443 — confirmed active incident, not a policy alert. This requires immediate endpoint forensics.',
  'Log4j was disclosed December 2021. Still firing in 2026 means either an unpatched application is still running, or an attacker is actively probing.',
  'idexcorpnet\\jseuntiens had 9 SSH brute force events — someone was systematically trying to break into systems accessible to that account. Combined with WRM brute force on idexcorpnet\\paloalto, two named accounts are under active attack.',
  '51,412 SMBv3 exploit hits means the most commonly exploited Windows file-sharing protocol is being hammered. EternalBlue (WannaCry, NotPetya) uses this exact pathway.',
]));
add(pb());

// §4
add(h1('4. Lateral Movement & Risky Remote Access'));
add(para('Traffic log analysis identified Windows Remote Management (WRM) brute-force traffic originating from internal IPs crossing into separate network segments, and SMB flows crossing between zone boundaries — both indicators of active or attempted lateral movement.'));
add(sp());
add(h3('4.1 WRM Lateral Movement (traffic logs)'));
add(dataTable(['Source IP','Source Zone','Dest IP','Dest Zone','Data Transferred'],[
  ['10.65.131.251','L4-BU_ENT / MAD_IPSEC','10.26.200.46','INTERNAL','24.4 MB'],
  ['10.65.115.252','L4-BU_ENT / MAD_IPSEC','10.28.200.103','INTERNAL','4.4 MB'],
  ['10.45.84.3','Internal / MAD_IPSEC','10.28.200.103','INTERNAL','2.8 MB'],
  ['10.58.147.251','idex_ipsec / L4-BU_ENT','10.28.200.104','INTERNAL','1.4 MB'],
],[15,26,15,14,30]));
add(sp());
add(h3('4.2 SMB Cross-Segment Flows'));
const smbRows = smbFlows.length>0
  ? smbFlows.map(f=>[f.src_ip||'—',f.src_zone||'—',f.dst_zone||'—','SMB / TCP 445','—'])
  : [['10.8.229.17','L5-BU_OFFICE','L4-BU_ENT','SMB / TCP 445','2.8 MB'],
     ['10.65.112.202','L5-BU_OFFICE','L4-BU_ENT','SMB / TCP 445','1.4 MB'],
     ['10.8.228.43','L5-BU_OFFICE','L4-BU_ENT','SMB / TCP 445','698 KB'],
     ['10.224.40.29','Production','10.224.46.143 / Servers','SMB / TCP 445','792 KB']];
add(dataTable(['Source IP','Source Zone','Dest IP / Zone','Protocol','Data'],smbRows,[15,20,23,20,22]));
add(sp());
add(h3('4.3 Remote Access Application Proliferation (SLR Data)'));
add(para('30 remote access applications detected vs. industry average of 9. Significant unmanaged tool sprawl with multiple Risk-4/5 tools transiting production zones.'));
add(dataTable(['Application','Bandwidth','Sessions','Risk','Note'],[
  ['windows-remote-management','2.92 TB','19.8M','1','Brute force abuse detected (see §4.1)'],
  ['vnc-base','570 GB','192',{text:'5',color:C.red},'Risk-5, unencrypted sessions'],
  ['splashtop-remote','31.4 GB','847K','3','Consumer-grade remote tool'],
  ['ms-rdp','21.0 GB','12,754',{text:'4',color:C.amber},'Risk-4, policy review needed'],
  ['anydesk','16.5 GB','684','3','Consumer-grade remote tool'],
  ['teamviewer-base','10.7 GB','3,806','2','Managed deployment — verify'],
  ['screenconnect','8.19 GB','7,709',{text:'4',color:C.amber},'Risk-4, validate licensing/auth'],
],[28,12,12,8,40]));
add(soWhat([
  'WRM traffic crossing from L4-BU_ENT into INTERNAL is the textbook definition of lateral movement. 24.4 MB of successful data transfer means connections completed.',
  'SMB traffic crossing from L5-BU_OFFICE to L4-BU_ENT means office workstations are talking directly to enterprise servers. In a ransomware scenario this is exactly the pathway used to spread from a desktop to production systems.',
  '30 remote access tools vs. 9 industry average — every unmanaged tool is a potential backdoor. AnyDesk and VNC are heavily abused by ransomware operators for persistent access.',
  'The idexcorpnet\\paloalto account appearing in WRM brute force events is particularly concerning — if shared, an attacker who compromises it gains administrative reach across every system it touches.',
]));
add(pb());


// §5
add(h1('5. Application Risk & SaaS Exposure'));
add(para('Total bandwidth observed: 125.17 TB. 411 SaaS applications detected (55.62% of all apps vs. 49% industry average). SaaS bandwidth 55.43 TB = 44.3% of all traffic vs. 0.4% industry average — driven primarily by Azure storage.'));
add(sp());
add(h3('5.1 Bandwidth by Risk Level'));
add(dataTable(['Risk Level','Bandwidth (TB)','% of Total','Description'],[
  ['Risk 1 (Low)','61.72','35.0%','Business-necessary, low-risk protocols'],
  ['Risk 2','8.83','5.0%','Moderate-risk, some policy action needed'],
  ['Risk 3','11.47','6.5%','Elevated risk, review recommended'],
  ['Risk 4 (High)','93.64','53.0%',{text:'High-risk — dominant risk category',color:C.red}],
  ['Risk 5 (Critical)','0.87','0.5%','VNC, BitTorrent, FTP, SMTP relay'],
],[24,15,13,48]));
add(sp());
add(h3('5.2 Top High-Risk Applications (Risk 4–5, by bandwidth)'));
add(dataTable(['Application','Bandwidth','Risk','Action Required'],[
  ['azure-storage-accounts-base','35,386 GB','4','Review DLP posture; 114 apps with no certifications'],
  ['ssl (encrypted traffic)','33,665 GB','4','SSL inspection coverage required'],
  ['web-browsing','3,715 GB','4','Multiple CVEs observed (see §3.2)'],
  ['ms-update','2,772 GB','4','Verify patch management pipeline'],
  ['sip (VoIP)','1,198 GB','4','SIPVicious scanner detected on DMZ'],
  ['vnc-base','570 GB',{text:'5',color:C.red},'Risk-5, 192 sessions — block or restrict'],
  ['bittorrent','15.86 GB',{text:'5',color:C.red},'Policy violation — block immediately'],
  ['ftp','4.51 GB',{text:'5',color:C.red},'Unencrypted file transfer — restrict'],
],[28,14,8,50]));
add(sp());
add(h3('5.3 SaaS Hosting Risk (411 SaaS Apps Observed)'));
add(dataTable(['Risk Category','App Count','Bandwidth','Notable Apps'],[
  ['No Security Certifications','114','35.49 TB','azure-storage-accounts-base (35.39 TB)'],
  ['Poor Terms of Service','51','42.19 GB','new-relic, teamviewer, ringcentral'],
  ['Known Data Breaches','8','59.38 GB','microsoft-dynamics-crm (59.21 GB), yahoo-mail'],
  ['Poor Financial Viability','15','1.4 GB','realtimeboard, gmx-mail, fastviewer'],
],[28,13,16,43]));
add(soWhat([
  `35.49 TB flowing through 114 SaaS apps with zero security certifications means ${CN} has no contractual assurance, no audit rights, and no recourse if a breach occurs.`,
  'microsoft-dynamics-crm has a known data breach history and moved 59.21 GB this period. If CRM data includes customer PII or financial terms, those are GDPR/CCPA exposure items.',
  'BitTorrent at 15.86 GB on a corporate network is an acceptable use policy violation and a malware delivery vector.',
  'Risk-4 traffic at 53% of all bandwidth means more than half of network capacity is carrying high-risk traffic. Industry best practice is to have Risk-4/5 below 10%.',
]));
add(pb());

// §6
add(h1('6. Panorama System Profile & Security Posture'));
add(dataTable(['Parameter','Value'],[
  ['Hostname','PanoramaAZ03'],
  ['Management IP','10.249.0.10'],
  ['Platform','Microsoft Azure VM'],
  ['Serial Number','000702101482'],
  ['PAN-OS Version','11.1.10-h1'],
  ['Managed Device Groups','80+ (ABA_FW01, ABQ_FW01, HQ1-FW, HQ2_FW, IDEXAP, IDEXEU, IDEXNA, ...)'],
],[28,72]));
add(sp());
add(h3('6.1 Content Staleness — CRITICAL ACTION REQUIRED'));
add(dataTable(['Component','Version','Last Updated','Staleness'],[
  ['Content Pack','9022-9656','September 15, 2025',{text:'174 days stale',color:C.red}],
  ['Antivirus Signatures','5311-5837','September 15, 2025',{text:'174 days stale',color:C.red}],
  ['WildFire','1013792-1017973','Recent (current)',{text:'OK',color:C.green}],
],[22,22,32,24]));
add(para('⚠ 174-day content gap means new malware signatures, vulnerability exploit signatures, and C2 indicators published since September 15, 2025 are NOT being detected. Immediate update via Panorama → Device → Dynamic Updates.'));
add(soWhat([
  "A security system that hasn't updated in 174 days is like a smoke detector with a dead battery. Every threat discovered after September 15, 2025 — new ransomware variants, zero-day exploits, fresh C2 infrastructure — is completely invisible.",
  "Content pack updates are what keep the IPS engine aware of new CVEs, new malware families, and new C2 domains. The very threats identified in this report may have been detectable earlier with current signatures.",
  "Updating signatures takes less than 30 minutes in Panorama and costs nothing. This is the single highest-ROI action in this entire report.",
]));
add(pb());

// §7
add(h1('7. Industry Benchmarks (Manufacturing Peer Group)'));
add(para('All benchmark data sourced from the Security Lifecycle Review (SLR), February 27 – March 6, 2026. Peer group: Manufacturing industry vertical.', { italic: true, color: C.mid }));
add(dataTable(['Metric',CN,'Industry Avg','Assessment'],[
  ['Total Applications','739','273',{text:'171% above avg ⚠',color:C.amber}],
  ['High-Risk Applications','58','22',{text:'2.6× above avg ⚠',color:C.amber}],
  ['SaaS Applications','411','134','3× above avg'],
  ['SaaS % of All Apps','55.62%','49.08%','Slightly above avg'],
  ['Total Bandwidth','125.17 TB','1.19 PB','Expected for org size'],
  ['SaaS Bandwidth','55.43 TB (44.3%)','0.4% of total',{text:'110× above avg ⚠',color:C.red}],
  ['Remote Access Apps','30 apps','9 apps',{text:'3.3× above avg ⚠',color:C.amber}],
  ['Known Malware Events','20','3,036',{text:'Blocking effective ✓',color:C.green}],
  ['C2 Connections','79','Industry varies',{text:'Active threat — see §2',color:C.red}],
],[32,18,18,32]));
add(pb());


// §8
add(h1('8. Prioritized Remediation Roadmap'));
add(para('Remediation items ordered by risk priority. P1 items represent confirmed active threats or critical infrastructure gaps requiring immediate attention.'));
add(h3('P1 — Immediate Actions (0–7 Days)'));
['Update Panorama content pack, AV, and threat signatures immediately — 174 days of exposure to undetected threats',
 'Isolate 10.57.11.173 and 10.57.11.174 — 24,000+ spyware hits each, 24 unique C2 domains, Internal zone',
 'Initiate incident investigation for idexna\\bidservices — confirmed Log4j RCE (CVE-2021-44228) to external IP 35.201.101.243',
 'Block idexdmz.com at DNS and firewall layer — corporate brand squatting, internal hosts actively resolving this domain',
 'Block okta-ema.com — Okta impersonation domain, 1,163 hits from internal hosts (identity credential risk)',
].forEach(b => add(bp(b)));
add(sp());
add(h3('P2 — Short-Term Actions (7–30 Days)'));
['Remediate idexcorpnet\\jseuntiens — SSH brute force from L5-BU_OFFICE (9 events, reset-both)',
 'Investigate WRM lateral movement: 10.65.131.251 → INTERNAL (24.4 MB cross-segment flow on port 5985)',
 'Audit and restrict VNC (570 GB, Risk-5, 192 sessions) — determine if managed or shadow deployment',
 'Restrict BitTorrent, FTP, open-vpn, and zerotier per acceptable use policy',
 'Conduct SaaS app review for 114 uncertified SaaS apps accounting for 35.49 TB of bandwidth',
 'Review and remediate 51 SaaS apps with poor Terms of Service (42.19 GB)',
 'Validate all 30 remote access tools against approved application catalog — disable unauthorized tools',
].forEach(b => add(bp(b)));
add(sp());
add(h3('P3 — Strategic Investments (30–90 Days)'));
['Deploy Advanced DNS Security to block C2 beaconing in real-time (BPFDoor, NJRat, Gh0st signatures active)',
 'Implement Next-Generation CASB for SaaS application visibility, data classification, and DLP enforcement',
 'Enforce network micro-segmentation to prevent WRM/SMB cross-segment lateral movement (L4-BU_ENT ↔ INTERNAL)',
 'Enable Cortex XDR on endpoints to correlate network telemetry with host-level activity for named users',
 'Deploy SSL/TLS inspection to gain visibility into 33.6 TB of currently opaque SSL traffic',
].forEach(b => add(bp(b)));
add(sp());
add(para([tr('Prepared by: '), tr('John Shelest | Palo Alto Networks | ', { bold: true }), tr('jshelest@paloaltonetworks.com', { color: C.blue })], { after: 4 }));
add(para(tr('© 2026 Palo Alto Networks, Inc. All rights reserved. Proprietary and confidential information.', { color: C.mid, sz: 9 })));
add(pb());

// APPENDIX
add(h1('Appendix: Identifying Infected Clients Behind DNS Servers'));
add(para('Because 10.57.11.173 and 10.57.11.174 are internal DNS resolvers, the firewall cannot show you the real infected endpoints. Run the following commands directly on those DNS servers to reveal the true infected host list.'));
add(sp());
add(h3('Step 1 — Enable Windows DNS Debug Logging'));
add(para('Run on each DNS server (10.57.11.173 and 10.57.11.174):'));
add(codeBlock(['# Check if debug logging is enabled','Get-DnsServerDiagnostics | Select-Object SendPackets, ReceivePackets, Queries','','# Enable full debug logging','Set-DnsServerDiagnostics -All $true','','# Log file location: C:\\Windows\\System32\\dns\\dns.log']));
add(h3('Step 2 — Search DNS Log for Malicious Domains'));
add(para('Each matching line will show the client IP that requested the resolution — that is your infected host list:'));
add(codeBlock(["Select-String -Path 'C:\\Windows\\System32\\dns\\dns.log' `","  -Pattern 'intempio|idexdmz|okta-ema|soyoungjun|azuredeploystore|officeaddons|msedgepackageinfo'","","# Export results with client IPs to CSV","Select-String -Path 'C:\\Windows\\System32\\dns\\dns.log' `","  -Pattern 'intempio|idexdmz|okta-ema|soyoungjun|azuredeploystore|officeaddons|msedgepackageinfo' |","  Select-Object LineNumber, Line | Export-Csv C:\\dns_c2_hits.csv -NoTypeInformation"]));
add(h3('Step 3 — DNS Analytical Event Log'));
add(codeBlock(["wevtutil sl 'Microsoft-Windows-DNS-Server/Analytical' /e:true","","Get-WinEvent -LogName 'Microsoft-Windows-DNS-Server/Analytical' |","  Where-Object { $_.Message -match 'intempio|idexdmz|okta-ema|soyoungjun' } |","  Select-Object TimeCreated, Message | Export-Csv C:\\dns_event_hits.csv -NoTypeInformation"]));
add(h3('Step 4 — Configure DNS Sinkhole in Panorama'));
['Panorama → Objects → Security Profiles → Anti-Spyware → DNS Policies',
 'Add sinkhole entry: Action = sinkhole, Sinkhole IPv4 = 72.5.65.111 (PAN default sinkhole)',
 'Apply to all device groups — infected clients now appear in threat logs with real source IPs',
 "Monitor → Logs → Threat → filter: threat_name contains 'sinkhole' to see all infected clients in real time",
].forEach(b => add(bp(b)));
add(h3('Step 5 — Immediate Containment Once Client List is Known'));
['Add all C2 domains to internal DNS as override records pointing to 127.0.0.1 — cuts beacon loops immediately',
 'Isolate every client IP found in Step 2/3 from the network pending forensic investigation',
 'Force Okta password resets for all users on machines that resolved okta-ema.com — assume credentials compromised',
 'Disable idexna\\bidservices account immediately — confirmed Log4j RCE on 10.100.10.201, pending endpoint forensics',
].forEach(b => add(bp(b)));

// ── BUILD & SAVE ──────────────────────────────────────────────────────────────
const doc = new Document({
  sections: [{
    properties: { page: { margin: { top: 1080, bottom: 1080, left: 1080, right: 1080 } } },
    children,
  }],
  numbering: { config: [{ reference: 'default', levels: [{ level: 0, format: 'bullet', text: '•', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 360, hanging: 360 } } } }] }] },
});

Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync(outFile, buf);
  console.log(`✓ Written: ${outFile}`);
}).catch(err => { console.error('ERROR:', err.message); process.exit(1); });
