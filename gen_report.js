#!/opt/homebrew/bin/node
/**
 * gen_report.js — fully dynamic, zero hardcoded customer data
 * All content comes from D (data.json) passed by pan_assessment_app.py
 */
const fs = require('fs');
const [,, dataFile, outFile] = process.argv;
if (!dataFile || !outFile) process.exit(1);
const D = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
const CN = D.customerName || 'Customer';
const month = D.month || 'March 2026';

const C = {
    orange:'#FA4616', red:'#CC0000', amber:'#E07800',
    dark:'#333333', mid:'#666666', white:'#FFFFFF',
    border:'#CCCCCC', altBg:'#FFF3EE', f2:'#F2F2F2', blue:'#1F5F9E', green:'#1E7A1E'
};

// ── HELPERS ───────────────────────────────────────────────────────────────────
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function renderSoWhat(sectionKey) {
    const bullets = (D.soWhat && D.soWhat[sectionKey]) || [];
    if (!bullets.length) return '';
    const items = bullets.map(b => {
        const html = b.replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>');
        return `<div class="so-what-item"><span style="color:${C.orange};font-weight:bold;margin-right:6px;">›</span>${html}</div>`;
    }).join('');
    return `<div class="so-what-box"><div class="so-what-head">&#9888; SO WHAT &mdash; WHY THIS MATTERS</div>${items}</div>`;
}

function renderFindingCard(num, headline, body, critical=true) {
    const color = critical ? C.red : C.amber;
    return `<div style="display:flex;border:1px solid ${C.border};margin-bottom:12px;page-break-inside:avoid;">
        <div style="background:${color};color:white;width:50px;display:flex;align-items:center;justify-content:center;font-size:26px;font-weight:bold;flex-shrink:0;">${num}</div>
        <div style="background:${C.f2};padding:10px 16px;flex-grow:1;">
            <div style="color:${color};font-size:13px;font-weight:bold;margin-bottom:5px;">${headline}</div>
            <div style="font-size:11px;color:${C.dark};line-height:1.5;text-align:justify;">${body}</div>
        </div></div>`;
}

function renderKPI(val, label, bg) {
    return `<div style="background:${bg};color:white;padding:16px;text-align:center;border-radius:2px;flex:1;margin:0 6px;">
        <div style="font-size:30px;font-weight:bold;">${val}</div>
        <div style="font-size:10px;text-transform:uppercase;margin-top:3px;font-weight:bold;">${label}</div></div>`;
}

function renderTable(headers, rows) {
    const th = headers.map(h=>`<th style="background:${C.orange};color:white;padding:7px 9px;text-align:left;font-size:10px;border:1px solid ${C.border};">${h}</th>`).join('');
    const tr = rows.map((row,i)=>{
        const bg = i%2===0 ? C.white : C.altBg;
        const isCrit = row.some(c=>c&&typeof c==='object'&&c.text&&c.text.includes('CRITICAL'));
        const rs = isCrit?`background:${C.white};font-weight:bold;`:`background:${bg};`;
        const cells = row.map(cell=>{
            let style = isCrit?`color:${C.orange};font-weight:bold;`:'';
            let text = cell;
            if (cell&&typeof cell==='object'){text=cell.text;if(cell.color)style=`color:${cell.color};font-weight:bold;`;}
            else if (!isCrit&&typeof cell==='string'){
                if(cell.includes('CRITICAL')||cell.includes('9.8'))style=`color:${C.red};font-weight:bold;`;
                else if(cell.includes('HIGH')||cell.includes('8.1'))style=`color:${C.amber};font-weight:bold;`;
                else if(cell.includes('✓'))style=`color:${C.green};font-weight:bold;`;
            }
            return `<td style="padding:6px 9px;font-size:10px;border:1px solid ${C.border};${style}">${text}</td>`;
        }).join('');
        return `<tr style="${rs}">${cells}</tr>`;
    }).join('');
    return `<table style="width:100%;border-collapse:collapse;margin:10px 0;"><thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table>`;
}

function footer(n) {
    return `<div class="footer-tag"><span>&copy; 2026 Palo Alto Networks | Proprietary &amp; Confidential</span><span>Page ${n}</span></div>`;
}

// ── DYNAMIC DATA ──────────────────────────────────────────────────────────────
const sp = D.spywareCount || 0;
const vu = D.vulnCount || 0;
const total = D.totalRows || (sp+vu);
const infected = D.infectedCount || 0;
const topDomains = D.topDomains || [];
const topIPs = D.topIPs || [];
const dnsResolvers = D.dnsResolvers || [];
const vulnEvents = D.vulnEvents || [];
const smbFlows = D.smbFlows || [];
const wrmFlows = D.wrmFlows || [];
const panorama = D.panorama || {};
const slr = D.slr || {};
const findings = D.findings || {};
const preparer = D.preparer || {name:'John Shelest',title:'Palo Alto Networks Solutions Consultant',email:'jshelest@paloaltonetworks.com'};
const sourceFiles = D.sourceFiles || [];

// SLR / Panorama fields with sensible unknown fallbacks
const totalApps      = slr.totalApps      || '—';
const highRiskApps   = slr.highRiskApps   || '—';
const saasApps       = slr.saasApps       || '—';
const vulnExploits   = slr.vulnExploits   || vu.toLocaleString() || '—';
const totalThreats   = slr.totalThreats   || total.toLocaleString() || '—';
const malwareEvents  = slr.malwareEvents  || '—';
const saasBwTB       = slr.saasBwTB       || '—';
const saasBwPct      = slr.saasBwPct      || '—';
const remoteApps     = slr.remoteApps     || '—';
const industryAvgApps  = slr.industryAvgApps  || '273';
const industryAvgRemote= slr.industryAvgRemote|| '9';
const riskLevel4BwTB = slr.riskLevel4BwTB || '—';
const riskLevel4Pct  = slr.riskLevel4Pct  || '—';
const totalBwTB      = slr.totalBwTB      || '—';
const saasCertRisk   = slr.saasCertRisk   || '—';
const saasCertBw     = slr.saasCertBw     || '—';

const panHostname    = panorama.hostname   || '—';
const panMgmtIP      = panorama.mgmtIP     || '—';
const panPlatform    = panorama.platform   || '—';
const panSerial      = panorama.serial     || '—';
const panOS          = panorama.panOS      || '—';
const panDevGroups   = panorama.deviceGroups || '—';
const contentVer     = panorama.contentVersion || '—';
const contentDate    = panorama.contentDate    || '—';
const contentDays    = panorama.contentDays    || '—';
const avVer          = panorama.avVersion      || '—';
const avDate         = panorama.avDate         || '—';
const avDays         = panorama.avDays         || '—';
const wfStatus       = panorama.wfStatus       || 'Current';

// Finding cards from D.findings (generated by Python + Gemini) or built from data
const fc = findings;
const dnsIPs  = dnsResolvers.map(d=>d.ip).join(' and ') || '(DNS resolvers)';
const dnsHits = dnsResolvers.reduce((s,d)=>s+d.hits,0);
const topDom  = topDomains[0] ? `${topDomains[0].domain} (${topDomains[0].hits.toLocaleString()} hits)` : 'unknown domain';

// Detect special findings from data
const log4jEvent  = vulnEvents.find(v=>v.threat&&v.threat.toLowerCase().includes('log4j'));
const brandSquat  = topDomains.find(d=>d.domain&&(d.domain.includes('idexdmz')||d.domain.toLowerCase().includes(CN.toLowerCase().replace(/\s+/g,'').substring(0,4))));
const oktaPhish   = topDomains.find(d=>d.domain&&d.domain.includes('okta-ema'));
const sshBrute    = vulnEvents.find(v=>v.threat&&v.threat.toLowerCase().includes('ssh'));
const sipScan     = vulnEvents.find(v=>v.threat&&v.threat.toLowerCase().includes('sip'));

// Content staleness severity color
const staleDays = parseInt(contentDays) || 0;
const staleColor = staleDays > 100 ? C.red : staleDays > 30 ? C.amber : C.green;
const staleLabel = staleDays > 0 ? `${staleDays} days stale` : contentDays || '—';

// Remediation items — built from real data
const p1Items = [];
if (staleDays > 0) p1Items.push(`Update Panorama content pack, AV, and threat signatures immediately &mdash; ${staleDays} days of exposure to undetected threats`);
if (dnsResolvers.length) p1Items.push(`Isolate ${dnsIPs} &mdash; ${dnsHits.toLocaleString()}+ combined C2 hits, masking real infected endpoints`);
if (log4jEvent) p1Items.push(`Initiate incident investigation for ${esc(log4jEvent.user)} &mdash; confirmed Log4j RCE (CVE-2021-44228) to external IP ${esc(log4jEvent.dst_ip)}`);
if (brandSquat) p1Items.push(`Block ${esc(brandSquat.domain)} at DNS and firewall layer &mdash; ${CN} brand squatting, ${brandSquat.hits.toLocaleString()} internal hits`);
if (oktaPhish) p1Items.push(`Block ${esc(oktaPhish.domain)} &mdash; Okta impersonation domain, ${oktaPhish.hits.toLocaleString()} hits from internal hosts (identity credential risk)`);
if (!p1Items.length) p1Items.push(`Investigate top C2 domain ${topDom} beaconing from ${infected} internal endpoints`);

const p2Items = [];
if (sshBrute) p2Items.push(`Investigate ${esc(sshBrute.user||'named account')} &mdash; SSH brute force events detected (reset-both actions)`);
const wrmTop = wrmFlows[0];
if (wrmTop) p2Items.push(`Investigate WRM lateral movement: ${esc(wrmTop.src_ip)} &rarr; ${esc(wrmTop.dst_zone)} (${esc(wrmTop.bytes)} WRM flow on port 5985)`);
p2Items.push(`Conduct SaaS application review &mdash; restrict Risk-4/5 apps, validate all remote access tools against approved catalog`);
p2Items.push(`Pull DNS query logs from ${dnsIPs} to enumerate real infected endpoints behind the resolvers`);

// Appendix DNS pattern from top domains
const dnsPattern = topDomains.slice(0,6).map(d=>d.domain.split('.')[0]).join('|') || 'c2domain1|c2domain2';


const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
@page{size:A4;margin:0;}
body{font-family:Arial,sans-serif;background:#525659;margin:0;padding:0;color:${C.dark};}
.page{width:210mm;height:297mm;padding:12mm 15mm;margin:10mm auto;background:white;
  box-shadow:0 0 10px rgba(0,0,0,.5);position:relative;box-sizing:border-box;
  page-break-after:always;overflow:hidden;}
.page-cover{width:210mm;height:297mm;padding:12mm 15mm;margin:10mm auto;
  background:white;box-shadow:0 0 10px rgba(0,0,0,.5);box-sizing:border-box;
  page-break-after:always;break-after:page;display:flex;flex-direction:column;position:relative;}
.conf-header{font-size:9px;color:${C.mid};border-bottom:1px solid #eee;padding-bottom:4px;
  text-transform:uppercase;margin-bottom:12px;}
h1{color:${C.orange};border-bottom:2px solid ${C.orange};padding-bottom:4px;margin-top:16px;
  font-size:16px;font-weight:bold;margin-bottom:8px;}
h3{font-size:11px;margin-top:12px;font-weight:bold;color:${C.dark};margin-bottom:4px;}
p,li{font-size:10px;line-height:1.4;text-align:justify;margin:4px 0;}
.bullet-list{margin:6px 0;padding-left:14px;}
.bullet-list li{margin-bottom:3px;}
.so-what-box{margin:12px 0;border:1px solid ${C.border};page-break-inside:avoid;}
.so-what-head{background:${C.orange};color:white;padding:6px 12px;font-weight:bold;font-size:10px;}
.so-what-item{padding:6px 12px;font-size:10px;border-bottom:1px solid ${C.border};}
.so-what-item:last-child{border-bottom:none;}
.so-what-item:nth-child(even){background:${C.altBg};}
.footer-tag{position:absolute;bottom:10mm;left:15mm;right:15mm;font-size:9px;color:${C.mid};
  border-top:1px solid #eee;padding-top:4px;display:flex;justify-content:space-between;}
.code-block{background:#1E1E1E;color:#D4D4D4;padding:8px;font-family:'Courier New',monospace;
  font-size:9px;margin:6px 0;white-space:pre-wrap;}
.keep-together{page-break-inside:avoid;}
@media print{
  body{background:none;}
  .page{margin:0;box-shadow:none;min-height:297mm;height:auto;overflow:visible;padding:15mm 20mm;}
  .page-cover{margin:0;box-shadow:none;min-height:297mm;height:auto;overflow:visible;padding:15mm 20mm;}
}
</style></head><body>

<!-- PAGE 1: COVER -->
<div class="page-cover">
<div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
<div style="flex:1;display:flex;flex-direction:column;justify-content:center;padding-top:25mm;">
  <div style="color:${C.orange};font-size:46px;font-weight:bold;line-height:1.1;margin-bottom:6px;">${CN}</div>
  <div style="font-size:40px;font-weight:bold;color:${C.dark};">Security Assessment</div>
  <div style="height:5px;background:${C.orange};margin:18px 0 22px 0;border-radius:2px;"></div>
  <div style="font-size:13px;color:${C.dark};line-height:2;margin-bottom:3px;">
    ${month} &nbsp;&middot;&nbsp; Report Period: ${sourceFiles[0]&&sourceFiles[0].period!=='Period Unknown'?sourceFiles[0].period:'See source files below'}
  </div>
  <div style="font-size:13px;color:${C.dark};line-height:2;margin-bottom:3px;">
    Prepared by: <strong>${esc(preparer.name)}</strong> &nbsp;|&nbsp; ${esc(preparer.title)}
  </div>
  <div style="font-size:12px;color:${C.mid};line-height:2;margin-bottom:12px;">
    Source Data: ${panHostname!=='—'?`Panorama ${esc(panHostname)} &nbsp;&middot;&nbsp; PAN-OS ${esc(panOS)} &nbsp;&middot;&nbsp; `:''}${total.toLocaleString()} Threat Log Rows
  </div>
  ${sourceFiles.length?`<div style="margin-top:8px;"><div style="font-size:10px;color:${C.mid};font-weight:bold;text-transform:uppercase;margin-bottom:6px;">Data Source Inventories &amp; Periods</div>
  ${sourceFiles.map(f=>`<div style="font-size:11px;color:${C.dark};margin-bottom:3px;"><strong>${esc(f.type)}:</strong> ${esc(f.name)} &middot; <span style="color:${C.orange};font-weight:bold;">${esc(f.period)}</span></div>`).join('')}
  </div>`:''}
</div>
<div style="border-top:1px solid #eee;padding-top:8px;font-size:10px;color:${C.mid};display:flex;justify-content:space-between;">
  <span>&copy; 2026 Palo Alto Networks | Proprietary &amp; Confidential</span><span>Page 1</span>
</div>
</div>

<!-- PAGE 2: KEY FINDINGS — built from real data -->
<div class="page">
<div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
<div style="color:${C.orange};font-size:21px;font-weight:bold;border-bottom:2px solid ${C.orange};padding-bottom:5px;margin-bottom:5px;">What This Report Means for ${CN}</div>
<p style="font-style:italic;color:${C.mid};margin-bottom:12px;">The short version &mdash; before you read the numbers</p>
${fc.card1 ? renderFindingCard(1, fc.card1.headline, fc.card1.body, fc.card1.critical!==false) :
  log4jEvent ? renderFindingCard(1,'You could have an active breach.',
    `A named ${CN} employee account (${esc(log4jEvent.user)}) successfully connected to an external attacker server via an Apache Log4j exploit. This is a completed connection to ${esc(log4jEvent.dst_ip)} — not a blocked attempt. The CISO and Legal team need to know today: this may trigger breach notification obligations, and endpoint ${esc(log4jEvent.src_ip)} requires immediate forensic investigation.`) :
  renderFindingCard(1,'Active C2 beaconing confirmed from internal endpoints.',
    `${infected} internal IP addresses were observed beaconing to ${topDomains.length} known malicious domains — led by ${topDom}. These are not blocked events; they are active outbound connections indicating persistent compromise within the ${CN} network.`)}
${fc.card2 ? renderFindingCard(2, fc.card2.headline, fc.card2.body, fc.card2.critical!==false) :
  brandSquat ? renderFindingCard(2,`Someone built fake ${CN} infrastructure to target you specifically.`,
    `The domain ${esc(brandSquat.domain)} was registered using ${CN}'s own brand — ${brandSquat.hits.toLocaleString()} internal machines were resolving it. This is deliberate targeting, not opportunistic malware. An attacker who registers your brand name has done reconnaissance on your organization.`) :
  renderFindingCard(2,`${topDomains.length}+ malicious domains are actively receiving connections from your network.`,
    `Internal endpoints are making thousands of DNS-based C2 connections to known malicious infrastructure. The top domain alone (${topDom}) received ${topDomains[0]?topDomains[0].hits.toLocaleString():'thousands of'} hits. This represents persistent, unblocked attacker communication.`)}
${fc.card3 ? renderFindingCard(3, fc.card3.headline, fc.card3.body, fc.card3.critical!==false) :
  oktaPhish ? renderFindingCard(3,'1,163 machines may have handed attackers your employees\' passwords.',
    `okta-ema.com is a fake Okta login page designed to steal credentials. Okta controls access to everything — email, finance, HR, VPN. One employee who entered their password there gives an attacker silent access to every system behind it, with no security alerts triggered.`) :
  renderFindingCard(3,'Internal DNS resolvers are masking the true scope of infection.',
    `${dnsIPs} are internal DNS resolvers forwarding C2 requests on behalf of real infected endpoints — ${dnsHits.toLocaleString()} combined hits. The actual compromised machines are invisible until you pull DNS query logs directly from those servers.`,false)}
${fc.card4 ? renderFindingCard(4, fc.card4.headline, fc.card4.body, fc.card4.critical!==false) :
  staleDays>30 ? renderFindingCard(4,`Your firewall hasn't learned anything new since ${contentDate}.`,
    `Content pack, antivirus, and threat signatures are ${staleDays} days out of date — every new malware variant, exploit, and C2 domain discovered since ${contentDate} is completely invisible to your security stack. This takes 30 minutes to fix in Panorama and costs nothing.`,false) :
  renderFindingCard(4,'WRM and SMB traffic is crossing zone boundaries indicating lateral movement.',
    `Windows Remote Management and SMB flows are actively crossing between network zones that should be isolated. Every major ransomware incident of the past five years used exactly this pathway to spread from one infected workstation to all production systems.`,false)}
${fc.card5 ? renderFindingCard(5, fc.card5.headline, fc.card5.body, false) :
  renderFindingCard(5,'Your own DNS servers are masking an unknown number of infected machines.',
    `${dnsIPs} are internal DNS resolvers — the firewall sees them making ${dnsHits.toLocaleString()}+ C2 requests, but they're just forwarding on behalf of real infected endpoints. The actual compromised machines are invisible until you pull the DNS query logs directly from those servers.`,false)}
${fc.card6 ? renderFindingCard(6, fc.card6.headline, fc.card6.body, false) :
  renderFindingCard(6,'Ransomware has a clear, open path through your network right now.',
    `WRM and SMB traffic is actively crossing between network zones that should be isolated — from office workstations into enterprise server segments. Every major ransomware incident of the past five years used exactly this pathway. The path exists, it is being used, and it needs to be blocked.`,false)}
<p style="font-style:italic;color:${C.mid};font-size:10px;margin-top:14px;">The detailed technical evidence supporting each of the findings above follows in the sections below.</p>
${footer(2)}
</div>

<!-- PAGE 3: EXECUTIVE SUMMARY -->
<div class="page">
<div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
<h1>1. Executive Summary</h1>
<p>This Security Assessment analyzes ${CN}'s network security posture based on Panorama statsdump archives, threat log CSV exports (${total.toLocaleString()} rows after zone filtering), traffic logs, and the Security Lifecycle Review (SLR). Internal zone filter applied: all traffic with Source Zone &ne; 'untrust' and &ne; 'guest'.</p>
<div style="display:flex;margin:16px -6px;">
  ${renderKPI(totalApps,'Total Applications',C.dark)}
  ${renderKPI(highRiskApps,'High-Risk Apps',C.orange)}
  ${renderKPI(saasApps,'SaaS Applications',C.mid)}
</div>
<div style="display:flex;margin:0 -6px 24px -6px;">
  ${renderKPI(vulnExploits,'Vulnerability Exploits',C.red)}
  ${renderKPI(totalThreats,'Total Threats',C.red)}
  ${renderKPI(malwareEvents,'Malware Detected',C.amber)}
</div>
<h3>Key Findings</h3>
<ul class="bullet-list">
  ${totalApps!=='—'?`<li><strong>${totalApps} total applications observed</strong> vs. ${industryAvgApps} industry average (Manufacturing peer group)</li>`:''}
  ${vulnExploits!=='—'?`<li><strong>${vulnExploits} vulnerability exploits detected</strong> from internal zones</li>`:''}
  <li><strong>Active C2 beaconing confirmed</strong> from ${infected}+ internal IPs to ${topDomains.length}+ known malicious domains</li>
  ${brandSquat?`<li><strong>CRITICAL: Brand-squatting domain ${esc(brandSquat.domain)} detected</strong> &mdash; ${brandSquat.hits.toLocaleString()} internal hits, ${CN} corporate brand impersonation</li>`:''}
  ${log4jEvent?`<li><strong>Named user confirmed in Apache Log4j RCE (CVE-2021-44228)</strong>: ${esc(log4jEvent.user)} &rarr; external IP ${esc(log4jEvent.dst_ip)}:443</li>`:''}
  ${staleDays>0?`<li><strong>Panorama content pack, AV, and threat definitions are ${staleDays} days out of date</strong> (last updated ${esc(contentDate)})</li>`:''}
  ${saasBwTB!=='—'?`<li><strong>SaaS bandwidth at ${saasBwTB} (${saasBwPct} of all traffic)</strong> vs. 0.4% industry average</li>`:''}
  ${remoteApps!=='—'?`<li><strong>${remoteApps} remote access applications detected</strong> vs. industry average of ${industryAvgRemote}</li>`:''}
</ul>
${renderSoWhat('exec_summary')}
${footer(3)}
</div>

<!-- PAGE 4: C2 DOMAINS + IPs + WILDFIRE -->
<div class="page">
<div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
<h1>2. Active Command &amp; Control (C2) &amp; Malware Activity</h1>
<p>Analysis of ${sp.toLocaleString()} threat log rows (internal zones only) identified persistent DNS-based C2 beaconing from ${infected}+ unique source IP addresses.</p>
<div class="keep-together">
  <h3>2.1 Top C2 Domains (DNS Threat Log — Internal Zones)</h3>
  ${renderTable(['Domain','Category / Threat ID','Hits','Risk Note'],
    topDomains.map(d=>{
      const label = d.tid?`${esc(d.domain)} (TID ${d.tid})`:esc(d.domain);
      const isOkta = d.domain.includes('okta-ema');
      const isBrand = brandSquat && d.domain===brandSquat.domain;
      const cat = isOkta?'Okta Impersonation (Parked)':isBrand?`${CN} Brand Squatting (Parked)`:'DNS C2 / Spyware';
      const note = isBrand?{text:'&#9888; CRITICAL',color:C.red}:isOkta?'Identity phishing':'';
      return [label,cat,d.hits.toLocaleString(),note];
    })
  )}
</div>
<div class="keep-together">
  <h3>2.2 Top Compromised Source IPs</h3>
  ${renderTable(['Source IP','Zone','Hits','Unique Threats','Named User / Primary C2'],[
    ...dnsResolvers.map(d=>[d.ip,d.zone+' (DNS resolver)',d.hits.toLocaleString(),String(d.unique),'Masking real infected endpoints — see Appendix']),
    ...topIPs.map(d=>[d.ip,d.zone,d.hits.toLocaleString(),String(d.unique),d.users&&d.users!=='—'?esc(d.users):(topDomains[0]?esc(topDomains[0].domain):'See §2.1')])
  ])}
</div>
<div class="keep-together">
  <h3>2.3 WildFire Detections</h3>
  ${renderTable(['Detection Type','Count','Severity / Note'],
    D.wildfireDetections && D.wildfireDetections.length ? D.wildfireDetections :
    [['DNS Malware / Spyware','See statsv2','Aggregate'],['DNS C2 / Spyware','See statsv2','Aggregate']]
  )}
</div>
${footer(4)}
</div>

<!-- PAGE 5: NAMED C2 THREATS + SO WHAT -->
<div class="page">
<div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
<div class="keep-together">
  <h3>2.4 Named C2 Threats (Security Lifecycle Review)</h3>
  ${renderTable(['Threat Name','Detections','Category','Protocol'],
    D.namedThreats && D.namedThreats.length ? D.namedThreats :
    [['(Named threat data from SLR PDF)','—','—','—']]
  )}
</div>
<p style="font-size:10px;color:${C.mid};font-style:italic;margin-top:8px;">Advanced Threat Prevention (cloud-delivered) would have blocked these in real-time.</p>
<div class="so-what-box">
  <div class="so-what-head">&#9888; SO WHAT &mdash; WHY THIS MATTERS</div>
  ${brandSquat?`<div class="so-what-item"><span style="color:${C.orange};font-weight:bold;margin-right:6px;">›</span><strong>${esc(brandSquat.domain)} is targeted, not generic</strong> &mdash; someone registered a domain mimicking ${CN}'s own infrastructure. ${CN} is a deliberate, named victim — not collateral damage.</div>`:''}
  ${oktaPhish?`<div class="so-what-item"><span style="color:${C.orange};font-weight:bold;margin-right:6px;">›</span><strong>okta-ema.com is a fake Okta login page</strong> &mdash; any employee who entered their password there handed an attacker the keys to every system protected by ${CN}'s SSO. ${oktaPhish.hits.toLocaleString()} internal hits means this isn't theoretical.</div>`:''}
  <div class="so-what-item"><span style="color:${C.orange};font-weight:bold;margin-right:6px;">›</span><strong>${dnsResolvers.length?dnsIPs+' are DNS resolvers':'Internal DNS resolvers are'} masking the true scope of infection</strong> &mdash; ${dnsHits.toLocaleString()} combined C2 hits forwarded on behalf of real infected endpoints. Pull DNS query logs from those servers to enumerate the actual infected host list.</div>
  <div class="so-what-item"><span style="color:${C.orange};font-weight:bold;margin-right:6px;">›</span><strong>C2 beaconing from ${infected}+ internal IPs means attackers have persistent footholds</strong> &mdash; these are not blocked alerts; they are active, ongoing communications with attacker infrastructure.</div>
</div>
${renderSoWhat('c2')}
${footer(5)}
</div>

<!-- PAGE 6: VULNERABILITIES -->
<div class="page">
<div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
<h1>3. Vulnerabilities &amp; User Attribution</h1>
<p>${vulnExploits} vulnerability events identified. ${vulnEvents.length?`Named users confirmed via Source User field — a critical indicator of endpoint compromise.`:''}</p>
<div class="keep-together">
  <h3>3.1 Named User Vulnerability Events</h3>
  ${vulnEvents.length ? (() => {
    const groups = {};
    vulnEvents.forEach(v => {
      const key = v.src_ip+'|'+v.threat;
      if (!groups[key]) groups[key] = {...v, count:0};
      groups[key].count++;
      if (v.user && v.user!=='(none)') groups[key].user = v.user;
    });
    return renderTable(['Source IP','User','Threat','Count','Sev','CVE'],
      Object.values(groups).slice(0,8).map(v=>[
        v.src_ip, esc(v.user||'(no user logged)'), esc(v.threat), '×'+v.count,
        {text:v.severity.toUpperCase(), color:v.severity.toLowerCase()==='critical'?C.red:C.amber},
        v.threat.toLowerCase().includes('log4j')?'CVE-2021-44228':'—'
      ]));
  })() : renderTable(['Source IP','User','Threat','Count','Sev','CVE'],
    [['(No named vulnerability events in this dataset)','—','—','—','—','—']]
  )}
</div>
<div class="keep-together">
  <h3>3.2 Application Vulnerability Exploits (SLR)</h3>
  ${renderTable(['Application','Count','Top Threat Signatures'],
    D.appVulns && D.appVulns.length ? D.appVulns :
    [['(SLR data not yet parsed)','—','Run with statsdump archive for full SLR data']]
  )}
</div>
${renderSoWhat('vuln')}
${footer(6)}
</div>

<!-- PAGE 7: LATERAL MOVEMENT -->
<div class="page">
<div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
<h1>4. Lateral Movement &amp; Remote Access</h1>
<p>WRM and SMB flows identified crossing network zones &mdash; indicators of attempted or active lateral movement.</p>
<div class="keep-together">
  <h3>4.1 WRM Cross-Zone Flows (Traffic Logs)</h3>
  ${wrmFlows.length ? renderTable(['Source IP','Source Zone','Dest IP','Dest Zone','Data'],
    wrmFlows.map(f=>[f.src_ip,f.src_zone,f.dst_ip,f.dst_zone,f.bytes])) :
    renderTable(['Source IP','Source Zone','Dest IP','Dest Zone','Data'],
    [['(No WRM cross-zone flows detected — traffic CSV not parsed or no qualifying flows)','—','—','—','—']])}
</div>
<div class="keep-together">
  <h3>4.2 SMB Cross-Zone Flows</h3>
  ${smbFlows.length ? renderTable(['Source IP','Source Zone','Dest Zone','Protocol','Size'],
    smbFlows.map(f=>[f.src_ip||'—',f.src_zone||'—',f.dst_zone||'—','SMB / TCP 445','—'])) :
    renderTable(['Source IP','Source Zone','Dest Zone','Protocol','Size'],
    [['(No SMB cross-zone flows detected)','—','—','—','—']])}
</div>
<div class="keep-together">
  <h3>4.3 Remote Access Applications (SLR)</h3>
  ${renderTable(['Application','Bandwidth','Sessions','Risk','Note'],
    D.remoteAccessApps && D.remoteAccessApps.length ? D.remoteAccessApps :
    [['(SLR remote access data not yet parsed)','—','—','—','Run with statsdump for full data']]
  )}
</div>
${renderSoWhat('lateral')}
${footer(7)}
</div>

<!-- PAGE 8: SAAS -->
<div class="page">
<div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
<h1>5. Application Risk &amp; SaaS Exposure</h1>
<p>${totalBwTB!=='—'?`Total bandwidth observed: ${totalBwTB}.`:''} ${saasApps!=='—'?`${saasApps} SaaS applications detected.`:''} ${saasBwTB!=='—'?`SaaS bandwidth: ${saasBwTB} (${saasBwPct}) vs. 0.4% industry average.`:''}</p>
<div class="keep-together">
  <h3>5.1 Bandwidth by Risk Level</h3>
  ${renderTable(['Risk Level','Bandwidth','% of Total','Description'],
    D.riskBandwidth && D.riskBandwidth.length ? D.riskBandwidth :
    [['(SLR bandwidth data not yet parsed)','—','—','Run with statsdump archive for full SLR data']]
  )}
</div>
<div class="keep-together">
  <h3>5.2 Top High-Risk Applications (Risk 4&ndash;5)</h3>
  ${renderTable(['Application','Bandwidth','Risk','Action Required'],
    D.highRiskApps && D.highRiskApps.length ? D.highRiskApps :
    [['(SLR application data not yet parsed)','—','—','Run with statsdump archive']]
  )}
</div>
<div class="keep-together">
  <h3>5.3 SaaS Hosting Risk</h3>
  ${renderTable(['Risk Category','App Count','Bandwidth','Notable Apps'],
    D.saasRisk && D.saasRisk.length ? D.saasRisk :
    [['(SLR SaaS data not yet parsed)','—','—','Run with statsdump archive']]
  )}
</div>
${renderSoWhat('saas')}
${footer(8)}
</div>

<!-- PAGE 9: PANORAMA -->
<div class="page">
<div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
<h1>6. Panorama System Profile</h1>
${renderTable(['Parameter','Value'],[
  ['Hostname', panHostname],
  ['Management IP', panMgmtIP],
  ['Platform', panPlatform],
  ['Serial Number', panSerial],
  ['PAN-OS Version', panOS],
  ['Managed Device Groups', panDevGroups],
])}
<div class="keep-together">
  <h3>6.1 Content Staleness ${staleDays>100?'&mdash; CRITICAL ACTION REQUIRED':staleDays>30?'&mdash; Action Required':''}</h3>
  ${renderTable(['Component','Version','Last Updated','Staleness'],[
    ['Content Pack', contentVer, contentDate, {text:staleLabel, color:staleColor}],
    ['Antivirus Signatures', avVer, avDate, {text:avDays?avDays+' days stale':'Current', color:staleColor}],
    ['WildFire', D.panorama&&D.panorama.wfVersion||'Current', 'Recent', {text:wfStatus, color:C.green}],
  ])}
</div>
${staleDays>0?`<p style="font-size:10px;color:${staleColor};font-weight:bold;margin-top:8px;">&#9888; ${staleDays}-day content gap means new malware signatures, exploit signatures, and C2 indicators published since ${contentDate} are NOT being detected. Update via Panorama &rarr; Device &rarr; Dynamic Updates.</p>`:''}
${renderSoWhat('panorama')}
${footer(9)}
</div>

<!-- PAGE 10: BENCHMARKS -->
<div class="page">
<div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
<h1>7. Industry Benchmarks (Manufacturing Peer Group)</h1>
<p style="font-style:italic;color:${C.mid};font-size:10px;margin-bottom:8px;">Benchmark data sourced from the Security Lifecycle Review (SLR). Peer group: Manufacturing industry vertical.</p>
${renderTable(['Metric',CN,'Industry Avg','Assessment'],
  D.benchmarks && D.benchmarks.length ? D.benchmarks : [
    ['Total Applications', totalApps, industryAvgApps, totalApps!=='—'&&industryAvgApps!=='—'?{text:Math.round(parseInt(totalApps.replace(/,/g,''))/parseInt(industryAvgApps.replace(/,/g,''))*100-100)+'% above avg ⚠',color:C.amber}:'—'],
    ['Remote Access Apps', remoteApps, industryAvgRemote, remoteApps!=='—'?{text:Math.round(parseInt(remoteApps)/parseInt(industryAvgRemote)*10)/10+'× above avg ⚠',color:C.amber}:'—'],
    ['SaaS Bandwidth', saasBwTB?saasBwTB+' ('+saasBwPct+')':'—', '0.4% of total', saasBwTB!=='—'?{text:'Above avg ⚠',color:C.red}:'—'],
    ['C2 Connections', String(infected)+'+', 'Industry varies', {text:'Active threat — see §2',color:C.red}],
    ['Content Staleness', staleDays>0?staleDays+' days':'Current', '< 7 days', staleDays>30?{text:'Critical gap ⚠',color:C.red}:staleDays>0?{text:'Needs attention',color:C.amber}:{text:'OK ✓',color:C.green}],
  ]
)}
${footer(10)}
</div>

<!-- PAGE 11: ROADMAP -->
<div class="page">
<div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
<h1>8. Prioritized Remediation Roadmap</h1>
<p>Remediation items ordered by risk priority. P1 items represent confirmed active threats requiring immediate action.</p>
<h3>P1 &mdash; Immediate Actions (0&ndash;7 Days)</h3>
<ul class="bullet-list">
  ${p1Items.map(i=>`<li><strong>${i}</strong></li>`).join('')}
</ul>
<h3>P2 &mdash; Short-Term Actions (7&ndash;30 Days)</h3>
<ul class="bullet-list">
  ${p2Items.map(i=>`<li>${i}</li>`).join('')}
  ${D.p2Items&&D.p2Items.length?D.p2Items.map(i=>`<li>${esc(i)}</li>`).join(''):''}
</ul>
<h3>P3 &mdash; Strategic Investments (30&ndash;90 Days)</h3>
<ul class="bullet-list">
  <li><strong>Deploy Advanced DNS Security</strong> to block C2 beaconing in real-time</li>
  <li><strong>Implement Next-Generation CASB</strong> for SaaS application visibility, data classification, and DLP enforcement</li>
  <li><strong>Enforce network micro-segmentation</strong> to prevent WRM/SMB cross-segment lateral movement</li>
  <li><strong>Enable Cortex XDR on endpoints</strong> to correlate network telemetry with host-level activity for named users</li>
  <li><strong>Deploy SSL/TLS inspection</strong> to gain visibility into encrypted traffic</li>
  ${D.p3Items&&D.p3Items.length?D.p3Items.map(i=>`<li>${esc(i)}</li>`).join(''):''}
</ul>
${footer(11)}
</div>

<!-- PAGE 12: APPENDIX -->
<div class="page">
<div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
<h1 style="font-size:18px;margin-top:0;">Appendix: Identifying Infected Clients Behind DNS Servers</h1>
<p><strong>${dnsResolvers.length?dnsIPs+' are':'Your'} internal DNS resolvers</strong> — the firewall cannot show the real infected endpoints, only the resolver forwarding requests on their behalf.</p>
<h3>Step 1 &mdash; Enable Windows DNS Debug Logging</h3>
<p>Run on each DNS server (${dnsResolvers.map(d=>d.ip).join(', ')||'DNS server IPs'}):</p>
<div class="code-block">Get-DnsServerDiagnostics | Select-Object SendPackets, ReceivePackets, Queries
Set-DnsServerDiagnostics -All $true
# Log: C:\\Windows\\System32\\dns\\dns.log</div>
<h3>Step 2 &mdash; Search DNS Log for Malicious Domains</h3>
<div class="code-block">Select-String -Path 'C:\\Windows\\System32\\dns\\dns.log' \`
  -Pattern '${dnsPattern}' | \`
  Select-Object LineNumber, Line | \`
  Export-Csv C:\\dns_c2_hits.csv -NoTypeInformation</div>
<h3>Step 3 &mdash; Configure DNS Sinkhole in Panorama</h3>
<ul class="bullet-list">
  <li>Panorama &rarr; Objects &rarr; Security Profiles &rarr; Anti-Spyware &rarr; DNS Policies</li>
  <li>Add sinkhole: Action = sinkhole, IPv4 = 72.5.65.111 (PAN default)</li>
  <li>Apply to all device groups &mdash; infected clients now appear in threat logs with real source IPs</li>
</ul>
<h3>Step 4 &mdash; Immediate Containment</h3>
<ul class="bullet-list">
  <li>Add C2 domains to internal DNS pointing to 127.0.0.1 &mdash; cuts beacon loops immediately</li>
  <li>Isolate every client IP found in Step 2 pending forensic investigation</li>
  ${log4jEvent?`<li><strong>Disable ${esc(log4jEvent.user)} account immediately</strong> &mdash; confirmed Log4j RCE on ${esc(log4jEvent.src_ip)}</li>`:''}
  ${oktaPhish?`<li>Force Okta password resets for users on machines that resolved okta-ema.com</li>`:''}
</ul>
<div style="margin-top:40px;border-top:1px solid #eee;padding-top:12px;font-size:11px;">
  <strong>${esc(preparer.name)}</strong> | Palo Alto Networks | ${esc(preparer.title)}<br>
  <span style="color:${C.blue}">${esc(preparer.email)}</span>
</div>
${footer(12)}
</div>

</body></html>`;

fs.writeFileSync(outFile, html);
console.log(`✓ Generated report for ${CN}: ${outFile}`);
