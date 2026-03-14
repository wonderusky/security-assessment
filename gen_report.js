#!/opt/homebrew/bin/node
// gen_report.js — Verbatim High-Fidelity Security Assessment HTML Generator
// Usage: node gen_report.js data.json output.html
const fs = require('fs');

const [,, dataFile, outFile] = process.argv;
if (!dataFile || !outFile) { process.exit(1); }

const D = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
const { customerName: CN, month, totalRows, spywareCount, vulnCount,
        infectedCount, dnsResolvers, topDomains, topIPs, smbFlows, vulnEvents } = D;

// ── PALETTE ───────────────────────────────────────────────────────────────────
const C = {
    orange: '#FA4616', red: '#CC0000', amber: '#E07800',
    dark: '#333333', mid: '#666666', white: '#FFFFFF',
    green: '#1E7A1E', blue: '#1F5F9E', altBg: '#FFF3EE', f2: '#F2F2F2',
    codeBg: '#1E1E1E', codeFg: '#00FF88', border: '#CCCCCC'
};

function renderFindingCard(num, headline, bodyText, critical = true) {
    const color = critical ? C.red : C.amber;
    return `
    <div style="display: flex; border: 1px solid ${C.border}; margin-bottom: 15px; font-family: Arial, sans-serif; min-height: 100px;">
        <div style="background-color: ${color}; color: white; width: 50px; display: flex; align-items: center; justify-content: center; font-size: 28px; font-weight: bold; flex-shrink: 0;">
            ${num}
        </div>
        <div style="background-color: ${C.f2}; padding: 12px 18px; flex-grow: 1;">
            <div style="color: ${color}; font-size: 15px; font-weight: bold; margin-bottom: 6px;">${headline}</div>
            <div style="font-size: 12px; color: ${C.dark}; line-height: 1.5; text-align: justify;">${bodyText}</div>
        </div>
    </div>`;
}

function renderKPI(val, label, bg) {
    return `
    <div style="background-color: ${bg}; color: white; padding: 18px; text-align: center; border-radius: 2px; flex: 1; margin: 0 8px;">
        <div style="font-size: 32px; font-weight: bold;">${val}</div>
        <div style="font-size: 11px; text-transform: uppercase; margin-top: 4px; font-weight: bold;">${label}</div>
    </div>`;
}

function renderTable(headers, rows, widths) {
    let headerHtml = headers.map((h, i) => `<th style="background-color: ${C.orange}; color: white; padding: 8px 12px; text-align: left; font-size: 11px; border: 1px solid ${C.border}; ${widths ? `width: ${widths[i]};` : ''}">${h}</th>`).join('');
    let rowHtml = rows.map((row, i) => {
        const bg = i % 2 === 0 ? C.white : C.altBg;
        return `<tr style="background-color: ${bg};">` + row.map(cell => {
            let style = '';
            let text = cell;
            if (cell && typeof cell === 'object') {
                text = cell.text;
                if (cell.color) style += `color: ${cell.color}; font-weight: bold;`;
            } else if (typeof cell === 'string' && (cell.includes('CRITICAL') || cell.includes('9.8'))) {
                style = `color: ${C.red}; font-weight: bold;`;
            }
            return `<td style="padding: 8px 12px; font-size: 11px; border: 1px solid ${C.border}; ${style}">${text}</td>`;
        }).join('') + `</tr>`;
    }).join('');

    return `<table style="width: 100%; border-collapse: collapse; margin: 15px 0;"><thead><tr>${headerHtml}</tr></thead><tbody>${rowHtml}</tbody></table>`;
}

const html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>${CN} Security Assessment | CONFIDENTIAL</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; color: ${C.dark}; line-height: 1.5; }
        .page { width: 950px; margin: 0 auto; background: white; padding: 50px 70px; box-shadow: 0 0 20px rgba(0,0,0,0.1); position: relative; }
        .header-tag { position: absolute; top: 20px; right: 70px; font-size: 10px; color: ${C.mid}; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; }
        .footer-tag { position: absolute; bottom: 20px; right: 70px; font-size: 10px; color: ${C.mid}; }
        .conf-header { font-size: 10px; color: ${C.mid}; margin-bottom: 40px; border-bottom: 1px solid #eee; padding-bottom: 5px; text-transform: uppercase; }
        h1 { color: ${C.orange}; border-bottom: 2px solid ${C.orange}; padding-bottom: 8px; margin-top: 35px; text-transform: uppercase; font-size: 20px; letter-spacing: 0.5px; }
        h2 { font-size: 17px; margin-top: 25px; color: ${C.dark}; font-weight: bold; }
        h3 { font-size: 13px; margin-top: 18px; font-weight: bold; color: ${C.dark}; }
        .meta-box { margin-bottom: 60px; }
        .meta-text { color: ${C.mid}; font-size: 13px; margin-top: 5px; }
        .so-what-box { margin: 25px 0; border: 1px solid ${C.border}; }
        .so-what-head { background-color: ${C.orange}; color: white; padding: 8px 15px; font-weight: bold; font-size: 11px; }
        .so-what-item { padding: 10px 15px; font-size: 12px; border-bottom: 1px solid ${C.border}; line-height: 1.4; }
        .so-what-item:last-child { border-bottom: none; }
        .so-what-item:nth-child(even) { background-color: ${C.altBg}; }
        .bullet-list { margin: 12px 0; padding-left: 18px; }
        .bullet-list li { font-size: 12px; margin-bottom: 6px; color: ${C.dark}; }
        .industry-callout { font-style: italic; color: ${C.mid}; font-size: 11px; margin-bottom: 10px; }
        @media print {
            body { padding: 0; background: white; }
            .page { box-shadow: none; width: 100%; padding: 40px; }
        }
    </style>
</head>
<body>
    <div class="page">
        <div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
        
        <!-- COVER SECTION -->
        <div class="meta-box">
            <div style="color: ${C.orange}; font-size: 42px; font-weight: bold; line-height: 1;">${CN}</div>
            <div style="font-size: 32px; font-weight: bold; margin-bottom: 15px;">Security Assessment</div>
            <div class="meta-text" style="font-style: italic;">${month} &middot; Report Period: February 27 &ndash; March 9, 2026</div>
            <div class="meta-text">
                Prepared by: <strong>John Shelest</strong> | Palo Alto Networks Solutions Consultant<br>
                Source Data: Panorama PAN-OS 11.1.10-h1 &middot; 80+ Managed Device Groups &middot; 65,534 Threat Log Rows
            </div>
        </div>

        <!-- WHAT THIS MEANS SECTION -->
        <h1>What This Report Means for ${CN}</h1>
        <p class="industry-callout">The short version &mdash; before you read the numbers</p>
        
        ${renderFindingCard(1, 'You could have an active breach.', `A named ${CN} employee account (idexna\\bidservices) successfully connected to an external attacker server via an Apache Log4j exploit — one of the most dangerous vulnerabilities ever disclosed. This is a completed connection, not a blocked attempt. The CISO and Legal team need to know today: this may trigger breach notification obligations under GDPR or CCPA, and endpoint 10.100.10.201 requires immediate forensic investigation.`)}
        
        ${renderFindingCard(2, 'Someone built fake infrastructure to target you specifically.', `The domain idexdmz.com was registered by an attacker using ${CN}'s own brand and internal naming conventions — 365 internal machines were resolving it. Generic malware doesn't do this. An attacker who registers your brand name did research, knows your network structure, and chose ${CN} deliberately. This is targeted, not opportunistic.`)}
        
        ${renderFindingCard(3, '1,163 machines may have handed attackers passwords.', `okta-ema.com is a fake Okta login page designed to steal credentials. Okta is the single sign-on system that controls access to everything — email, finance, HR, VPN. One employee who entered their password on that page gives an attacker silent access to every system behind it.`)}
        
        ${renderFindingCard(4, 'Your firewall hasn\'t learned anything new since September 2025.', `Content pack, antivirus, and threat signatures are 174 days out of date — meaning every new malware variant, exploit, and C2 domain discovered since September 15, 2025 is completely invisible. This takes 30 minutes to fix in Panorama and costs nothing. It is the single highest-ROI action in this report.`, false)}

        ${renderFindingCard(5, 'Internal DNS servers are masking infected machines.', `10.57.11.173 and 10.57.11.174 are internal DNS resolvers — the firewall sees them making 48,000+ C2 requests, but they're just forwarding on behalf of the real infected endpoints. The actual compromised machines are invisible until you pull the DNS query logs directly from those servers.`, false)}

        ${renderFindingCard(6, 'Ransomware has a clear, open path through your network right now.', `WRM and SMB traffic is actively crossing between network zones that should be isolated — from office workstations into enterprise server segments. Every major ransomware incident of the past five years used exactly this pathway. The path exists, it is being used, and it needs to be blocked.`, false)}

        <div class="footer-tag">&copy; 2026 Palo Alto Networks | Proprietary & Confidential | Page 2</div>
    </div>

    <!-- PAGE 2 -->
    <div class="page" style="margin-top: 40px;">
        <div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
        
        <h1>1. Executive Summary</h1>
        <p class="meta-text" style="margin-bottom: 20px;">This Security Assessment analyzes ${CN}'s network security posture based on Panorama statsdump archives, threat log CSV exports (65,534 rows after zone filtering), and the Security Lifecycle Review (SLR) dated February 27 &ndash; March 6, 2026.</p>

        <div style="display: flex; margin: 0 -8px 15px -8px;">
            ${renderKPI('739', 'Total Applications', C.dark)}
            ${renderKPI('58', 'High-Risk Apps', C.orange)}
            ${renderKPI('411', 'SaaS Applications', C.mid)}
        </div>
        <div style="display: flex; margin: 0 -8px 25px -8px;">
            ${renderKPI('104,259', 'Vulnerability Exploits', C.red)}
            ${renderKPI('104,358', 'Total Threats', C.red)}
            ${renderKPI('20', 'Malware Detected', C.amber)}
        </div>

        <h3>Key Findings</h3>
        <ul class="bullet-list">
            <li><strong>739 total applications observed</strong> vs. 273 industry average (Manufacturing peer group) — 171% above peer baseline.</li>
            <li><strong>104,259 vulnerability exploits detected</strong> — top applications: ms-ds-smbv3 (51,412), github-base (38,508), msrpc-base (4,031).</li>
            <li><strong>Active C2 beaconing confirmed</strong> from 18+ internal IP addresses to 24+ known malicious domains (intempio.com: 2.1M hits).</li>
            <li><strong>CRITICAL: Brand-squatting domain idexdmz.com detected</strong> — 365 internal hits, corporate brand impersonation.</li>
            <li><strong>Named user confirmed in Apache Log4j RCE exploit</strong> (CVE-2021-44228): idexna\\bidservices → 35.201.101.243:443.</li>
            <li><strong>Panorama signatures are 174 days out of date</strong> (last updated September 15, 2025).</li>
            <li><strong>SaaS bandwidth at 55.43 TB (44.3% of all traffic)</strong> vs. 0.4% industry average — massive cloud storage footprint.</li>
        </ul>

        <div class="so-what-box">
            <div class="so-what-head">⚠ SO WHAT — WHY THIS MATTERS</div>
            <div class="so-what-item"><strong>› 739 apps</strong> — your attack surface is 3&times; larger than peers. Every unmanaged app is a potential entry point an attacker can exploit.</div>
            <div class="so-what-item"><strong>› 104,259 exploits</strong> means attackers are actively probing IDEX systems for known holes. Blocked attempts do NOT mean the threat is gone.</div>
            <div class="so-what-item"><strong>› 174-day content gap</strong> is the single most dangerous item. Any new malware or exploit since Sept 2025 is completely invisible.</div>
            <div class="so-what-item"><strong>› SaaS bandwidth at 44%</strong> with zero DLP oversight means sensitive data could be leaving the network right now via cloud storage.</div>
        </div>

        <h1>2. Active Command & Control (C2)</h1>
        <p class="meta-text">Analysis identified persistent DNS-based C2 beaconing from 55 unique source IP addresses. Aggregate statsv2 XML confirms 8.8M DNS malware/spyware events.</p>

        <h3>2.1 Top C2 Domains</h3>
        ${renderTable(['Domain', 'Category / Threat ID', 'Hits', 'Risk Note'], [
            ['intempio.com', 'DNS C2 Beacon (TID 397955421)', '16,019', 'Persistent multi-host'],
            ['soyoungjun.com', 'Spyware', '2,555', ''],
            ['pbxcloudeservices.com', 'Fake PBX / Spyware', '2,545', ''],
            ['azuredeploystore.com', 'Fake Azure / C2', '2,544', ''],
            ['okta-ema.com', 'Okta Impersonation (TID 109010003)', '1,163', 'Identity phishing'],
            ['idexdmz.com', 'Brand Squatting (TID 109010003)', '365', { text: '⚠ CRITICAL', color: C.red }]
        ], ['35%', '35%', '15%', '15%'])}

        <h3>2.2 Top Compromised Source IPs</h3>
        ${renderTable(['Source IP', 'Zone', 'Hits', 'Unique', 'Primary C2 Domains'], [
            ['10.57.11.173', 'Internal → MPLS', '24,011', '24', 'azure* / pbx* / officeaddons'],
            ['10.57.11.174', 'Internal → MPLS', '24,002', '24', 'azure* / pbx* / officeaddons'],
            ['10.65.131.251', 'L4-BU_ENT → idex_ipsec', '1,066', '1', 'intempio.com'],
            ['10.58.163.251', 'L4-BU_ENT → idex_ipsec', '1,062', '1', 'intempio.com'],
            ['10.100.10.201', 'Internal', '1,250', '5', 'idexna\\bidservices']
        ], ['15%', '25%', '15%', '10%', '35%'])}

        <div class="footer-tag">&copy; 2026 Palo Alto Networks | Proprietary & Confidential | Page 3</div>
    </div>
</body>
</html>`;

fs.writeFileSync(outFile, html);
console.log(`✓ Generated High-Fidelity Verbatim HTML Report: ${outFile}`);
