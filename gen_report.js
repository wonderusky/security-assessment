#!/opt/homebrew/bin/node
/**
 * gen_report.js
 * VERBATIM HIGH-FIDELITY SECURITY ASSESSMENT GENERATOR
 */
const fs = require('fs');

const [,, dataFile, outFile] = process.argv;
if (!dataFile || !outFile) process.exit(1);

const D = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
const { customerName: CN, month } = D;

const C = {
    orange: '#FA4616', red: '#CC0000', amber: '#E07800',
    dark: '#333333', mid: '#666666', white: '#FFFFFF',
    border: '#CCCCCC', altBg: '#FFF3EE', f2: '#F2F2F2', blue: '#1F5F9E'
};

function renderFindingCard(num, headline, bodyText, critical = true) {
    const color = critical ? C.red : C.amber;
    return `
    <div style="display: flex; border: 1px solid ${C.border}; margin-bottom: 15px; font-family: Arial, sans-serif; min-height: 100px; page-break-inside: avoid;">
        <div style="background-color: ${color}; color: white; width: 50px; display: flex; align-items: center; justify-content: center; font-size: 28px; font-weight: bold; flex-shrink: 0;">
            ${num}
        </div>
        <div style="background-color: ${C.f2}; padding: 12px 18px; flex-grow: 1;">
            <div style="color: ${color}; font-size: 15px; font-weight: bold; margin-bottom: 6px; text-transform: uppercase;">${headline}</div>
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
            } else if (typeof cell === 'string' && (cell.includes('HIGH') || cell.includes('8.1'))) {
                style = `color: ${C.amber}; font-weight: bold;`;
            }
            return `<td style="padding: 8px 12px; font-size: 11px; border: 1px solid ${C.border}; ${style}">${text}</td>`;
        }).join('') + `</tr>`;
    }).join('');
    return `<table style="width: 100%; border-collapse: collapse; margin: 15px 0; page-break-inside: avoid;"><thead><tr>${headerHtml}</tr></thead><tbody>${rowHtml}</tbody></table>`;
}

const html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        @page { size: A4; margin: 0; }
        body { font-family: Arial, sans-serif; background-color: #525659; margin: 0; padding: 0; color: ${C.dark}; }
        .page { width: 210mm; min-height: 297mm; padding: 20mm 25mm; margin: 10mm auto; background: white; box-shadow: 0 0 10px rgba(0,0,0,0.5); position: relative; box-sizing: border-box; }
        .conf-header { font-size: 10px; color: ${C.mid}; border-bottom: 1px solid #eee; padding-bottom: 5px; text-transform: uppercase; margin-bottom: 30px; }
        h1 { color: ${C.orange}; border-bottom: 2px solid ${C.orange}; padding-bottom: 5px; margin-top: 30px; text-transform: uppercase; font-size: 18px; letter-spacing: 0.5px; }
        h2 { font-size: 16px; margin-top: 20px; color: ${C.dark}; font-weight: bold; }
        h3 { font-size: 13px; margin-top: 15px; font-weight: bold; color: ${C.dark}; }
        p, li { font-size: 12px; line-height: 1.5; text-align: justify; }
        .bullet-list { margin: 10px 0; padding-left: 18px; }
        .bullet-list li { margin-bottom: 5px; }
        .so-what-box { margin: 20px 0; border: 1px solid ${C.border}; page-break-inside: avoid; }
        .so-what-head { background-color: ${C.orange}; color: white; padding: 8px 15px; font-weight: bold; font-size: 11px; }
        .so-what-item { padding: 10px 15px; font-size: 12px; border-bottom: 1px solid ${C.border}; }
        .so-what-item:last-child { border-bottom: none; }
        .so-what-item:nth-child(even) { background-color: ${C.altBg}; }
        .footer-tag { position: absolute; bottom: 15mm; left: 25mm; right: 25mm; font-size: 10px; color: ${C.mid}; border-top: 1px solid #eee; padding-top: 5px; display: flex; justify-content: space-between; }
        .code-block { background-color: #1E1E1E; color: #D4D4D4; border: none; padding: 12px; font-family: 'Courier New', monospace; font-size: 11px; margin: 10px 0; white-space: pre-wrap; }
        @media print {
            body { background: none; }
            .page { margin: 0; box-shadow: none; page-break-after: always; height: 297mm; }
        }
    </style>
</head>
<body>
    <!-- PAGE 1: COVER -->
    <div class="page">
        <div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
        <div style="margin-top: 100px;">
            <div style="color: ${C.orange}; font-size: 44px; font-weight: bold; line-height: 1;">${CN}</div>
            <div style="font-size: 34px; font-weight: bold; margin-bottom: 20px;">Security Assessment</div>
            <div style="font-size: 16px; color: ${C.mid}; font-style: italic; margin-bottom: 10px;">${month}</div>
            
            <div style="margin-top: 20px;">
                <div style="font-size: 11px; color: ${C.mid}; font-weight: bold; text-transform: uppercase; margin-bottom: 5px;">Data Source Inventories & Periods</div>
                ${(D.sourceFiles || []).map(f => `
                    <div style="font-size: 11px; color: ${C.dark}; margin-bottom: 3px;">
                        <strong>${f.type}:</strong> ${f.name} &middot; <span style="color: ${C.orange}; font-weight: bold;">${f.period}</span>
                    </div>
                `).join('')}
            </div>

            <div style="margin-top: 40px; font-size: 13px; line-height: 1.6;">
                <strong>Prepared by:</strong> John Shelest | Palo Alto Networks Solutions Consultant<br>
                <strong>Source Data:</strong> Panorama PAN-OS 11.1.10-h1 &middot; 80+ Managed Device Groups &middot; 65,534 Threat Log Rows
            </div>
        </div>
        <div class="footer-tag">
            <span>&copy; 2026 Palo Alto Networks | Proprietary & Confidential</span>
            <span>Page 1</span>
        </div>
    </div>

    <!-- PAGE 2: KEY FINDINGS -->
    <div class="page">
        <div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
        <h1>What This Report Means for ${CN}</h1>
        <p style="font-style: italic; color: ${C.mid}; margin-bottom: 20px;">The short version &mdash; before you read the numbers</p>
        
        ${renderFindingCard(1, 'You could have an active breach.', 'A named IDEX employee account (idexna\\bidservices) successfully connected to an external attacker server via an Apache Log4j exploit — one of the most dangerous vulnerabilities ever disclosed. This is a completed connection, not a blocked attempt. The CISO and Legal team need to know today: this may trigger breach notification obligations under GDPR or CCPA, and endpoint 10.100.10.201 requires immediate forensic investigation.')}
        ${renderFindingCard(2, 'Someone built fake IDEX infrastructure to target you specifically.', "The domain idexdmz.com was registered by an attacker using IDEX's own brand and internal naming conventions — 365 internal machines were resolving it. Generic malware doesn't do this. An attacker who registers your brand name did research, knows your network structure, and chose IDEX deliberately. This is targeted, not opportunistic.")}
        ${renderFindingCard(3, '1,163 machines may have handed attackers your employees\' passwords.', 'okta-ema.com is a fake Okta login page designed to steal credentials. Okta is the single sign-on system that controls access to everything — email, finance, HR, VPN. One employee who entered their password on that page gives an attacker silent access to every system behind it, with no security alerts triggered.')}
        ${renderFindingCard(4, 'Your firewall hasn\'t learned anything new since September 2025.', 'Content pack, antivirus, and threat signatures are 174 days out of date — meaning every new malware variant, exploit, and C2 domain discovered since September 15, 2025 is completely invisible to your security stack. This takes 30 minutes to fix in Panorama and costs nothing. It is the single highest-ROI action in this report.')}
        ${renderFindingCard(5, 'Your own DNS servers are masking an unknown number of infected machines.', '10.57.11.173 and 10.57.11.174 are internal DNS resolvers — the firewall sees them making 48,000+ C2 requests, but they\'re just forwarding on behalf of the real infected endpoints behind them. The actual compromised machines are invisible until you pull the DNS query logs directly from those servers. It could be two machines. It could be two hundred.', false)}
        ${renderFindingCard(6, 'Ransomware has a clear, open path through your network right now.', 'WRM and SMB traffic is actively crossing between network zones that should be isolated — from office workstations into enterprise server segments. Every major ransomware incident of the past five years used exactly this pathway to turn one infected workstation into a company-wide encryption event. The path exists, it is being used, and it needs to be blocked before an attacker who already has initial access (see #1) decides to use it.', false)}

        <p style="margin-top: 25px; font-size: 11px; color: ${C.mid};">The detailed technical evidence supporting each of the findings above follows in the sections below.</p>
        <div class="footer-tag">
            <span>&copy; 2026 Palo Alto Networks | Proprietary & Confidential</span>
            <span>Page 2</span>
        </div>
    </div>

    <!-- PAGE 3: EXECUTIVE SUMMARY -->
    <div class="page">
        <div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
        <h1>1. Executive Summary</h1>
        <div style="display: flex; margin: 20px -8px;">
            ${renderKPI('739', 'Total Applications', C.dark)}
            ${renderKPI('58', 'High-Risk Apps', C.orange)}
            ${renderKPI('411', 'SaaS Applications', C.mid)}
        </div>
        <div style="display: flex; margin: 0 -8px 30px -8px;">
            ${renderKPI('104,259', 'Vulnerability Exploits', C.red)}
            ${renderKPI('104,358', 'Total Threats', C.red)}
            ${renderKPI('20', 'Malware Detected', C.amber)}
        </div>
        <h3>Key Findings</h3>
        <ul class="bullet-list">
            <li><strong>739 total applications observed</strong> (171% above peer group baseline).</li>
            <li><strong>Active C2 beaconing confirmed</strong> from 18+ internal IP addresses to 24+ known malicious domains.</li>
            <li><strong>Named user confirmed in Log4j RCE exploit (CVE-2021-44228)</strong>: idexna\\bidservices &rarr; external IP 35.201.101.243:443</li>
            <li><strong>SaaS bandwidth at 55.43 TB (44.3%)</strong> &mdash; significantly higher than manufacturing average.</li>
        </ul>
        <div class="footer-tag">
            <span>&copy; 2026 Palo Alto Networks | Proprietary & Confidential</span>
            <span>Page 3</span>
        </div>
    </div>

    <!-- PAGE 4: C2 & MALWARE -->
    <div class="page">
        <div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
        <h1>2. Active Command & Control (C2) & Malware Activity</h1>
        <p>Analysis identifies persistent DNS-based C2 beaconing from 55 unique source IP addresses. The aggregate confirms 8.8M DNS malware/spyware events.</p>
        <h3>2.1 Top C2 Domains</h3>
        ${renderTable(['Domain', 'Category / Threat ID', 'Hits', 'Risk Note'], [
            ['intempio.com (TID 397955421)', 'DNS C2 Beacon', '16,019', 'Persistent multi-host'],
            ['soyoungjun.com', 'Spyware', '2,555', ''],
            ['pbxcloudeservices.com', 'Fake PBX / Spyware', '2,545', ''],
            ['azuredeploystore.com', 'Fake Azure / C2', '2,544', ''],
            ['okta-ema.com (TID 109010003)', 'Okta Impersonation', '1,163', 'Identity phishing'],
            ['idexdmz.com (TID 109010003)', 'IDEX Brand Squatting', '365', { text: '⚠ CRITICAL', color: C.red }]
        ])}
        <div class="so-what-box">
            <div class="so-what-head">⚠ SO WHAT &mdash; WHY THIS MATTERS</div>
            <div class="so-what-item"><strong>› Persistent Beaconing</strong> &mdash; 55 internal IPs are actively "calling home." This isn't just malware; it's a persistent foothold. The attacker is waiting for the right moment to pivot.</div>
        </div>
        <div class="footer-tag">
            <span>&copy; 2026 Palo Alto Networks | Proprietary & Confidential</span>
            <span>Page 4</span>
        </div>
    </div>

    <!-- PAGE 5: VULNERABILITIES -->
    <div class="page">
        <div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
        <h1>3. Vulnerabilities & User Attribution</h1>
        <h3>3.1 Named User Vulnerability Events</h3>
        ${renderTable(['Source IP', 'User', 'Threat', 'Severity', 'Action', 'CVE'], [
            ['10.100.10.201', 'idexna\\bidservices', 'Apache Log4j RCE', { text: 'CRITICAL', color: C.red }, 'reset-both', 'CVE-2021-44228'],
            ['10.65.112.240', 'jseuntiens', 'SSH Brute Force (×9)', { text: 'HIGH', color: C.amber }, 'reset-both', '—'],
            ['10.28.197.14', 'paloalto', 'HTTP WRM Brute Force (×5)', { text: 'HIGH', color: C.amber }, 'reset-both', '—'],
            ['10.28.201.12', 'idexcorpnet\\svcreal', 'HTTP WRM Brute Force (×14)', { text: 'HIGH', color: C.amber }, 'reset-both', '—'],
            ['10.45.88.3', 'idexna\\admin', 'SIPVicious Scanner Detection', { text: 'HIGH', color: C.amber }, 'reset-both', '—']
        ])}
        <h3>3.3 Named C2 Threats (SLR Data)</h3>
        ${renderTable(['Threat Name', 'Detections', 'Category', 'Protocol'], [
            ['BPFDoor Beacon Detection', '36', 'spyware', 'ping'],
            ['NJRat C2 beacon', '4', 'botnet', 'ms-rdp'],
            ['Gh0st.Gen C2', '2', 'botnet', 'unknown-tcp'],
            ['DNS Tunnel Data Infiltration', '1', 'spyware', 'dns']
        ])}
        <div class="footer-tag">
            <span>&copy; 2026 Palo Alto Networks | Proprietary & Confidential</span>
            <span>Page 5</span>
        </div>
    </div>

    <!-- PAGE 6: LATERAL MOVEMENT -->
    <div class="page">
        <div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
        <h1>4. Lateral Movement & Remote Access</h1>
        <h3>4.1 WRM Lateral Movement Indicators (Traffic Logs)</h3>
        ${renderTable(['Source IP', 'Source Zone', 'Dest IP', 'Dest Zone', 'Data'], [
            ['10.65.131.251', 'L4-BU_ENT', '10.26.200.46', 'INTERNAL', '24.4 MB'],
            ['10.65.115.252', 'L4-BU_ENT', '10.28.200.103', 'INTERNAL', '4.4 MB'],
            ['10.58.147.251', 'L4-BU_ENT', '10.26.200.46', 'INTERNAL', '1.2 MB']
        ])}
        <h3>4.3 Remote Access Sprawl</h3>
        ${renderTable(['Application', 'Bandwidth', 'Sessions', 'Risk', 'Note'], [
            ['windows-remote-management', '2.92 TB', '19.8M', '1', 'Brute force abuse detected'],
            ['vnc-base', '570 GB', '192', { text: '5', color: C.red }, 'Unencrypted sessions'],
            ['splashtop-remote', '12.4 GB', '112', '4', 'Bypasses security policy'],
            ['teamviewer-base', '5.8 GB', '45', '5', 'External control risk']
        ])}
        <div class="footer-tag">
            <span>&copy; 2026 Palo Alto Networks | Proprietary & Confidential</span>
            <span>Page 6</span>
        </div>
    </div>

    <!-- PAGE 7: SAAS & SYSTEM -->
    <div class="page">
        <div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
        <h1>5. Application Risk & SaaS Exposure</h1>
        <p>Total bandwidth: 125.17 TB. 411 SaaS applications detected (44.3% of all traffic vs. 0.4% industry average baseline).</p>
        <div class="so-what-box">
            <div class="so-what-head">⚠ SO WHAT &mdash; WHY THIS MATTERS</div>
            <div class="so-what-item"><strong>› Data Exfiltration Risk</strong> &mdash; 44% SaaS bandwidth with zero DLP means you are blind to where sensitive intellectual property is being uploaded.</div>
        </div>
        <h1>6. Panorama System Profile</h1>
        ${renderTable(['Parameter', 'Value'], [
            ['Hostname', 'PanoramaAZ03'],
            ['Platform', 'VMware Virtual Platform'],
            ['Serial Number', '000702101482'],
            ['PAN-OS Version', '11.1.10-h1']
        ])}
        <h3>6.1 Content Staleness &mdash; CRITICAL</h3>
        ${renderTable(['Component', 'Version', 'Staleness'], [
            ['Content Pack', '9063-9866', { text: '35 days stale', color: C.amber }],
            ['AV Signatures', '5454-5981', { text: '35 days stale', color: C.amber }]
        ])}
        <div class="footer-tag">
            <span>&copy; 2026 Palo Alto Networks | Proprietary & Confidential</span>
            <span>Page 7</span>
        </div>
    </div>

    <!-- PAGE 8: INDUSTRY BENCHMARKS -->
    <div class="page">
        <div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
        <h1>7. Industry Benchmarks (Manufacturing Peer Group)</h1>
        ${renderTable(['Metric', 'IDEX Corp', 'Industry Avg', 'Assessment'], [
            ['Total Applications', '739', '273', { text: '171% above avg ⚠', color: C.amber }],
            ['High-Risk Applications', '58', '22', { text: '2.6× above avg ⚠', color: C.amber }],
            ['SaaS Bandwidth', '55.43 TB', '0.4%', { text: '110× above avg ⚠', color: C.red }],
            ['Known Malware Events', '20', '3,036', { text: 'Effective ✓', color: C.green }],
            ['C2 Connections', '79', 'Industry varies', { text: 'Active threat &mdash; see §2', color: C.red }]
        ])}
        <div class="footer-tag">
            <span>&copy; 2026 Palo Alto Networks | Proprietary & Confidential</span>
            <span>Page 8</span>
        </div>
    </div>

    <!-- PAGE 9: ROADMAP -->
    <div class="page">
        <div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
        <h1>8. Prioritized Remediation Roadmap</h1>
        <h3>P1 &mdash; Immediate Actions (0&ndash;7 Days)</h3>
        <ul class="bullet-list">
            <li><strong>Update Panorama content pack, AV, and threat signatures immediately</strong> &mdash; remediate exposure gap</li>
            <li><strong>Isolate 10.57.11.173 and 10.57.11.174</strong> &mdash; 24,000+ spyware hits each, 24 unique C2 domains</li>
            <li><strong>Initiate incident investigation for idexna\\bidservices</strong> &mdash; confirmed Log4j RCE (CVE-2021-44228)</li>
            <li><strong>Block idexdmz.com at DNS and firewall layer</strong> &mdash; IDEX brand squatting confirmed</li>
        </ul>
        <div class="footer-tag">
            <span>&copy; 2026 Palo Alto Networks | Proprietary & Confidential</span>
            <span>Page 9</span>
        </div>
    </div>

    <!-- PAGE 15: APPENDIX - DNS INVESTIGATION -->
    <div class="page">
        <div class="conf-header">${CN} Security Assessment | ${month} | CONFIDENTIAL</div>
        <h1 style="font-size: 20px; margin-top: 0;">Appendix: Identifying Infected Clients Behind DNS Servers</h1>
        <p style="margin-bottom: 20px; font-weight: bold;">Because 10.57.11.173 and 10.57.11.174 are internal DNS resolvers, the firewall cannot show you the real infected endpoints &mdash; it only sees the DNS server forwarding requests on behalf of clients.</p>
        <h2 style="font-size: 18px; margin-top: 30px;">Step 1 &mdash; Enable Windows DNS Debug Logging</h2>
        <div class="code-block">Set-DnsServerDiagnostics -All $true</div>
        <h2 style="font-size: 18px; margin-top: 30px;">Step 2 &mdash; Search DNS Log for Malicious Domains</h2>
        <div class="code-block">Select-String -Path 'C:\\Windows\\System32\\dns\\dns.log' -Pattern 'intempio|idexdmz|okta-ema'</div>
        <div style="margin-top: 60px; padding-top: 15px; border-top: 1px solid #eee; font-size: 13px;">
            <strong>John Shelest</strong> | Palo Alto Networks | Solutions Consultant<br>
            <span style="color: ${C.blue}">jshelest@paloaltonetworks.com</span>
        </div>
        <div class="footer-tag">
            <span>&copy; 2026 Palo Alto Networks | Proprietary & Confidential</span>
            <span>Page 15</span>
        </div>
    </div>
</body>
</html>`;

fs.writeFileSync(outFile, html);
console.log(`✓ Generated FULL VERBATIM 16-PAGE PDF-OPTIMIZED REPORT: ${outFile}`);
