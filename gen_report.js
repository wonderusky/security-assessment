#!/opt/homebrew/bin/node
// gen_report.js — generates exact high-fidelity HTML security assessment report based on verbatim content
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
    <div style="display: flex; border: 1px solid ${C.border}; margin-bottom: 20px; font-family: Arial, sans-serif;">
        <div style="background-color: ${color}; color: white; width: 60px; display: flex; align-items: center; justify-content: center; font-size: 32px; font-weight: bold; flex-shrink: 0;">
            ${num}
        </div>
        <div style="background-color: ${C.f2}; padding: 15px; flex-grow: 1;">
            <div style="color: ${color}; font-size: 16px; font-weight: bold; margin-bottom: 8px;">${headline}</div>
            <div style="font-size: 13px; color: ${C.dark}; line-height: 1.4;">${bodyText}</div>
        </div>
    </div>`;
}

function renderKPI(val, label, bg) {
    return `
    <div style="background-color: ${bg}; color: white; padding: 20px; text-align: center; border-radius: 4px; flex: 1; margin: 0 10px;">
        <div style="font-size: 36px; font-weight: bold;">${val}</div>
        <div style="font-size: 12px; text-transform: uppercase; margin-top: 5px;">${label}</div>
    </div>`;
}

function renderTable(headers, rows) {
    let headerHtml = headers.map(h => `<th style="background-color: ${C.orange}; color: white; padding: 10px; text-align: left; font-size: 12px; border: 1px solid ${C.border};">${h}</th>`).join('');
    let rowHtml = rows.map((row, i) => {
        const bg = i % 2 === 0 ? C.white : C.altBg;
        return `<tr style="background-color: ${bg};">` + row.map(cell => {
            let style = '';
            let text = cell;
            if (cell && typeof cell === 'object') {
                text = cell.text;
                if (cell.color) style += `color: ${cell.color}; font-weight: bold;`;
            } else if (typeof cell === 'string' && cell.includes('CRITICAL')) {
                style = `color: ${C.red}; font-weight: bold;`;
            }
            return `<td style="padding: 8px; font-size: 12px; border: 1px solid ${C.border}; ${style}">${text}</td>`;
        }).join('') + `</tr>`;
    }).join('');

    return `<table style="width: 100%; border-collapse: collapse; margin: 20px 0;"><thead><tr>${headerHtml}</tr></thead><tbody>${rowHtml}</tbody></table>`;
}

const html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Assessment - ${CN}</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 40px; color: ${C.dark}; line-height: 1.6; }
        .page { width: 900px; margin: 0 auto; background: white; padding: 60px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        h1 { color: ${C.orange}; border-bottom: 2px solid ${C.orange}; padding-bottom: 10px; margin-top: 40px; text-transform: uppercase; font-size: 22px; }
        h2 { font-size: 18px; margin-top: 30px; color: ${C.dark}; }
        h3 { font-size: 14px; margin-top: 20px; font-weight: bold; }
        .meta { color: ${C.mid}; font-style: italic; margin-bottom: 20px; }
        .so-what { background-color: ${C.orange}; color: white; padding: 10px 15px; font-weight: bold; font-size: 12px; margin-top: 20px; }
        .so-what-list { border: 1px solid ${C.border}; margin-bottom: 30px; }
        .so-what-item { padding: 10px 15px; font-size: 13px; border-bottom: 1px solid ${C.border}; }
        .so-what-item:last-child { border-bottom: none; }
        .so-what-item:nth-child(even) { background-color: ${C.altBg}; }
        .code { background-color: ${C.codeBg}; color: ${C.codeFg}; padding: 15px; font-family: 'Courier New', Courier, monospace; font-size: 13px; border-radius: 4px; overflow-x: auto; margin: 15px 0; }
        .bullet-list { margin: 15px 0; padding-left: 20px; }
        .bullet-list li { font-size: 13px; margin-bottom: 8px; }
    </style>
</head>
<body>
    <div class="page">
        <!-- COVER -->
        <div style="text-align: left; margin-bottom: 100px;">
            <div style="color: ${C.orange}; font-size: 48px; font-weight: bold;">${CN}</div>
            <div style="font-size: 32px; font-weight: bold;">Security Assessment</div>
            <div class="meta">${month} &middot; Report Period: February 27 &ndash; March 9, 2026</div>
            <div style="color: ${C.mid}; font-size: 14px;">
                Prepared by: <strong>John Shelest</strong> | Palo Alto Networks Solutions Consultant<br>
                Source Data: Panorama PAN-OS 11.1.10-h1 &middot; 80+ Device Groups &middot; ${totalRows.toLocaleString()} Threat Log Rows
            </div>
        </div>

        <!-- EXECUTIVE SUMMARY FINDINGS -->
        <h1>What This Report Means for ${CN}</h1>
        <p class="meta">The short version &mdash; before you read the numbers</p>
        
        ${renderFindingCard(1, 'You could have an active breach.', `A named employee account (idexna\\bidservices) connected to an external attacker server via an Apache Log4j exploit — one of the most dangerous vulnerabilities ever disclosed. This is a completed connection, not a blocked attempt. The CISO and Legal team need to know today: this may trigger breach notification obligations under GDPR or CCPA, and endpoint 10.100.10.201 requires immediate forensic investigation.`)}
        ${renderFindingCard(2, 'Someone built fake infrastructure to target you specifically.', `The domain idexdmz.com was registered by an attacker using your brand and internal naming conventions — 365 internal machines were resolving it. Generic malware doesn't do this. This is targeted, not opportunistic.`)}
        ${renderFindingCard(3, '1,163 machines may have handed attackers passwords.', `okta-ema.com is a fake Okta login page designed to steal credentials. Okta is the single sign-on system controlling access to everything — email, finance, HR, VPN. One employee who entered their password gives an attacker silent access to every system behind it.`)}
        ${renderFindingCard(4, 'Your firewall hasn\'t learned anything new since September 2025.', `Content pack, antivirus, and threat signatures are 174 days out of date — every new malware variant, exploit, and C2 domain discovered since September 15, 2025 is completely invisible.`, false)}
        ${renderFindingCard(5, 'Internal DNS servers are masking infected machines.', `10.57.11.173 and 10.57.11.174 are internal DNS resolvers — the firewall sees them making 48,000+ C2 requests, but they're just forwarding on behalf of the real infected endpoints.`, false)}
        ${renderFindingCard(6, 'Ransomware has a clear, open path through your network.', `WRM and SMB traffic is actively crossing between network zones that should be isolated — from office workstations into enterprise server segments.`, false)}

        <!-- §1 EXECUTIVE SUMMARY -->
        <h1>1. Executive Summary</h1>
        <div style="display: flex; margin: 0 -10px 20px -10px;">
            ${renderKPI('739', 'Total Applications', C.dark)}
            ${renderKPI('58', 'High-Risk Apps', C.orange)}
            ${renderKPI('411', 'SaaS Applications', C.mid)}
        </div>
        <div style="display: flex; margin: 0 -10px 30px -10px;">
            ${renderKPI('104,259', 'Vulnerability Exploits', C.red)}
            ${renderKPI('104,358', 'Total Threats', C.red)}
            ${renderKPI('20', 'Malware Detected', C.amber)}
        </div>

        <h3>Key Findings</h3>
        <ul class="bullet-list">
            <li>739 total applications observed (171% above Manufacturing peer baseline).</li>
            <li>104,259 vulnerability exploits detected — top apps: ms-ds-smbv3, github-base, msrpc-base.</li>
            <li>Active C2 beaconing confirmed from ${infectedCount}+ internal IP addresses to known malicious domains.</li>
            <li>CRITICAL: Brand-squatting domain idexdmz.com detected — 365 internal hits.</li>
            <li>Panorama content pack, AV, and threat definitions are 174 days out of date.</li>
            <li>SaaS bandwidth at 55.43 TB (44.3% of all traffic) vs. 0.4% industry average.</li>
        </ul>

        <div class="so-what">⚠ SO WHAT — WHY THIS MATTERS</div>
        <div class="so-what-list">
            <div class="so-what-item">› Your attack surface is 3&times; larger than peers. Every unmanaged app is an entry point.</div>
            <div class="so-what-item">› Attackers are actively probing systems. Blocked attempts do not mean the threat is gone.</div>
            <div class="so-what-item">› The 174-day content gap is the single most dangerous item in this report. You are blind to recent discovery.</div>
            <div class="so-what-item">› SaaS bandwidth at 44% with zero DLP oversight means sensitive data could be leaving the network undetected.</div>
        </div>

        <!-- §2 C2 ACTIVITY -->
        <h1>2. Active Command & Control (C2)</h1>
        <h3>2.1 Top C2 Domains</h3>
        ${renderTable(['Domain', 'Category / Threat ID', 'Hits', 'Risk Note'], topDomains.map(d => [
            d.tid ? `${d.domain} (TID ${d.tid})` : d.domain,
            d.domain === 'idexdmz.com' ? 'Brand Squatting' : d.domain === 'okta-ema.com' ? 'Okta Impersonation' : 'DNS C2 / Spyware',
            d.hits.toLocaleString(),
            d.domain === 'idexdmz.com' ? { text: '⚠ CRITICAL', color: C.red } : d.domain === 'okta-ema.com' ? 'Identity phishing' : ''
        ]))}

        <h3>2.2 Top Compromised Source IPs</h3>
        ${renderTable(['Source IP', 'Zone', 'Hits', 'Unique', 'Primary C2 Domains'], [
            ...dnsResolvers.map(d => [d.ip, 'Internal → MPLS', d.hits.toLocaleString(), d.unique, 'azure* / pbx* / officeaddons']),
            ...topIPs.map(d => [d.ip, d.zone, d.hits.toLocaleString(), d.unique, d.users || 'intempio.com'])
        ])}

        <!-- §3 VULNERABILITIES -->
        <h1>3. Vulnerabilities & User Attribution</h1>
        <h3>3.1 Named User Vulnerability Events</h3>
        ${renderTable(['Source IP', 'User', 'Threat', 'Severity', 'Action', 'CVE'], [
            ['10.100.10.201', 'idexna\\bidservices', 'Apache Log4j RCE', { text: 'CRITICAL', color: C.red }, 'reset-both', 'CVE-2021-44228'],
            ['10.65.112.240', 'jseuntiens', 'SSH Brute Force', { text: 'HIGH', color: C.amber }, 'reset-both', '—'],
            ['10.28.197.14', 'paloalto', 'HTTP WRM Brute Force', { text: 'HIGH', color: C.amber }, 'reset-both', '—']
        ])}

        <!-- §8 ROADMAP -->
        <h1>8. Prioritized Remediation Roadmap</h1>
        <h3>P1 — Immediate Actions (0–7 Days)</h3>
        <ul class="bullet-list">
            <li>Update Panorama content pack, AV, and threat signatures immediately (174 days stale).</li>
            <li>Isolate 10.57.11.173 and 10.57.11.174 — resolvers making 24k+ C2 requests.</li>
            <li>Initiate forensic investigation for idexna\\bidservices (confirmed Log4j RCE).</li>
            <li>Block idexdmz.com and okta-ema.com at the DNS and firewall layers.</li>
        </ul>

        <!-- FOOTER -->
        <div style="margin-top: 80px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: ${C.mid};">
            <strong>John Shelest</strong> | Palo Alto Networks | <span style="color: #1F5F9E">jshelest@paloaltonetworks.com</span><br>
            &copy; 2026 Palo Alto Networks, Inc. Proprietary and confidential.
        </div>
    </div>
</body>
</html>`;

fs.writeFileSync(outFile, html);
console.log(`✓ Generated High-Fidelity HTML Report: ${outFile}`);
