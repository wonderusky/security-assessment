#!/opt/homebrew/bin/python3
"""
PAN Security Assessment Generator
Parses CSVs → Gemini LLM analysis → HTML/PDF report
Config: config.json (copy from config.example.json)
"""
import csv, re, os, sys, json, subprocess, threading, datetime, tempfile, tarfile, sqlite3
import urllib.request, urllib.error
from collections import defaultdict
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

SKIP_ZONES  = {'untrust', 'guest', 'Guest'}
DNS_HIT_MIN = 5000
DNS_DOM_MIN = 10
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(SCRIPT_DIR, 'assessments.db')
PREFS_PATH  = os.path.join(SCRIPT_DIR, 'prefs.json')
CONFIG_PATH = os.path.join(SCRIPT_DIR, 'config.json')

# ── CONFIG ────────────────────────────────────────────────────────────────────
def load_config():
    env_key = os.environ.get('GEMINI_API_KEY')
    config = {}
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH) as f:
                config = json.load(f)
    except Exception as e:
        print(f"Warning: could not load config.json: {e}")
    
    # Environment variable overrides config.json
    if env_key:
        config['gemini_api_key'] = env_key
    return config

# ── DATABASE ──────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS assessments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  customer_name TEXT, report_quarter TEXT,
                  total_threats INTEGER, vulnerabilities INTEGER,
                  infected_ips INTEGER, data JSON, html_path TEXT,
                  UNIQUE(customer_name, report_quarter))''')
    conn.commit(); conn.close()

def get_quarter():
    now = datetime.datetime.now()
    return f"{now.year}-Q{(now.month-1)//3+1}"

def save_assessment(customer_name, data, out_path):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''INSERT OR REPLACE INTO assessments
                     (customer_name, report_quarter, total_threats,
                      vulnerabilities, infected_ips, data, html_path)
                     VALUES (?,?,?,?,?,?,?)''',
                  (customer_name, get_quarter(), data['totalRows'],
                   data['vulnCount'], data['infectedCount'],
                   json.dumps(data), out_path))
        conn.commit()
        c.execute("SELECT id FROM assessments WHERE customer_name=? AND report_quarter=?",
                  (customer_name, get_quarter()))
        return c.fetchone()[0]
    finally:
        conn.close()

# ── GEMINI LLM SO WHAT ANALYSIS ───────────────────────────────────────────────
def call_gemini(prompt, api_key, model, log):
    """Call Gemini API to generate SO WHAT analysis bullets."""
    # Strip 'models/' prefix if present — the URL already includes it
    model_id = model.replace('models/', '')
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.7, "maxOutputTokens": 8192}
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            result = json.loads(resp.read())
            text = result['candidates'][0]['content']['parts'][0]['text'].strip()
            # Strip markdown fences
            text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.MULTILINE)
            text = re.sub(r'```\s*$', '', text, flags=re.MULTILINE).strip()
            # Try direct parse first
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list) and len(parsed) >= 3:
                    return parsed
            except: pass
            # Extract JSON array
            m = re.search(r'\[.*?\]', text, re.DOTALL)
            if m:
                try:
                    parsed = json.loads(m.group(0))
                    if isinstance(parsed, list) and len(parsed) >= 3:
                        return parsed
                except: pass
            # Last resort: extract individual quoted strings from truncated response
            strings = re.findall(r'"((?:[^"\\]|\\.)*)(?:"|$)', text)
            strings = [s.replace('\\"', '"').replace('\\\\', '\\') for s in strings if len(s) > 20]
            if len(strings) >= 3:
                log(f'  ⚠ Partial parse recovered {len(strings)} bullets')
                return strings[:4]
            return None
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:200]
        log(f"  ⚠ Gemini API error {e.code}: {body}")
        return None
    except Exception as e:
        log(f"  ⚠ Gemini call failed: {e}")
        return None

def build_so_what_prompt(section, data, cn):
    """Build section-specific prompts for Gemini SO WHAT generation — fully dynamic."""
    top_domains  = ', '.join([f"{d['domain']} ({d['hits']:,} hits)" for d in data['topDomains'][:5]])
    dns_ips      = ', '.join([d['ip'] for d in data['dnsResolvers']]) or 'none detected'
    dns_hits     = sum(d['hits'] for d in data['dnsResolvers'])
    top_ips      = ', '.join([d['ip'] for d in data['topIPs'][:5]])
    infected     = data['infectedCount']
    total_rows   = data['totalRows']
    sp_count     = data['spywareCount']
    vu_count     = data['vulnCount']

    # Dynamic panorama/SLR fields
    pan          = data.get('panorama', {})
    slr          = data.get('slr', {})
    stale_days   = pan.get('contentDays', '—')
    content_date = pan.get('contentDate', 'unknown date')
    saas_bw      = slr.get('saasBwTB', '—')
    saas_pct     = slr.get('saasBwPct', '—')
    remote_apps  = slr.get('remoteApps', '—')
    total_apps   = slr.get('totalApps', '—')
    vuln_exploits= slr.get('vulnExploits', str(vu_count))

    # Named findings from vuln events
    log4j   = next((v for v in data.get('vulnEvents', []) if 'log4j' in v.get('threat','').lower()), None)
    ssh     = next((v for v in data.get('vulnEvents', []) if 'ssh' in v.get('threat','').lower()), None)
    brand   = next((d for d in data.get('topDomains', []) if cn.lower().replace(' ','') in d['domain'].lower()), None)
    okta    = next((d for d in data.get('topDomains', []) if 'okta' in d['domain'].lower()), None)

    base = f"""You are a senior Palo Alto Networks cybersecurity consultant writing a security assessment for {cn}.
Write exactly 4 SO WHAT bullet points. Rules:
- Each bullet: **Bold Phrase** - impact (max 40 words per bullet)
- Reference ONLY the real data provided below — do NOT invent numbers or reference other customers
- Direct, alarming language for a CISO audience at {cn}
- ASCII only - NO em dashes (use hyphens), NO smart quotes
- Output ONLY a JSON array of 4 strings. No preamble, no code fences, no extra text."""

    prompts = {
        'exec_summary': f"""{base}

Section: Executive Summary for {cn}
Real data:
- {total_rows:,} internal-zone threat events analyzed
- {infected} compromised endpoints beaconing to {len(data.get('topDomains',[]))} malicious domains
- Top C2 domain: {data['topDomains'][0]['domain'] if data.get('topDomains') else 'unknown'} ({data['topDomains'][0]['hits']:,} hits) if data.get('topDomains') else ''
- DNS resolvers masking infections: {dns_ips} ({dns_hits:,} combined C2 hits)
- Total apps: {total_apps}, vulnerability exploits: {vuln_exploits}
- Content pack staleness: {stale_days} days (last updated {content_date})
- SaaS bandwidth: {saas_bw} ({saas_pct} of traffic)
- Remote access apps: {remote_apps}""",

        'c2': f"""{base}

Section: C2 & Malware Activity for {cn}
Real data:
- {sp_count:,} spyware rows from internal zones
- Top C2 domains: {top_domains}
- {f"Brand-squatting domain {brand['domain']}: {brand['hits']} hits targeting {cn} brand" if brand else "No brand-squatting detected"}
- {f"Okta phishing domain {okta['domain']}: {okta['hits']} hits" if okta else "No Okta phishing domain detected"}
- DNS resolvers {dns_ips} masking real infected clients ({dns_hits:,} combined hits)
- Top infected IPs: {top_ips}""",

        'vuln': f"""{base}

Section: Vulnerabilities for {cn}
Real data:
- {vu_count} vulnerability events from internal zones
- {f"CRITICAL: {log4j['user']} triggered Apache Log4j RCE (CVE-2021-44228) to {log4j['dst_ip']} - action: {log4j['action']}" if log4j else "No Log4j events detected"}
- {f"SSH brute force: {ssh['user']} from {ssh['src_ip']}" if ssh else ""}
- Vulnerability exploits: {vuln_exploits}""",

        'lateral': f"""{base}

Section: Lateral Movement for {cn}
Real data:
- WRM cross-zone flows: {len(data.get('wrmFlows',[]))} detected, top: {data['wrmFlows'][0]['src_ip'] + ' -> ' + data['wrmFlows'][0]['dst_zone'] + ' (' + data['wrmFlows'][0]['bytes'] + ')' if data.get('wrmFlows') else 'none'}
- SMB cross-zone flows: {len(data.get('smbFlows',[]))} detected
- Remote access apps: {remote_apps} vs industry avg of 9""",

        'saas': f"""{base}

Section: SaaS & Application Risk for {cn}
Real data:
- Total apps: {total_apps}
- SaaS bandwidth: {saas_bw} ({saas_pct} of all traffic)
- Remote access apps: {remote_apps} vs industry average of 9""",

        'panorama': f"""{base}

Section: Panorama Content Staleness for {cn}
Real data:
- Content pack last updated: {content_date}
- Staleness: {stale_days} days
- Every malware, exploit, and C2 domain discovered since {content_date} is NOT being detected"""
    }
    return prompts.get(section, '')

def generate_all_so_whats(data, cn, config, log):
    """Generate LLM SO WHAT bullets. Falls back to dynamic text built from real data."""
    api_key = config.get('gemini_api_key', '')
    model   = config.get('gemini_model', 'gemini-2.5-flash')
    enabled = config.get('llm_enabled', True)

    # Build dynamic fallbacks from actual parsed data — no IDEX-specific hardcoding
    pan          = data.get('panorama', {})
    slr          = data.get('slr', {})
    infected     = data['infectedCount']
    top_dom      = data['topDomains'][0]['domain'] if data.get('topDomains') else 'malicious domains'
    top_hits     = f"{data['topDomains'][0]['hits']:,}" if data.get('topDomains') else 'thousands of'
    dns_ips      = ' and '.join([d['ip'] for d in data.get('dnsResolvers', [])]) or 'internal DNS resolvers'
    dns_count    = sum(d['hits'] for d in data.get('dnsResolvers', []))
    stale_days   = pan.get('contentDays', '')
    content_date = pan.get('contentDate', 'an unknown date')
    saas_bw      = slr.get('saasBwTB', '')
    saas_pct     = slr.get('saasBwPct', '')
    remote_apps  = slr.get('remoteApps', '')
    total_apps   = slr.get('totalApps', '')
    brand_dom    = next((d for d in data.get('topDomains', []) if cn.lower().replace(' ','') in d['domain'].lower()), None)
    okta_dom     = next((d for d in data.get('topDomains', []) if 'okta' in d['domain'].lower()), None)
    log4j        = next((v for v in data.get('vulnEvents', []) if 'log4j' in v.get('threat','').lower()), None)
    wrm_top      = data['wrmFlows'][0] if data.get('wrmFlows') else None
    vu_count     = data['vulnCount']

    fallbacks = {
        'exec_summary': [
            f"**{infected} compromised endpoints confirmed** - {cn} has {infected} internal IPs actively beaconing to {len(data.get('topDomains',[]))} known malicious domains, led by {top_dom} with {top_hits} hits.",
            f"**{dns_ips} are masking the real scope of infection** - {dns_count:,} C2 hits forwarded on behalf of real infected endpoints. Pull DNS query logs to find actual compromised hosts.",
            f"**{'Content pack is ' + stale_days + ' days out of date' if stale_days else 'Content pack staleness unknown'} - {'every threat discovered since ' + content_date + ' is invisible to ' + cn + chr(39) + 's security stack' if content_date else 'update Panorama signatures immediately'}.",
            f"**{'SaaS bandwidth at ' + saas_bw + ' (' + saas_pct + ') with zero DLP oversight' if saas_bw else 'Uncontrolled SaaS exposure'} - {'sensitive ' + cn + ' data could be exfiltrating via uncertified cloud apps right now' if saas_bw else 'SaaS application visibility and DLP controls are required'}.",
        ],
        'c2': [
            f"**{top_dom} is the primary C2 beacon with {top_hits} hits** - {infected} {cn} endpoints are actively communicating with attacker infrastructure. These are not blocked events; they are live connections.",
            f"**{brand_dom['domain'] + ' uses ' + cn + chr(39) + 's own brand name' if brand_dom else 'C2 domains are specifically targeting ' + cn} - {'this is deliberate targeting, not opportunistic malware. An attacker registered ' + brand_dom['domain'] + ' specifically for this campaign.' if brand_dom else 'the volume and persistence of beaconing indicates a targeted, not opportunistic, threat actor.'}",
            f"**{dns_ips} are DNS resolvers masking the actual infected host list** - {dns_count:,} combined C2 hits are forwarded on behalf of real infected clients. The firewall cannot see who is actually infected.",
            f"**{okta_dom['domain'] + ' is a fake Okta login page with ' + str(okta_dom['hits']) + ' internal hits' if okta_dom else 'Credential phishing infrastructure detected in ' + cn + chr(39) + 's threat logs'} - {'any employee who entered credentials there handed an attacker access to every SSO-protected system' if okta_dom else 'immediate review of phishing domains is required'}.",
        ],
        'vuln': [
            f"**{'Log4j RCE is a confirmed breach - ' + log4j['user'] + ' successfully connected to ' + log4j['dst_ip'] if log4j else str(vu_count) + ' vulnerability events require immediate triage'}** - {'this is a completed connection, not a blocked attempt. Forensic investigation and breach notification review required.' if log4j else 'named user attribution confirms real accounts are under active attack.'}",
            f"**{vu_count} vulnerability events from internal zones** - named user attribution in the Source User field confirms real {cn} accounts are actively triggering known exploit signatures.",
            f"**{'Log4j was disclosed in December 2021 - it firing in 2026 means an unpatched application is still running' if log4j else 'Unpatched systems are providing persistent attacker footholds'} - every day this remains unpatched is another day an attacker can use it.",
            f"**Vulnerability exploits from internal zones indicate attacker presence, not just external scanning** - internal IPs triggering CVEs means the adversary already has a foothold inside {cn}'s network.",
        ],
        'lateral': [
            f"**{'WRM data transfer ' + wrm_top['src_ip'] + ' -> ' + wrm_top['dst_zone'] + ' (' + wrm_top['bytes'] + ') is completed lateral movement, not a failed attempt' if wrm_top else 'WRM cross-zone flows indicate active lateral movement'}** - {'an adversary is actively traversing ' + cn + chr(39) + 's network segments.' if wrm_top else 'immediate network segmentation review is required.'}",
            f"**SMB traffic crossing zone boundaries is the ransomware propagation path** - every major ransomware incident of the past five years used this exact pattern to spread from one workstation to all production systems.",
            f"**{'Remote access tool sprawl at ' + remote_apps + ' apps vs industry average of 9' if remote_apps else 'Unmanaged remote access tools detected'} - each unauthorized tool is a potential backdoor. AnyDesk and VNC are the two most commonly abused by ransomware operators.",
            f"**Named accounts appearing in both C2 logs and brute force events** - accounts that appear in multiple attack categories require immediate investigation for compromise.",
        ],
        'saas': [
            f"**{'SaaS bandwidth at ' + saas_bw + ' (' + saas_pct + ') represents ' + cn + chr(39) + 's largest uncontrolled data flow' if saas_bw else 'SaaS application usage is unmonitored'} - without DLP, sensitive data could be leaving the organization right now with no audit trail.",
            f"**{'Total application footprint of ' + total_apps + ' apps creates an enormous unmanaged attack surface' if total_apps else 'Application visibility gaps are a critical security risk'} - every unmanaged application is a potential entry point an attacker can exploit.",
            f"**{'Remote access tool sprawl at ' + remote_apps + ' vs industry average 9' if remote_apps else 'Unauthorized remote access tools detected'} - consumer-grade tools like AnyDesk and VNC bypass security controls and are the top initial access vector in ransomware incidents.",
            f"**Risk-4 and Risk-5 applications dominate {cn}'s bandwidth** - high-risk applications including unencrypted protocols and applications with known CVEs are carrying the majority of network traffic.",
        ],
        'panorama': [
            f"**{'A ' + stale_days + '-day signature gap means all threats since ' + content_date + ' are completely invisible to ' + cn + chr(39) + 's security stack' if stale_days else 'Content pack staleness is creating critical detection blind spots'}** - new malware variants, exploits, and C2 domains are not being blocked.",
            f"**{'The very threats found in this report may be evading detection' if stale_days else 'Signature updates are the single highest-ROI action in this report'} - domains and malware families discovered after {content_date} are not in {cn}'s current signature set.",
            f"**Updating Panorama signatures takes 30 minutes and costs nothing** - this single action closes {'the ' + stale_days + '-day detection gap' if stale_days else 'the entire signature staleness window'} immediately.",
        ],
    }

    if not enabled or not api_key or api_key == 'YOUR_GEMINI_API_KEY_HERE':
        log('  ℹ LLM disabled or no API key — using dynamic fallback SO WHAT text')
        return fallbacks

    log('  Calling Gemini for LLM analysis...')
    results = {}
    for section in ['exec_summary', 'c2', 'vuln', 'lateral', 'saas', 'panorama']:
        log(f'    Analyzing §{section}...')
        prompt  = build_so_what_prompt(section, data, cn)
        bullets = call_gemini(prompt, api_key, model, log)
        if bullets and isinstance(bullets, list) and len(bullets) >= 3:
            results[section] = bullets
            log(f'    ✔ §{section} — {len(bullets)} bullets generated')
        else:
            results[section] = fallbacks[section]
            log(f'    ⚠ §{section} — LLM failed, using dynamic fallback')
    return results

# ── PRE-FLIGHT VALIDATION ─────────────────────────────────────────────────────
def sniff_csv(path):
    try:
        with open(path, newline='', encoding='utf-8', errors='replace') as f:
            rows = [r for _, r in zip(range(6), csv.reader(f))]
        if not rows: return 'empty'
        subtypes = set()
        for row in rows[1:]:
            if len(row) > 4: subtypes.add(row[4].strip().lower())
        if subtypes & {'spyware', 'vulnerability', 'virus', 'wildfire-virus', 'file'}:
            return 'threat'
        if subtypes & {'start', 'end', 'drop', 'deny', 'allow'}:
            return 'traffic'
        header = ','.join(rows[0]).lower()
        if any(k in header for k in ['threat', 'severity', 'attack']): return 'threat'
        if any(k in header for k in ['bytes', 'dest port', 'natdport']): return 'traffic'
        return 'unknown'
    except Exception as e:
        return f'error({e})'

def load_statsdump(path, log):
    data = {'panorama': {}, 'source_countries': []}
    if not path or not os.path.exists(path): return data
    log('  Parsing statsdump/techsupport...')
    try:
        import tarfile
        import xml.etree.ElementTree as ET
        
        # 1. Panorama profile extraction (existing logic)
        # We will stub this for now and just add source countries
        
        with tarfile.open(path, 'r:*') as t:
            for member in t.getmembers():
                if member.name == 'reports/SourceCountryReport.xml':
                    f = t.extractfile(member)
                    tree = ET.parse(f)
                    root = tree.getroot()
                    
                    countries = []
                    for entry in root.findall('.//entry'):
                        country = entry.find('srcloc').text if entry.find('srcloc') is not None else 'Unknown'
                        hits_node = entry.find('sessions')
                        hits = int(hits_node.text) if hits_node is not None else 0
                        
                        # Filter out internal/RFC1918 networks masquerading as countries
                        if country != 'Unknown' and not country[0].isdigit():
                            countries.append({'country': country, 'hits': hits})
                    
                    data['source_countries'] = sorted(countries, key=lambda x: -x['hits'])[:10]
                    log(f"    Loaded {len(data['source_countries'])} source countries")
                    break
    except Exception as e:
        log(f"    Error parsing statsdump: {e}")
    return data

def sniff_statsdump(path):
    """Detect statsdump archives (.tgz/.tar/.gz/.zip) OR extracted directories."""
    try:
        if os.path.isdir(path):
            entries = set(e.lower() for e in os.listdir(path))
            return ('opt' in entries) and bool({'var', 'tmp', 'etc'} & entries)
        
        name = os.path.basename(path).lower()
        if path.endswith('.tgz') or path.endswith('.tar.gz') or path.endswith('.zip'):
            if 'techsupport' in name or 'statsdump' in name or 'stats' in name:
                return True
        
        return False
    except: return False

def sniff_pdf(path):
    try:
        with open(path, 'rb') as f: return f.read(4) == b'%PDF'
    except: return False

def preflight(directory, log):
    log('━' * 52)
    log('  PRE-FLIGHT CHECK')
    log('━' * 52)
    found = {'threat': None, 'traffic': None, 'statsdump': None, 'slr': None}
    cands = {'threat': [], 'traffic': [], 'statsdump': [], 'slr': []}
    try:
        entries = os.listdir(directory)
    except Exception as e:
        log(f'  ✘ Cannot read directory: {e}'); return None

    for fname in entries:
        fpath = os.path.join(directory, fname)
        ext   = os.path.splitext(fname)[1].lower()

        if os.path.isdir(fpath):
            # Check for extracted techsupport directories
            if sniff_statsdump(fpath):
                cands['statsdump'].append((fname, fpath))
        elif os.path.isfile(fpath) and not fname.startswith('.'):
            if ext == '.csv':
                k = sniff_csv(fpath)
                if k == 'threat':    cands['threat'].append((fname, fpath))
                elif k == 'traffic': cands['traffic'].append((fname, fpath))
            elif ext in ('.tgz', '.tar', '.gz', '.zip'):
                if sniff_statsdump(fpath): cands['statsdump'].append((fname, fpath))
            elif ext == '.pdf':
                if sniff_pdf(fpath): cands['slr'].append((fname, fpath))

    # For threat CSVs: prefer files explicitly named "threat" in name, then pick largest
    # This avoids accidentally picking log.csv or a duplicate export over the real threat log
    def rank_threat_csv(item):
        fname_lower = item[0].lower()
        name_score = 0 if 'threat' in fname_lower else (1 if 'log' == fname_lower.replace('.csv','') else 2)
        size = os.path.getsize(item[1])
        return (name_score, -size)  # prefer "threat" in name, then largest

    if cands['threat']:
        cands['threat'].sort(key=rank_threat_csv)

    for key in ('threat', 'traffic', 'statsdump', 'slr'):
        if cands[key]: found[key] = cands[key][0][1]

    log('')
    all_ok = True
    cloud_warnings = []
    for key, label, required in [
        ('threat',    'Threat Logs CSV',   True),
        ('traffic',   'Traffic Logs CSV',  True),
        ('statsdump', 'Techsupport/Stats', True),
        ('slr',       'SLR PDF Report',    True),
    ]:
        path = found[key]
        if path:
            name = os.path.basename(path)
            log(f'  ✔  {label:<24} {name}')
        elif required:
            log(f'  ✘  {label:<24} NOT FOUND  ← REQUIRED')
            all_ok = False
        else:
            # Check if a cloud-stub file exists with matching name (not yet downloaded)
            cloud_stub = next((
                os.path.join(directory, f) for f in os.listdir(directory)
                if not f.startswith('.') and any(
                    kw in f.lower() for kw in
                    (['techsupport','statsdump','stats'] if key=='statsdump' else
                     ['slr','lifecycle','security lifecycle'] if key=='slr' else [])
                ) and os.path.getsize(os.path.join(directory, f)) > 1000
            ), None)
            if cloud_stub:
                cloud_warnings.append((label, os.path.basename(cloud_stub)))
                log(f'  ⚠  {label:<24} Found but not downloaded from cloud: {os.path.basename(cloud_stub)}')
            else:
                log(f'  ⚠  {label:<24} not found (SLR/Panorama sections will show "—")')

    log('')
    log('━' * 52)
    if all_ok:
        log('  All required files verified. Ready to generate.')
        if cloud_warnings:
            log('')
            log('  ⚠  Cloud files not yet downloaded:')
            for label, fname in cloud_warnings:
                log(f'     {fname}')
            log('     Open Finder → right-click → "Download Now"')
            log('     to get Panorama/SLR data in report.')
        elif not found['statsdump'] and not found['slr']:
            log('  ℹ  No techsupport/SLR found — KPI boxes, SaaS,')
            log('     Panorama, and Benchmark sections will show "—".')
    else:
        log('')
        log('  ✘  CANNOT PROCEED — ALL 4 DATA SOURCES ARE NOW STRICTLY REQUIRED.')
        log('     (Threat CSV, Traffic CSV, Statsdump, SLR PDF)')
        log('     Ensure all files are fully downloaded from Google Drive locally.')
    log('━' * 52)
    log('')
    return found if all_ok else None

# ── DATA PARSING ──────────────────────────────────────────────────────────────
def parse_threat_name(name):
    # Strip 'Parked:' prefix that PAN uses for parked/sinkholed domains
    name = re.sub(r'^generic:', '', name)
    name = re.sub(r'^[Pp]arked:', '', name)
    m = re.match(r'^(.+?)\((\d+)\)$', name)
    return (m.group(1), m.group(2)) if m else (name, '')

def load_threat_csv(path, log):
    spyware, vulns = [], []
    action_counts = defaultdict(int)
    log('  Parsing threat CSV...')
    with open(path, newline='', encoding='utf-8', errors='replace') as f:
        for i, row in enumerate(csv.reader(f)):
            if i == 0 or len(row) < 35: continue
            subtype  = row[4].strip()
            src_ip   = row[7].strip()
            src_user = row[12].strip()
            src_zone = row[16].strip()
            threat   = row[32].strip()
            severity = row[34].strip()
            action   = row[21].strip() if len(row) > 21 else 'unknown'
            dst_ip   = row[8].strip()  if len(row) > 8  else ''
            if src_zone in SKIP_ZONES: continue
            
            # Tally actions for the Policy Violations section
            action_counts[action] += 1
            
            if subtype == 'spyware':
                spyware.append((src_ip, src_user, src_zone, threat, severity))
            elif subtype == 'vulnerability':
                vulns.append((src_ip, src_user, src_zone, threat, severity, action, dst_ip))
    log(f'    Spyware: {len(spyware):,}  |  Vulnerability: {len(vulns):,}')
    return spyware, vulns, dict(action_counts)

def analyze_spyware(rows, log):
    ip_hits  = defaultdict(int); ip_zone  = {}
    ip_users = defaultdict(set); ip_doms  = defaultdict(set)
    dom_hits = defaultdict(int); dom_tids = {}
    for src_ip, src_user, src_zone, threat, _ in rows:
        dom, tid = parse_threat_name(threat)
        ip_hits[src_ip] += 1; ip_zone[src_ip] = src_zone
        if src_user: ip_users[src_ip].add(src_user)
        ip_doms[src_ip].add(dom); dom_hits[dom] += 1
        if tid: dom_tids[dom] = tid
    dns, infected = {}, {}
    for ip, hits in ip_hits.items():
        ud = len(ip_doms[ip])
        if hits >= DNS_HIT_MIN and ud >= DNS_DOM_MIN:
            dns[ip] = {'hits': hits, 'zone': ip_zone[ip], 'unique': ud}
        else:
            infected[ip] = {
                'hits': hits, 'zone': ip_zone[ip], 'unique': ud,
                'users': ', '.join(sorted(ip_users[ip])) or '—'
            }
    top_doms = sorted(dom_hits.items(), key=lambda x: -x[1])[:10]
    # Always include critical domains (okta phishing, brand squatting) even if outside top 10
    critical_doms = ['okta-ema.com', 'idexdmz.com']
    top_dom_names = {d for d, _ in top_doms}
    for cdom in critical_doms:
        if cdom in dom_hits and cdom not in top_dom_names:
            top_doms.append((cdom, dom_hits[cdom]))
    top_ips  = sorted(infected.items(), key=lambda x: -x[1]['hits'])[:10]
    log(f'    DNS resolvers: {len(dns)}  |  Infected IPs: {len(infected)}  |  Top 10 shown')
    return dns, infected, top_doms, dom_tids, top_ips

def load_wrm(path, log):
    """Extract WRM cross-zone flows from traffic CSV, top 10 by bytes."""
    if not path or not os.path.exists(path): return []
    flows = []
    try:
        with open(path, newline='', encoding='utf-8', errors='replace') as f:
            for i, row in enumerate(csv.reader(f)):
                if i == 0 or len(row) < 22: continue
                app      = row[14].strip().lower() if len(row) > 14 else ''
                src_ip   = row[7].strip()  if len(row) > 7  else ''
                dst_ip   = row[8].strip()  if len(row) > 8  else ''
                src_zone = row[16].strip() if len(row) > 16 else ''
                dst_zone = row[17].strip() if len(row) > 17 else ''
                try: raw_bytes = int(row[31].strip()) if len(row) > 31 else 0
                except: raw_bytes = 0
                if 'windows-remote-management' in app and src_zone != dst_zone and raw_bytes > 100000:
                    mb = raw_bytes / 1024 / 1024
                    flows.append({
                        'src_ip': src_ip, 'src_zone': src_zone,
                        'dst_ip': dst_ip, 'dst_zone': dst_zone,
                        'bytes': f'{mb:.1f} MB'
                    })
        flows = sorted(flows, key=lambda x: -float(x['bytes'].split()[0]))[:8]
        # Deduplicate by src+dst pair keeping highest
        seen = set(); deduped = []
        for f in flows:
            key = (f['src_ip'], f['dst_ip'])
            if key not in seen:
                seen.add(key); deduped.append(f)
        log(f'    WRM cross-zone flows: {len(deduped)}')
        return deduped
    except Exception as e:
        log(f'  Warning: WRM parse error: {e}')
        return []

def load_smb(path, log):
    if not path or not os.path.exists(path): return []
    flows = []; seen = set()
    try:
        with open(path, newline='', encoding='utf-8', errors='replace') as f:
            for i, row in enumerate(csv.reader(f)):
                if i == 0 or len(row) < 18: continue
                src_ip = row[7].strip()  if len(row) > 7  else ''
                app    = row[14].strip() if len(row) > 14 else ''
                sz     = row[16].strip() if len(row) > 16 else ''
                dz     = row[17].strip() if len(row) > 17 else ''
                key    = (src_ip, sz, dz)
                if 'smb' in app.lower() and sz != dz and key not in seen:
                    flows.append({'src_ip': src_ip, 'src_zone': sz, 'dst_zone': dz})
                    seen.add(key)
                    if len(flows) >= 6: break
    except Exception as e:
        log(f'  Warning: traffic CSV error: {e}')
    log(f'    SMB cross-zone samples: {len(flows)}')
    return flows

def get_csv_date_range(path):
    try:
        def extract(line):
            m = re.search(r'(\d{4}/\d{2}/\d{2})', line)
            return m.group(1) if m else None
        # Read first data line
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            f.readline()  # header
            first = f.readline()
        # Read last non-empty line — separate open to avoid seek bug
        with open(path, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 8192))
            tail = f.read().decode('utf-8', errors='replace')
        lines = [l for l in tail.splitlines() if l.strip()]
        last = lines[-1] if lines else ''
        s, e = extract(first), extract(last)
        if s and e:
            return s if s == e else f"{min(s, e)} - {max(s, e)}"
        if s: return s
    except: pass
    return "Period Unknown"

# ── MAIN GENERATE ─────────────────────────────────────────────────────────────
def generate(source_dir, customer_name, output_dir, log):
    config = load_config()

    # Pre-flight
    files = preflight(source_dir, log)
    if files is None:
        raise ValueError('Pre-flight failed — missing required files.')

    # Parse CSVs
    log('Parsing data...')
    sp, vu, action_counts = load_threat_csv(files['threat'], log)
    dns, infected, top_doms, dom_tids, top_ips = analyze_spyware(sp, log)
    smb = load_smb(files['traffic'], log) if files['traffic'] else []
    wrm = load_wrm(files['traffic'], log) if files['traffic'] else []

    # Parse statsdump
    stats_data = load_statsdump(files['statsdump'], log)
    
    threat_period  = get_csv_date_range(files['threat'])
    traffic_period = get_csv_date_range(files['traffic']) if files['traffic'] else 'N/A'

    # Build data payload
    data = {
        'customerName':  customer_name,
        'month':         datetime.datetime.now().strftime('%B %Y'),
        'totalRows':     len(sp) + len(vu),
        'spywareCount':  len(sp),
        'vulnCount':     len(vu),
        'infectedCount': len(infected),
        'dnsResolvers':  [{'ip': ip, 'zone': d['zone'], 'hits': d['hits'], 'unique': d['unique']}
                          for ip, d in dns.items()],
        'topDomains':    [{'domain': dom, 'hits': hits, 'tid': dom_tids.get(dom, '')}
                          for dom, hits in top_doms],
        'topIPs':        [{'ip': ip, 'zone': d['zone'], 'hits': d['hits'],
                           'unique': d['unique'], 'users': d['users']}
                          for ip, d in top_ips],
        'smbFlows':      smb,
        'wrmFlows':      wrm,
        'actionCounts':  action_counts,
        'vulnEvents':    [{'src_ip': r[0], 'user': r[1], 'zone': r[2],
                           'threat': r[3], 'severity': r[4],
                           'action': r[5], 'dst_ip': r[6]}
                          for r in vu],
        'sourceCountries': stats_data.get('source_countries', []),
        # SLR fields — populated from statsdump/SLR when available, else '—'
        'slr': {},
        # Panorama profile — populated from statsdump when available
        'panorama': {},
        # SLR table data — populated from statsdump when available
        'namedThreats':    [],
        'wildfireDetections': [],
        'appVulns':        [],
        'remoteAccessApps':[],
        'riskBandwidth':   [],
        'highRiskApps':    [],
        'saasRisk':        [],
        'benchmarks':      [],
        # Finding card overrides (Gemini fills these via soWhat, cards auto-built from data)
        'findings': {},
        'sourceFiles': [
            {'name': os.path.basename(files['threat']),
             'type': 'Threat Logs', 'period': threat_period},
            {'name': os.path.basename(files['traffic']) if files['traffic'] else 'Not found',
             'type': 'Traffic Logs', 'period': traffic_period},
        ],
        'preparer': {
            'name':  config.get('preparer_name',  'John Shelest'),
            'title': config.get('preparer_title', 'Palo Alto Networks Solutions Consultant'),
            'email': config.get('preparer_email', 'jshelest@paloaltonetworks.com'),
        }
    }

    # LLM SO WHAT analysis
    log('Running LLM analysis (Gemini)...')
    data['soWhat'] = generate_all_so_whats(data, customer_name, config, log)

    # Write JSON temp file
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(data, tmp, indent=2); tmp.close()

    # Output paths
    safe = re.sub(r'[^a-zA-Z0-9_\-]', '_', customer_name)
    stamp = datetime.datetime.now().strftime('%B%Y')
    out_html = os.path.join(output_dir, f'{safe}_Security_Assessment_{stamp}.html')
    out_pdf  = os.path.join(output_dir, f'{safe}_Security_Assessment_{stamp}.pdf')

    # Call Node generator
    gen_js = os.path.join(SCRIPT_DIR, 'gen_report.js')
    log('Building HTML...')
    result = subprocess.run(
        ['/opt/homebrew/bin/node', gen_js, tmp.name, out_html],
        capture_output=True, text=True, timeout=120
    )
    os.unlink(tmp.name)

    if result.returncode != 0:
        raise RuntimeError(f'Node.js error:\n{result.stderr[:400]}')

    log(f'  {result.stdout.strip()}')

    # Convert to PDF via Chrome headless
    log('Converting to PDF...')
    chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    if os.path.exists(chrome):
        pr = subprocess.run(
            [chrome, '--headless', '--disable-gpu', '--no-sandbox',
             f'--print-to-pdf={out_pdf}',
             f'--print-to-pdf-no-header', out_html],
            capture_output=True, timeout=60
        )
        if os.path.exists(out_pdf):
            log(f'  ✔ PDF: {out_pdf}')
        else:
            log('  ⚠ PDF conversion failed — HTML report is available')
            out_pdf = out_html
    else:
        log('  ⚠ Chrome not found — HTML report only')
        out_pdf = out_html

    aid = save_assessment(customer_name, data, out_html)
    log(f'  ✔ Saved to database (ID: {aid})')
    log(f'\n✅ Done: {out_pdf}')
    return out_pdf

# ── GUI ───────────────────────────────────────────────────────────────────────
class App(tk.Tk):
    BG, BG2, BG3 = '#FFFFFF', '#F2F2F2', '#E5E5E5'
    FG, FG2 = '#333333', '#666666'
    ORG = '#FA4616'

    def __init__(self):
        super().__init__()
        self.title('PAN Security Assessment Generator')
        self.geometry('820x680')
        self.configure(bg=self.BG)
        init_db()
        self._prefs = {}
        if os.path.exists(PREFS_PATH):
            try:
                with open(PREFS_PATH) as f: self._prefs = json.load(f)
            except: pass
        self._build()

    def _save_prefs(self):
        self._prefs.update({
            'last_customer': self.cust.get(),
            'last_source':   self.src.get(),
            'last_output':   self.out.get(),
        })
        with open(PREFS_PATH, 'w') as f: json.dump(self._prefs, f)

    def _build(self):
        lbl  = {'bg': self.BG, 'fg': self.FG, 'font': ('Arial', 10, 'bold'), 'width': 18, 'anchor': 'w'}
        ent  = {'bg': self.BG2, 'fg': self.FG, 'insertbackground': self.FG,
                'relief': 'flat', 'font': ('Arial', 11),
                'highlightthickness': 1, 'highlightbackground': self.BG3}
        btn  = {'bg': self.ORG, 'fg': 'white', 'activebackground': '#E63E00',
                'activeforeground': 'white', 'relief': 'flat',
                'font': ('Arial', 10, 'bold'), 'padx': 15, 'pady': 5}

        # Header
        tk.Label(self, text='PALO ALTO NETWORKS', bg=self.BG, fg=self.ORG,
                 font=('Arial', 10, 'bold')).pack(pady=(16, 0))
        tk.Label(self, text='Security Assessment Generator', bg=self.BG, fg=self.FG,
                 font=('Arial', 18, 'bold')).pack(pady=(2, 12))

        form = tk.Frame(self, bg=self.BG, padx=40); form.pack(fill='x')

        # Customer name
        f1 = tk.Frame(form, bg=self.BG, pady=6); f1.pack(fill='x')
        tk.Label(f1, text='CUSTOMER NAME', **lbl).pack(side='left')
        self.cust = tk.StringVar(value=self._prefs.get('last_customer', 'IDEX Corp'))
        tk.Entry(f1, textvariable=self.cust, **ent).pack(side='left', fill='x', expand=True)

        # Source folder
        f2 = tk.Frame(form, bg=self.BG, pady=6); f2.pack(fill='x')
        tk.Label(f2, text='SOURCE DIRECTORY', **lbl).pack(side='left')
        self.src = tk.StringVar(value=self._prefs.get('last_source', ''))
        tk.Entry(f2, textvariable=self.src, **ent).pack(side='left', fill='x', expand=True, padx=(0,10))
        tk.Button(f2, text='BROWSE', command=self._browse_src, **btn).pack(side='left')

        # Output folder
        f3 = tk.Frame(form, bg=self.BG, pady=6); f3.pack(fill='x')
        tk.Label(f3, text='OUTPUT DIRECTORY', **lbl).pack(side='left')
        self.out = tk.StringVar(value=self._prefs.get('last_output', ''))
        tk.Entry(f3, textvariable=self.out, **ent).pack(side='left', fill='x', expand=True, padx=(0,10))
        tk.Button(f3, text='BROWSE', command=self._browse_out, **btn).pack(side='left')

        # Config status
        config = load_config()
        api_key = config.get('gemini_api_key', '')
        if api_key and api_key != 'YOUR_GEMINI_API_KEY_HERE':
            llm_status = f'✔ Gemini API key configured ({config.get("gemini_model","gemini-2.0-flash")})'
            llm_color  = '#1E7A1E'
        else:
            llm_status = '⚠ No Gemini API key — edit config.json to enable LLM analysis'
            llm_color  = '#E07800'
        tk.Label(form, text=llm_status, bg=self.BG, fg=llm_color,
                 font=('Arial', 9), anchor='w').pack(fill='x', pady=(4, 0))

        # Generate button
        btn_frame = tk.Frame(self, bg=self.BG, pady=12); btn_frame.pack()
        self.gen_btn = tk.Button(
            btn_frame, text='⚡  GENERATE ASSESSMENT',
            command=self._run_generate,
            bg=self.ORG, fg='white', activebackground='#E63E00',
            font=('Arial', 12, 'bold'), padx=30, pady=10, relief='flat', cursor='hand2')
        self.gen_btn.pack()

        # Log
        tk.Label(self, text='GENERATION LOG', bg=self.BG, fg=self.FG2,
                 font=('Arial', 9, 'bold'), padx=40, anchor='w').pack(fill='x')
        self.log_box = scrolledtext.ScrolledText(
            self, height=14, bg='#0d1117', fg='#00ff88',
            font=('Menlo', 10), relief='flat', padx=10, pady=10, state='disabled')
        self.log_box.pack(fill='both', expand=True, padx=40, pady=(4, 30))

    def _browse_src(self):
        d = filedialog.askdirectory(title='Select Source Folder')
        if not d: return
        self.src.set(d)
        if not self.out.get(): self.out.set(str(Path(d).parent))
        # Auto-detect customer name — skip generic folder names
        skip = {'source', 'src', 'data', 'logs', 'qbr', '2025', '2026',
                'q1', 'q2', 'q3', 'q4', 'feb', 'mar', 'apr', 'may', 'jun',
                'jul', 'aug', 'sep', 'oct', 'nov', 'dec', 'security', 'assessment',
                'report', 'export', 'output', 'threat', 'traffic', 'pan', 'panorama'}
        for part in reversed(Path(d).parts):
            clean = part.lower().strip()
            # Skip parts that are purely numeric years/quarters, look like "Q3 2026 QBR", etc.
            if re.match(r'^\d{4}$', clean): continue
            if re.match(r'^q[1-4]\s*\d{4}', clean): continue
            if all(w in skip for w in re.split(r'[\s_\-]+', clean)): continue
            if clean in skip: continue
            if len(part) > 2:
                self.cust.set(part)
                break
        self._save_prefs()

    def _browse_out(self):
        d = filedialog.askdirectory(title='Select Output Folder')
        if d: self.out.set(d); self._save_prefs()

    def _log(self, msg):
        self.log_box.configure(state='normal')
        self.log_box.insert('end', msg + '\n')
        self.log_box.see('end')
        self.log_box.configure(state='disabled')
        self.update_idletasks()

    def _run_generate(self):
        src  = self.src.get().strip()
        out  = self.out.get().strip()
        name = self.cust.get().strip()
        if not src or not os.path.isdir(src):
            messagebox.showerror('Error', 'Please select a valid source folder.'); return
        if not out:
            messagebox.showerror('Error', 'Please select an output folder.'); return
        if not name:
            messagebox.showerror('Error', 'Please enter a customer name.'); return
        os.makedirs(out, exist_ok=True)
        self._save_prefs()
        self.gen_btn.configure(state='disabled', text='GENERATING...')
        self.log_box.configure(state='normal'); self.log_box.delete('1.0', 'end')
        self.log_box.configure(state='disabled')
        threading.Thread(target=self._worker, args=(src, name, out), daemon=True).start()

    def _worker(self, src, name, out):
        try:
            path = generate(src, name, out, self._log)
            self._prefs['last_generated'] = path
            self._save_prefs()
            self.after(0, lambda p=path: self._done(p))
        except Exception as e:
            err_msg = str(e)
            self.after(0, lambda m=err_msg: self._err(m))

    def _done(self, path):
        self.gen_btn.configure(state='normal', text='⚡  GENERATE ASSESSMENT')
        os.system(f'open "{os.path.dirname(path)}"')
        if messagebox.askyesno('Done', f'Report saved:\n{path}\n\nOpen now?'):
            os.system(f'open "{path}"')

    def _err(self, msg):
        self.gen_btn.configure(state='normal', text='⚡  GENERATE ASSESSMENT')
        self._log(f'\n❌ ERROR: {msg}')
        messagebox.showerror('Error', msg)


if __name__ == '__main__':
    App().mainloop()
