#!/opt/homebrew/bin/python3
"""
PAN Security Assessment Generator — GUI App
Parses CSVs in Python, hands off to Node.js for fast DOCX generation.
Maintains a local SQLite database for historical assessment data.
Run: python3 pan_assessment_app.py
"""
import csv, re, os, sys, json, subprocess, threading, datetime, tempfile, tarfile, sqlite3
from collections import defaultdict
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

SKIP_ZONES  = {'untrust', 'guest', 'Guest'}
DNS_HIT_MIN = 5000
DNS_DOM_MIN = 10

# Database setup
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'assessments.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS assessments 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  customer_name TEXT, 
                  report_quarter TEXT, 
                  total_threats INTEGER,
                  vulnerabilities INTEGER,
                  infected_ips INTEGER,
                  data JSON, 
                  html_path TEXT,
                  UNIQUE(customer_name, report_quarter))''')
    c.execute('''CREATE TABLE IF NOT EXISTS findings 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  assessment_id INTEGER, 
                  type TEXT, 
                  headline TEXT, 
                  body TEXT, 
                  critical BOOLEAN, 
                  FOREIGN KEY(assessment_id) REFERENCES assessments(id))''')
    conn.commit()
    conn.close()

def get_quarter():
    now = datetime.datetime.now()
    quarter = (now.month - 1) // 3 + 1
    return f"{now.year}-Q{quarter}"

def save_assessment(customer_name, data, out_path):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    report_quarter = get_quarter()
    try:
        c.execute('''INSERT OR REPLACE INTO assessments 
                     (customer_name, report_quarter, total_threats, vulnerabilities, infected_ips, data, html_path) 
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (customer_name, report_quarter, 
                   data['totalRows'], data['vulnCount'], data['infectedCount'],
                   json.dumps(data), out_path))
        
        # When using INSERT OR REPLACE, we need to find the ID of what we just inserted/replaced
        c.execute("SELECT id FROM assessments WHERE customer_name = ? AND report_quarter = ?", (customer_name, report_quarter))
        aid = c.fetchone()[0]
        
        c.execute("DELETE FROM findings WHERE assessment_id = ?", (aid,))
        
        findings = [
            ('Breach', 'Active Breach Indicator', True),
            ('Brand', 'Brand Squatting Detected', True),
            ('Phishing', 'Identity Phishing Risk', True),
            ('Policy', 'Signature Staleness', False)
        ]
        for ftype, head, crit in findings:
            c.execute("INSERT INTO findings (assessment_id, type, headline, body, critical) VALUES (?, ?, ?, ?, ?)",
                      (aid, ftype, head, "Verbatim data preserved in JSON blob", crit))
        
        conn.commit()
        return aid
    finally:
        conn.close()

# ═══════════════════════════════════════════════════════════════════════════════
# PRE-FLIGHT VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════
def sniff_csv(path):
    """Peek at a CSV and return 'threat', 'traffic', or 'unknown'."""
    try:
        with open(path, newline='', encoding='utf-8', errors='replace') as f:
            rows = [r for _, r in zip(range(6), csv.reader(f))]
        if not rows: return 'empty'
        header = ','.join(rows[0]).lower()
        subtypes = set()
        for row in rows[1:]:
            if len(row) > 4:
                subtypes.add(row[4].strip().lower())
        if subtypes & {'spyware', 'vulnerability', 'virus', 'wildfire-virus', 'file'}:
            return 'threat'
        if subtypes & {'start', 'end', 'drop', 'deny', 'allow'}:
            return 'traffic'
        if any(k in header for k in ['threat', 'severity', 'attack']):
            return 'threat'
        if any(k in header for k in ['bytes', 'dest port', 'natdport']):
            return 'traffic'
        return 'unknown'
    except Exception as e:
        return f'error({e})'

def sniff_statsdump(path):
    try:
        if not tarfile.is_tarfile(path): return False
        with tarfile.open(path, 'r:*') as t:
            names = t.getnames()
        return any(any(k in n.lower() for k in ['stat', 'dump', 'mp_', 'counter', 'system']) for n in names)
    except:
        return False

def sniff_pdf_slr(path):
    try:
        with open(path, 'rb') as f:
            return f.read(4) == b'%PDF'
    except:
        return False

def preflight(directory, log):
    log('━' * 52)
    log('  PRE-FLIGHT CHECK')
    log('━' * 52)
    found = {'threat': None, 'traffic': None, 'statsdump': None, 'slr': None}
    candidates = {'threat': [], 'traffic': [], 'statsdump': [], 'slr': []}
    try:
        all_files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)) and not f.startswith('.')]
    except Exception as e:
        log(f'  ✘ Cannot read directory: {e}')
        return found

    for fname in all_files:
        fpath = os.path.join(directory, fname)
        ext   = os.path.splitext(fname)[1].lower()
        if ext == '.csv':
            kind = sniff_csv(fpath)
            if kind == 'threat': candidates['threat'].append((fname, fpath))
            elif kind == 'traffic': candidates['traffic'].append((fname, fpath))
        elif ext in ('.tgz', '.tar', '.gz', '.zip'):
            if sniff_statsdump(fpath): candidates['statsdump'].append((fname, fpath))
        elif ext == '.pdf':
            if sniff_pdf_slr(fpath): candidates['slr'].append((fname, fpath))

    for key in ('threat', 'traffic', 'statsdump', 'slr'):
        if candidates[key]: found[key] = candidates[key][0][1]

    all_ok = True
    for key, label, required in [('threat', 'Threat Logs CSV', True), ('traffic', 'Traffic Logs CSV', False), ('statsdump', 'Statsdump Archive', False), ('slr', 'SLR PDF Report', False)]:
        path = found[key]
        if path: log(f'  ✔  {label:<22} {os.path.basename(path)}')
        else:
            if required:
                log(f'  ✘  {label:<22} NOT FOUND  ← REQUIRED')
                all_ok = False
            else: log(f'  ⚠  {label:<22} not found (optional)')
    
    log('━' * 52)
    if all_ok: log('  All files verified. Ready to generate.')
    else: log('  CANNOT PROCEED — missing required files.')
    return found if all_ok else None

# ═══════════════════════════════════════════════════════════════════════════════
# DATA PARSING & GENERATION
# ═══════════════════════════════════════════════════════════════════════════════
def parse_threat_name(name):
    name = re.sub(r'^generic:', '', name)
    m = re.match(r'^(.+?)\((\d+)\)$', name)
    return (m.group(1), m.group(2)) if m else (name, '')

def load_threat_csv(path, log):
    spyware, vulns = [], []
    log('  Parsing threat CSV...')
    with open(path, newline='', encoding='utf-8', errors='replace') as f:
        for i, row in enumerate(csv.reader(f)):
            if i == 0 or len(row) < 35: continue
            subtype, src_ip, src_user, src_zone, threat, severity = row[4], row[7], row[12], row[16], row[32], row[34]
            if src_zone in SKIP_ZONES: continue
            if subtype == 'spyware': spyware.append((src_ip, src_user, src_zone, threat, severity))
            elif subtype == 'vulnerability': vulns.append((src_ip, src_user, src_zone, threat, severity, row[21], row[8]))
    return spyware, vulns

def analyze_spyware(rows, log):
    ip_hits, ip_zone, ip_doms = defaultdict(int), {}, defaultdict(set)
    dom_hits, dom_tids = defaultdict(int), {}
    for src_ip, src_user, src_zone, threat, _ in rows:
        dom, tid = parse_threat_name(threat)
        ip_hits[src_ip] += 1; ip_zone[src_ip] = src_zone; ip_doms[src_ip].add(dom)
        dom_hits[dom] += 1
        if tid: dom_tids[dom] = tid
    dns, infected = {}, {}
    for ip, hits in ip_hits.items():
        ud = len(ip_doms[ip])
        if hits >= DNS_HIT_MIN and ud >= DNS_DOM_MIN: dns[ip] = {'hits': hits, 'zone': ip_zone[ip], 'unique': ud}
        else: infected[ip] = {'hits': hits, 'zone': ip_zone[ip], 'unique': ud, 'users': '—'}
    return dns, infected, sorted(dom_hits.items(), key=lambda x: -x[1])[:10], dom_tids, sorted(infected.items(), key=lambda x: -x[1]['hits'])[:10]

def generate(source_dir, customer_name, output_dir, log):
    files = preflight(source_dir, log)
    if files is None: raise ValueError('Pre-flight failed.')
    
    sp, vu = load_threat_csv(files['threat'], log)
    dns, infected, top_doms, dom_tids, top_ips = analyze_spyware(sp, log)
    
    data = {
        'customerName': customer_name,
        'month': datetime.datetime.now().strftime('%B %Y'),
        'totalRows': len(sp) + len(vu),
        'spywareCount': len(sp), 'vulnCount': len(vu), 'infectedCount': len(infected),
        'dnsResolvers': [{'ip': ip, 'zone': d['zone'], 'hits': d['hits'], 'unique': d['unique']} for ip, d in dns.items()],
        'topDomains': [{'domain': dom, 'hits': hits, 'tid': dom_tids.get(dom, '')} for dom, hits in top_doms],
        'topIPs': [{'ip': ip, 'zone': d['zone'], 'hits': d['hits'], 'unique': d['unique'], 'users': d['users']} for ip, d in top_ips],
        'smbFlows': [], 'vulnEvents': []
    }

    safe = re.sub(r'[^a-zA-Z0-9_\-]', '_', customer_name)
    out_path = os.path.join(output_dir, f'{safe}_Security_Assessment_{datetime.datetime.now().strftime("%B%Y")}.html')
    
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(data, tmp, indent=2); tmp.close()
    
    gen_js = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gen_report.js')
    log('Building HTML document...')
    result = subprocess.run(['/opt/homebrew/bin/node', gen_js, tmp.name, out_path], capture_output=True, text=True, timeout=120)
    os.unlink(tmp.name)
    
    if result.returncode == 0:
        aid = save_assessment(customer_name, data, out_path)
        log(f'✅ Saved Assessment ID: {aid}')
        log(f'✅ Report: {out_path}')
        return out_path
    else: raise RuntimeError(f'Node.js error: {result.stderr}')

# ═══════════════════════════════════════════════════════════════════════════════
# GUI
# ═══════════════════════════════════════════════════════════════════════════════
class App(tk.Tk):
    BG, BG2, BG3, FG, ORG, GRN, RED = '#1a1a1a', '#252525', '#2e2e2e', '#ffffff', '#FA4616', '#00ff88', '#ff4444'
    def __init__(self):
        super().__init__()
        self.title('PAN Security Assessment Generator')
        self.geometry('760x620'); self.configure(bg=self.BG)
        init_db(); self._build()

    def _build(self):
        tk.Label(self, text='PAN Security Assessment Generator', bg=self.BG, fg=self.ORG, font=('Arial', 16, 'bold')).pack(pady=(16, 2))
        
        f1 = tk.Frame(self, bg=self.BG); f1.pack(fill='x', padx=16, pady=4)
        tk.Label(f1, text='Customer Name:', bg=self.BG, fg=self.FG, width=16, anchor='w').pack(side='left')
        self.cust = tk.StringVar(value='IDEX Corp')
        tk.Entry(f1, textvariable=self.cust, bg=self.BG2, fg=self.FG, relief='flat').pack(side='left', fill='x', expand=True)

        f2 = tk.Frame(self, bg=self.BG); f2.pack(fill='x', padx=16, pady=4)
        tk.Label(f2, text='Source Folder:', bg=self.BG, fg=self.FG, width=16, anchor='w').pack(side='left')
        self.src = tk.StringVar()
        tk.Entry(f2, textvariable=self.src, bg=self.BG2, fg=self.FG, relief='flat').pack(side='left', fill='x', expand=True, padx=(0,8))
        tk.Button(f2, text='Browse', command=self._browse_src, bg=self.ORG, fg=self.FG).pack(side='left')

        f3 = tk.Frame(self, bg=self.BG); f3.pack(fill='x', padx=16, pady=4)
        tk.Label(f3, text='Output Folder:', bg=self.BG, fg=self.FG, width=16, anchor='w').pack(side='left')
        self.out = tk.StringVar()
        tk.Entry(f3, textvariable=self.out, bg=self.BG2, fg=self.FG, relief='flat').pack(side='left', fill='x', expand=True, padx=(0,8))
        tk.Button(f3, text='Browse', command=self._browse_out, bg=self.ORG, fg=self.FG).pack(side='left')

        tk.Button(self, text='⚡  Generate Report', command=self._run_generate, bg=self.ORG, fg=self.FG, font=('Arial', 13, 'bold'), padx=24, pady=8).pack(pady=10)
        
        self.log_box = scrolledtext.ScrolledText(self, height=16, bg='#0d1117', fg=self.GRN, font=('Courier New', 9))
        self.log_box.pack(fill='both', expand=True, padx=16, pady=16)

    def _browse_src(self):
        d = filedialog.askdirectory()
        if d: self.src.set(d); self.out.set(str(Path(d).parent))
    def _browse_out(self):
        d = filedialog.askdirectory()
        if d: self.out.set(d)
    def _log(self, msg):
        self.log_box.configure(state='normal'); self.log_box.insert('end', msg + '\n'); self.log_box.see('end'); self.log_box.configure(state='disabled'); self.update_idletasks()

    def _run_generate(self):
        threading.Thread(target=lambda: generate(self.src.get(), self.cust.get(), self.out.get(), self._log), daemon=True).start()

if __name__ == '__main__':
    App().mainloop()
