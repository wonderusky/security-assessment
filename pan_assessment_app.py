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
    # Professional Palo Alto Networks Theme (Light/Clean)
    BG, BG2, BG3 = '#FFFFFF', '#F2F2F2', '#E5E5E5'
    FG, FG2 = '#333333', '#666666'
    ORG, GRN, RED = '#FA4616', '#1E7A1E', '#CC0000'
    
    def __init__(self):
        super().__init__()
        self.title('PAN Security Assessment Generator')
        self.geometry('800x650')
        self.configure(bg=self.BG)
        init_db()
        self._build()

    def _build(self):
        # Prefs handling
        self._prefs_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'prefs.json')
        self._prefs = {}
        if os.path.exists(self._prefs_file):
            try:
                with open(self._prefs_file, 'r') as f: self._prefs = json.load(f)
            except: pass

        # Header with Logo-style text
        header_frame = tk.Frame(self, bg=self.BG, pady=20)
        header_frame.pack(fill='x')
        tk.Label(header_frame, text='PALO ALTO NETWORKS', bg=self.BG, fg=self.ORG, font=('Arial', 10, 'bold'), letterspacing=2).pack()
        tk.Label(header_frame, text='Security Assessment Generator', bg=self.BG, fg=self.FG, font=('Arial', 18, 'bold')).pack()
        
        # Form Container
        form = tk.Frame(self, bg=self.BG, padx=40)
        form.pack(fill='x')

        # Style configuration
        lbl_style = {'bg': self.BG, 'fg': self.FG, 'font': ('Arial', 10, 'bold'), 'width': 18, 'anchor': 'w'}
        entry_style = {'bg': self.BG2, 'fg': self.FG, 'insertbackground': self.FG, 'relief': 'flat', 'font': ('Arial', 11), 'highlightthickness': 1, 'highlightbackground': self.BG3}
        btn_style = {'bg': self.ORG, 'fg': 'white', 'activebackground': '#E63E00', 'activeforeground': 'white', 'relief': 'flat', 'font': ('Arial', 10, 'bold'), 'padx': 15, 'pady': 5}

        # Customer Name
        f1 = tk.Frame(form, bg=self.BG, pady=8); f1.pack(fill='x')
        tk.Label(f1, text='CUSTOMER NAME', **lbl_style).pack(side='left')
        self.cust = tk.StringVar(value=self._prefs.get('last_customer', 'IDEX Corp'))
        tk.Entry(f1, textvariable=self.cust, **entry_style).pack(side='left', fill='x', expand=True)

        # Source Folder
        f2 = tk.Frame(form, bg=self.BG, pady=8); f2.pack(fill='x')
        tk.Label(f2, text='SOURCE DIRECTORY', **lbl_style).pack(side='left')
        self.src = tk.StringVar(value=self._prefs.get('last_source', ''))
        tk.Entry(f2, textvariable=self.src, **entry_style).pack(side='left', fill='x', expand=True, padx=(0,10))
        tk.Button(f2, text='BROWSE', command=self._browse_src, **btn_style).pack(side='left')

        # Output Folder
        f3 = tk.Frame(form, bg=self.BG, pady=8); f3.pack(fill='x')
        tk.Label(f3, text='OUTPUT DIRECTORY', **lbl_style).pack(side='left')
        self.out = tk.StringVar(value=self._prefs.get('last_output', ''))
        tk.Entry(f3, textvariable=self.out, **entry_style).pack(side='left', fill='x', expand=True, padx=(0,10))
        tk.Button(f3, text='BROWSE', command=self._browse_out, **btn_style).pack(side='left')

        # Action Button
        gen_frame = tk.Frame(self, bg=self.BG, pady=20)
        gen_frame.pack(fill='x')
        self.gen_btn = tk.Button(gen_frame, text='GENERATE SECURITY ASSESSMENT', command=self._run_generate, 
                                 bg=self.ORG, fg='white', activebackground='#E63E00', activeforeground='white',
                                 font=('Arial', 12, 'bold'), padx=40, pady=12, relief='flat', cursor='hand2')
        self.gen_btn.pack()
        
        # Log Box with better contrast
        tk.Label(self, text='GENERATION LOG', bg=self.BG, fg=self.FG2, font=('Arial', 9, 'bold'), padx=40, anchor='w').pack(fill='x')
        self.log_box = scrolledtext.ScrolledText(self, height=12, bg=self.BG2, fg=self.FG, font=('Menlo', 10), relief='flat', padx=10, pady=10)
        self.log_box.pack(fill='both', expand=True, padx=40, pady=(5, 40))

    def _save_prefs(self):
        self._prefs['last_customer'] = self.cust.get()
        self._prefs['last_source'] = self.src.get()
        self._prefs['last_output'] = self.out.get()
        with open(self._prefs_file, 'w') as f: json.dump(self._prefs, f)

    def _browse_src(self):
        d = filedialog.askdirectory()
        if d: 
            self.src.set(d)
            if not self.out.get(): self.out.set(str(Path(d).parent))
            self._save_prefs()
    def _browse_out(self):
        d = filedialog.askdirectory()
        if d: 
            self.out.set(d)
            self._save_prefs()
    
    def _run_generate(self):
        self._save_prefs()
        threading.Thread(target=lambda: generate(self.src.get(), self.cust.get(), self.out.get(), self._log), daemon=True).start()

if __name__ == '__main__':
    App().mainloop()
