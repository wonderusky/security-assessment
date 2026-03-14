#!/opt/homebrew/bin/python3
"""
PAN Security Assessment Generator — GUI App
Parses CSVs in Python, hands off to Node.js for fast DOCX generation.
Run: python3 pan_assessment_app.py
"""
import csv, re, os, sys, json, subprocess, threading, datetime, tempfile, tarfile
from collections import defaultdict
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

SKIP_ZONES  = {'untrust', 'guest', 'Guest'}
DNS_HIT_MIN = 5000
DNS_DOM_MIN = 10

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
        # Collect subtype values from data rows
        subtypes = set()
        for row in rows[1:]:
            if len(row) > 4:
                subtypes.add(row[4].strip().lower())
        if subtypes & {'spyware', 'vulnerability', 'virus', 'wildfire-virus', 'file'}:
            return 'threat'
        if subtypes & {'start', 'end', 'drop', 'deny', 'allow'}:
            return 'traffic'
        # Fallback: check header keywords
        if any(k in header for k in ['threat', 'severity', 'attack']):
            return 'threat'
        if any(k in header for k in ['bytes', 'dest port', 'natdport']):
            return 'traffic'
        return 'unknown'
    except Exception as e:
        return f'error({e})'

def sniff_statsdump(path):
    """Return True if file is a tar archive containing statsdump data."""
    try:
        if not tarfile.is_tarfile(path): return False
        with tarfile.open(path, 'r:*') as t:
            names = t.getnames()
        return any(
            any(k in n.lower() for k in ['stat', 'dump', 'mp_', 'counter', 'system'])
            for n in names
        )
    except:
        return False

def sniff_pdf_slr(path):
    """Return True if file is a PDF (SLR report)."""
    try:
        with open(path, 'rb') as f:
            return f.read(4) == b'%PDF'
    except:
        return False

def preflight(directory, log):
    """
    Scan directory for all 4 required files by content, not just name.
    Returns dict: {'threat': path|None, 'traffic': path|None,
                   'statsdump': path|None, 'slr': path|None}
    Logs a clear status line for each file.
    """
    log('━' * 52)
    log('  PRE-FLIGHT CHECK')
    log('━' * 52)

    found = {'threat': None, 'traffic': None, 'statsdump': None, 'slr': None}
    candidates = {'threat': [], 'traffic': [], 'statsdump': [], 'slr': []}

    try:
        all_files = [f for f in os.listdir(directory)
                     if os.path.isfile(os.path.join(directory, f))
                     and not f.startswith('.')]
    except Exception as e:
        log(f'  ✘ Cannot read directory: {e}')
        return found

    for fname in all_files:
        fpath = os.path.join(directory, fname)
        ext   = os.path.splitext(fname)[1].lower()

        if ext == '.csv':
            kind = sniff_csv(fpath)
            if kind == 'threat':
                candidates['threat'].append((fname, fpath))
            elif kind == 'traffic':
                candidates['traffic'].append((fname, fpath))
            else:
                # Unknown CSV — try harder using filename hints
                nl = fname.lower()
                if any(k in nl for k in ['threat', 'alert', 'security']):
                    candidates['threat'].append((fname, fpath))
                elif any(k in nl for k in ['traffic', 'flow', 'session']):
                    candidates['traffic'].append((fname, fpath))

        elif ext in ('.tgz', '.tar', '.gz', '.zip'):
            if sniff_statsdump(fpath):
                candidates['statsdump'].append((fname, fpath))

        elif ext == '.pdf':
            if sniff_pdf_slr(fpath):
                candidates['slr'].append((fname, fpath))

    # Pick best candidate for each type (first match wins)
    for key in ('threat', 'traffic', 'statsdump', 'slr'):
        if candidates[key]:
            found[key] = candidates[key][0][1]

    # ── Log results ──────────────────────────────────────────────────────────
    checks = [
        ('threat',    'Threat Logs CSV',   True),
        ('traffic',   'Traffic Logs CSV',  False),
        ('statsdump', 'Statsdump Archive', False),
        ('slr',       'SLR PDF Report',    False),
    ]
    all_ok   = True
    warnings = []
    for key, label, required in checks:
        path = found[key]
        if path:
            fname = os.path.basename(path)
            log(f'  ✔  {label:<22} {fname}')
        else:
            if required:
                log(f'  ✘  {label:<22} NOT FOUND  ← REQUIRED')
                all_ok = False
            else:
                log(f'  ⚠  {label:<22} not found (optional)')
                warnings.append(label)

    log('━' * 52)
    if not all_ok:
        log('  CANNOT PROCEED — missing required files.')
        log('  Add the missing file(s) and try again.')
    elif warnings:
        log(f'  Ready — {len(warnings)} optional file(s) missing.')
        log('  Report will use available data only.')
    else:
        log('  All files verified. Ready to generate.')
    log('')

    return found if all_ok else None

# ═══════════════════════════════════════════════════════════════════════════════
# DATA PARSING
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
            subtype  = row[4].strip()
            src_ip   = row[7].strip()
            src_user = row[12].strip()
            src_zone = row[16].strip()
            threat   = row[32].strip()
            severity = row[34].strip()
            action   = row[21].strip() if len(row) > 21 else ''
            dst_ip   = row[8].strip()  if len(row) > 8  else ''
            if src_zone in SKIP_ZONES: continue
            if subtype == 'spyware':
                spyware.append((src_ip, src_user, src_zone, threat, severity))
            elif subtype == 'vulnerability':
                vulns.append((src_ip, src_user, src_zone, threat, severity, action, dst_ip))
    log(f'    Spyware: {len(spyware):,}  |  Vulnerability: {len(vulns):,}')
    return spyware, vulns

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
            infected[ip] = {'hits': hits, 'zone': ip_zone[ip],
                            'users': ', '.join(sorted(ip_users[ip])) or '—', 'unique': ud}
    top_doms = sorted(dom_hits.items(), key=lambda x: -x[1])[:10]
    top_ips  = sorted(infected.items(),  key=lambda x: -x[1]['hits'])[:10]
    log(f'    DNS resolvers: {len(dns)}  |  Infected IPs: {len(infected)}')
    return dns, infected, top_doms, dom_tids, top_ips

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
                    flows.append({'src_ip': src_ip, 'app': app, 'src_zone': sz, 'dst_zone': dz})
                    seen.add(key)
                    if len(flows) >= 6: break
    except Exception as e:
        log(f'  Warning: traffic CSV parse error: {e}')
    log(f'    SMB cross-zone samples: {len(flows)}')
    return flows

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN GENERATE
# ═══════════════════════════════════════════════════════════════════════════════
def generate(source_dir, customer_name, output_dir, log):
    # ── Pre-flight ────────────────────────────────────────────────────────────
    files = preflight(source_dir, log)
    if files is None:
        raise ValueError('Pre-flight failed — missing required files. See log above.')

    threat_csv  = files['threat']
    traffic_csv = files['traffic']

    # ── Parse ─────────────────────────────────────────────────────────────────
    log('Parsing data...')
    sp, vu = load_threat_csv(threat_csv, log)
    dns, infected, top_doms, dom_tids, top_ips = analyze_spyware(sp, log)
    smb = load_smb(traffic_csv, log)

    # ── Build JSON payload for Node ───────────────────────────────────────────
    data = {
        'customerName':  customer_name,
        'month':         datetime.datetime.now().strftime('%B %Y'),
        'totalRows':     len(sp) + len(vu),
        'spywareCount':  len(sp),
        'vulnCount':     len(vu),
        'infectedCount': len(infected),
        'dnsResolvers': [{'ip': ip, 'zone': d['zone'], 'hits': d['hits'], 'unique': d['unique']}
                         for ip, d in dns.items()],
        'topDomains':   [{'domain': dom, 'hits': hits, 'tid': dom_tids.get(dom, '')}
                         for dom, hits in top_doms],
        'topIPs':       [{'ip': ip, 'zone': d['zone'], 'hits': d['hits'],
                          'unique': d['unique'], 'users': d['users']}
                         for ip, d in top_ips],
        'smbFlows':     smb,
        'vulnEvents':   [{'src_ip': r[0], 'user': r[1], 'zone': r[2],
                          'threat': r[3], 'severity': r[4],
                          'action': r[5] if len(r) > 5 else '',
                          'dst_ip': r[6] if len(r) > 6 else ''}
                         for r in vu],
    }

    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(data, tmp, indent=2); tmp.close()

    # ── Output path ───────────────────────────────────────────────────────────
    safe  = re.sub(r'[^a-zA-Z0-9_\-]', '_', customer_name)
    month = datetime.datetime.now().strftime('%B%Y')
    fname = f'{safe}_Security_Assessment_{month}.docx'
    out_path = os.path.join(output_dir, fname)

    # ── Call Node.js ──────────────────────────────────────────────────────────
    gen_js = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gen_report.js')
    log(f'Building document...')
    result = subprocess.run(
        ['/opt/homebrew/bin/node', gen_js, tmp.name, out_path],
        capture_output=True, text=True, timeout=120
    )
    os.unlink(tmp.name)

    if result.returncode != 0:
        raise RuntimeError(f'Node.js error: \n{result.stderr[:500]}')

    log(f'\n✔  {result.stdout.strip()}')
    log(f'✅ Saved: {out_path}')
    return out_path

# ═══════════════════════════════════════════════════════════════════════════════
# PREFS — persist last output dir
# ═══════════════════════════════════════════════════════════════════════════════
PREFS_FILE = os.path.expanduser('~/.pan_assessment_prefs.json')

def load_prefs():
    try:
        return json.load(open(PREFS_FILE))
    except:
        return {}

def save_prefs(prefs):
    try:
        json.dump(prefs, open(PREFS_FILE, 'w'), indent=2)
    except:
        pass

# ═══════════════════════════════════════════════════════════════════════════════
# GUI
# ═══════════════════════════════════════════════════════════════════════════════
class App(tk.Tk):
    BG   = '#1a1a1a'
    BG2  = '#252525'
    BG3  = '#2e2e2e'
    FG   = '#ffffff'
    ORG  = '#FA4616'
    GRAY = '#aaaaaa'
    GRN  = '#00ff88'
    RED  = '#ff4444'

    def __init__(self):
        super().__init__()
        self.title('PAN Security Assessment Generator')
        self.geometry('760x620')
        self.resizable(True, True)
        self.configure(bg=self.BG)
        self._prefs = load_prefs()
        self._build()

    def _lbl(self, parent, text, **kw):
        return tk.Label(parent, text=text, bg=self.BG, fg=self.FG,
                        font=('Arial', 11), **kw)

    def _entry(self, parent, var):
        return tk.Entry(parent, textvariable=var, font=('Arial', 10),
                        bg=self.BG2, fg=self.FG, insertbackground=self.FG,
                        relief='flat', highlightthickness=1,
                        highlightcolor=self.ORG, highlightbackground='#444')

    def _browse_btn(self, parent, cmd):
        return tk.Button(parent, text='Browse', command=cmd,
                         bg=self.ORG, fg=self.FG, font=('Arial', 10, 'bold'),
                         relief='flat', padx=10, cursor='hand2',
                         activebackground='#d43a10', activeforeground=self.FG)

    def _build(self):
        PAD = 16

        # Title
        tk.Label(self, text='PAN Security Assessment Generator',
                 bg=self.BG, fg=self.ORG,
                 font=('Arial', 16, 'bold')).pack(pady=(PAD, 2))
        tk.Label(self, text='Palo Alto Networks  ·  No LLM  ·  Local CSV → DOCX',
                 bg=self.BG, fg=self.GRAY,
                 font=('Arial', 10)).pack(pady=(0, PAD - 4))

        # ── Row: Customer Name ────────────────────────────────────────────────
        r1 = tk.Frame(self, bg=self.BG); r1.pack(fill='x', padx=PAD, pady=4)
        self._lbl(r1, 'Customer Name:', width=16, anchor='w').pack(side='left')
        self.cust = tk.StringVar(value='IDEX Corp')
        self._entry(r1, self.cust).pack(side='left', fill='x', expand=True)

        # ── Row: Source Folder ────────────────────────────────────────────────
        r2 = tk.Frame(self, bg=self.BG); r2.pack(fill='x', padx=PAD, pady=4)
        self._lbl(r2, 'Source Folder:', width=16, anchor='w').pack(side='left')
        self.src = tk.StringVar()
        self._entry(r2, self.src).pack(side='left', fill='x', expand=True, padx=(0, 8))
        self._browse_btn(r2, self._browse_src).pack(side='left')

        # ── Row: Output Folder ────────────────────────────────────────────────
        r3 = tk.Frame(self, bg=self.BG); r3.pack(fill='x', padx=PAD, pady=4)
        self._lbl(r3, 'Output Folder:', width=16, anchor='w').pack(side='left')
        self.out = tk.StringVar(value=self._prefs.get('last_output_dir', ''))
        self._entry(r3, self.out).pack(side='left', fill='x', expand=True, padx=(0, 8))
        self._browse_btn(r3, self._browse_out).pack(side='left')

        # ── Hint ──────────────────────────────────────────────────────────────
        tk.Label(self,
                 text='Source folder needs: Threat Logs CSV (required), Traffic Logs CSV, Statsdump archive, SLR PDF',
                 bg=self.BG, fg=self.GRAY,
                 font=('Arial', 9), wraplength=720).pack(pady=(2, 8))

        # ── Buttons row ───────────────────────────────────────────────────────
        btn_row = tk.Frame(self, bg=self.BG); btn_row.pack(pady=(0, 10))

        self.preflight_btn = tk.Button(
            btn_row, text='🔍  Check Files', command=self._run_preflight,
            bg=self.BG3, fg=self.FG, font=('Arial', 11, 'bold'),
            relief='flat', padx=18, pady=8, cursor='hand2',
            activebackground='#3a3a3a', activeforeground=self.FG)
        self.preflight_btn.pack(side='left', padx=(0, 12))

        self.gen_btn = tk.Button(
            btn_row, text='⚡  Generate Report', command=self._run_generate,
            bg=self.ORG, fg=self.FG, font=('Arial', 13, 'bold'),
            relief='flat', padx=24, pady=8, cursor='hand2',
            activebackground='#d43a10', activeforeground=self.FG)
        self.gen_btn.pack(side='left')

        # ── Status / Log ──────────────────────────────────────────────────────
        self.log_box = scrolledtext.ScrolledText(
            self, height=16, font=('Courier New', 9),
            bg='#0d1117', fg=self.GRN,
            insertbackground=self.GRN, relief='flat',
            state='disabled')
        self.log_box.pack(fill='both', expand=True, padx=PAD, pady=(0, PAD))

        # colour tags for log
        self.log_box.tag_config('ok',   foreground=self.GRN)
        self.log_box.tag_config('warn', foreground='#ffcc00')
        self.log_box.tag_config('err',  foreground=self.RED)
        self.log_box.tag_config('head', foreground='#ffffff')

    # ── Browse helpers ────────────────────────────────────────────────────────
    def _browse_src(self):
        d = filedialog.askdirectory(title='Select Source Folder')
        if not d: return
        self.src.set(d)
        # Auto-set output to parent of source if nothing saved
        if not self.out.get().strip():
            self.out.set(str(Path(d).parent))
        # Auto-detect customer name
        skip = {'source', 'src', 'data', 'logs', 'qbr', '2025', '2026'}
        for part in reversed(Path(d).parts):
            if part.lower() not in skip and not re.match(r'^\d{4}$', part) and len(part) > 2:
                self.cust.set(part); break

    def _browse_out(self):
        d = filedialog.askdirectory(title='Select Output Folder')
        if d: 
            self.out.set(d)
            self._prefs['last_output_dir'] = d
            save_prefs(self._prefs)

    # ── Logging ───────────────────────────────────────────────────────────────
    def _log(self, msg, tag=None):
        self.log_box.configure(state='normal')
        if tag is None:
            # Auto-colour based on content
            if msg.startswith('  ✔') or msg.startswith('✅'):
                tag = 'ok'
            elif msg.startswith('  ✘') or msg.startswith('❌'):
                tag = 'err'
            elif msg.startswith('  ⚠'):
                tag = 'warn'
            elif msg.startswith('━') or 'PRE-FLIGHT' in msg:
                tag = 'head'
        self.log_box.insert('end', msg + '\n', tag or '')
        self.log_box.see('end')
        self.log_box.configure(state='disabled')
        self.update_idletasks()

    def _clear_log(self):
        self.log_box.configure(state='normal')
        self.log_box.delete('1.0', 'end')
        self.log_box.configure(state='disabled')

    # ── Validate inputs ───────────────────────────────────────────────────────
    def _validate(self):
        src  = self.src.get().strip()
        out  = self.out.get().strip()
        name = self.cust.get().strip()
        if not src or not os.path.isdir(src):
            messagebox.showerror('Error', 'Please select a valid source folder.'); return None
        if not out:
            messagebox.showerror('Error', 'Please select an output folder.'); return None
        if not os.path.isdir(out):
            try: os.makedirs(out)
            except Exception as e:
                messagebox.showerror('Error', f'Cannot create output folder: \n{e}'); return None
        if not name:
            messagebox.showerror('Error', 'Please enter a customer name.'); return None
        return src, out, name

    # ── Check Files button ────────────────────────────────────────────────────
    def _run_preflight(self):
        vals = self._validate()
        if not vals: return
        src, out, name = vals
        self._clear_log()
        self.preflight_btn.configure(state='disabled', text='Checking...')
        def worker():
            preflight(src, self._log)
            self.after(0, lambda: self.preflight_btn.configure(
                state='normal', text='🔍  Check Files'))
        threading.Thread(target=worker, daemon=True).start()

    # ── Generate button ───────────────────────────────────────────────────────
    def _run_generate(self):
        vals = self._validate()
        if not vals: return
        src, out, name = vals
        # Save output dir preference
        self._prefs['last_output_dir'] = out
        save_prefs(self._prefs)
        self._clear_log()
        self.gen_btn.configure(state='disabled', text='Generating...')
        self.preflight_btn.configure(state='disabled')
        def worker():
            try:
                path = generate(src, name, out, self._log)
                self.after(0, lambda: self._done(path))
            except Exception as e:
                self.after(0, lambda: self._err(str(e)))
        threading.Thread(target=worker, daemon=True).start()

    def _done(self, path):
        self.gen_btn.configure(state='normal', text='⚡  Generate Report')
        self.preflight_btn.configure(state='normal')
        os.system(f'open "{os.path.dirname(path)}"')
        if messagebox.askyesno('Done', f'Report saved: \n{path}\n\nOpen now?'):
            os.system(f'open "{path}"')

    def _err(self, msg):
        self.gen_btn.configure(state='normal', text='⚡  Generate Report')
        self.preflight_btn.configure(state='normal')
        self._log(f'❌ ERROR: {msg}', 'err')
        messagebox.showerror('Error', msg)


if __name__ == '__main__':
    App().mainloop()
