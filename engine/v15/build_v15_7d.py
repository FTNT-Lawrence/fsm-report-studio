#!/usr/bin/env python3
"""Build FortiSIEM 七日安全報告 v1.5 from v1.3 ECharts 7-day base + art brief."""
from __future__ import annotations
import json, os, re, pathlib
from datetime import datetime, timezone, timedelta

ENGINE = pathlib.Path(os.environ.get('FORTISIEM_ENGINE_DIR') or pathlib.Path(__file__).resolve().parents[1])
ROOT = pathlib.Path(os.environ.get('FORTISIEM_REPORT_ROOT') or ENGINE)
BASE = pathlib.Path(os.environ.get('FORTISIEM_BASE_HTML') or (ROOT / 'v15' / '_base_v13_7day.html'))
if not BASE.exists():
    BASE = ENGINE / 'v15' / '_base_v13_7day.html'
PULSE = json.loads((ROOT / 'fsm-v15-7d-data.json').read_text(encoding='utf-8'))
FULL = json.loads((ROOT / 'fsm-v15-7d-full-data.json').read_text(encoding='utf-8'))
OUT = pathlib.Path(os.environ.get('FORTISIEM_SIEM_DARK_OUT') or (ROOT / 'fortisiem-7day-report-v1.5.html'))
HKT = timezone(timedelta(hours=8))

def _span_zh_default():
    env = (os.environ.get('FORTISIEM_SPAN_ZH') or '').strip()
    if env:
        return env
    try:
        import sys
        sys.path.insert(0, str(ENGINE))
        from studio_lib import zh_day_phrase
        days = float(os.environ.get('FORTISIEM_REPORT_DAYS') or (FULL.get('meta') or {}).get('days') or 7)
        return zh_day_phrase(days)
    except Exception:
        return '七日'

SPAN_ZH = _span_zh_default()

def ms_to_hkt(ms):
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=HKT).strftime('%Y-%m-%d %H:%M HKT')
    except Exception:
        return '—'

# ---------- pick 5 flows from real 7d data ----------
pd = PULSE.get('data') or {}
fd = FULL.get('data') or {}
rules = {r.get('rule'): r for r in (fd.get('inc_top_rules') or pd.get('inc_top_rules') or []) if isinstance(r, dict)}
top_high = [r for r in (fd.get('inc_top_count_high') or []) if isinstance(r, dict)]

def rule_c(name):
    return int((rules.get(name) or {}).get('c') or 0)

def pick_high(substr):
    for r in top_high:
        t = (r.get('incident_title') or '') + ' ' + (r.get('rule') or '')
        if substr in t:
            return r
    return {}

def detail_last(d):
    if not isinstance(d, dict):
        return '—'
    hk = d.get('incidentLastSeen_hkt')
    if hk:
        s = str(hk)
        return s if 'HKT' in s else s + ' HKT'
    return ms_to_hkt(d.get('incidentLastSeen'))

rdp = pick_high('Remote Desktop from Internet')
stealth = pick_high('Stealth scanning tool')
zgrab = pick_high('ZGrab.Scanner')

def find_detail(*needles):
    for k, v in fd.items():
        if not (isinstance(k, str) and k.startswith('inc_') and k.endswith('_detail') and isinstance(v, dict)):
            continue
        blob = ' '.join(str(v.get(x) or '') for x in ('incidentTitle', 'incidentSrc', 'incidentTarget', 'incidentDetail'))
        if all(n.lower() in blob.lower() for n in needles):
            return v
    return {}

def parse_ip(blob, key):
    import re as _re
    m = _re.search(rf'{key}:([0-9.]+)', str(blob or ''))
    return m.group(1) if m else None

def parse_port(blob):
    import re as _re
    m = _re.search(r'destIpPort:(\d+)', str(blob or ''))
    return m.group(1) if m else None

def ips_from_title(title):
    import re as _re
    return _re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(title or ''))

clear_detail = (
    find_detail('cleartext')
    or find_detail('IMAP')
    or find_detail('port 143')
    or fd.get('inc_597294_detail')
    or fd.get('inc_597014_detail')
    or fd.get('inc_597007_detail')
    or {}
)
rdp_detail = (
    find_detail('Remote Desktop')
    or fd.get('inc_596701_detail')
    or {}
)

rdp_src = parse_ip(rdp_detail.get('incidentSrc'), 'srcIpAddr') or (ips_from_title(rdp.get('incident_title') or rdp_detail.get('incidentTitle')) or [None])[0] or '—'
rdp_dst = parse_ip(rdp_detail.get('incidentTarget'), 'destIpAddr') or (ips_from_title(rdp.get('incident_title') or rdp_detail.get('incidentTitle')) or [None, None])[-1] or '—'
clr_src = parse_ip(clear_detail.get('incidentSrc'), 'srcIpAddr') or '—'
clr_dst = parse_ip(clear_detail.get('incidentTarget'), 'destIpAddr') or '—'
clr_port = parse_port(clear_detail.get('incidentTarget')) or '143'
sth_ips = ips_from_title(stealth.get('incident_title'))
sth_src = sth_ips[0] if len(sth_ips) > 0 else '—'
sth_dst = sth_ips[1] if len(sth_ips) > 1 else '—'

risky = (PULSE.get('kpis') or {}).get('top_risky_devices') or []
risky_txt = ' / '.join(f"{r.get('ip')}（{r.get('score')}）" for r in risky[:3]) or '高風險設備'

FLOWS = [
  {
    'id': 'AF01',
    'sev': 'HIGH',
    'name': 'Remote Desktop from Internet',
    'title': 'Firewall · RDP from Internet',
    'count': int(rdp.get('incident_count') or 0),
    'last_seen': detail_last(rdp_detail) if rdp_detail else 'Open',
    'why': '七日內 incident_count 最高嘅 HIGH 事故；外網直連內網主機 RDP，屬初始存取／橫向移動風險。',
    'meta': '事故 #{} · {} · 規則 Firewall: Remote Desktop traffic from Internet'.format(
        rdp.get('incident_id') or '—', rdp.get('incident_title') or 'Remote Desktop from Internet'),
    'stages': [
      {'k': 'actor', 'label': f'SRC {rdp_src}', 'known': rdp_src != '—'},
      {'k': 'action', 'label': 'Internet ingress', 'known': True},
      {'k': 'host', 'label': 'FortiGate allow', 'known': True},
      {'k': 'action', 'label': 'RDP (3389)', 'known': True},
      {'k': 'target', 'label': f'DST {rdp_dst}', 'known': rdp_dst != '—'},
      {'k': 'action', 'label': 'Lateral / Persist', 'known': False},
    ],
  },
  {
    'id': 'AF02',
    'sev': 'MEDIUM',
    'name': f'Inbound cleartext IMAP :{clr_port}',
    'title': 'Inbound insecure protocol · IMAP',
    'count': rule_c('Inbound insecure protocol traffic detected'),
    'last_seen': detail_last(clear_detail) if clear_detail else 'Open',
    'why': f'風險設備 {risky_txt} 對外開明文 IMAP；多個外網來源用明文協定撞入。',
    'meta': '規則 Inbound insecure protocol traffic detected 七日合計 {} 宗 Open · 例 {}'.format(
        rule_c('Inbound insecure protocol traffic detected'),
        clear_detail.get('incidentTitle') or f'cleartext → :{clr_port}'),
    'stages': [
      {'k': 'actor', 'label': f'SRC {clr_src}', 'known': clr_src != '—'},
      {'k': 'action', 'label': 'Internet probe', 'known': True},
      {'k': 'host', 'label': 'PortMap / Mail path', 'known': True},
      {'k': 'action', 'label': 'IMAP cleartext', 'known': True},
      {'k': 'target', 'label': f'DST {clr_dst}:{clr_port}', 'known': clr_dst != '—'},
      {'k': 'action', 'label': 'Cred harvest', 'known': False},
    ],
  },
  {
    'id': 'AF03',
    'sev': 'HIGH',
    'name': 'Code Injection · NIPS',
    'title': 'Code Injection Attack detected by NIPS',
    'count': rule_c('Code Injection Attack detected by NIPS'),
    'last_seen': 'Open（規則合計，未抽單一 last_seen）',
    'why': '非噪音 Permit；NIPS 偵測到代碼注入，屬 exploit 階段，七日 HIGH 規則合計可觀。',
    'meta': '規則 Code Injection Attack detected by NIPS · HIGH {} 宗全部 Open'.format(
        rule_c('Code Injection Attack detected by NIPS')),
    'stages': [
      {'k': 'actor', 'label': 'External / internal SRC', 'known': False},
      {'k': 'action', 'label': 'Recon', 'known': False},
      {'k': 'action', 'label': 'Exploit / Inject', 'known': True},
      {'k': 'host', 'label': 'NIPS Detect', 'known': True},
      {'k': 'target', 'label': 'App / Host', 'known': False},
      {'k': 'action', 'label': 'Follow-on', 'known': False},
    ],
  },
  {
    'id': 'AF04',
    'sev': 'HIGH',
    'name': 'Stealth Scan using a tool',
    'title': 'Stealth scanning tool attack',
    'count': rule_c('Stealth Scan using a tool'),
    'last_seen': 'Open · 例 {} → {}'.format(sth_src, sth_dst),
    'why': '工具型隱蔽掃描；對 SIEM／內網主機持續探測，屬偵察階段可行動信號。',
    'meta': '規則 Stealth Scan using a tool 七日合計 {} 宗 · 頂部事故 incident_count={}'.format(
        rule_c('Stealth Scan using a tool'), int(stealth.get('incident_count') or 0)),
    'stages': [
      {'k': 'actor', 'label': f'SRC {sth_src}', 'known': sth_src != '—'},
      {'k': 'action', 'label': 'Stealth probe', 'known': True},
      {'k': 'host', 'label': 'Scan tool sig', 'known': True},
      {'k': 'target', 'label': f'DST {sth_dst}', 'known': sth_dst != '—'},
      {'k': 'action', 'label': 'Map services', 'known': False},
      {'k': 'action', 'label': 'Exploit prep', 'known': False},
    ],
  },
  {
    'id': 'AF05',
    'sev': 'HIGH',
    'name': 'ZGrab.Scanner Intrusion',
    'title': 'Intrusion Attacks · ZGrab.Scanner',
    'count': int(zgrab.get('incident_count') or 0),
    'last_seen': 'Open · status {}'.format(zgrab.get('status') or 'Open'),
    'why': '互聯網掃描器特徵（ZGrab）；反映對外暴露面被持續掃瞄，需核對是否預期資產。',
    'meta': '事故 #{} · {} · 規則 Intrusion Attacks Detected（規則級 {} 宗）'.format(
        zgrab.get('incident_id') or '—',
        zgrab.get('incident_title') or 'ZGrab.Scanner',
        rule_c('Intrusion Attacks Detected')),
    'stages': [
      {'k': 'actor', 'label': 'Internet scanner', 'known': False},
      {'k': 'action', 'label': 'ZGrab sweep', 'known': True},
      {'k': 'host', 'label': 'IPS / IDS hit', 'known': True},
      {'k': 'target', 'label': 'Exposed service', 'known': False},
      {'k': 'action', 'label': 'Fingerprint', 'known': True},
      {'k': 'action', 'label': 'Follow-on scan', 'known': False},
    ],
  },
]

FLOWS = [f for f in FLOWS if int(f.get('count') or 0) > 0]

def _generic_flow(r, sev=None):
    title = (r.get('incident_title') or r.get('rule') or r.get('name') or 'Incident').strip()
    sev = sev or r.get('severity_cat') or r.get('sev') or 'MEDIUM'
    cnt = int(r.get('incident_count') or r.get('c') or r.get('count') or 0)
    last = r.get('last_seen') or r.get('status') or 'Open'
    if isinstance(last, (int, float)):
        last = ms_to_hkt(last)
    return {
        'id': 'AF00', 'sev': str(sev).upper(), 'name': title, 'title': title, 'count': cnt,
        'last_seen': str(last), 'why': '由本期 incident 數據自動選入攻擊流程。',
        'meta': '事故 #{} · {}'.format(r.get('incident_id') or '—', title),
        'stages': [
            {'k': 'actor', 'label': 'SRC', 'known': False},
            {'k': 'action', 'label': 'Recon / Probe', 'known': False},
            {'k': 'action', 'label': 'Delivery / Exploit', 'known': True},
            {'k': 'host', 'label': 'Detect / Control', 'known': True},
            {'k': 'target', 'label': 'DST / Asset', 'known': False},
            {'k': 'action', 'label': 'Impact', 'known': False},
        ],
    }

if len(FLOWS) < 5:
    used = {f['name'] for f in FLOWS}
    pool = []
    for src in (top_high, fd.get('inc_top_titles') or [], pd.get('inc_top_titles') or [], fd.get('inc_top_rules') or []):
        for r in src or []:
            if isinstance(r, dict):
                pool.append(r)
    for r in pool:
        title = (r.get('incident_title') or r.get('rule') or '')
        if not title or title in used:
            continue
        used.add(title)
        FLOWS.append(_generic_flow(r))
        if len(FLOWS) >= 5:
            break
if len(FLOWS) < 5:
    raise SystemExit('need >=5 real flows, got %d' % len(FLOWS))
FLOWS = FLOWS[:5]
for i, f in enumerate(FLOWS):
    f['id'] = 'AF%02d' % (i + 1)

# persist selection into pulse for audit
PULSE.setdefault('attack_flows', FLOWS)
PULSE['meta']['report'] = 'fortisiem-7day-report-v1.5.html'
(ROOT / 'fsm-v15-7d-data.json').write_text(json.dumps(PULSE, indent=1, ensure_ascii=False, default=str), encoding='utf-8')
(ROOT / 'v15' / 'attack-flows-7d.json').write_text(json.dumps(FLOWS, indent=2, ensure_ascii=False, default=str), encoding='utf-8')

# ---------- SVG card builder ----------
EDGE = {
  'actor': '#7B61FF',
  'host': '#00E5FF',
  'action': '#FFB020',
  'target': '#FF4D6A',
}
CHIP = {
  'CRITICAL': '#FF4D6A',
  'CRIT': '#FF4D6A',
  'HIGH': '#FFB020',
  'MEDIUM': '#00E5FF',
  'MED': '#00E5FF',
  'LOW': '#6B7A8F',
}

def esc(s):
    return (str(s) if s is not None else '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')

def flow_svg(flow, idx):
    stages = flow['stages'][:6]
    n = len(stages)
    W, H = 980, 86
    pad = 18
    gap = 14
    node_h = 30
    usable = W - pad * 2 - gap * (n - 1)
    node_w = max(110, usable // n)
    # recompute to fit
    total = n * node_w + (n - 1) * gap
    if total > W - pad * 2:
        node_w = (W - pad * 2 - (n - 1) * gap) // n
        total = n * node_w + (n - 1) * gap
    start_x = pad + max(0, (W - pad * 2 - total) // 2)
    y = 28
    nodes = []
    arrows = []
    for i, st in enumerate(stages):
        x = start_x + i * (node_w + gap)
        color = EDGE.get(st['k'], '#00E5FF')
        known = st.get('known', True)
        dash = '' if known else 'stroke-dasharray="4 3"'
        opacity = '1' if known else '.7'
        nodes.append(
            f'<g class="fn" opacity="{opacity}">'
            f'<rect x="{x}" y="{y}" width="{node_w}" height="{node_h}" rx="8" fill="#1A2330" stroke="#243041" stroke-width="1"/>'
            f'<rect x="{x}" y="{y}" width="4" height="{node_h}" rx="2" fill="{color}"/>'
            f'<text x="{x + node_w/2}" y="{y + 20}" text-anchor="middle" fill="#E8EEF6" font-size="11" font-family="IBM Plex Sans,Segoe UI,sans-serif">{esc(st["label"])}</text>'
            f'</g>'
        )
        if i < n - 1:
            x1 = x + node_w + 2
            x2 = x + node_w + gap - 2
            mid = y + node_h / 2
            hl = color if known and stages[i + 1].get('known', True) else '#6B7A8F'
            arrows.append(
                f'<line class="farrow" x1="{x1}" y1="{mid}" x2="{x2}" y2="{mid}" stroke="{hl}" stroke-width="1.5" {dash} marker-end="url(#ah{idx})"/>'
            )
    return f'''<svg class="flow-svg" viewBox="0 0 {W} {H}" width="100%" height="{H}" role="img" aria-label="{esc(flow['name'])}">
  <defs>
    <marker id="ah{idx}" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
      <path d="M0,0 L6,3 L0,6 Z" fill="#6B7A8F"/>
    </marker>
  </defs>
  {''.join(arrows)}
  {''.join(nodes)}
</svg>'''

def flow_card(flow, idx):
    chip = CHIP.get(flow['sev'], '#6B7A8F')
    return f'''<article class="flow-card" data-sev="{esc(flow['sev'])}">
  <header class="flow-head">
    <span class="sev-chip" style="--chip:{chip}">{esc(flow['sev'])} <span class="mono">×{int(flow['count']):,}</span></span>
    <div class="flow-titles">
      <h3>{esc(flow['title'])}</h3>
      <div class="flow-sub mono">{esc(flow['name'])} · last {esc(flow['last_seen'])}</div>
    </div>
  </header>
  <div class="flow-body">{flow_svg(flow, idx)}</div>
  <footer class="flow-meta">{esc(flow['meta'])} · {esc(flow['why'])}</footer>
</article>'''

FLOWS_HTML = '\n'.join(flow_card(f, i) for i, f in enumerate(FLOWS))

ART_CSS = r'''
/* === v1.5 art brief overrides (青雅) === */
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');
:root{
  --bg:#0B0F14; --panel:#121820; --panel2:#1A2330; --line:#243041;
  --ink:#E8EEF6; --ink2:#9AA8BC; --mut:#6B7A8F;
  --cyan:#00E5FF; --violet:#7B61FF; --amber:#FFB020; --red:#FF4D6A; --ok:#3DDC97;
  --sans:"IBM Plex Sans","Segoe UI",system-ui,sans-serif;
  --mono:"IBM Plex Mono","JetBrains Mono",ui-monospace,monospace;
  --num:"IBM Plex Mono","JetBrains Mono",ui-monospace,monospace;
  --head:"IBM Plex Sans","Segoe UI",system-ui,sans-serif;
}
body{font-family:var(--sans);background:
  radial-gradient(1000px 500px at 90% -10%,rgba(0,229,255,.05),transparent 55%),
  radial-gradient(800px 500px at -5% 10%,rgba(123,97,255,.04),transparent 55%),
  linear-gradient(rgba(0,229,255,.025) 1px,transparent 1px) 0 0/48px 48px,
  linear-gradient(90deg,rgba(0,229,255,.025) 1px,transparent 1px) 0 0/48px 48px,var(--bg)!important}
body:after{opacity:.35;background:repeating-linear-gradient(0deg,rgba(255,255,255,.012) 0 1px,transparent 1px 4px)}
nav{background:rgba(11,15,20,.9)!important;border-bottom-color:var(--line)!important}
nav .brand{letter-spacing:.08em}
nav a.active{background:linear-gradient(90deg,#00E5FF,#2a7fff)!important;color:#041018!important;box-shadow:0 0 0 1px #00E5FF33}
.card,.stat,.find,.case{background:var(--line)!important}
.card:before,.stat:before,.find:before,.case:before{background:linear-gradient(180deg,#161E28 0%,#0F141C 100%)!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.06)}
.stat{position:relative}
.stat .bar{height:1px!important;opacity:.7}
.stat .v{font-family:var(--num)!important;font-variant-numeric:tabular-nums;font-size:34px!important;animation:kpiIn .18s ease both}
.stat .d{font-family:var(--mono);color:var(--mut)!important}
.stat .spark{position:absolute;left:12px;right:12px;bottom:8px;height:24px;opacity:.9;pointer-events:none}
@keyframes kpiIn{from{opacity:0}to{opacity:1}}
.hero-main{background:linear-gradient(180deg,#161E28 0%,#0F141C 100%)!important;border-left-color:#00E5FF!important}
.hero-main:before{opacity:.35}
.hero-main .eyebrow .vtag{display:inline-block;margin-left:10px;padding:2px 8px;border:1px solid #243041;color:#00E5FF;font-family:var(--mono);font-size:11px;letter-spacing:.08em;text-transform:uppercase}
.industrial{font:600 12px var(--sans);letter-spacing:.08em;text-transform:uppercase;color:#9AA8BC}
section.active-sec,.sec-head:target{outline:none}
section:target .sec-head,section.in-view .sec-head{box-shadow:inset 3px 0 0 #00E5FF33}
/* Attack Flows — art brief aligned, normal title */
#flows{padding-top:8px}
#flows .flows-head{margin:0 0 14px;padding:14px 16px;background:linear-gradient(180deg,#161E28 0%,#0F141C 100%);border:1px solid #243041;box-shadow:inset 0 1px 0 rgba(255,255,255,.06);border-top:1px solid rgba(0,229,255,.7)}
#flows .flows-title{margin:6px 0 8px;font:600 22px/1.25 var(--sans);color:#E8EEF6;letter-spacing:0}
#flows .flows-lead{margin:0;font:14px/1.55 var(--sans);color:#9AA8BC;max-width:920px}
#flows .flows-lead .leg{display:inline-block;margin:0 6px 0 2px;padding:1px 8px;border:1px solid #243041;background:#1A2330;font:600 11px var(--mono);color:#E8EEF6;vertical-align:middle}
#flows .flows-lead .leg.actor{border-left:3px solid #7B61FF}
#flows .flows-lead .leg.host{border-left:3px solid #00E5FF}
#flows .flows-lead .leg.action{border-left:3px solid #FFB020}
#flows .flows-lead .leg.target{border-left:3px solid #FF4D6A}
#flows .flow-grid{display:grid;grid-template-columns:1fr;gap:14px}
.flow-filters{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:0 0 14px;padding:10px 14px;background:linear-gradient(180deg,#161E28,#0F141C);border:1px solid #243041;box-shadow:inset 0 1px 0 rgba(255,255,255,.06)}
.flow-filters label{font:600 12px var(--sans);letter-spacing:.08em;text-transform:uppercase;color:#9AA8BC}
.flow-filters select{background:#1A2330;border:1px solid #243041;color:#E8EEF6;font:12px var(--mono);padding:6px 10px}
.flow-card{background:linear-gradient(180deg,#161E28 0%,#0F141C 100%);border:1px solid #243041;box-shadow:inset 0 1px 0 rgba(255,255,255,.06);padding:14px 16px 12px;min-height:150px;position:relative}
.flow-card:before{content:"";position:absolute;left:0;right:0;top:0;height:1px;background:#00E5FF;opacity:.7}
.flow-card[data-sev="HIGH"]:before,.flow-card[data-sev="CRITICAL"]:before{background:#FFB020}
.flow-card[data-sev="MEDIUM"]:before{background:#00E5FF}
.flow-card[data-sev="LOW"]:before{background:#6B7A8F}
.flow-head{display:flex;gap:14px;align-items:flex-start;margin-bottom:6px}
.sev-chip{flex:none;font:700 11px var(--mono);letter-spacing:.04em;padding:4px 10px;border:1px solid var(--chip,#6B7A8F);color:var(--chip,#6B7A8F);background:color-mix(in srgb,var(--chip,#6B7A8F) 12%,transparent)}
.sev-chip .mono{opacity:.95;color:#E8EEF6}
.flow-titles h3{margin:0;font:600 16px/1.3 var(--sans);color:#E8EEF6}
.flow-sub{font-size:11.5px;color:#6B7A8F;margin-top:2px}
.flow-body{margin:4px 0}
.flow-svg .farrow{stroke-dasharray:6 4;animation:dashmove 3s ease-in-out infinite}
@keyframes dashmove{to{stroke-dashoffset:-24}}
.flow-meta{font-size:12px;color:#6B7A8F;border-top:1px solid #243041;padding-top:8px;margin-top:4px;line-height:1.45}
.flow-card.is-hidden{display:none}
'''

# Injection JS that runs after main render — safer than splicing huge template literals
INJECT_JS = r'''
(function(){
  // scrub hero: no supervisor IP / READ-ONLY chip dominance
  try{
    document.querySelectorAll('.hero-meta').forEach(el=>{
      el.textContent = el.textContent
        .replace(/\s*·\s*https?:\/\/[0-9.]+[^\s·]*/g,'')
        .replace(/\s*·\s*經 FortiSIEM MCP 唯讀查詢/g,' · FortiSIEM MCP')
        .replace(/READ-ONLY/g,'pulse');
    });
    document.querySelectorAll('.chip').forEach(el=>{
      const t=el.textContent||'';
      if(/Read-only|唯讀 Read-only|READ-ONLY/i.test(t)) el.remove();
    });
    document.querySelectorAll('.eyebrow').forEach(el=>{
      if(!el.querySelector('.vtag')){
        const tag=document.createElement('span');
        tag.className='vtag';
        tag.textContent='v1.5 · 7D';
        el.appendChild(tag);
      }
    });
    document.querySelectorAll('.hero-main h1').forEach(el=>{
      // soften sensational absolute wording if any
      el.innerHTML = el.innerHTML.replace(/XX萬筆|九成九/g,'');
    });
  }catch(e){}

  // KPI sparklines from daily events
  try{
    const raw=JSON.parse(document.getElementById('data').textContent);
    const days=(raw.data.ev_per_day||[]).map(d=>+d.c||0);
    if(days.length){
      const max=Math.max(...days,1);
      document.querySelectorAll('.stat').forEach((el,i)=>{
        if(el.querySelector('.spark')) return;
        const ns='http://www.w3.org/2000/svg';
        const svg=document.createElementNS(ns,'svg');
        svg.setAttribute('class','spark');
        svg.setAttribute('viewBox','0 0 100 24');
        svg.setAttribute('preserveAspectRatio','none');
        const w=100/(days.length-1||1);
        let pts=days.map((v,i)=>`${(i*w).toFixed(2)},${(24-(v/max)*20-2).toFixed(2)}`).join(' ');
        const area=document.createElementNS(ns,'polygon');
        area.setAttribute('points', `0,24 ${pts} 100,24`);
        area.setAttribute('fill','#00E5FF');
        area.setAttribute('fill-opacity','0.08');
        const poly=document.createElementNS(ns,'polyline');
        poly.setAttribute('points', pts);
        poly.setAttribute('fill','none');
        poly.setAttribute('stroke','#00E5FF');
        poly.setAttribute('stroke-width','1.2');
        poly.style.strokeDasharray='120';
        poly.style.strokeDashoffset='120';
        poly.style.animation='sparkDraw .4s ease forwards';
        svg.appendChild(area); svg.appendChild(poly);
        el.appendChild(svg);
      });
      const st=document.createElement('style');
      st.textContent='@keyframes sparkDraw{to{stroke-dashoffset:0}}';
      document.head.appendChild(st);
    }
  }catch(e){}

  // Attack Flows section
  const deep=document.getElementById('deep');
  const findings=document.getElementById('findings');
  if(!document.getElementById('flows') && findings){
    const sec=document.createElement('section');
    sec.id='flows';
    sec.innerHTML = `FLOW_SECTION_PLACEHOLDER`;
    findings.parentNode.insertBefore(sec, findings);
    // filter
    const sevSel=sec.querySelector('#flowSev');
    const apply=()=>{
      const v=sevSel.value;
      sec.querySelectorAll('.flow-card').forEach(c=>{
        c.classList.toggle('is-hidden', v!=='ALL' && c.getAttribute('data-sev')!==v);
      });
    };
    if(sevSel) sevSel.addEventListener('change', apply);
  }

  // active section border hint
  try{
    const secs=[...document.querySelectorAll('section[id]')];
    const io=new IntersectionObserver(entries=>{
      entries.forEach(en=>{ if(en.isIntersecting){ secs.forEach(s=>s.classList.remove('in-view')); en.target.classList.add('in-view'); }});
    },{threshold:0.18});
    secs.forEach(s=>io.observe(s));
  }catch(e){}
})();
'''

FLOW_SECTION = f'''
<div class="flows-head">
  <div class="industrial">Attack flows · 7 day</div>
  <h2 class="flows-title">攻擊流程</h2>
  <p class="flows-lead">{SPAN_ZH}內 5 個具保安意義嘅攻擊／鏈路。虛線節點 = 數據未直接觀測到嘅階段。節點色：<span class="leg actor">actor</span> <span class="leg host">host</span> <span class="leg action">action</span> <span class="leg target">target</span>。</p>
</div>
<div class="flow-filters">
  <label>篩選</label>
  <select id="flowSev"><option value="ALL">全部嚴重度</option><option value="HIGH">HIGH</option><option value="MEDIUM">MEDIUM</option><option value="LOW">LOW</option></select>
  <span class="industrial">窗口 · 近 {SPAN_ZH} · HKT</span>
</div>
<div class="flow-grid">
{FLOWS_HTML}
</div>
'''

# escape for JS template literal
flow_section_js = json.dumps(FLOW_SECTION)
inject = INJECT_JS.replace('`FLOW_SECTION_PLACEHOLDER`', flow_section_js)

html = BASE.read_text(encoding='utf-8')

# Title / brand / nav
html = html.replace(
    '<title>FortiSIEM 安全回顧 · v1.3</title>',
    f'<title>FortiSIEM {SPAN_ZH}安全報告 · v1.5</title>',
)
html = html.replace(
    'FORTI<em>SIEM</em> // 週報',
    f'FORTI<em>SIEM</em> // {SPAN_ZH} · v1.5',
)
# insert nav link before findings
html = html.replace(
    '<a href="#findings">發現與建議</a>',
    '<a href="#flows">攻擊流程</a><a href="#findings">發現與建議</a>',
)

# Hero title: FortiSIEM {N}日安全報告
html = html.replace(
    '<h1>${SPAN} <span class="hl">${wan(T.events||0)}</span> 筆事件，<br>${esc(X.fam||"—")} 告警佔咗<span class="hl">${esc(X.fam_pct_zh||"—")}</span>事故</h1>',
    '<h1>FortiSIEM ${SPAN}安全報告</h1>',
)
html = html.replace(
    '<title>FortiSIEM 五日保安態勢報告 · v1.5</title>',
    f'<title>FortiSIEM {SPAN_ZH}安全報告 · v1.5</title>',
)

# Soften hero JS strings: remove supervisor from meta template & readonly chip
html = html.replace(
    ' · ${esc(M.supervisor)} · 經 FortiSIEM MCP 唯讀查詢',
    ' · FortiSIEM MCP',
)
html = html.replace(
    '<span class="chip"><i style="background:#ffb000"></i>唯讀 Read-only</span>',
    '',
)
html = html.replace(
    ' --mode READ-ONLY`)}"',
    ' --mode pulse`)}"',
)

# Fallback 七日 → 五日 (span_zh already 5 日)
html = html.replace("X.span_zh||'七日'", f"X.span_zh||'{SPAN_ZH}'")

# Theme meta bump inside embedded JSON if present
html = html.replace('"theme": "v1.3"', '"theme": "v1.5"')
html = html.replace('"theme":"v1.3"', '"theme":"v1.5"')

# Inject art CSS before </style> of main (first </style>)
html = html.replace('</style>', ART_CSS + '\n</style>', 1)

# Inject runtime only before the FINAL </body> (echarts contains '</body>' strings)
_inj = '<script>\n' + inject + '\n</script>\n'
_i = html.rfind('</body>')
if _i < 0:
    raise SystemExit('no </body> in base HTML')
html = html[:_i] + _inj + html[_i:]

# Scrub remaining obvious supervisor host from visible hero-only contexts is handled in JS;
# also scrub ticker command if it echoes supervisor — leave data JSON intact for appendix honesty? User said no on hero.
# Remove supervisor field from meta in embedded JSON to avoid accidental display
html = re.sub(r',?\s*"supervisor"\s*:\s*"[^"]*"', '', html)
html = html.replace('165.84.173.36', '')
_host = (os.environ.get('FORTISIEM_HOST') or '').strip()
if _host:
    import re as _re
    bare = _re.sub(r'^https?://', '', _host, flags=_re.I).split('/')[0]
    if bare:
        html = html.replace(bare, '').replace(_host, '')
    html = html.replace('https:///', 'https://')
# Narrative 七日 → requested span (FLOWS why / meta text)
if SPAN_ZH != '七日':
    html = html.replace('七日', SPAN_ZH)

if OUT.exists() or OUT.is_symlink():
    OUT.unlink()
OUT.write_text(html, encoding='utf-8')

# sanity
text = OUT.read_text(encoding='utf-8')
assert 'v1.5' in text
assert '攻擊流程' in text
assert SPAN_ZH in text or '安全報告' in text
assert any(f.get('name') for f in FLOWS)
# hero should not prominently show IP after our scrub of meta supervisor in first occurrence;
# JS also strips. Allow IP only if buried in data tables.
print('Wrote', OUT, OUT.stat().st_size)
print('is_symlink', OUT.is_symlink())
k = PULSE.get('kpis') or {}
print('KPIs events', k.get('total_events'), 'open', k.get('incidents_open'), 'by_sev', k.get('incidents_by_sev'))
print('Flows:')
for f in FLOWS:
    print(' -', f['sev'], f['name'], 'count=', f['count'])
print('pulse errors', len(PULSE.get('errors') or []))
print('full sources failed', sum(1 for s in (FULL.get('sources') or []) if not s.get('ok')))
