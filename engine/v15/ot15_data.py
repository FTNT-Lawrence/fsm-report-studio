#!/usr/bin/env python3
"""Data-driven payload, findings, flows and stories for the OT 1.5 3-day report."""
from __future__ import annotations

import os
import json
import re
from collections import Counter
from datetime import datetime, timezone, timedelta

HKT = timezone(timedelta(hours=8))

SIMULATED_CMDB = {
    's1-agent-01', 'pa-fw-01', 'cp-fw-01', 'cs-falcon-01', 'trend-dsa-01',
}

OT_CMDB_ALLOW = [
    ('FortiGateRugged-70G-5G-Dual', '172.16.0.254', 'Fortinet', 'FortiOS'),
    ('FDCVMSTM26000372', '172.16.0.117', 'Fortinet', 'FortiDeceptor'),
    ('FDCVM', '192.168.27.3', 'Fortinet', 'FortiDeceptor'),
    ('HOST-172.16.0.114', '172.16.0.114', 'Generic', 'Unix'),
    ('FPAVULTM26001793', '172.16.0.112', 'Fortinet', 'FortiPAM'),
    ('Workshop-27.2', '192.168.27.2', 'Fortinet', 'FortiOS'),
]

OT_NAME_HINTS = ('Rugged', 'FDC', 'Deceptor', 'PAM', 'PLC', 'SCADA', 'OT')


def ip_clean(s):
    if s is None:
        return None
    t = str(s)
    if t.lower().startswith('::ffff:'):
        t = t[7:]
    if t in ('', 'None', 'null'):
        return None
    return t


def esc(s):
    return (str(s) if s is not None else '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


def fmt_n(n):
    try:
        return f'{int(n):,}'
    except Exception:
        return str(n)


def wan_zh(n):
    n = int(n or 0)
    if n >= 10000:
        v = n / 10000
        s = f'{v:.1f}'.rstrip('0').rstrip('.')
        return f'{s} 萬'
    return fmt_n(n)


def fmt_win(iso):
    if not iso:
        return '—'
    t = str(iso).replace('T', ' ').replace('+08:00', '').replace('Z', '')
    return t[:16]


def fmt_bytes(n):
    try:
        n = int(n)
    except Exception:
        return str(n)
    if n >= 1_000_000_000:
        return f'{n/1_000_000_000:.2f} GB'
    if n >= 1_000_000:
        return f'{n/1_000_000:.1f} MB'
    if n >= 1_000:
        return f'{n/1_000:.1f} KB'
    return f'{n} B'


def parse_outgoing(title):
    m = re.search(r'Abnormal Large Content\s+(\d+)\s+Outgoing Traffic Detected from\s+(\S+)', title or '', re.I)
    if not m:
        return None
    return {'bytes': int(m.group(1)), 'src': ip_clean(m.group(2)), 'title': title}


def slim_inc(r):
    return {
        'incident_id': r.get('incident_id'),
        'incident_title': r.get('incident_title'),
        'severity_cat': r.get('severity_cat'),
        'status': r.get('status') or r.get('incident_status'),
        'src_ip_addr': ip_clean(r.get('src_ip_addr')),
        'dest_ip_addr': ip_clean(r.get('dest_ip_addr')),
        'host_name': r.get('host_name'),
        'host_ip_addr': ip_clean(r.get('host_ip_addr')),
        'first_seen': r.get('first_seen'),
        'last_seen': r.get('last_seen'),
        'rule_name': r.get('rule_name'),
        'incident_count': r.get('incident_count') or r.get('count') or 1,
        'user_attr': r.get('user_attr'),
    }


def lookup_row(rows, *ids):
    by = {int(r['incident_id']): r for r in rows if r.get('incident_id') is not None}
    for i in ids:
        if int(i) in by:
            return by[int(i)]
    return {}


def inc_detail(row):
    if not row:
        return None
    st = row.get('status') or ''
    status_code = 0 if str(st).lower() == 'open' else st
    src = ip_clean(row.get('src_ip_addr'))
    dst = ip_clean(row.get('dest_ip_addr'))
    host = row.get('host_name') or ip_clean(row.get('host_ip_addr'))
    title = row.get('incident_title') or ''
    rule = row.get('rule_name') or ''
    first = row.get('first_seen') or ''
    last = row.get('last_seen') or ''
    return {
        'incidentTitle': title,
        'eventSeverityCat': row.get('severity_cat') or 'MEDIUM',
        'eventSeverity': row.get('severity_cat') or 'MEDIUM',
        'eventName': rule,
        'eventType': rule,
        'incidentSrc': f'srcIpAddr:{src}' if src else '',
        'incidentTarget': f'destIpAddr:{dst}' if dst else (f'host:{host}' if host else ''),
        'incidentRptDevName': host or '',
        'incidentRptIp': ip_clean(row.get('host_ip_addr')) or '',
        'incidentFirstSeen_hkt': first,
        'incidentLastSeen_hkt': last,
        'incidentFirstSeen': first,
        'incidentLastSeen': last,
        'count': row.get('incident_count') or 1,
        'incidentStatus': status_code,
        'attackTactic': '',
        'attackTechnique': '[]',
        'incidentTagName': '',
        'incidentDetail': title,
    }


def grp_for(et, en):
    et = et or ''
    en = en or ''
    if 'Siemens_PLC' in et or 'PLC' in et:
        return 'OT / PLC'
    if et.startswith('PH_RULE_TRAFFIC_NOT') or 'Purdue' in en:
        return 'Purdue segmentation'
    if 'Unknown_EventType' in et:
        return 'Unparsed / Modbus'
    if 'wireless-rogue' in et or 'FTNT' in et:
        return 'Wireless IoT'
    if 'Port_Scanning' in et or 'Port Scan' in en:
        return 'Recon / Scan'
    if 'FortiGate-traffic' in et:
        return 'Permitted Network Traffic'
    if 'appctrl' in et or 'IPS' in en or 'ips' in et:
        return 'AppCtrl / IPS'
    return 'Other OT/IoT'


def type_count(types, *substrs):
    n = 0
    for r in types:
        et = r.get('eventType') or ''
        if any(s.lower() in et.lower() for s in substrs):
            n += int(r.get('count') or 0)
    return n


def is_ot_asset(name, ip):
    name = name or ''
    ip = ip_clean(ip) or ''
    if name in SIMULATED_CMDB:
        return False
    if any(name == n and ip == i for n, i, *_ in OT_CMDB_ALLOW):
        return True
    if ip.startswith('172.16.0.') or ip.startswith('192.168.27.'):
        return True
    if any(h.lower() in name.lower() for h in OT_NAME_HINTS):
        return True
    return False


def ilike_ot_stats(raw):
    rows = raw.get('ot_incidents_by_sev_status') or []
    total = sum(int(r.get('c') or 0) for r in rows)
    high_open = sum(
        int(r.get('c') or 0)
        for r in rows
        if str(r.get('severity_cat') or '').upper() == 'HIGH' and str(r.get('status') or '') == 'Open'
    )
    return total, high_open


def build_payload(raw: dict, hkci_src=None) -> tuple[dict, list]:
    ot_incs = [slim_inc(r) for r in (raw.get('incidents_touching_ot_ips') or [])]
    needles = raw.get('protocol_needle_breakdown') or {}
    daily = raw.get('daily_trend_hkt') or []
    hourly_all = raw.get('hourly_all_hkt') or []
    hourly_today = raw.get('hourly_today_hkt') or []
    peak = max(daily, key=lambda x: x.get('count') or 0) if daily else {'day': '—', 'count': 0}
    types = raw.get('top_event_types') or []
    repts = raw.get('top_reporting_devices') or []
    sev = raw.get('severity_breakdown') or []
    window = raw.get('window') or {}
    start_iso = window.get('start_hkt') or ''
    end_iso = window.get('end_hkt') or ''
    start_disp = fmt_win(start_iso)
    end_disp = fmt_win(end_iso)
    total = int(raw.get('total_ot_iot_related_events') or 0)

    # Parameterized window wording (defaults remain 三日 when the collect is a 3-day window)
    try:
        import sys
        from pathlib import Path as _P
        _eng = _P(__file__).resolve().parents[1]
        if str(_eng) not in sys.path:
            sys.path.insert(0, str(_eng))
        from studio_lib import parse_hkt, calendar_span_days, zh_day_phrase, en_day_phrase, badge_ot
        _s = parse_hkt(str(start_iso).replace('T', ' ').replace('+08:00', '')) or parse_hkt(start_disp)
        _e = parse_hkt(str(end_iso).replace('T', ' ').replace('+08:00', '')) or parse_hkt(end_disp)
        if _s and _e and _e > _s:
            _days = calendar_span_days(_s, _e)
        else:
            _days = 3.0
    except Exception:
        _days = 3.0
    env_days = (os.environ.get('FORTISIEM_REPORT_DAYS') or '').strip()
    if env_days:
        try:
            _days = float(env_days)
        except ValueError:
            pass
    SPAN_ZH = (os.environ.get('FORTISIEM_SPAN_ZH') or '').strip() or zh_day_phrase(_days)
    SPAN_EN = (os.environ.get('FORTISIEM_SPAN_EN') or '').strip() or en_day_phrase(_days)
    WK = '近' + SPAN_ZH
    THEME = (os.environ.get('FORTISIEM_THEME') or 'light').strip().lower()
    LANG = (os.environ.get('FORTISIEM_LANG') or 'zh').strip().lower()
    THEME_LABEL = 'Light' if THEME == 'light' else 'Dark'
    BADGE = (os.environ.get('FORTISIEM_BADGE') or '').strip() or badge_ot(_days)
    TITLE_SHORT = f'FortiSIEM {SPAN_ZH} OT 安全報告'
    TITLE_DOC = f'{TITLE_SHORT} · v1.5 · {THEME_LABEL}'
    if LANG == 'en':
        TITLE_SHORT = f'FortiSIEM {SPAN_EN} OT Security Report'
        TITLE_DOC = f'{TITLE_SHORT} · v1.5 · {THEME_LABEL}'
    DAYS_N = _days

    fdc = int(raw.get('fortideceptor_modbus_count') or 0)

    ev_per_day = [{'day': r['day'], 'c': int(r['count'])} for r in daily]
    ev_heatmap = [
        {'day': r['day'], 'hr': int(r['hour']), 'c': int(r['count'])}
        for r in hourly_all
    ]
    ev_top_types = [
        {
            'eventType': r.get('eventType'),
            'eventName': r.get('eventName') or r.get('eventType'),
            'grp': grp_for(r.get('eventType'), r.get('eventName')),
            'c': int(r.get('count') or 0),
        }
        for r in types
    ]
    ev_by_sev = [
        {'sev': (r.get('severity') or 'UNKNOWN') or 'UNKNOWN', 'c': int(r.get('count') or 0)}
        for r in sev
    ]

    ev_top_rept, ev_rept_list = [], []
    for r in repts:
        ip = ip_clean(r.get('reptDevIpAddr') or r.get('ip'))
        item = {
            'reptDevName': r.get('reptDevName'),
            'ip': ip,
            'model': r.get('model') or '',
            'c': int(r.get('count') or 0),
            'vendor': r.get('vendor') or '',
            'last': end_iso,
        }
        ev_top_rept.append({k: item[k] for k in ('reptDevName', 'ip', 'model', 'c')})
        ev_rept_list.append(item)

    ev_top_src = [{'ip': ip_clean(r.get('ip')), 'c': int(r.get('count') or 0)} for r in (raw.get('top_src') or [])]
    ev_top_dst = [{'ip': ip_clean(r.get('ip')), 'c': int(r.get('count') or 0)} for r in (raw.get('top_dst') or [])]
    ev_top_dport = [
        {'port': int(r.get('port')), 'ipProto': int(r.get('ipProto') or 0), 'c': int(r.get('c') or r.get('count') or 0)}
        for r in (raw.get('top_dport') or [])
    ]
    ev_sev_daily = [{'day': r['day'], 'sev': 'ALL', 'c': int(r['count'])} for r in daily]

    eps_hourly = []
    for r in hourly_all:
        day, h, c = r['day'], int(r['hour']), int(r['count'])
        # last hour of an exclusive end: if this is the end date and end minute
        sec = 3600
        if end_iso and day == end_iso[:10] and end_iso[11:13].isdigit():
            eh = int(end_iso[11:13])
            em = int(end_iso[14:16] or 0)
            es = int(end_iso[17:19] or 0) if len(end_iso) >= 19 else 0
            if h == eh:
                sec = max(em * 60 + es, 1)
        eps_hourly.append({'h': f'{day}T{h:02d}:00:00+08:00', 'eps': round(c / sec, 4)})

    unparsed = []
    for r in (raw.get('unknown_eventtype_breakdown') or []):
        unparsed.append({'reptDevName': r.get('reptDevName'), 'c': int(r.get('c') or 0)})

    # OT-relevant CMDB only (exclude simulated log devices and org-wide FortiGates)
    by_name_ip = {}
    for src in (raw.get('cmdb_ot_ish') or []) + (raw.get('cmdb_event_hosts') or []):
        name = src.get('name')
        ip = ip_clean(src.get('access_ip'))
        if not name or name in SIMULATED_CMDB or not is_ot_asset(name, ip):
            continue
        # skip SIEM / IT-edge boxes from the OT inventory table
        if 'SIEM' in name or (ip or '').startswith('192.168.10.') or (ip or '').startswith('192.168.101.') or (ip or '').startswith('192.168.115.'):
            continue
        by_name_ip[(name, ip)] = {
            'name': name,
            'access_ip': ip,
            'vendor': src.get('vendor') or '',
            'model': src.get('model') or '',
            'discover_method': src.get('discover_method') or 'LOG',
            'version': src.get('version'),
            'hw_serial_no': src.get('hw_serial_no'),
            'discovered': src.get('created_hkt') or src.get('discovered'),
            'created': src.get('created_hkt') or src.get('created'),
            'id': src.get('id'),
            'asset_weight': src.get('asset_weight') or 1,
        }
    for name, ip, vendor, model in OT_CMDB_ALLOW:
        if not any(d['name'] == name and d['access_ip'] == ip for d in by_name_ip.values()):
            by_name_ip[(name, ip)] = {
                'name': name, 'access_ip': ip, 'vendor': vendor, 'model': model,
                'discover_method': 'LOG', 'version': None, 'hw_serial_no': None,
                'discovered': None, 'created': None, 'id': None, 'asset_weight': 1,
            }
    cmdb_devices = list(by_name_ip.values())
    order = {n: i for i, (n, *_rest) in enumerate(OT_CMDB_ALLOW)}
    cmdb_devices.sort(key=lambda d: (order.get(d['name'], 100), d['name']))

    cmdb_fortios = [d for d in cmdb_devices if d.get('model') == 'FortiOS' or 'FortiGate' in (d.get('name') or '')]
    vend_ctr = Counter((d.get('vendor') or '—', d.get('model') or '—') for d in cmdb_devices)
    cmdb_vendor_model = [{'vendor': v, 'model': m, 'c': c} for (v, m), c in vend_ctr.most_common()]

    sev_c = Counter(r.get('severity_cat') or 'UNKNOWN' for r in ot_incs)
    st_c = Counter(r.get('status') or 'Unknown' for r in ot_incs)
    inc_by_sev = [{'severity_cat': k, 'c': v} for k, v in sev_c.most_common()]
    inc_by_status = [{'status': k, 'c': v} for k, v in st_c.most_common()]
    inc_by_reso = [
        {'reso': 'Open', 'c': st_c.get('Open', 0)},
        {'reso': 'Cleared', 'c': sum(v for k, v in st_c.items() if k != 'Open')},
    ]
    last_day = Counter((r.get('last_seen') or '')[:10] for r in ot_incs)
    inc_daily_sev = []
    for day, c in sorted(last_day.items()):
        if day:
            inc_daily_sev.append({'severity_cat': 'MEDIUM', 'c': c, 'day': day})

    title_c = Counter()
    for r in ot_incs:
        title_c[(r.get('incident_title') or '—', r.get('severity_cat') or 'MEDIUM')] += 1
    inc_top_titles = [
        {'incident_title': t, 'severity_cat': s, 'c': c}
        for (t, s), c in title_c.most_common(20)
    ]
    rule_c = Counter()
    rule_sev = {}
    rule_open = Counter()
    for r in ot_incs:
        name = r.get('rule_name') or '(none)'
        rule_c[name] += 1
        rule_sev[name] = r.get('severity_cat') or 'MEDIUM'
        if (r.get('status') or '') == 'Open':
            rule_open[name] += 1
    inc_top_rules = []
    for name, c in rule_c.most_common(20):
        sev_name = rule_sev.get(name) or 'MEDIUM'
        inc_top_rules.append({
            'rule': name,
            'category': 'Security' if any(k in name for k in ('Outgoing', 'DNS', 'Config', 'Scan')) else 'Availability',
            'high': c if sev_name == 'HIGH' else 0,
            'medium': c if sev_name == 'MEDIUM' else 0,
            'low': c if sev_name == 'LOW' else 0,
            'c': c,
            'open': int(rule_open[name]),
        })

    host_c = Counter()
    host_high = Counter()
    src_c = Counter()
    dst_c = Counter()
    for r in ot_incs:
        ent = r.get('host_name') or r.get('host_ip_addr') or r.get('src_ip_addr') or r.get('dest_ip_addr') or '—'
        ip = r.get('host_ip_addr') or r.get('src_ip_addr') or r.get('dest_ip_addr')
        host_c[(ent, ip)] += 1
        if (r.get('severity_cat') or '') == 'HIGH':
            host_high[(ent, ip)] += 1
        if r.get('src_ip_addr'):
            src_c[r['src_ip_addr']] += 1
        if r.get('dest_ip_addr'):
            dst_c[r['dest_ip_addr']] += 1
    inc_top_hosts = [
        {'entity': ent, 'ip': ip, 'c': c, 'high': int(host_high[(ent, ip)])}
        for (ent, ip), c in host_c.most_common(20)
    ]
    inc_top_src_ip = [{'ip': ip, 'c': c} for ip, c in src_c.most_common(15)]
    inc_top_dest_ip = [{'ip': ip, 'c': c} for ip, c in dst_c.most_common(15)]

    # Config from incidents + events
    notable = raw.get('notable_rule_hits') or []
    cfg_types = []
    for r in notable:
        if 'wireless-rogue' in (r.get('eventType') or '') or 'Config' in (r.get('eventName') or '') or 'config' in (r.get('eventType') or ''):
            cfg_types.append({
                'eventType': r.get('eventType'),
                'eventName': r.get('eventName'),
                'c': int(r.get('count') or 0),
            })
    for r in (raw.get('config_events_ot') or []):
        et = r.get('eventType')
        if et and not any(x['eventType'] == et for x in cfg_types):
            cfg_types.append({'eventType': et, 'eventName': r.get('eventName'), 'c': 1})

    cfg_recent, cfg_by_dev_user = [], []
    for r in ot_incs:
        title = r.get('incident_title') or ''
        if 'gateway[' in title or 'Config Change' in (r.get('rule_name') or '') or 'config on' in title:
            cfg_recent.append({
                'phRecvTime': (r.get('last_seen') or '').replace(' ', 'T') + ('+08:00' if r.get('last_seen') and 'T' not in str(r.get('last_seen')) else ''),
                'reptDevName': r.get('host_name') or r.get('dest_ip_addr') or '',
                'user': 'admin' if 'admin' in title.lower() else '',
                'eventType': r.get('rule_name') or 'FortiGate: Config Change Detected',
                'raw': title,
            })
    # also config events
    for r in (raw.get('config_events_ot') or []):
        cfg_recent.append({
            'phRecvTime': (r.get('t') or '').replace(' ', 'T') + '+08:00' if r.get('t') and 'T' not in str(r.get('t')) else (r.get('t') or ''),
            'reptDevName': r.get('reptDevName') or '',
            'user': r.get('userName') or '',
            'eventType': r.get('eventName') or r.get('eventType') or '',
            'raw': (r.get('msg') or '')[:200],
        })
    devu = Counter()
    for r in cfg_recent:
        if r.get('reptDevName') or r.get('user'):
            devu[(r.get('reptDevName') or '—', r.get('user') or '—')] += 1
    cfg_by_dev_user = [{'reptDevName': a, 'user': b, 'c': c} for (a, b), c in devu.most_common()]

    days_only = [r['day'] for r in daily]
    # first day starts 00:00 and is a complete calendar day if start is midnight and it's not the end day
    full_days = []
    end_day = (end_iso or '')[:10]
    start_day = (start_iso or '')[:10]
    start_is_midnight = (start_iso or '').endswith('T00:00:00+08:00') or (start_disp.endswith('00:00'))
    for r in daily:
        if r['day'] == end_day:
            continue
        if r['day'] == start_day and not start_is_midnight:
            continue
        full_days.append(r['day'])

    auth_daily = [{'day': r['day'], 'success': 0, 'failure': 0} for r in daily]

    talkers = []
    for r in (raw.get('top_talker_pairs') or []):
        talkers.append({
            'src': ip_clean(r.get('src')) or '(empty)',
            'dst': ip_clean(r.get('dst')) or '(empty)',
            'c': int(r.get('count') or 0),
        })

    new_devs = raw.get('cmdb_new_in_window') or []
    sim_new = [r for r in new_devs if (r.get('name') in SIMULATED_CMDB)]
    real_new = [r for r in new_devs if r.get('name') not in SIMULATED_CMDB]
    new_note = '、'.join(
        f"{r.get('name')} ({ip_clean(r.get('access_ip'))}, {r.get('created_hkt')})"
        for r in sim_new if r.get('name')
    )

    # ---- derived investigation facts ----
    plc_n = type_count(types, 'Siemens_PLC_Start_Stop')
    unk_n = type_count(types, 'Unknown_EventType')
    unk_plc = 0
    unk_msg = ''
    for r in (raw.get('unknown_eventtype_breakdown') or []):
        if '172.16.0.1' in str(r.get('reptDevName') or '') or '172.16.0.1' in str(r.get('msg') or ''):
            unk_plc += int(r.get('c') or 0)
            unk_msg = r.get('msg') or unk_msg
    purdue_l35 = type_count(types, 'PH_RULE_TRAFFIC_NOT_L35_TO_L3')
    purdue_l4 = type_count(types, 'PH_RULE_TRAFFIC_NOT_L4_TO_L35')
    purdue_n = purdue_l35 + purdue_l4
    scan_n = type_count(types, 'Port_Scanning', 'Port_Scan')
    rogue_off = type_count([{'eventType': r.get('eventType'), 'count': r.get('count')} for r in (raw.get('wireless_rogue_breakdown') or []) if 'offair' in (r.get('eventType') or '')], 'offair')
    # use notable / wireless breakdown more carefully
    wr = raw.get('wireless_rogue_breakdown') or []
    wr_off = sum(int(r.get('count') or 0) for r in wr if 'offair' in (r.get('eventType') or ''))
    wr_det = sum(int(r.get('count') or 0) for r in wr if r.get('eventType', '').endswith('rogue-detect'))
    wr_chg = sum(int(r.get('count') or 0) for r in wr if 'detect-chg' in (r.get('eventType') or ''))
    wr_rugged = sum(int(r.get('count') or 0) for r in wr if 'Rugged' in (r.get('reptDevName') or ''))

    s7_fwd = 0
    s7_rst = 0
    for r in (raw.get('plc_scada_ics_comms') or []):
        if ip_clean(r.get('src')) == '172.16.0.2' and ip_clean(r.get('dst')) == '172.16.0.1' and str(r.get('dport')) == '102':
            if 'rst' in (r.get('eventType') or '').lower() or 'rst' in (r.get('evtName') or '').lower():
                s7_rst += int(r.get('c') or 0)
            else:
                s7_fwd += int(r.get('c') or 0)
    s7_n = s7_fwd + s7_rst
    intra = 0
    intra_name = ''
    for r in (raw.get('ot_related_policies_detail') or raw.get('ot_related_policies') or []):
        if 'Intra-SCADA' in (r.get('policy') or '') or 'SCADA' in (r.get('policy') or ''):
            intra += int(r.get('count') or 0)
            intra_name = intra_name or r.get('policy')

    outbound = []
    for r in ot_incs:
        parsed = parse_outgoing(r.get('incident_title') or '')
        if parsed:
            outbound.append({**r, **parsed})
    outbound.sort(key=lambda x: -(x.get('bytes') or 0))
    out_by_src = Counter(r.get('src') or r.get('src_ip_addr') for r in outbound)

    dns_incs = [r for r in ot_incs if 'DNS' in ((r.get('incident_title') or '') + (r.get('rule_name') or ''))]
    gw_incs = [r for r in ot_incs if 'gateway[' in (r.get('incident_title') or '') or 'Config Change' in (r.get('rule_name') or '')]
    drop_incs = [r for r in ot_incs if 'Sudden Decrease' in (r.get('incident_title') or '')]
    delay_open = [r for r in ot_incs if 'log receiving delay' in (r.get('incident_title') or '') and r.get('status') == 'Open']
    delay_all = [r for r in ot_incs if 'log receiving delay' in (r.get('incident_title') or '')]
    ping_incs = [r for r in ot_incs if 'ping' in (r.get('incident_title') or '').lower()]
    license_incs = [r for r in ot_incs if 'License' in (r.get('incident_title') or '') or 'License' in (r.get('rule_name') or '')]

    fail_n = len(raw.get('failed_logins_ot') or [])
    remote_n = len(raw.get('remote_access_ot_net') or [])
    ext_n = len(raw.get('external_to_ot') or [])
    high_ot_ev = sum(int(r.get('count') or 0) for r in sev if str(r.get('severity') or '').upper() in ('HIGH', 'CRITICAL'))

    scan_srcs = raw.get('ot_port_scan_sources') or []
    scan_dests = [ip_clean(r.get('dst')) for r in scan_srcs if ip_clean(r.get('dst'))]
    scan_ot_dest = [d for d in scan_dests if d.startswith('172.16.0.') or d.startswith('192.168.27.')]
    top_scan = scan_srcs[0] if scan_srcs else {}
    # HIGH stealth from window
    stealth = []
    for r in (raw.get('high_sev_incidents_window') or []):
        t = r.get('incident_title') or ''
        if 'Stealth scanning' in t or 'stealth' in t.lower():
            stealth.append(slim_inc(r) if 'src_ip_addr' in r or True else r)
    stealth_targets = sorted({ip_clean(r.get('dest_ip_addr')) for r in (raw.get('high_sev_incidents_window') or []) if 'Stealth scanning' in (r.get('incident_title') or '') and ip_clean(r.get('dest_ip_addr'))})

    ilike_n, ilike_hi = ilike_ot_stats(raw)
    fp_examples = []
    for r in (raw.get('ot_high_incidents') or []):
        fp_examples.append(f"#{r.get('incident_id')} {r.get('incident_title')}")

    open_n = st_c.get('Open', 0)
    high_inc_n = sev_c.get('HIGH', 0)

    # weekday labels
    wd = {'2026-11-09': '星期一', '2026-11-10': '星期二', '2026-11-11': '星期三'}
    daily_zh = '、'.join(
        f"{r['day'][5:]}（{wd.get(r['day'], '')}）<b>{fmt_n(r['count'])}</b>"
        for r in daily
    )

    # 11-09 ramp
    h09 = [r for r in hourly_all if r['day'] == '2026-11-09']
    ramp_note = ''
    if h09:
        pre = [r for r in h09 if int(r['hour']) < 17]
        post = [r for r in h09 if int(r['hour']) >= 17]
        pre_s = sum(r['count'] for r in pre)
        post_s = sum(r['count'] for r in post)
        if post_s > pre_s * 5:
            ramp_note = (
                f'11-09 00:00–16:59 僅 {fmt_n(pre_s)} 筆，17:00 起升至每小時約 '
                f'{fmt_n(min(r["count"] for r in post)) }–{fmt_n(max(r["count"] for r in post))} 筆'
                f'（合共 {fmt_n(post_s)}），與 Rugged 閘道變更（17:09）同一時段，其後 PLC 遙測持續。'
            )

    h10 = [r for r in hourly_all if r['day'] == '2026-11-10']
    h11 = [r for r in hourly_all if r['day'] == '2026-11-11']
    def hr_range(rows):
        if not rows:
            return '—'
        vs = [r['count'] for r in rows]
        return f'{fmt_n(min(vs))}–{fmt_n(max(vs))}'

    plc_pct = (plc_n / total * 100) if total else 0
    fam_re = r'Siemens PLC Start Stop'
    top_rept = ev_rept_list[0] if ev_rept_list else {}

    # Findings (computed, not templates from previous window)
    findings = []
    findings.append({
        'lvl': 'medium',
        'title': f'OT/IoT 流量：{fmt_n(total)} 筆，以 demo PLC 遙測為主',
        'body': (
            f'視窗 {esc(start_disp)} 至 {esc(end_disp)} HKT 共 <b>{fmt_n(total)}</b> 筆 OT/IoT 相關事件：'
            f'{daily_zh}（{end_disp[5:]} 為不完整日，截至於 {esc(end_disp[11:])}）。'
            + (f' {ramp_note}' if ramp_note else '')
            + (f' 11-10 小時量幾乎平坦（{hr_range(h10)} 筆/小時，全日完整）。' if h10 else '')
            + (f' 11-11 截至 {end_disp[11:]} 同樣平坦（{hr_range(h11)} 筆/小時）。' if h11 else '')
            + f'主導類型 Siemens_PLC_Start_Stop_Status_Change <b>{fmt_n(plc_n)}</b>（{plc_pct:.1f}%），'
            f'報告來源 HOST-172.16.0.1（訊息識別為 SIEMENS S7-1200 PLC HK DEMO）。'
            + _sev_sentence(sev)
            + '呢啲係持續展示／實驗室遙測，而唔係爆發式入侵。'
        ),
        'todo': '核對展示／維護時段同 11-09 17:00 起嘅遙測啟動是否預期；唔好單憑全日筆數解讀為入侵尖峰。',
    })

    # outbound finding
    if outbound:
        lines = []
        # group 172.16.0.116
        from_116 = [r for r in outbound if (r.get('src') or r.get('src_ip_addr')) == '172.16.0.116']
        from_114 = [r for r in outbound if (r.get('src') or r.get('src_ip_addr')) == '172.16.0.114']
        from_112 = [r for r in outbound if (r.get('src') or r.get('src_ip_addr')) == '172.16.0.112']
        if from_116:
            biggest = from_116[0]
            days_116 = sorted({(r.get('last_seen') or '')[:10] for r in from_116})
            lines.append(
                f'<b>{len(from_116)}</b> 宗來自未入 OT CMDB 子集嘅 <span class="mono">172.16.0.116</span>'
                f'（{ "、".join(days_116) }），最大一筆 <b>#{biggest.get("incident_id")}</b> 約 {fmt_bytes(biggest.get("bytes"))}'
                f' → <span class="mono">{esc(biggest.get("dest_ip_addr"))}</span>'
                f'（{esc(biggest.get("last_seen"))} HKT）。'
            )
            # mention dest classes
            dests = Counter(r.get('dest_ip_addr') for r in from_116)
            topd = '、'.join(f'{k} ×{v}' for k, v in dests.most_common(6))
            lines.append(f'目的包括 Fastly 199.232.210.172 / 199.232.214.172、61.244.242.x 同 192.168.13.100。')
        if from_114:
            r = from_114[0]
            lines.append(
                f'<b>#{r.get("incident_id")}</b> Purdue 對講 <span class="mono">172.16.0.114</span> → '
                f'<span class="mono">{esc(r.get("dest_ip_addr"))}</span>（AWS）約 {fmt_bytes(r.get("bytes"))}'
                f'（{esc(r.get("last_seen"))}）。'
            )
        if from_112:
            r = from_112[0]
            lines.append(
                f'<b>#{r.get("incident_id")}</b> FortiPAM <span class="mono">172.16.0.112</span>（FPAVULTM26001793）→ '
                f'<span class="mono">{esc(r.get("dest_ip_addr"))}</span> 約 {fmt_bytes(r.get("bytes"))}'
                f'（{esc(r.get("last_seen"))}）。'
            )
        dns_txt = ''
        if dns_incs:
            bits = []
            for r in dns_incs:
                bits.append(
                    f'<b>#{r.get("incident_id")}</b> {esc(r.get("incident_title"))}'
                    f'（{esc(r.get("status"))}，{esc(r.get("first_seen"))}–{esc(r.get("last_seen"))}）'
                )
            dns_txt = ' DNS 方面：' + '；'.join(bits) + '。'
        findings.append({
            'lvl': 'high',
            'title': '跟進 OT 鄰近 IP 異常大流量出站與 DNS',
            'body': (
                f'需調查嘅 Open MEDIUM 出站事故共 <b>{len(outbound)}</b> 宗。'
                + ''.join(lines)
                + dns_txt
                + '未見 Internet 來源直連進入 172.16.0.x / 192.168.27.x。'
            ),
            'todo': '盤點 172.16.0.116 並核對出站目的、裝載同變更視窗；同步檢查 192.168.27.4 DNS 與 FortiPAM 出站是否預期備份／更新流量。',
        })

    if purdue_n or unk_n:
        findings.append({
            'lvl': 'medium',
            'title': 'Purdue 分層告警與未解析 Modbus holding-register',
            'body': (
                f'Purdue 規則：L3.5→L3（PH_RULE_TRAFFIC_NOT_L35_TO_L3）<b>{fmt_n(purdue_l35)}</b>；'
                f'L4→L3.5（PH_RULE_TRAFFIC_NOT_L4_TO_L35）<b>{fmt_n(purdue_l4)}</b>，來源主要係 <span class="mono">172.16.0.114</span>。'
                '呢啲係分段政策訊號，並非已確認攻擊。'
                + (f' 另有 Unknown_EventType <b>{fmt_n(unk_n)}</b> 筆，其中 {fmt_n(unk_plc)} 筆來自 172.16.0.1 的未解析 Modbus holding-register 訊息（SIEMENS S7-1200 PLC HK DEMO）。' if unk_n else '')
                + f' 針刺（可重疊）：'
                + '、'.join(f'{k} {fmt_n(v)}' for k, v in sorted(((k, int(v or 0)) for k, v in needles.items() if int(v or 0) > 0), key=lambda kv: -kv[1])[:6])
                + '。'
                + (' S7comm 針刺計數為 0，但 Siemens/S7 活動經 Siemens_S7 + PLC 類型'
                   + (f' 同 172.16.0.2→172.16.0.1:102（×{fmt_n(s7_n)}）' if s7_n else '')
                   + ' 可以證實。' if int(needles.get('S7comm') or 0) == 0 else '')
            ),
            'todo': '對照防火牆允許清單與 Purdue 模型；為 172.16.0.1 的 Modbus 日誌補解析器，避免長期以 Unknown_EventType 堆積。',
        })

    if wr_off or wr_det or wr_chg or int(needles.get('FTNT_IOT') or 0):
        findings.append({
            'lvl': 'medium',
            'title': 'SSID FTNT-IOT rogue AP 事件（FortiGateRugged）',
            'body': (
                f'無線 rogue 事件：off-air <b>{fmt_n(wr_off)}</b>、detect <b>{fmt_n(wr_det)}</b>、change <b>{fmt_n(wr_chg)}</b>'
                + (f'（其中 FortiGateRugged 佔 {fmt_n(wr_rugged)} 筆）' if wr_rugged else '')
                + '。針刺 FTNT-IOT {n}。'.format(n=fmt_n(needles.get('FTNT_IOT') or 0))
                + '外觀似實驗室／展示 SSID，但仍需確認是否授權。'
                + (f' 本視窗 FortiDeceptor Modbus-device 計數為 <b>0</b>，唔好將歷史 FDC Modbus 輪廓當作本期發現。' if fdc == 0 else f' FortiDeceptor Modbus-device 計數為 <b>{fmt_n(fdc)}</b>。')
            ),
            'todo': '確認 FTNT-IOT 是否授權展示 SSID；未授權 rogue 應定位／抑制，並保留完整無線日誌。',
        })

    # ops finding
    ops_bits = []
    if gw_incs:
        g = gw_incs[0]
        ops_bits.append(
            f'<b>#{g.get("incident_id")}</b>（{esc(g.get("status"))}，{esc(g.get("last_seen"))}）{esc(g.get("incident_title"))}'
        )
    if drop_incs:
        d = drop_incs[0]
        ops_bits.append(
            f'同一時段 <b>#{d.get("incident_id")}</b> {esc(d.get("incident_title"))}（{esc(d.get("status"))}）'
        )
    extra_cfg = [r for r in (raw.get('config_events_ot') or []) if '01:07' in (r.get('t') or '')]
    if extra_cfg:
        e = extra_cfg[0]
        ops_bits.append(
            f'另於 {esc(e.get("t"))} 錄得 {esc(e.get("reptDevName"))} 由 {esc(e.get("userName") or "admin")} 作出 Configuration changed（樣本訊息已截斷，細節需查原日誌）'
        )
    if delay_open:
        ops_bits.append(
            '仍為 Open 的收日誌延遲：'
            + '；'.join(f'<b>#{r.get("incident_id")}</b> {esc(r.get("incident_title"))}（{esc(r.get("last_seen"))}）' for r in delay_open)
        )
    if ping_incs:
        ops_bits.append(
            f'短暫 ping 損失／降級 {len(ping_incs)} 宗（{esc(ping_incs[0].get("last_seen"))} 附近），其後狀態為 '
            + '、'.join(sorted({r.get('status') or '' for r in ping_incs}))
        )
    if license_incs:
        lic = license_incs[0]
        ops_bits.append(f'執照問題 <b>#{lic.get("incident_id")}</b> {esc(lic.get("incident_title"))} 現為 {esc(lic.get("status"))}')
    if ops_bits:
        findings.append({
            'lvl': 'medium',
            'title': '營運：Rugged 閘道／設定變更、日誌延遲與短暫 ping 損失',
            'body': '。'.join(ops_bits) + '。',
            'todo': '核對閘道變更同 11-10 01:07 設定變更是否已批准；處理仍 Open 的收日誌延遲。',
        })

    # judgement
    scan_txt = (
        f'OT_Suspicious_Port_Scanning_Activities <b>{fmt_n(scan_n)}</b> 筆，報告來源 SIEM.fortinethk.com，'
        + ('目的地欄位全部空白；' if not scan_dests else f'事件列目的地 {fmt_n(len(scan_dests))} 個；')
        + ('相關 HIGH stealth-scan 事故目標係 ' + ' / '.join(f'<span class="mono">{esc(t)}</span>' for t in stealth_targets) + '（IT/SIEM 邊緣），' if stealth_targets else '')
        + ('未見進入 172.16.0.x。' if not scan_ot_dest else f'其中 {fmt_n(len(scan_ot_dest))} 個目的落在 OT 網段，需另行核對。')
    )
    findings.append({
        'lvl': 'info',
        'title': '未確認 OT 網段入侵；標題含 OT 的事故計數屬假陽性',
        'body': (
            f'對 172.16.0.0/24 與 192.168.27.0/24：失敗登入 {fmt_n(fail_n)}、VPN/RDP/SSH 進入 {fmt_n(remote_n)}、Internet 來源直連 OT 事件 {fmt_n(ext_n)}。'
            f'真正觸及 OT IP 的事故為 <b>{fmt_n(len(ot_incs))}</b> 宗，'
            + ('無 HIGH。' if high_inc_n == 0 else f'其中 HIGH {fmt_n(high_inc_n)} 宗。')
            + (f' 以事故標題 ILIKE \'%OT%\' 得出的 {fmt_n(ilike_n)} 宗（含 {fmt_n(ilike_hi)} 宗 HIGH Open）係字串假陽性'
               + (('（例如 ' + '；'.join(esc(x) for x in fp_examples[:4]) + '）。') if fp_examples else '。')
               if ilike_n else '')
            + ' ' + scan_txt
            + ' <b>初步判斷：未確認有入侵進入 OT 網段</b>；外圍掃描唔應當作 OT 失陷。仍需跟進出站、DNS 與閘道／設定變更。'
        ),
        'todo': '調查清單以 OT-IP 事故同出站／DNS／閘道為準，唔好用標題模糊搜尋擴大 OT 事故範圍。',
    })

    # HKCI
    hkci = {}
    if hkci_src:
        try:
            from pathlib import Path
            p = Path(hkci_src)
            if p.exists():
                hkci = (json.loads(p.read_text(encoding='utf-8')).get('hkci') or {})
        except Exception:
            hkci = {}
    disclaimer = hkci.get('disclaimer') or (
        f'本頁將{WK} FortiSIEM OT/IoT 觀測映射至公開的控制主題，僅供內部改善參考，'
        '並非法律意見，亦非斷言貴司屬《保護關鍵基礎設施電腦系統條例》下的指定營運者。'
        '實際法定責任僅適用於被正式指定的關鍵基礎設施營運者及其關鍵電腦系統。'
    )
    disclaimer = disclaimer.replace('本週', WK).replace('五日', SPAN_ZH).replace('三日', SPAN_ZH)

    compliance = [
        {
            'lvl': 'high' if outbound else 'medium',
            'ctrl': 'CoP §6.2.21',
            'ctrl_title': '網絡保安／出站監控',
            'title': 'OT 鄰近主機出現異常大流量出站，需優先核對' if outbound else '出站監控',
            'body': (
                f'{fmt_n(len(ot_incs))} 宗觸及 OT IP 的事故中，{fmt_n(len(outbound))} 宗為 Abnormal Large Content Outgoing Traffic。'
                + ('來源包括未入 OT CMDB 子集的 172.16.0.116、Purdue 對講 172.16.0.114，以及 FortiPAM 172.16.0.112。' if outbound else '')
                + '未見對向 OT 網段的 Internet 直連。'
            ),
            'todo': '將出站允許清單同資產擁有者對齊，並把 172.16.0.116 補入資產清單。',
        },
        {
            'lvl': 'medium',
            'ctrl': 'CoP §6.2.21(c) / OT §6.5.1',
            'ctrl_title': '網域劃分 · Purdue',
            'title': 'L3.5→L3 與 L4→L3.5 政策訊號持續出現',
            'body': (
                f'Purdue 針刺 {fmt_n(needles.get("Purdue") or 0)}；規則 L3.5→L3 {fmt_n(purdue_l35)}、L4→L3.5 {fmt_n(purdue_l4)}，主要來源 172.16.0.114。'
                '屬分段政策檢測，不是已確認攻擊。'
            ),
            'todo': '核對 Purdue 模型與防火牆政策；越級流量應改為 deny 或經 jump host，並文件化允許清單。',
        },
        {
            'lvl': 'medium',
            'ctrl': 'CoP §6.2.16 / OT §6.5.6',
            'ctrl_title': '變更管理',
            'title': 'Rugged 閘道／設定曾被 admin 更改',
            'body': ' '.join(ops_bits[:3]) if ops_bits else '本視窗未抽出閘道變更事故。',
            'todo': '確認閘道變更工單與回滾；PLC Start/Stop 應有展示／維護窗口紀錄。',
        },
        {
            'lvl': 'medium',
            'ctrl': 'CoP §6.2.21(e)',
            'ctrl_title': '無線接達',
            'title': 'FTNT-IOT rogue AP 訊號需確認授權',
            'body': f'無線 rogue：off-air {fmt_n(wr_off)}、detect {fmt_n(wr_det)}、change {fmt_n(wr_chg)}。FortiDeceptor Modbus 計數本期為 {fmt_n(fdc)}。',
            'todo': '確認是否授權展示 SSID；未授權應抑制／定位，無線接達 OT 區須認證、加密與完整日誌。',
        },
        {
            'lvl': 'medium',
            'ctrl': 'CoP §6.2.9',
            'ctrl_title': '資產管理',
            'title': '172.16.0.116 與 demo PLC 未入 OT CMDB 子集',
            'body': (
                'OT 相關資產包括 FortiGateRugged 172.16.0.254、FDCVMSTM 172.16.0.117、FDCVM 192.168.27.3、'
                'HOST-172.16.0.114、FortiPAM 172.16.0.112、Workshop-27.2。HOST-172.16.0.1（S7-1200 demo PLC）主要以事件源出現。'
                + (f' 視窗內新增 CMDB（LOG、公網 IP，視為模擬／日誌來源，未列入 OT 資產表）：{new_note}。' if new_note else '')
            ),
            'todo': '為 172.16.0.1 / 172.16.0.116 補資產紀錄；將模擬日誌裝置從 OT 資產清單分開標註。',
        },
        {
            'lvl': 'info',
            'ctrl': '第3類 / 應急',
            'ctrl_title': '監察、偵測與事故分級',
            'title': '外圍掃描存在，但未見進入 OT 網段' if not scan_ot_dest else '外圍掃描需核對目的',
            'body': scan_txt + f' 失敗登入 {fmt_n(fail_n)}、遙距登入 OT 網段 {fmt_n(remote_n)}。本頁映射僅供內部改善，並非法律意見或指定營運者斷言。',
            'todo': '保持 OT 規則監控，但分級時區分 IT/SIEM 邊緣掃描與真正觸及 172.16.0.0/24 的事件。',
        },
    ]

    # Deep-dive picks
    pick_ids = []
    if from_116 := [r for r in outbound if (r.get('src') or r.get('src_ip_addr')) == '172.16.0.116']:
        pick_ids.append((from_116[0]['incident_id'], f'OT 鄰近主機 172.16.0.116（未入 OT CMDB 子集）異常大流量出站約 {fmt_bytes(from_116[0].get("bytes"))} → {from_116[0].get("dest_ip_addr")}'))
    if from_114 := [r for r in outbound if (r.get('src') or r.get('src_ip_addr')) == '172.16.0.114']:
        pick_ids.append((from_114[0]['incident_id'], f'Purdue 對講主機 172.16.0.114 出站約 {fmt_bytes(from_114[0].get("bytes"))} → {from_114[0].get("dest_ip_addr")}'))
    if from_112 := [r for r in outbound if (r.get('src') or r.get('src_ip_addr')) == '172.16.0.112']:
        pick_ids.append((from_112[0]['incident_id'], f'FortiPAM 172.16.0.112 出站約 {fmt_bytes(from_112[0].get("bytes"))} → {from_112[0].get("dest_ip_addr")}'))
    if dns_incs:
        d0 = dns_incs[0]
        pick_ids.append((d0['incident_id'], f'{d0.get("incident_title")}（{d0.get("status")}）'))
    picks, details = [], {}
    seen = set()
    for iid, why in pick_ids:
        if iid in seen:
            continue
        seen.add(iid)
        row = lookup_row(ot_incs, iid)
        if not row:
            continue
        picks.append({'id': iid, 'why': why, 'ctx': None, 'extra': None})
        details[f'inc_{iid}_detail'] = inc_detail(row)

    deep_story = (
        f'揀咗 {len(picks)} 宗最值得跟進、並實際觸及 OT／OT 鄰近位址嘅事故（全部 MEDIUM，無 HIGH）：'
        '172.16.0.116 大流量出站（本視窗有新一輪星期三紀錄）、172.16.0.114／FortiPAM 出站，以及 192.168.27.4 DNS。'
        f'視窗內未見對 OT 網段嘅失敗登入、遙距登入或 Internet 直連；外圍掃描未顯示進入 172.16.0.x。'
        '本期未再抽取完整 trigger raw／外部信譽，個案資料以事故欄位為準。'
    )

    limits = [
        f'本報告視窗為絕對香港時間 {start_disp} 至 {end_disp}（星期一 00:00 至查詢當刻，非滾動 72 小時）；最後一日為不完整日。',
        'OT/IoT 事件匹配採用 token-safe 邏輯（eventType/eventName 詞界；排除 PH_AUDIT%）。',
        f'事故主表只用「觸及 OT IP／主機」的 {fmt_n(len(ot_incs))} 宗；不以標題 ILIKE \'%OT%\' 作為 OT 事故總數（該計數含 Remote/Botnet/protocol 假陽性，本期 {fmt_n(ilike_n)} 宗／{fmt_n(ilike_hi)} 宗 HIGH Open）。',
        '沒有 HIGH/CRITICAL OT 事件。' if high_ot_ev == 0 and high_inc_n == 0 else f'OT 事件 HIGH/CRITICAL 計數為 {fmt_n(high_ot_ev)}。',
        '小時熱圖覆蓋視窗內全部日期的 phRecvTime（香港時間）。',
        '本視窗沒有按日的 OT Permit/Deny 拆帳，流量頁不以企業全域拒絕率解讀 OT；相關空圖已隱藏。',
        f'失敗登入 {fmt_n(fail_n)}、VPN/RDP/SSH 進入 OT 網段 {fmt_n(remote_n)}、Internet→OT 事件 {fmt_n(ext_n)}。',
        f'FortiDeceptor Modbus-device 計數為 {fmt_n(fdc)}' + ('，不沿用歷史 FDC Modbus 發現。' if fdc == 0 else '。'),
        'S7comm 針刺計數為 0，但 Siemens_S7／PLC 類型與 172.16.0.2→172.16.0.1:102 交通可證實 Siemens/S7 活動。' if int(needles.get('S7comm') or 0) == 0 else '',
        '風險裝置／使用者名單來自組織全域工具，不是 OT 失陷清單。',
        '視窗內新增的 pa-fw-01 / cp-fw-01 / s1-agent-01 / cs-falcon-01 / trend-dsa-01 視為模擬／日誌來源，未列入 OT 資產表。' if sim_new else '',
        '合規頁將觀測映射至公開 HKCI／CoP 控制主題，僅供內部改善參考，並非法律意見或指定營運者斷言。',
        '附錄列出今次已收集查詢；本檔建置時不再連線 Supervisor。',
    ]
    limits = [x for x in limits if x]

    sources = []
    for key, q in (raw.get('sql_used') or {}).items():
        sources.append({
            'key': key,
            'tool': 'query_fsm_clickhouse_or_postgres',
            'query': q if isinstance(q, str) else json.dumps(q, ensure_ascii=False)[:2000],
            'ok': True,
            'secs': None,
            'error': '',
        })
    for err in (raw.get('mcp_failures') or []):
        if isinstance(err, dict):
            sources.append({
                'key': err.get('key') or err.get('query') or 'mcp_failure',
                'tool': err.get('tool') or 'mcp',
                'query': err.get('query') or '',
                'ok': False,
                'secs': err.get('secs'),
                'error': err.get('error') or str(err),
            })

    n_types = len({r.get('eventType') for r in types if r.get('eventType')})
    n_repts = len(ev_rept_list)
    n_ips = len({r.get('ip') for r in ev_rept_list if r.get('ip')})

    # stories as HTML fragments for the shell
    def _pct(part, whole):
        return f'{(100*part/whole):.1f}%' if whole else '—'
    r0 = ev_rept_list[0] if ev_rept_list else {}
    top_type = ev_top_types[0] if ev_top_types else {}
    lead_html = (
        f'視窗 {esc(start_disp)} 至 {esc(end_disp)} HKT 共 '
        f'<span class="hl">{wan_zh(total)}</span> 筆 OT/IoT 事件'
    )
    ev_story_html = (
        (ramp_note + ' ' if ramp_note else '')
        + (f'11-10 小時量幾乎平坦（{hr_range(h10)} 筆/小時）；' if h10 else '')
        + (f'11-11 截至 {esc(end_disp[11:])} 同樣平坦（{hr_range(h11)} 筆/小時）。' if h11 else '')
        + f'<b>{esc(r0.get("reptDevName"))}</b> 貢獻 {_pct(int(r0.get("c") or 0), total)} 事件；最多類型係 '
        + f'<span class="mono">{esc(top_type.get("eventType"))}</span>（{_pct(int(top_type.get("c") or 0), total)}）。'
        + '主導係展示／實驗室 PLC 持續遙測，而唔係爆發式入侵。'
        + ('OT 事件無 HIGH/CRITICAL。' if high_ot_ev == 0 else '')
    )
    tr_story_html = (
        'OT/IoT 相關對講主要喺 <span class="mono">172.16.0.0/24</span> 內。'
        + (f'Intra-SCADA 政策 <span class="mono">{esc(intra_name)}</span> 錄得 {fmt_n(intra)} 筆。' if intra else '')
        + (f'S7/ISO-on-TCP：<span class="mono">172.16.0.2 → 172.16.0.1:102</span> 共 {fmt_n(s7_fwd)} 筆經 FortiGateRugged-70G-5G-Dual 放行'
           + (f'（另 {fmt_n(s7_rst)} 筆 RST）' if s7_rst else '')
           + '。' if s7_n else '')
        + '本視窗無獨立 OT Permit/Deny 日拆帳，唔好用企業全域拒絕率解讀 OT 流量；相關空圖已隱藏。'
    )
    au_story_html = (
        f'針對 <span class="mono">172.16.0.0/24</span> 同 <span class="mono">192.168.27.0/24</span>：'
        f'失敗登入 <b>{fmt_n(fail_n)}</b> 筆；VPN / RDP / SSH（目的埠 22、3389、5900）進入該等網段 <b>{fmt_n(remote_n)}</b> 筆；'
        f'Internet 來源直連 172.16.0.x / 192.168.27.x <b>{fmt_n(ext_n)}</b> 筆。'
        '以下空嘅企業全域登入圖表已隱藏，以免留下空白掛版。'
    )
    if dns_incs:
        dns_story_html = (
            '需要跟進：'
            + '；'.join(
                f'事故 <b>#{r.get("incident_id")}</b>（{esc(r.get("status"))}，{esc(r.get("first_seen"))}–{esc(r.get("last_seen"))}）——來源 <span class="mono">{esc(r.get("src_ip_addr") or "")}</span> 的 DNS 異常'
                for r in dns_incs
            )
            + '。此頁無獨立 OT DNS 事件量統計，以事故為準；空嘅 Sankey／類型圖已隱藏。'
        )
    else:
        dns_story_html = '本視窗未見觸及 OT／OT 鄰近網段的 DNS 事故。空嘅企業全域 DNS 圖已隱藏。'

    if gw_incs:
        g = gw_incs[0]
        cfg_story_html = (
            f'{esc(g.get("last_seen"))}：{esc(g.get("incident_title"))}'
            f'（事故 #{g.get("incident_id")}，{esc(g.get("status"))}）'
            + (f'；{esc(drop_incs[0].get("incident_title"))}（#{drop_incs[0].get("incident_id")}，{esc(drop_incs[0].get("status"))}）' if drop_incs else '')
            + (f'。另於 {esc(extra_cfg[0].get("t"))} 有 Configuration changed。' if extra_cfg else '。')
            + f'SSID FTNT-IOT 另有 rogue AP 變更 {fmt_n(wr_chg)} 筆。'
        )
    else:
        cfg_story_html = f'本視窗抽出的 OT 相關設定事件見下表。SSID FTNT-IOT rogue 變更 {fmt_n(wr_chg)} 筆。'

    inc_story_html = (
        f'本表只計觸及 OT IP／主機嘅 <b>{fmt_n(len(ot_incs))}</b> 宗事故'
        + ('（全部 MEDIUM，無 HIGH）' if high_inc_n == 0 else '')
        + f'。Open {fmt_n(open_n)} 宗，其餘已清除。'
        + (f"唔好用標題 ILIKE '%OT%' 嘅 {fmt_n(ilike_n)} 宗／{fmt_n(ilike_hi)} 宗 HIGH Open 當作真正 OT 事故。" if ilike_n else '')
        + '優先跟進未入 CMDB 子集嘅 172.16.0.116 出站以及 DNS／閘道變更。'
    )
    risk_story_html = (
        '以下為<b>組織全域</b>風險工具名單，唔等於 OT 失陷主機。'
        f'最高分裝置來自企業風險清單，唔代表 OT 失陷。{WK} OT 網段未確認入侵。'
    )


    data = {
        'ev_total': [{
            'events': total,
            'rept_ips': n_ips,
            'rept_names': n_repts,
            'event_types': n_types,
            'first': start_iso,
            'last': end_iso,
        }],
        'ev_per_day': ev_per_day,
        'ev_heatmap': ev_heatmap,
        'ev_top_types': ev_top_types,
        'ev_by_sev': ev_by_sev,
        'ev_by_cat': [],
        'ev_by_vendor': [],  # no per-event vendor tallies in this collect; do not reuse CMDB device counts
        'ev_top_rept': ev_top_rept,
        'ev_rept_list': ev_rept_list,
        'ev_top_src': ev_top_src,
        'ev_top_dst': ev_top_dst,
        'ev_top_users': [],
        'ev_top_dport': ev_top_dport,
        'ev_src_country': [],
        'ev_dst_country': [],
        'ev_rept_daily': [],
        'ev_sev_daily': ev_sev_daily,
        'traffic_daily': [],
        'traffic_fgt_action': [],
        'traffic_deny_top_src': [],
        'traffic_deny_top_dport': [],
        'auth_daily': auth_daily,
        'auth_fail_top': [],
        'auth_success_top': [],
        'auth_types': [],
        'vpn_events': [],
        'admin_logins': [],
        'dns_groups': [{'common_dns': 0, 'uncommon_dns': 0, 'denied_dns': 0}],
        'dns_types': [],
        'dns_top_src': [],
        'cfg_types': cfg_types,
        'cfg_by_dev_user': cfg_by_dev_user,
        'cfg_recent': cfg_recent,
        'eps_hourly': eps_hourly,
        'unparsed': unparsed,
        'security_attacks': ([{
            'eventType': 'OT_Suspicious_Port_Scanning_Activities',
            'eventName': 'OT_Suspicious_Port_Scanning_Activities',
            'sev': 'MEDIUM',
            'c': scan_n,
        }] if scan_n else []),
        'malware': [],
        'inc_by_sev': inc_by_sev,
        'inc_new_by_sev': inc_by_sev,
        'inc_by_status': inc_by_status,
        'inc_by_reso': inc_by_reso,
        'inc_daily_sev': inc_daily_sev,
        'inc_new_daily_sev': inc_daily_sev,
        'inc_hourly': [],
        'inc_top_rules': inc_top_rules,
        'inc_by_category': [],
        'inc_top_titles': inc_top_titles,
        'inc_top_hosts': inc_top_hosts,
        'inc_top_src_ip': inc_top_src_ip,
        'inc_top_dest_ip': inc_top_dest_ip,
        'inc_top_users': [],
        'inc_latest_high': [],
        'inc_tactics_raw': [],
        'inc_techniques_raw': [],
        'inc_by_org': [],
        'inc_top_count_high': [],
        'cmdb_count': [{'c': len(cmdb_devices)}],
        'cmdb_vendor_model': cmdb_vendor_model,
        'cmdb_discover': [{'discover_method': 'LOG', 'c': len(cmdb_devices)}],
        'cmdb_orgs': [],
        'cmdb_all_orgs': [],
        'cmdb_devices': cmdb_devices,
        'cmdb_fortios': cmdb_fortios,
        'cmdb_status': [],
        'health': [],
        'storage_type': [],
        'fsm_users': [],
        'malware_ip_count': [{'c': 0}],
        'ext_rep_count': [],
        'risky_devices': raw.get('top_10_risky_devices') or {},
        'risky_users': raw.get('top_10_risky_users') or {},
        'ndr_virus_top': [],
        'ndr_pairs': talkers[:10],
        'iocs': [],
        'rep_ips': [],
        'rep_pg': [],
        'related_summary': {},
        'trigger_tool_errors': {},
        'picks_raw': picks,
        'exposure_raw': {},
        'needles': needles,
        'talkers': talkers,
        'policies': raw.get('ot_related_policies_detail') or raw.get('ot_related_policies') or [],
        'fdc_modbus': fdc,
        'derived': {
            'days': DAYS_N,
            'span_zh': SPAN_ZH,
            'wk': WK,
            'lang': LANG,
            'fam': 'Siemens PLC Start/Stop',
            'fam_n': plc_n,
            'fam_pct': plc_pct,
            'fam_pct_zh': f'{plc_pct:.0f}%' if plc_pct else '—',
            'fam_re': fam_re,
            'fam_top_src': (top_rept.get('ip') or '172.16.0.1'),
            'fam_top_src_c': plc_n,
            'picks': picks,
            'exposure': None,
            'deep_story': deep_story,
            'alias_notes': [],
            'findings': findings,
            'compliance': compliance,
            'limits': limits,
            'title': TITLE_DOC,
            'hkci_disclaimer': disclaimer,
            'full_days': full_days,
            'lead_html': lead_html,
            'ev_story_html': ev_story_html,
            'tr_story_html': tr_story_html,
            'au_story_html': au_story_html,
            'dns_story_html': dns_story_html,
            'cfg_story_html': cfg_story_html,
            'inc_story_html': inc_story_html,
            'risk_story_html': risk_story_html,
            'win_start': start_disp,
            'win_end': end_disp,
            'win_label': f'{start_disp} 至 {end_disp} HKT',
            'fail_ext_n': fail_n + remote_n + ext_n,
        },
    }
    data.update(details)

    queried = raw.get('queried_at_hkt') or ''
    q_hkt = queried.replace('T', ' ').replace('+08:00', ' HKT')
    if q_hkt and 'HKT' not in q_hkt:
        q_hkt = q_hkt + ' HKT'

    TITLE = TITLE_SHORT
    meta = {
        'generated_hkt': q_hkt,
        'queried_at_hkt': queried,
        'window': f'{start_disp} to {end_disp} HKT (exclusive upper bound)',
        'days': DAYS_N,
        'start_hkt': start_disp,
        'end_hkt': end_disp,
        'timezone': 'Asia/Hong_Kong (HKT, UTC+8)',
        'tool_version': 'OT 1.5',
        'theme': 'v1.5',
        'lang': LANG,
        'title': TITLE,
        'badge': BADGE,
        'match_scope': raw.get('match_scope'),
        'match_note': raw.get('match_note'),
    }

    flows = build_flows(
        WK=WK, plc_n=plc_n, total=total, end_disp=end_disp, start_disp=start_disp,
        purdue_n=purdue_n, purdue_l35=purdue_l35, purdue_l4=purdue_l4,
        unk_n=unk_n, unk_plc=unk_plc, fdc=fdc,
        outbound=outbound, scan_n=scan_n, scan_srcs=scan_srcs,
        stealth_targets=stealth_targets, scan_dests=scan_dests,
        hourly_all=hourly_all,
    )

    payload = {'meta': meta, 'data': data, 'sources': sources, 'hkci': {'disclaimer': disclaimer, 'framework': hkci.get('framework')}}
    extras = {
        'peak_day': peak.get('day'),
        'peak_count': peak.get('count'),
        'needle_active': sorted(
            ((k, int(v or 0)) for k, v in needles.items() if int(v or 0) > 0),
            key=lambda kv: -kv[1],
        ),
        'rule_count': sum(int(r.get('count') or 0) for r in notable),
        'inc_ot_n': len(ot_incs),
        'inc_ot_open': open_n,
        'cmdb_ot_n': len(cmdb_devices),
        'fdc_modbus': fdc,
        'total_events': total,
        'ilike_ot_n': ilike_n,
        'ilike_ot_high_open': ilike_hi,
        'outbound_n': len(outbound),
        'fail_n': fail_n,
        'remote_n': remote_n,
        'ext_n': ext_n,
        'scan_n': scan_n,
        's7_n': s7_n,
        'plc_n': plc_n,
    }
    payload['extras'] = extras
    payload['fp_notes'] = dict(raw.get('false_positive_notes') or {})
    payload['fp_notes']['title_ilike_ot'] = (
        f"Incident title ILIKE '%OT%' is not genuine OT "
        f"(matches protocol/Remote/Botnet/Protection). Use the {len(ot_incs)} OT-IP incidents instead. "
        f"Period total {ilike_n} (including {ilike_hi} HIGH Open). "
        + (('Examples: ' + '; '.join(fp_examples[:4]) + '.') if fp_examples else '')
    )
    payload['findings'] = findings
    payload['flows'] = flows
    return payload, flows


def _sev_sentence(sev):
    parts = []
    has_high = False
    for r in sev:
        label = r.get('severity') or '空白'
        if not str(label).strip():
            label = '空白'
        parts.append(f'{label} {fmt_n(r.get("count") or 0)}')
        if str(r.get('severity') or '').upper() in ('HIGH', 'CRITICAL'):
            has_high = True
            if int(r.get('count') or 0) == 0:
                has_high = False
    if not parts:
        return ''
    s = '嚴重度：' + '、'.join(parts) + '。'
    if not has_high:
        s += '<b>沒有 HIGH 或 CRITICAL OT 事件</b>。'
    return s


def build_flows(**kw):
    WK = kw.get('WK') or kw.get('wk') or ('近' + (os.environ.get('FORTISIEM_SPAN_ZH') or '三日'))
    plc_n = kw['plc_n']
    end_disp = kw['end_disp']
    start_disp = kw['start_disp']
    purdue_n = kw['purdue_n']
    purdue_l35 = kw['purdue_l35']
    purdue_l4 = kw['purdue_l4']
    unk_n = kw['unk_n']
    unk_plc = kw['unk_plc']
    fdc = kw['fdc']
    outbound = kw['outbound']
    scan_n = kw['scan_n']
    scan_srcs = kw['scan_srcs']
    stealth_targets = kw['stealth_targets']
    scan_dests = kw['scan_dests']

    last_seen_default = end_disp + ' HKT'
    flows = []
    if plc_n:
        flows.append({
            'id': 'AF01',
            'sev': 'MEDIUM',
            'name': 'PLC Start/Stop 遙測（展示環境）',
            'title': 'Siemens PLC Start/Stop 狀態變更',
            'count': plc_n,
            'last_seen': last_seen_default,
            'why': f'主導{WK} OT 事件；報告來源 HOST-172.16.0.1（S7-1200 PLC HK DEMO）。屬持續展示／實驗室遙測，需核對維護或展示窗口，而非逕行當成入侵。',
            'meta': f'事件類型 Siemens_PLC_Start_Stop_Status_Change · {fmt_n(plc_n)} 筆 · MEDIUM · 報告裝置 HOST-172.16.0.1',
            'stages': [
                {'k': 'actor', 'label': '展示 / 工程端', 'known': False},
                {'k': 'host', 'label': 'HOST-172.16.0.1', 'known': True},
                {'k': 'action', 'label': 'PLC Start/Stop', 'known': True},
                {'k': 'target', 'label': 'S7-1200 HK DEMO', 'known': True},
                {'k': 'action', 'label': 'SIEM 規則命中', 'known': True},
            ],
        })
    if purdue_n:
        flows.append({
            'id': 'AF02',
            'sev': 'MEDIUM',
            'name': 'Purdue 分層越界訊號',
            'title': 'L3.5→L3 / L4→L3.5 政策告警',
            'count': purdue_n,
            'last_seen': last_seen_default,
            'why': '分段政策訊號，主要來源 172.16.0.114，並非已確認攻擊。',
            'meta': f'PH_RULE_TRAFFIC_NOT_L35_TO_L3 ×{fmt_n(purdue_l35)} + PH_RULE_TRAFFIC_NOT_L4_TO_L35 ×{fmt_n(purdue_l4)} · 來源 172.16.0.114',
            'stages': [
                {'k': 'actor', 'label': 'SRC 172.16.0.114', 'known': True},
                {'k': 'action', 'label': 'L4 / L3.5 跨越', 'known': True},
                {'k': 'host', 'label': '分段政策規則', 'known': True},
                {'k': 'target', 'label': 'L3 / L3.5 資產', 'known': False},
                {'k': 'action', 'label': '政策告警', 'known': True},
            ],
        })
    if unk_n:
        flows.append({
            'id': 'AF03',
            'sev': 'MEDIUM',
            'name': '未解析 Modbus holding-register',
            'title': 'Unknown_EventType 解析空隙',
            'count': unk_plc or unk_n,
            'last_seen': last_seen_default,
            'why': f'{fmt_n(unk_plc or unk_n)} 筆未解析 Modbus holding-register 來自 172.16.0.1（S7-1200 PLC HK DEMO），屬解析器空隙而非已確認 Modbus Write 濫用。本期 FDC Modbus 計數為 {fmt_n(fdc)}。',
            'meta': f'Unknown_EventType ×{fmt_n(unk_plc or unk_n)} · 報告裝置 HOST-172.16.0.1 · FortiDeceptor Modbus = {fmt_n(fdc)}',
            'stages': [
                {'k': 'actor', 'label': '172.16.0.1 PLC', 'known': True},
                {'k': 'action', 'label': 'Modbus holding reg', 'known': True},
                {'k': 'host', 'label': '未解析日誌', 'known': True},
                {'k': 'target', 'label': 'Unknown_EventType', 'known': True},
                {'k': 'action', 'label': '需補 parser', 'known': True},
            ],
        })
    if outbound:
        top = outbound[0]
        last = (top.get('last_seen') or end_disp) + (' HKT' if 'HKT' not in str(top.get('last_seen') or '') else '')
        srcs = sorted({r.get('src') or r.get('src_ip_addr') for r in outbound})
        flows.append({
            'id': 'AF04',
            'sev': 'HIGH',
            'name': 'OT 鄰近主機大流量出站',
            'title': '調查 ' + ' / '.join(srcs) + ' 出站',
            'count': len(outbound),
            'last_seen': last,
            'why': (
                f'優先調查項：#{top.get("incident_id")} {top.get("src") or top.get("src_ip_addr")} → {top.get("dest_ip_addr")} 約 {fmt_bytes(top.get("bytes"))}'
                f'（{top.get("last_seen")}）。共 {fmt_n(len(outbound))} 宗出站事故。未見 Internet 直連進入 OT 網段。'
            ),
            'meta': f'事故 #{top.get("incident_id")} MEDIUM {top.get("status")} · {fmt_bytes(top.get("bytes"))} · {top.get("last_seen")} HKT · 共 {fmt_n(len(outbound))} 宗',
            'stages': [
                {'k': 'actor', 'label': f'SRC {top.get("src") or top.get("src_ip_addr")}', 'known': True},
                {'k': 'host', 'label': 'OT 鄰近網段', 'known': True},
                {'k': 'action', 'label': '大流量出站', 'known': True},
                {'k': 'target', 'label': str(top.get('dest_ip_addr') or '外部'), 'known': bool(top.get('dest_ip_addr'))},
                {'k': 'action', 'label': '需核對用途', 'known': False},
            ],
        })
    if scan_n:
        ts = scan_srcs[0] if scan_srcs else {}
        last = (ip_clean(ts.get('last_t')) or end_disp)
        if last and 'HKT' not in last:
            last = last[:16] + ' HKT' if len(last) >= 16 else last + ' HKT'
        tgt = ' / '.join(stealth_targets) if stealth_targets else '目的地常缺'
        flows.append({
            'id': 'AF05',
            'sev': 'MEDIUM',
            'name': 'OT 標籤 Port Scan（目的地常缺）',
            'title': f'OT_Suspicious_Port_Scanning ×{fmt_n(scan_n)}',
            'count': scan_n,
            'last_seen': last,
            'why': (
                '報告來源 SIEM.fortinethk.com，'
                + ('事件列目的地往往空白。' if not scan_dests else '事件列有部分目的地。')
                + (f'相關 HIGH stealth-scan 事故目標為 {"/".join(stealth_targets)}（IT/SIEM 邊緣），未見進入 172.16.0.x。' if stealth_targets else '')
                + '不要當作 OT 網段失陷。'
            ),
            'meta': f'規則 OT_Suspicious_Port_Scanning_Activities · {fmt_n(scan_n)} 筆 MEDIUM · 例來源 {ip_clean(ts.get("src")) or "—"}（{ts.get("c") or ""} 筆）',
            'stages': [
                {'k': 'actor', 'label': f'SRC {ip_clean(ts.get("src")) or "外部"}', 'known': bool(ts.get("src"))},
                {'k': 'action', 'label': 'Stealth / port scan', 'known': True},
                {'k': 'host', 'label': 'SIEM.fortinethk.com', 'known': True},
                {'k': 'target', 'label': '目的地常缺' if not scan_dests else tgt, 'known': bool(scan_dests)},
                {'k': 'action', 'label': '未見入 172.16.0.x', 'known': True},
            ],
        })
    return flows
