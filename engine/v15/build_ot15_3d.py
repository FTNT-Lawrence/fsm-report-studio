#!/usr/bin/env python3
"""Build FortiSIEM 3-day OT/IoT report in v1.5 ZH-light format.

Reuses the v1.3 ECharts 7-day base chrome + v1.5 art/flow overlay + apply_light.
Does not overwrite 7-day SIEM HTML or 5-day OT 1.3 files.
Does not query FortiSIEM.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import sys
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone, timedelta

_V15_DIR = pathlib.Path(__file__).resolve().parent
if str(_V15_DIR) not in sys.path:
    sys.path.insert(0, str(_V15_DIR))
from ot15_data import build_payload as build_payload_data

ENGINE = pathlib.Path(os.environ.get('FORTISIEM_ENGINE_DIR') or pathlib.Path(__file__).resolve().parents[1])
ROOT = pathlib.Path(os.environ.get('FORTISIEM_REPORT_ROOT') or ENGINE)
V15 = ENGINE / 'v15'
BASE = pathlib.Path(os.environ.get('FORTISIEM_BASE_HTML') or (ROOT / 'v15' / '_base_v13_7day.html'))
if not BASE.exists():
    BASE = V15 / '_base_v13_7day.html'
COLLECT = pathlib.Path(os.environ.get('FORTISIEM_OT_JSON') or (ROOT / 'ot-collect.json'))
_hkci_default = ENGINE / 'assets' / 'ot-5d-embed-v13.json'
if not _hkci_default.exists():
    _hkci_default = ROOT / 'ot-5d-embed-v13.json'
HKCI_SRC = pathlib.Path(os.environ.get('FORTISIEM_HKCI_JSON') or _hkci_default)
OUT = pathlib.Path(os.environ.get('FORTISIEM_OT_OUT') or (ROOT / 'fortisiem-ot-iot-report-v1.5.html'))
OUT_DATA = pathlib.Path(os.environ.get('FORTISIEM_OT_EMBED') or (ROOT / 'ot-v15-embed.json'))
OUT_SUM = pathlib.Path(os.environ.get('FORTISIEM_OT_SUMMARY') or (ROOT / 'ot-v15-summary.json'))

HKT = timezone(timedelta(hours=8))
THEME = (os.environ.get('FORTISIEM_THEME') or 'light').strip().lower()
LANG = (os.environ.get('FORTISIEM_LANG') or 'zh').strip().lower()
SPAN_ZH = (os.environ.get('FORTISIEM_SPAN_ZH') or '三日').strip()
SPAN_EN = (os.environ.get('FORTISIEM_SPAN_EN') or '3-Day').strip()
THEME_LABEL = 'Light' if THEME == 'light' else 'Dark'
WK = '近' + SPAN_ZH
if LANG == 'en':
    TITLE = f'FortiSIEM {SPAN_EN} OT Security Report'
    TITLE_DOC = f'{TITLE} · v1.5 · {THEME_LABEL}'
else:
    TITLE = f'FortiSIEM {SPAN_ZH} OT 安全報告'
    TITLE_DOC = f'{TITLE} · v1.5 · {THEME_LABEL}'
BADGE = (os.environ.get('FORTISIEM_BADGE') or '').strip() or f"OT · {SPAN_EN.replace('-Day', 'D')}"

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


def ip_clean(s):
    if s is None:
        return None
    t = str(s)
    if t.lower().startswith('::ffff:'):
        t = t[7:]
    return t


def esc(s):
    return (str(s) if s is not None else '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


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
    """Minimal get_incident_by_id-shaped object for the deep-dive renderer."""
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


def build_payload(raw: dict) -> dict:
    ot_incs = [slim_inc(r) for r in (raw.get('incidents_touching_ot_ips') or [])]
    needles = raw.get('protocol_needle_breakdown') or {}
    daily = raw.get('daily_trend_hkt') or []
    hourly = raw.get('hourly_today_hkt') or []
    peak = max(daily, key=lambda x: x.get('count') or 0) if daily else {'day': '—', 'count': 0}
    types = raw.get('top_event_types') or []
    repts = raw.get('top_reporting_devices') or []
    sev = raw.get('severity_breakdown') or []

    ev_per_day = [{'day': r['day'], 'c': int(r['count'])} for r in daily]
    ev_heatmap = [
        {'day': '2026-11-10', 'hr': int(r['hour']), 'c': int(r['count'])}
        for r in hourly
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
            'last': '2026-11-10T18:16:00+08:00',
        }
        ev_top_rept.append({k: item[k] for k in ('reptDevName', 'ip', 'model', 'c')})
        ev_rept_list.append(item)

    ev_top_src = [{'ip': ip_clean(r.get('ip')), 'c': int(r.get('count') or 0)} for r in (raw.get('top_src') or [])]
    ev_top_dst = [{'ip': ip_clean(r.get('ip')), 'c': int(r.get('count') or 0)} for r in (raw.get('top_dst') or [])]

    ev_sev_daily = [{'day': r['day'], 'sev': 'ALL', 'c': int(r['count'])} for r in daily]

    # Hourly EPS only where we have counts (11-10, window ends 18:16)
    eps_hourly = []
    for r in hourly:
        h = int(r['hour'])
        sec = 16 * 60 if h == 18 else 3600
        eps_hourly.append({
            'h': f'2026-11-10T{h:02d}:00:00+08:00',
            'eps': round(int(r['count']) / sec, 4),
        })

    unparsed = []
    for r in (raw.get('unknown_eventtype_breakdown') or []):
        unparsed.append({'reptDevName': r.get('reptDevName'), 'c': int(r.get('c') or 0)})

    # CMDB: OT-relevant + related FortiOS; exclude simulated/log security devices
    by_name_ip = {}
    for src in (raw.get('cmdb_ot_ish') or []) + (raw.get('cmdb_event_hosts') or []) + (raw.get('cmdb_fortios') or []):
        name = src.get('name')
        if not name or name in SIMULATED_CMDB:
            continue
        ip = ip_clean(src.get('access_ip'))
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
    # Ensure the six OT-relevant assets are present even if only in the allow list
    for name, ip, vendor, model in OT_CMDB_ALLOW:
        if not any(d['name'] == name and d['access_ip'] == ip for d in by_name_ip.values()):
            by_name_ip[(name, ip)] = {
                'name': name, 'access_ip': ip, 'vendor': vendor, 'model': model,
                'discover_method': 'LOG', 'version': None, 'hw_serial_no': None,
                'discovered': None, 'created': None, 'id': None, 'asset_weight': 1,
            }
    cmdb_devices = list(by_name_ip.values())
    # Keep OT-relevant first
    order = {n: i for i, (n, *_rest) in enumerate(OT_CMDB_ALLOW)}
    cmdb_devices.sort(key=lambda d: (order.get(d['name'], 100), d['name']))

    cmdb_fortios = [d for d in cmdb_devices if d.get('model') == 'FortiOS' or 'FortiGate' in (d.get('name') or '')]
    # Prefer collected fortios field shapes
    if raw.get('cmdb_fortios'):
        cmdb_fortios = []
        for r in raw['cmdb_fortios']:
            if r.get('name') in SIMULATED_CMDB:
                continue
            cmdb_fortios.append({
                'name': r.get('name'),
                'access_ip': ip_clean(r.get('access_ip')),
                'vendor': r.get('vendor'),
                'model': r.get('model'),
                'version': r.get('version'),
                'hw_serial_no': r.get('hw_serial_no'),
                'discover_method': r.get('discover_method') or 'LOG',
            })

    vend_ctr = Counter((d.get('vendor') or '—', d.get('model') or '—') for d in cmdb_devices)
    cmdb_vendor_model = [{'vendor': v, 'model': m, 'c': c} for (v, m), c in vend_ctr.most_common()]

    # Incidents: ONLY the 44 OT-IP incidents (not ILIKE %OT%)
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
            'category': 'Security' if 'Outgoing' in name or 'DNS' in name or 'Config' in name else 'Availability',
            'high': c if sev_name == 'HIGH' else 0,
            'medium': c if sev_name == 'MEDIUM' else 0,
            'low': c if sev_name == 'LOW' else 0,
            'c': c,
            'open': int(rule_open[name]),
        })

    # hosts / src / dst from the 44
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

    # No HIGH OT-IP incidents
    inc_latest_high = []
    inc_top_count_high = []

    # Config: gateway change + wireless rogue change count
    cfg_types = []
    notable = raw.get('notable_rule_hits') or []
    for r in notable:
        if 'wireless-rogue' in (r.get('eventType') or '') or 'Config' in (r.get('eventName') or ''):
            cfg_types.append({
                'eventType': r.get('eventType'),
                'eventName': r.get('eventName'),
                'c': int(r.get('count') or 0),
            })
    row_554 = lookup_row(ot_incs, 597554)
    cfg_recent = []
    if row_554:
        cfg_recent.append({
            'phRecvTime': '2026-11-09T17:09:00+08:00',
            'reptDevName': 'FortiGateRugged-70G-5G-Dual',
            'user': 'admin',
            'eventType': 'FortiGate: Config Change Detected',
            'raw': row_554.get('incident_title') or '',
        })
    cfg_by_dev_user = [
        {'reptDevName': 'FortiGateRugged-70G-5G-Dual', 'user': 'admin', 'c': 1}
    ] if row_554 else []

    # Auth / remote / external: honestly empty/zero
    auth_daily = [{'day': r['day'], 'success': 0, 'failure': 0} for r in daily]
    days_only = [r['day'] for r in daily]

    # Unparsed + Siemens talkers for traffic context (no invented deny split)
    talkers = []
    for r in (raw.get('top_talker_pairs') or []):
        talkers.append({
            'src': ip_clean(r.get('src')) or '(empty)',
            'dst': ip_clean(r.get('dst')) or '(empty)',
            'c': int(r.get('count') or 0),
        })

    # New CMDB in window (simulated) — notes only, not cmdb_devices
    new_devs = raw.get('cmdb_new_in_window') or []
    new_note = '、'.join(
        f"{r.get('name')} ({ip_clean(r.get('access_ip'))}, {r.get('created_hkt')})"
        for r in new_devs if r.get('name')
    )

    findings = [
        {
            'lvl': 'medium',
            'title': 'OT/IoT 流量脈衝：29,110 筆，以 demo PLC 遙測為主',
            'body': (
                '視窗 2026-11-08 00:00 至 2026-11-10 18:16 HKT 共 <b>29,110</b> 筆 OT/IoT 相關事件：'
                '11-08 <b>71</b>、11-09 <b>7,935</b>、11-10 <b>21,104</b>（至 18:16，當日為不完整日）。'
                '11-10 小時脈衝幾乎平坦（約 1,109–1,184 筆/小時）；18:00 僅 318 筆因為視窗於 18:16 結束。'
                '主導類型 Siemens_PLC_Start_Stop_Status_Change <b>17,442</b>，報告來源 HOST-172.16.0.1'
                '（訊息識別為 SIEMENS S7-1200 PLC HK DEMO）。'
                '嚴重度：MEDIUM 19,708、LOW 5,610、空白 3,792；<b>沒有 HIGH 或 CRITICAL OT 事件</b>。'
                '星期日低量其後上升，符合實驗室／展示環境啟動後嘅持續 PLC 遙測，而唔係爆發式入侵。'
            ),
            'todo': '核對展示／維護時段是否預期；唔好單憑 11-10 全日筆數解讀為入侵尖峰。',
        },
        {
            'lvl': 'high',
            'title': '跟進 OT 鄰近 IP 異常大流量出站與 DNS',
            'body': (
                '需調查嘅 Open MEDIUM 事故：'
                '<b>#597664</b> <span class="mono">172.16.0.116</span> → 61.244.242.115 約 136MB（11-10 12:43 HKT；'
                '此主機不在今次 OT CMDB 子集）；'
                '<b>#597619 / #597620</b> 同一來源 → Fastly 199.232.210.172 / 199.232.214.172 各約 53.5MB（11-10 07:10）；'
                '<b>#597577</b> <span class="mono">172.16.0.114</span>（Purdue 對講、Generic Unix）→ 18.65.14.73（AWS）約 83MB（11-09 19:51）；'
                '<b>#597562</b> FortiPAM <span class="mono">172.16.0.112</span>（FPAVULTM26001793）→ 173.243.140.6 約 76MB（11-09 17:11）；'
                '以及 <span class="mono">192.168.27.4</span> 的 DNS 事故 <b>#677</b>（Open，自 10-08，最後 11-10 15:13）與 <b>#597553</b>（11-09 17:00–18:36）。'
                '另有 Workshop-27.2 執照問題 <b>#596693</b> 仍為 Open。'
            ),
            'todo': '盤點 172.16.0.116 並核對出站目的、裝載同變更視窗；同步檢查 192.168.27.4 DNS 與 FortiPAM 出站是否預期備份／更新流量。',
        },
        {
            'lvl': 'medium',
            'title': 'Purdue 分層告警與未解析 Modbus holding-register',
            'body': (
                'Purdue 規則：L3.5→L3（PH_RULE_TRAFFIC_NOT_L35_TO_L3）<b>1,493</b>；'
                'L4→L3.5（PH_RULE_TRAFFIC_NOT_L4_TO_L35）<b>746</b>，來源主要係 <span class="mono">172.16.0.114</span>。'
                '呢啲係分段政策訊號，並非已確認攻擊。'
                '另有 Unknown_EventType <b>3,792</b> 筆，其中幾乎全部（3,790）係來自 172.16.0.1 的未解析 Modbus holding-register 訊息'
                '（SIEMENS S7-1200 PLC HK DEMO）。針刺（可重疊）：Siemens_S7 23,475、PLC 21,232、SCADA 5,110、Modbus 3,790、Purdue 2,239。'
                'S7comm 針刺計數為 0，但 Siemens/S7 活動經 Siemens_S7 + PLC 類型同 172.16.0.2→172.16.0.1:102（×751）可以證實。'
            ),
            'todo': '對照防火牆允許清單與 Purdue 模型；為 172.16.0.1 的 Modbus 日誌補解析器，避免長期以 Unknown_EventType 堆積。',
        },
        {
            'lvl': 'medium',
            'title': 'SSID FTNT-IOT rogue AP 事件（FortiGateRugged）',
            'body': (
                'FortiGateRugged-70G-5G-Dual 錄得 SSID <span class="mono">FTNT-IOT</span> 相關無線 rogue：'
                'off-air 470、detect 23、change 3。'
                '外觀似實驗室／展示 SSID，但仍需確認是否授權。'
                '本視窗 FortiDeceptor Modbus-device 計數為 <b>0</b>，唔好將歷史 FDC Modbus 輪廓當作本期發現。'
            ),
            'todo': '確認 FTNT-IOT 是否授權展示 SSID；未授權 rogue 應定位／抑制，並保留完整無線日誌。',
        },
        {
            'lvl': 'medium',
            'title': '營運：Rugged 閘道變更、日誌延遲與短暫 ping 損失',
            'body': (
                '<b>#597554</b>（Cleared (Rule)，11-09 17:09）admin 將 Rugged 閘道由 <span class="mono">10.8.8.1</span> 改為'
                ' <span class="mono">192.168.108.1</span>；同一分鐘 <b>#597561</b> 錄得該裝置事件量驟降（已清除）。'
                'FDCVM 192.168.27.3 出現多宗「High log receiving delay」，其中一宗於 11-10 14:37 仍為 Open（#597673）。'
                '11-10 11:09 FortiGateRugged 172.16.0.254 與 FortiDeceptor 172.16.0.117 出現短暫 ping 損失／降級，其後全部 Cleared (FortiSIEM)。'
            ),
            'todo': '核對閘道變更是否已批准，並追查 17:09 事件驟降原因；處理仍 Open 的 FDCVM 收日誌延遲。',
        },
        {
            'lvl': 'info',
            'title': '未確認 OT 網段入侵；標題含 OT 的事故計數屬假陽性',
            'body': (
                '對 172.16.0.0/24 與 192.168.27.0/24：失敗登入 0、VPN/RDP/SSH 進入 0、Internet 來源直連 OT 事件 0。'
                '真正觸及 OT IP 的事故為 <b>44</b> 宗，無 HIGH。'
                '以事故標題 ILIKE \'%OT%\' 得出的 217 宗（含 4 宗 HIGH Open）係字串假陽性'
                '（例如 #596890 React RCE「Remote」、#596701 外網 RDP 至 10.255.254.101、#596127 Bladabindi、#596248 Gh0st）。'
                'OT_Suspicious_Port_Scanning_Activities 27 筆，報告來源 SIEM.fortinethk.com，目的地欄位往往空白；'
                '對應 HIGH stealth-scan 事故目標係 192.168.10.99 / 192.168.10.97（IT/SIEM 邊緣），未見進入 172.16.0.x。'
                '<b>初步判斷：未確認有入侵進入 OT 網段</b>；外圍掃描唔應當作 OT 失陷。仍需跟進出站、DNS 與閘道變更。'
            ),
            'todo': '調查清單以 OT-IP 事故同出站／DNS／閘道為準，唔好用標題模糊搜尋擴大 OT 事故範圍。',
        },
    ]

    hkci = {}
    if HKCI_SRC.exists():
        try:
            hkci = (json.loads(HKCI_SRC.read_text(encoding='utf-8')).get('hkci') or {})
        except Exception:
            hkci = {}
    disclaimer = hkci.get('disclaimer') or (
        '本頁將近三日 FortiSIEM OT/IoT 觀測映射至公開的控制主題，僅供內部改善參考，'
        '並非法律意見，亦非斷言貴司屬《保護關鍵基礎設施電腦系統條例》下的指定營運者。'
        '實際法定責任僅適用於被正式指定的關鍵基礎設施營運者及其關鍵電腦系統。'
    )
    disclaimer = disclaimer.replace('本週', '近三日').replace('五日', '三日')

    compliance = [
        {
            'lvl': 'high',
            'ctrl': 'CoP §6.2.21',
            'ctrl_title': '網絡保安／出站監控',
            'title': 'OT 鄰近主機出現異常大流量出站，需優先核對',
            'body': (
                '44 宗觸及 OT IP 的事故中，5 宗為 Abnormal Large Content Outgoing Traffic'
                '（#597664 / #597619 / #597620 / #597577 / #597562），來源包括未入 OT CMDB 子集的 172.16.0.116、'
                'Purdue 對講 172.16.0.114，以及 FortiPAM 172.16.0.112。未見對向 OT 網段的 Internet 直連。'
            ),
            'todo': '將出站允許清單同資產擁有者對齊，並把 172.16.0.116 補入資產清單。',
        },
        {
            'lvl': 'medium',
            'ctrl': 'CoP §6.2.21(c) / OT §6.5.1',
            'ctrl_title': '網域劃分 · Purdue',
            'title': 'L3.5→L3 與 L4→L3.5 政策訊號持續出現',
            'body': (
                f'Purdue 針刺 {needles.get("Purdue") or 0}；規則 L3.5→L3 1,493、L4→L3.5 746，主要來源 172.16.0.114。'
                '屬分段政策檢測，不是已確認攻擊。'
            ),
            'todo': '核對 Purdue 模型與防火牆政策；越級流量應改為 deny 或經 jump host，並文件化允許清單。',
        },
        {
            'lvl': 'medium',
            'ctrl': 'CoP §6.2.16 / OT §6.5.6',
            'ctrl_title': '變更管理',
            'title': 'Rugged 閘道被 admin 更改，並與事件驟降同一分鐘',
            'body': (
                '#597554（11-09 17:09，已清除）記錄閘道 10.8.8.1→192.168.108.1；同分鐘 #597561 事件量驟降（已清除）。'
                'Siemens PLC Start/Stop 17,442 筆屬展示 PLC 遙測，應與變更窗口分開看待。'
            ),
            'todo': '確認閘道變更工單與回滾；PLC Start/Stop 應有展示／維護窗口紀錄。',
        },
        {
            'lvl': 'medium',
            'ctrl': 'CoP §6.2.21(e)',
            'ctrl_title': '無線接達',
            'title': 'FTNT-IOT rogue AP 訊號需確認授權',
            'body': 'FortiGateRugged 上 SSID FTNT-IOT：off-air 470、detect 23、change 3。FortiDeceptor Modbus 計數本期為 0。',
            'todo': '確認是否授權展示 SSID；未授權應抑制／定位，無線接達 OT 區須認證、加密與完整日誌。',
        },
        {
            'lvl': 'medium',
            'ctrl': 'CoP §6.2.9',
            'ctrl_title': '資產管理',
            'title': '172.16.0.116 未入 OT CMDB 子集；部分新裝置屬模擬日誌源',
            'body': (
                'OT 相關資產包括 FortiGateRugged 172.16.0.254、FDCVMSTM 172.16.0.117、FDCVM 192.168.27.3、'
                'HOST-172.16.0.114、FortiPAM 172.16.0.112、Workshop-27.2。HOST-172.16.0.1（S7-1200 demo PLC）主要以事件源出現。'
                + (f' 視窗內新增 CMDB（11-09 13:42–13:47，LOG、公網 IP）：{new_note}。' if new_note else '')
                + '該等名稱似模擬／日誌來源安全裝置，不是新的廠房／PLC 資產（s1-agent 會因 Protection 匹配 %OT% 而誤入 OT-ish 篩選）。'
            ),
            'todo': '為 172.16.0.1 / 172.16.0.116 補資產紀錄；將模擬日誌裝置從 OT 資產清單分開標註。',
        },
        {
            'lvl': 'info',
            'ctrl': '第3類 / 應急',
            'ctrl_title': '監察、偵測與事故分級',
            'title': '外圍掃描存在，但未見進入 OT 網段',
            'body': (
                '27 筆 OT_Suspicious_Port_Scanning 目的地往往空白；相關 HIGH stealth-scan 指向 192.168.10.99/97，而非 172.16.0.x。'
                '失敗登入與遙距登入 OT 網段均為 0。本頁映射僅供內部改善，並非法律意見或指定營運者斷言。'
            ),
            'todo': '保持 OT 規則監控，但分級時區分 IT/SIEM 邊緣掃描與真正觸及 172.16.0.0/24 的事件。',
        },
    ]

    # Deep-dive picks (investigate set)
    pick_ids = [
        (597664, 'OT 鄰近主機（未入 OT CMDB 子集）異常大流量出站約 136MB → 61.244.242.115'),
        (597577, 'Purdue 對講主機 172.16.0.114 出站約 83MB → AWS 18.65.14.73'),
        (597562, 'FortiPAM 172.16.0.112 出站約 76MB → 173.243.140.6'),
        (677, '192.168.27.4 對未授權 DNS 伺服器的過量查詢（Open，跨視窗仍活躍）'),
    ]
    picks = []
    details = {}
    for iid, why in pick_ids:
        row = lookup_row(ot_incs, iid)
        if not row:
            continue
        picks.append({'id': iid, 'why': why, 'ctx': None, 'extra': None})
        details[f'inc_{iid}_detail'] = inc_detail(row)

    deep_story = (
        '揀咗 4 宗最值得跟進、並實際觸及 OT／OT 鄰近位址嘅事故（全部 MEDIUM，無 HIGH）：'
        '未入 CMDB 子集嘅 172.16.0.116 大流量出站、172.16.0.114／FortiPAM 出站，以及 192.168.27.4 DNS。'
        '近三日未見對 OT 網段嘅失敗登入、遙距登入或 Internet 直連；外圍掃描未顯示進入 172.16.0.x。'
        '本期未再抽取完整 trigger raw／外部信譽，個案資料以事故欄位為準。'
    )

    limits = [
        '本報告視窗為絕對香港時間 2026-11-08 00:00 至 2026-11-10 18:16（非滾動 72 小時）；11-10 為不完整日。',
        'OT/IoT 事件匹配採用 token-safe 邏輯（eventType/eventName 詞界；排除 PH_AUDIT%）。',
        '事故主表只用「觸及 OT IP／主機」的 44 宗；不以標題 ILIKE \'%OT%\' 作為 OT 事故總數（該計數含 Remote/Botnet/protocol 假陽性）。',
        '沒有 HIGH/CRITICAL OT 事件；incidents_hi / HIGH 抽樣為空。',
        '11-08、11-09 無小時熱圖原始數據，小時分佈僅覆蓋 11-10 00:00–18:16。',
        '本視窗沒有按日的 OT Permit/Deny 拆帳，流量頁不以企業全域拒絕率解讀 OT。',
        '失敗登入、VPN/RDP/SSH 進入 OT 網段、Internet→OT 事件查詢結果均為 0。',
        'FortiDeceptor Modbus-device 計數為 0，不沿用歷史 FDC Modbus 發現。',
        'S7comm 針刺計數為 0，但 Siemens_S7／PLC 類型與 172.16.0.2→172.16.0.1:102 交通可證實 Siemens/S7 活動。',
        '風險裝置／使用者名單來自組織全域工具，不是 OT 失陷清單。',
        '11-09 13:42–13:47 新增的 pa-fw-01 / cp-fw-01 / s1-agent-01 / cs-falcon-01 / trend-dsa-01 視為模擬／日誌來源，未列入 OT 資產表。',
        '合規頁將觀測映射至公開 HKCI／CoP 控制主題，僅供內部改善參考，並非法律意見或指定營運者斷言。',
        '附錄列出今次已收集查詢；本檔建置時不再連線 Supervisor。',
    ]

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
                'key': err.get('key') or 'mcp_failure',
                'tool': err.get('tool') or 'mcp',
                'query': err.get('query') or '',
                'ok': False,
                'secs': err.get('secs'),
                'error': err.get('error') or str(err),
            })

    window = raw.get('window') or {}
    total = int(raw.get('total_ot_iot_related_events') or 0)
    n_types = len({r.get('eventType') for r in types if r.get('eventType')})
    n_repts = len(ev_rept_list)
    n_ips = len({r.get('ip') for r in ev_rept_list if r.get('ip')})

    data = {
        'ev_total': [{
            'events': total,
            'rept_ips': n_ips,
            'rept_names': n_repts,
            'event_types': n_types,
            'first': window.get('start_hkt') or '2026-11-08T00:00:00+08:00',
            'last': window.get('end_hkt') or '2026-11-10T18:16:00+08:00',
        }],
        'ev_per_day': ev_per_day,
        'ev_heatmap': ev_heatmap,
        'ev_top_types': ev_top_types,
        'ev_by_sev': ev_by_sev,
        'ev_by_cat': [],
        'ev_by_vendor': cmdb_vendor_model and [
            {'reptVendor': r['vendor'], 'reptModel': r['model'], 'c': r['c']} for r in cmdb_vendor_model
        ] or [],
        'ev_top_rept': ev_top_rept,
        'ev_rept_list': ev_rept_list,
        'ev_top_src': ev_top_src,
        'ev_top_dst': ev_top_dst,
        'ev_top_users': [],
        'ev_top_dport': [{'port': 102, 'ipProto': 6, 'c': 751}],
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
        'security_attacks': [{
            'eventType': 'OT_Suspicious_Port_Scanning_Activities',
            'eventName': 'OT_Suspicious_Port_Scanning_Activities',
            'sev': 'MEDIUM',
            'c': 27,
        }],
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
        'inc_latest_high': inc_latest_high,
        'inc_tactics_raw': [],
        'inc_techniques_raw': [],
        'inc_by_org': [],
        'inc_top_count_high': inc_top_count_high,
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
        'fdc_modbus': int(raw.get('fortideceptor_modbus_count') or 0),
        'derived': {
            'days': 3,
            'span_zh': '三日',
            'wk': '近三日',
            'lang': 'zh',
            'fam': 'Siemens PLC Start/Stop',
            'fam_n': 17442,
            'fam_pct': (17442 / total * 100) if total else 0,
            'fam_pct_zh': '約六成',
            'fam_re': r'Siemens PLC Start Stop',
            'fam_top_src': '172.16.0.1',
            'fam_top_src_c': 17442,
            'picks': picks,
            'exposure': None,
            'deep_story': deep_story,
            'alias_notes': [
                {
                    'serial': 'simulated-log',
                    'name': 'pa-fw-01 / cp-fw-01 / s1-agent-01 / cs-falcon-01 / trend-dsa-01',
                }
            ] if False else [],
            'findings': findings,
            'compliance': compliance,
            'limits': limits,
            'title': TITLE_DOC,
            'hkci_disclaimer': disclaimer,
        },
    }
    data.update(details)

    queried = raw.get('queried_at_hkt') or '2026-11-10T18:18:29+08:00'
    # Display form
    q_hkt = queried.replace('T', ' ').replace('+08:00', ' HKT')
    if 'HKT' not in q_hkt:
        q_hkt = q_hkt + ' HKT'

    meta = {
        'generated_hkt': q_hkt,
        'queried_at_hkt': queried,
        'window': (
            '2026-11-08 00:00 to 2026-11-10 18:16 HKT '
            '(absolute calendar window, not rolling 72h)'
        ),
        'days': 3,
        'start_hkt': '2026-11-08 00:00',
        'end_hkt': '2026-11-10 18:16',
        'timezone': 'Asia/Hong_Kong (HKT, UTC+8)',
        'tool_version': 'OT 1.5',
        'theme': 'v1.5',
        'lang': 'zh',
        'title': TITLE,
        'badge': BADGE,
        'match_scope': raw.get('match_scope'),
        'match_note': raw.get('match_note'),
        # no supervisor field
    }

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
        'cmdb_ot_n': sum(1 for d in cmdb_devices if d['name'] in {n for n, *_ in OT_CMDB_ALLOW}),
        'fdc_modbus': payload['extras'].get('fdc_modbus'),
        'total_events': total,
    }
    payload['extras'] = extras
    payload['fp_notes'] = dict(raw.get('false_positive_notes') or {})
    payload['fp_notes']['title_ilike_ot'] = (
        "Incident title ILIKE '%OT%' is not genuine OT "
        "(matches protocol/Remote/Botnet/Protection). Use the 44 OT-IP incidents instead. "
        "Examples of false positives: 596890 React RCE, 596701 RDP 119.247.91.227→10.255.254.101, "
        "596127 Bladabindi, 596248 Gh0st."
    )
    payload['findings'] = findings
    return payload


# ---------------- v1.5 chrome / flows (adapted from build_v15_7d.py) ----------------

FLOWS = []  # filled in main() from collect

EDGE = {'actor': '#7B61FF', 'host': '#00E5FF', 'action': '#FFB020', 'target': '#FF4D6A'}
CHIP = {'CRITICAL': '#FF4D6A', 'CRIT': '#FF4D6A', 'HIGH': '#FFB020', 'MEDIUM': '#00E5FF', 'MED': '#00E5FF', 'LOW': '#6B7A8F'}


def flow_svg(flow, idx):
    stages = flow['stages'][:6]
    n = len(stages)
    W, H = 980, 86
    pad, gap, node_h = 18, 14, 30
    node_w = (W - pad * 2 - (n - 1) * gap) // n
    total = n * node_w + (n - 1) * gap
    start_x = pad + max(0, (W - pad * 2 - total) // 2)
    y = 28
    nodes, arrows = [], []
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


def art_css() -> str:
    # Identical tokens to build_v15_7d.py (apply_light rewrites them)
    return (V15 / 'build_v15_7d.py').read_text(encoding='utf-8').split("ART_CSS = r'''", 1)[1].split("'''", 1)[0]


def patch_shell(html: str) -> str:
    html = html.replace(
        '<title>FortiSIEM 安全回顧 · v1.3</title>',
        f'<title>{TITLE_DOC}</title>',
    )
    html = html.replace(
        'FORTI<em>SIEM</em> // 週報',
        f'FORTI<em>SIEM</em> // {SPAN_ZH} OT · v1.5',
    )
    html = html.replace(
        '<a href="#findings">發現與建議</a>',
        '<a href="#flows">攻擊流程</a><a href="#findings">發現與建議</a>',
    )
    html = html.replace(
        '<a href="#compliance">合規</a>',
        '<a href="#compliance">HKCI 合規</a>',
    )
    # Hero title / lead / KPI (avoid 7-day SIEM narrative and NaN deny %)
    html = html.replace(
        '<div class="eyebrow">FortiSIEM ${SPAN}安全回顧 · Super 組織 · 香港時間 HKT</div>',
        f'<div class="eyebrow">FortiSIEM {SPAN_ZH} OT 安全報告 · 香港時間 HKT</div>',
    )
    html = html.replace(
        '<h1>${SPAN} <span class="hl">${wan(T.events||0)}</span> 筆事件，<br>${esc(X.fam||"—")} 告警佔咗<span class="hl">${esc(X.fam_pct_zh||"—")}</span>事故</h1>',
        f'<h1>{TITLE}</h1>',
    )
    old_lead = '<p class="lead">${esc(dl(peak&&peak.day))} 係${WK}最忙嘅一日（${wan(peak?peak.c:0)} 筆）。期內共開出 ${fmt(incTotal)} 宗事故，${pct(incOpen,incTotal)} 仍然未處理；其中 ${pct(ndrInc,incTotal)} 由 ${esc(X.fam||"—")} 規則觸發。</p>'
    new_lead = '<p class="lead">${X.lead_html||""}</p>'
    if old_lead not in html:
        raise SystemExit('hero lead template not found')
    html = html.replace(old_lead, new_lead)
    html = html.replace(
        '<div><b>${sh(incSev.HIGH||0)}</b><span>高嚴重度 HIGH</span></div><div><b>${denyR.toFixed(1)}%</b><span>流量被拒絕</span></div>',
        '<div><b>${sh(incSev.HIGH||0)}</b><span>OT 事故 HIGH</span></div><div><b>${fmt((X.fail_ext_n!=null)?X.fail_ext_n:0)}</b><span>失敗登入 / 外連入 OT</span></div>',
    )
    html = html.replace(
        ' --mode READ-ONLY`)}"',
        ' --mode pulse`)}"',
    )
    html = html.replace(
        ' · ${esc(M.supervisor)} · 經 FortiSIEM MCP 唯讀查詢',
        ' · FortiSIEM MCP',
    )
    html = html.replace(
        '<span class="chip"><i style="background:#ffb000"></i>唯讀 Read-only</span>',
        '',
    )
    # SPAN / WK fallbacks
    html = html.replace("const SPAN=X.span_zh||'七日'", f"const SPAN=X.span_zh||'{SPAN_ZH}'")
    html = html.replace("const WK=X.wk||'本週'", f"const WK=X.wk||'{WK}'")

    # Section stories that would otherwise keep 7-day SIEM wording or break on empty series
    ev_story_old = '`最繁忙嘅一個鐘係 <b>${esc(busy&&busy.day)} ${busy?busy.hr:\'\'}:00</b>（${fmt(busy&&busy.c)} 筆）。<b>${esc(r0.reptDevName)}</b> 一部機已經貢獻 ${pct(r0.c,T.events)} 事件；最多嘅事件類型係 <span class="mono">${esc(topType.eventType)}</span>（${pct(topType.c,T.events)}）。EPS 最高約 ${epsMax?epsMax.eps.toFixed(1):\'—\'}，10-18 下午之後明顯回落。`'
    ev_story_new = '`${X.ev_story_html||""}`'
    if ev_story_old not in html:
        raise SystemExit('events story template not found')
    html = html.replace(ev_story_old, ev_story_new)

    tr_story_old = '`${SPAN}內 ${wan(permTot)} 筆流量獲放行、${wan(denyTot)} 筆被拒絕（${denyR.toFixed(1)}%）。拒絕比例最高嗰日係 <b>${esc(dl(dMax&&dMax.day))}</b>（${dMax?dMax.r.toFixed(1):\'—\'}%${dMax&&evDay.length&&dMax.day===evDay[evDay.length-1].day?\'，當日為不完整日\':\'\'}）。被拒絕最多嘅來源係 <span class="mono">${esc(((D.traffic_deny_top_src||[])[0]||{}).ip)}</span>，目的埠以 <b>53（DNS）</b>居首。`'
    tr_story_new = '`${X.tr_story_html||""}`'
    if tr_story_old not in html:
        raise SystemExit('traffic story template not found')
    html = html.replace(tr_story_old, tr_story_new)
    html = html.replace(
        "head('traffic','04',G.teal,'防火牆流量','FortiGate allowed vs denied'",
        "head('traffic','04',G.teal,'OT 網段流量','OT talkers · Intra-SCADA · S7:102'",
    )

    au_story_old = '`成功登入 ${fmt(authS)} 次，失敗只有 <b>${authF}</b> 次。成功登入入面 ${pct((at[0]||{}).success,authS)} 係 <span class="mono">${esc((at[0]||{}).eventType)}</span>（SIEM 主機上嘅 su 切換）；FortiGate 管理員登入主要來自 <span class="mono">${esc(((D.admin_logins||[])[0]||{}).src)}</span>。`'
    au_story_new = '`${X.au_story_html||""}`'
    if au_story_old not in html:
        raise SystemExit('auth story template not found')
    html = html.replace(au_story_old, au_story_new)
    html = html.replace(
        "head('auth','05',G.amber,'登入與認證','Authentication'",
        "head('auth','05',G.amber,'OT 登入與遙距存取','OT auth & remote access'",
    )

    dns_story_old = '`內部主機直接問公共 DNS 好普遍：<span class="mono">${esc(dtop.ip)} → ${esc(dtop.dns_server)}</span> 一條路已經有 ${wan(dtop.c||0)} 筆。FortiSIEM 規則「End User DNS Queries to Unauthorized DNS Servers」觸發 ${fmt(unauth)} 次，53 埠被拒絕 ${wan(d53)} 筆。`'
    dns_story_new = '`${X.dns_story_html||""}`'
    if dns_story_old not in html:
        raise SystemExit('dns story template not found')
    html = html.replace(dns_story_old, dns_story_new)

    cfg_story_old = '`${SPAN}共有 ${fmt(cfgTot)} 筆設定相關事件。最多變更來自 <span class="mono">${esc(cfgTop[0]&&cfgTop[0][0])}</span>${cfgTop[1]?`，其次係 <span class="mono">${esc(cfgTop[1][0])}</span>`:\'\'}。最近一次記錄喺 ${esc((cr0.phRecvTime||\'\').replace(\'T\',\' \').slice(0,16))} HKT，由 ${esc(cr0.user)} 喺 ${esc(cr0.reptDevName)} 進行（${esc(cr0.eventType)}）。`'
    # The nested template in source may use different quoting. Use a more robust slice replace if needed.
    cfg_story_new = '`${X.cfg_story_html||""}`'
    if cfg_story_old not in html:
        # fallback: regex
        html2, n = re.subn(
            r'\$\{SPAN\}共有 \$\{fmt\(cfgTot\)\} 筆設定相關事件。[\s\S]*?\$\{esc\(cr0\.eventType\)\}\)。`',
            cfg_story_new[1:-1] + '`',
            html,
            count=1,
        )
        if n != 1:
            # show a snippet to debug
            i = html.find('cfgTot')
            raise SystemExit('cfg story template not found, around: ' + html[i-80:i+240])
        html = html2
    else:
        html = html.replace(cfg_story_old, cfg_story_new)

    inc_story_old = '`事故量集中喺 <b>${esc(bS&&bS.hour)} 至 ${esc(bE&&bE.hour)}</b> HKT（每小時 ≥ 100 宗），最高峰係 <b>${esc(dl(incPeak&&incPeak.day))}</b>（${fmt(incPeak&&incPeak.c)} 宗）。${pct(ndrInc,incTotal)} 嚟自 ${esc(X.fam||"—")} 規則，${fmt(tp161)} 宗來源都係 <span class="mono">${esc(X.fam_top_src||"—")}</span>。${pct(incOpen,incTotal)} 仍未處理。`'
    inc_story_new = '`${X.inc_story_html||""}`'
    if inc_story_old not in html:
        raise SystemExit('incidents story template not found')
    html = html.replace(inc_story_old, inc_story_new)
    html = html.replace(
        "head('inc','08',G.coral,'事故','Incidents'",
        "head('inc','08',G.coral,'OT 相關事故','Incidents touching OT IPs'",
    )

    risk_story_old = '`<span class="mono">${esc(rd[0]&&rd[0].entity)}</span> 以 <b>${rd[0]?rd[0].score:\'\'}</b> 分遙遙領先，原因係「${esc(rd[0]&&rd[0].rules[0])}」（${rd[0]?rd[0].n:0} 宗）。其餘設備介乎 ${rd.length>1?rd[rd.length-1].score:\'\'}–${rd.length>1?rd[1].score:\'\'} 分。使用者方面工具只回傳 ${ru.length} 個實體，最高係 <span class="mono">${esc(ru[0]&&ru[0].entity)}</span>（${ru[0]?ru[0].score:\'\'} 分，境外 VPN 登入）。`'
    risk_story_new = '`${X.risk_story_html||""}`'
    if risk_story_old not in html:
        raise SystemExit('risk story template not found')
    html = html.replace(risk_story_old, risk_story_new)
    html = html.replace(
        "head('risk','09',G.amber,'風險實體','Top risky devices & users'",
        "head('risk','09',G.amber,'風險實體（組織全域）','Org-wide risky devices & users'",
    )

    html = html.replace(
        "head('compliance','12',G.lime,'合規建議 ISO 27001','Compliance recommendations','只根據本報告收集嘅數據，對應 Annex A 控制目標；冇推測數字')",
        "head('compliance','12',G.lime,'HKCI 合規對照','HKCI / PCICSO control themes','只根據本報告收集嘅數據映射公開控制主題；並非法律意見或指定營運者斷言')",
    )
    html = html.replace(
        '`以下建議對應 ISO/IEC 27001:2022 Annex A 常見控制（日誌、監控、網絡、存取、變更）。每一條都綁定本報告實際觀察到嘅狀況。`',
        f'`以下將{WK} OT/IoT 觀測映射至《保護關鍵基礎設施電腦系統條例》同 CoP 嘅公開控制主題（資產、分段、變更、無線、出站、偵測），方便內部改善，而非判定合規結果或法定身份。`',
    )

    html = html.replace(
        '<dt>Supervisor</dt><dd>${esc(M.supervisor)}</dd>',
        '<dt>查詢範圍</dt><dd>FortiSIEM MCP（已收集數據；報告不含 Supervisor 位址）</dd>',
    )
    html = html.replace(
        'document.getElementById(\'foot\').innerHTML=`FortiSIEM ${SPAN}安全回顧 · ${esc(M.theme||"")} · 生成於 ${esc(M.generated_hkt)} · 數據來源 FortiSIEM MCP（唯讀）· 圖表 Apache ECharts（已內嵌）`;',
        f'document.getElementById(\'foot\').innerHTML=`FortiSIEM {SPAN_ZH} OT 安全報告 · ${{esc(M.theme||"")}} · 生成於 ${{esc(M.generated_hkt)}} · 數據來源 FortiSIEM MCP · 圖表 Apache ECharts（已內嵌）`;',
    )
    # theme bump inside leftover embedded strings
    html = html.replace('"theme": "v1.3"', '"theme": "v1.5"')
    html = html.replace('"theme":"v1.3"', '"theme":"v1.5"')
    return html


def inject_flows_and_art(html: str) -> str:
    css = art_css()
    html = html.replace('</style>', css + '\n</style>', 1)

    flows_html = '\n'.join(flow_card(f, i) for i, f in enumerate(FLOWS))
    flow_section = f'''
<div class="flows-head">
  <div class="industrial">Attack flows · 3 day OT</div>
  <h2 class="flows-title">攻擊流程</h2>
  <p class="flows-lead">{WK} 5 個 OT/IoT 相關流程（遙測、分段、解析空隙、出站調查、邊緣掃描）。虛線節點 = 數據未直接觀測到嘅階段。節點色：<span class="leg actor">actor</span> <span class="leg host">host</span> <span class="leg action">action</span> <span class="leg target">target</span>。</p>
</div>
<div class="flow-filters">
  <label>篩選</label>
  <select id="flowSev"><option value="ALL">全部嚴重度</option><option value="HIGH">HIGH</option><option value="MEDIUM">MEDIUM</option><option value="LOW">LOW</option></select>
  <span class="industrial">窗口 · __WIN_LABEL__</span>
</div>
<div class="flow-grid">
{flows_html}
</div>
'''
    inject_js = r'''
(function(){
  try{
    document.querySelectorAll('.hero-meta').forEach(el=>{
      el.textContent = el.textContent
        .replace(/\s*·\s*https?:\/\/[0-9.]+[^\s·]*/g,'')
        .replace(/\s*·\s*經 FortiSIEM MCP 唯讀查詢/g,' · FortiSIEM MCP')
        .replace(/READ-ONLY/g,'pulse')
        .replace(/165\.84\.173\.36/g,'');
    });
    document.querySelectorAll('.chip').forEach(el=>{
      const t=el.textContent||'';
      if(/Read-only|唯讀 Read-only|READ-ONLY/i.test(t)) el.remove();
    });
    document.querySelectorAll('.eyebrow').forEach(el=>{
      if(!el.querySelector('.vtag')){
        const tag=document.createElement('span');
        tag.className='vtag';
        tag.textContent='v1.5 · 3D';
        el.appendChild(tag);
      }
    });
  }catch(e){}

  try{
    const raw=JSON.parse(document.getElementById('data').textContent);
    const days=((raw.data||{}).ev_per_day||[]).map(d=>+d.c||0);
    if(days.length){
      const max=Math.max(...days,1);
      document.querySelectorAll('.stat').forEach((el)=>{
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

  const findings=document.getElementById('findings');
  if(!document.getElementById('flows') && findings){
    const sec=document.createElement('section');
    sec.id='flows';
    sec.innerHTML = FLOW_SECTION_PLACEHOLDER;
    findings.parentNode.insertBefore(sec, findings);
    const sevSel=sec.querySelector('#flowSev');
    const apply=()=>{
      const v=sevSel.value;
      sec.querySelectorAll('.flow-card').forEach(c=>{
        c.classList.toggle('is-hidden', v!=='ALL' && c.getAttribute('data-sev')!==v);
      });
    };
    if(sevSel) sevSel.addEventListener('change', apply);
  }

  try{
    const secs=[...document.querySelectorAll('section[id]')];
    const io=new IntersectionObserver(entries=>{
      entries.forEach(en=>{ if(en.isIntersecting){ secs.forEach(s=>s.classList.remove('in-view')); en.target.classList.add('in-view'); }});
    },{threshold:0.18});
    secs.forEach(s=>io.observe(s));
  }catch(e){}
})();
'''
    inject_js = inject_js.replace('FLOW_SECTION_PLACEHOLDER', json.dumps(flow_section, ensure_ascii=False))
    # harden: the placeholder in source was not quoted as a JS expression if we naively replace
    # We used: sec.innerHTML = FLOW_SECTION_PLACEHOLDER;  → sec.innerHTML = "<html...>";
    _inj = '<script>\n' + inject_js.replace('</script>', '<\\/script>') + '\n</script>\n'
    i = html.rfind('</body>')
    if i < 0:
        raise SystemExit('no </body>')
    return html[:i] + _inj + html[i:]


def replace_data(html: str, payload: dict) -> str:
    blob = json.dumps(payload, ensure_ascii=False, separators=(',', ':'), default=str)
    if '</script>' in blob.lower():
        blob = blob.replace('</script>', '<\\/script>').replace('</SCRIPT>', '<\\/SCRIPT>')
    new = '<script id="data" type="application/json">' + blob + '</script>'
    html2, n = re.subn(
        r'<script id="data" type="application/json">[\s\S]*?</script>',
        lambda _m: new,
        html,
        count=1,
    )
    if n != 1:
        raise SystemExit(f'data script replace count={n}')
    return html2


def patch_overlay_3d(html: str) -> str:
    needle = "'五日安全報告':'5-Day Security Report'"
    extra = (
        "'五日安全報告':'5-Day Security Report',"
        "'七日安全報告':'7-Day Security Report',"
        f"'{SPAN_ZH} OT 安全報告':'{SPAN_EN} OT Security Report',"
        f"'{SPAN_ZH} OT · v1.5':'{SPAN_EN} OT · v1.5',"
        f"'{WK}':'Last {SPAN_EN} window',"
        f"'{SPAN_ZH}內':'In {SPAN_EN}'"
    )
    if needle in html and f"'{SPAN_ZH} OT 安全報告'" not in html:
        html = html.replace(needle, extra, 1)
    return html


def smoke(path: pathlib.Path) -> None:
    t = path.read_text(encoding='utf-8')
    if LANG == 'en':
        assert 'lang="en"' in t[:400], 'lang'
    else:
        assert 'lang="zh-HK"' in t[:400], 'lang'
    title = re.search(r'<title>([^<]+)</title>', t).group(1)
    assert title == TITLE_DOC or TITLE in title, title
    assert TITLE in t or TITLE_DOC in t
    if THEME == 'light':
        assert 'theme-light' in t
    assert BADGE in t or 'v1.5' in t or SPAN_ZH in t or SPAN_EN in t
    assert '五日 OT' not in t or SPAN_ZH == '五日'
    assert 'Oct 29 Siemens PLC' not in t
    assert '165.84.173.36' not in t
    assert 'LAWRENCE LAU' not in t
    assert '為 LAWRENCE' not in t
    assert 'plotly.js' not in t.lower() or 'echarts' in t.lower()
    # echarts present (inlined)
    assert 'echarts' in t.lower()
    assert '攻擊流程' in t
    assert 'pageFlows' not in t or 'flows-title' in t
    # findings / flows must come from this collect (titles may vary)
    assert '未確認 OT 網段入侵' in t or '未確認有入侵進入 OT 網段' in t
    assert '假陽性' in t
    assert '攻擊流程' in t

    assert 'layout-fix' in t
    # Short hero lead only (window + count); ticker / repeating meta gone from under h1
    assert '筆 OT/IoT 事件' in t
    assert "class=\"ticker\"" not in t
    assert '資料時段 ${esc(firstT)}' not in t
    assert 'fsm.query --window' not in t
    # contrast tokens (light theme only)
    if THEME == 'light':
        assert "#e8eef5" in t or "'#e8eef5'" in t
        assert "backgroundColor:'rgba(255,255,255,.97)'" in t
        assert "textStyle:{color:'#0E1216'" in t
        cut = t.find('const TT=')
        assert cut > 0
        app = t[cut:]
        assert "inRange:{color:['#e8eef5'" in app or "splitArea:{areaStyle:{color:['#e8eef5','#f0f4f8']}}" in app
        assert "color:['#0c1218','#090d12']" not in app
        assert "inRange:{color:['#0b1a22'" not in app
        assert "backgroundStyle:{color:'#E8ECF0'" in t
    # should not keep 7-day SIEM headline leftovers
    assert 'Remote Desktop from Internet 119.247.91.227' not in t or '假陽性' in t
    # 7-day SIEM volume must not remain
    assert '29997148' not in t
    assert '九日內' not in t
    size = path.stat().st_size
    assert size > 400_000, f'too small: {size}'
    print(f'OK {path}  {size:,} bytes  title={title}')



LAYOUT_CSS = r"""
/* === layout-fix (掛版) === */
:root{--nav-offset:64px;}
html.theme-light nav, body.theme-light nav, nav{
  flex-wrap:nowrap !important;
  white-space:nowrap !important;
  row-gap:4px;
  max-width:100%;
  align-items:center;
  overflow-x:auto;
  overflow-y:hidden;
}
nav .brand{flex:0 1 auto; max-width:42%; overflow:hidden; text-overflow:ellipsis;}
nav a{flex:0 0 auto;}
@media (max-width:1100px){
  html.theme-light nav, body.theme-light nav, nav{
    flex-wrap:wrap !important;
    white-space:normal !important;
    overflow-y:visible;
  }
}
html{scroll-padding-top:var(--nav-offset, 64px) !important;}
section[id]{
  scroll-margin-top:0 !important;
  padding-top:20px;
}
section#overview{padding-top:8px;}
.wrap, .bento, .grid, .hero, .flow-grid{max-width:100%;}
.bento, .grid, .card, .stat, .find, .case, .hero-main, .hero-side{min-width:0;}
.card, .find, .case{overflow:hidden; max-width:100%;}
.card .chart, .chart{max-width:100%; overflow:hidden;}
.tbl-scroll{display:block; width:100%; max-width:100%; overflow-x:auto; -webkit-overflow-scrolling:touch;}
.tbl{overflow:auto; max-width:100%;}
.card .tbl{max-height:none;}
.tbl-scroll, .tbl{
  scrollbar-width:thin;
  scrollbar-color:#9AA3AD transparent;
}
.tbl-scroll::-webkit-scrollbar, .tbl::-webkit-scrollbar{height:8px; width:8px;}
.tbl-scroll::-webkit-scrollbar-thumb, .tbl::-webkit-scrollbar-thumb{background:#C4CCD6; border-radius:4px;}
.tbl-scroll table, .card .tbl-scroll table{
  width:100%;
  min-width:0;
  max-width:100%;
  border-collapse:collapse;
  table-layout:auto;
  font-size:12.5px;
}
th{white-space:nowrap; padding:7px 8px; font-size:11px; letter-spacing:0.02em; overflow:hidden; text-overflow:ellipsis;}
td{padding:6px 8px; overflow-wrap:break-word; word-break:normal; hyphens:none; line-height:1.45;}
td.code, td.nw, td.host-name, .host-name{
  white-space:nowrap;
  overflow-wrap:normal;
  word-break:keep-all;
  overflow:hidden;
  text-overflow:ellipsis;
  max-width:16em;
}
td.code{overflow-wrap:normal !important; word-break:keep-all !important;}
#cmdb table{font-size:12px;}
#cmdb th, #cmdb td{padding:6px 7px;}
#cmdb td:first-child, #cmdb th:first-child{max-width:12.5em;}
#events [data-card="事件類型明細"] td:nth-child(1),
#events [data-card="事件類型明細"] td:nth-child(2){max-width:18em; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
.mono{overflow-wrap:normal; word-break:keep-all;}
.card[data-card="最常見事故標題"] td:first-child,
.card[data-card="規則排行"] td:first-child{
  white-space:normal;
  overflow:visible;
  text-overflow:unset;
  max-width:none;
  overflow-wrap:break-word;
  word-break:normal;
  line-height:1.4;
}
.hero-main p.lead{max-width:100%; margin:8px 0 0; line-height:1.5;}
.story, .flow-meta, .hint, .flows-lead, .find p, .find{overflow-wrap:break-word; word-break:normal; overflow-x:hidden;}
.filter{box-sizing:border-box; max-width:100%;}
/* 日誌來源速覽：dt/dd 同行，名稱不在連字號斷行 */
.card .kv, #overview .kv, .kv{
  display:grid;
  grid-template-columns:minmax(220px,max-content) minmax(0,1fr);
  gap:6px 18px;
  align-items:baseline;
}
.kv dt{
  color:var(--cyan, #007a94);
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
  min-width:0;
  max-width:280px;
  word-break:keep-all;
  overflow-wrap:normal;
}
.kv dd{margin:0; overflow-wrap:break-word; word-break:normal;}
.card.is-empty-hidden, .stat.is-empty-hidden{display:none !important;}
#traffic .ot-talkers-card, #traffic .ot-policy-card{min-height:0;}
.flow-card, .flow-grid, .flow-body{max-width:100%; overflow:hidden;}
.flow-svg{max-width:100%; height:auto;}
"""

LAYOUT_JS = r"""
(function(){
  try{
    const raw=JSON.parse(document.getElementById('data').textContent);
    const D=(raw.data||{}), X=D.derived||{};
    const hideChart=id=>{
      const el=document.getElementById(id);
      if(!el) return;
      const card=el.closest('.card')||el.closest('.stat');
      if(card){ card.classList.add('is-empty-hidden'); }
    };
    const empty=[];
    if(!(D.ev_by_cat||[]).length) empty.push('c_cat');
    if(!(D.ev_src_country||[]).length && !(D.ev_dst_country||[]).length) empty.push('c_geo');
    if(!(D.ev_top_users||[]).length) empty.push('c_users');
    if(!(D.traffic_daily||[]).length) empty.push('c_tr_daily','c_tr_sankey','c_tr_dsrc','c_tr_dport');
    const ad=D.auth_daily||[];
    if(!(D.auth_types||[]).length && ad.every(r=>!(r.success||r.failure))) empty.push('c_auth','c_auth_t');
    if(!(D.auth_fail_top||[]).length){
      document.querySelectorAll('#auth .card').forEach(c=>{
        const h=(c.querySelector('h3')||{}).textContent||'';
        if(/登入失敗明細|管理員登入/.test(h)) c.classList.add('is-empty-hidden');
      });
    }
    if(!(D.dns_types||[]).length) empty.push('c_dns_types');
    if(!(D.dns_top_src||[]).length) empty.push('c_dns_sankey');
    if(!(D.cmdb_status||[]).length) empty.push('c_cm_st');
    if(!(D.health||[]).length) empty.push('c_health');
    empty.push('c_ov_gauge'); // no OT permit/deny split (would render NaN%)
    // Empty / misleading leftover incident charts (would show blank panels or "undefined")
    if(!(D.inc_hourly||[]).length) empty.push('c_inc_hour');
    const sevOk=(D.ev_sev_daily||[]).some(r=>/^(LOW|MEDIUM|HIGH)$/.test(r.sev||''));
    if(!sevOk) empty.push('c_evsev'); // stacked sev chart would be empty (we only have daily totals)
    if(!(D.ev_by_vendor||[]).length) empty.push('c_tree');

    if(!(D.inc_by_category||[]).length) empty.push('c_inc_sun');
    if(!(D.ndr_virus_top||[]).length && !(D.malware||[]).length) empty.push('c_virus');
    // ndr_pairs in this collect uses src/dst (talkers), but the shell Sankey reads src_ip_addr/dest_ip_addr
    const ndrPairs=(D.ndr_pairs||[]).filter(r=>r.src_ip_addr && r.dest_ip_addr);
    if(!ndrPairs.length) empty.push('c_pair');
    if(!(D.inc_tactics_raw||[]).length) empty.push('c_tac');
    if(!(D.inc_techniques_raw||[]).length) empty.push('c_tec');
    if(!(D.inc_top_users||[]).length) empty.push('c_inc_users');
    empty.forEach(hideChart);
    const hideCardByTitle=(secId, re)=>{
      const sec=document.getElementById(secId);
      if(!sec) return;
      sec.querySelectorAll('.card').forEach(c=>{
        const h=(c.querySelector('h3')||{}).textContent||'';
        if(re.test(h)) c.classList.add('is-empty-hidden');
      });
    };
    if(!(D.inc_latest_high||[]).length) hideCardByTitle('inc', /最新高嚴重度事故/);
    if(!(D.inc_top_count_high||[]).length) hideCardByTitle('inc', /出現次數最多的 HIGH/);
    if(!(D.fsm_users||[]).length) hideCardByTitle('cmdb', /FortiSIEM 使用者及角色/);
    if(!(D.health||[]).length) hideCardByTitle('cmdb', /FortiSIEM 節點資源|平台健康細項/);
    // Hide org-wide DNS KPI tiles that are all zero (not OT telemetry)
    const dns=document.getElementById('dns');
    if(dns){
      if(!(D.dns_types||[]).length && !(D.dns_top_src||[]).length){
        dns.querySelectorAll('.stat').forEach(el=>el.classList.add('is-empty-hidden'));
      }
    }
    // Caption org-wide risk lists so they are not read as OT compromise
    const risk=document.getElementById('risk');
    if(risk && !risk.querySelector('.ot-risk-caption')){
      const head=risk.querySelector('.sec-h, .section-head, header, .kicker')||risk.firstElementChild;
      const note=document.createElement('div');
      note.className='note ot-risk-caption';
      note.setAttribute('style','margin:8px 0 14px');
      note.textContent='以下風險分來自 FortiSIEM 全域排行（非僅 OT 資產），並不表示該主機已被確認攻入 OT 網段。';
      const bento=risk.querySelector('.bento');
      if(bento) risk.insertBefore(note, bento);
      else if(head&&head.nextSibling) risk.insertBefore(note, head.nextSibling);
      else risk.appendChild(note);
    }
    // Tables: wrap overflowing tables so they cannot hang off the page
    document.querySelectorAll('.card table, section table').forEach(tb=>{
      if(tb.parentElement && tb.parentElement.classList.contains('tbl-scroll')) return;
      const wrap=document.createElement('div');
      wrap.className='tbl-scroll';
      tb.parentNode.insertBefore(wrap, tb);
      wrap.appendChild(tb);
    });

    // Inject OT talkers into traffic if permit/deny charts were hidden
    const traf=document.getElementById('traffic');
    if(traf && (D.talkers||[]).length){
      const bento=traf.querySelector('.bento');
      if(bento && !traf.querySelector('.ot-talkers-card')){
        const card=document.createElement('div');
        card.className='card c8 ot-talkers-card';
        const rows=(D.talkers||[]).slice(0,12).map(r=>`<tr><td class="mono">${(r.src||'')}</td><td class="mono">${(r.dst||'')}</td><td>${(r.c||0).toLocaleString('en-US')}</td></tr>`).join('');
        card.innerHTML='<h3>OT 網段對講 Top</h3><div class="hint">src → dst（OT/IoT 匹配事件）</div><table><thead><tr><th>來源</th><th>目的</th><th>筆數</th></tr></thead><tbody>'+rows+'</tbody></table>';
        bento.prepend(card);
      }
    }
    if(traf && (D.policies||[]).length){
      const bento=traf.querySelector('.bento');
      if(bento && !traf.querySelector('.ot-policy-card')){
        const card=document.createElement('div');
        card.className='card c4 ot-policy-card';
        const rows=(D.policies||[]).map(r=>`<tr><td class="mono">${(r.policy||'')}</td><td>${(r.count||r.c||0).toLocaleString('en-US')}</td></tr>`).join('');
        card.innerHTML='<h3>OT 相關政策</h3><div class="hint">policyname（SCADA / Modbus）</div><table><thead><tr><th>政策</th><th>筆數</th></tr></thead><tbody>'+rows+'</tbody></table>';
        bento.appendChild(card);
      }
    }

    // Sticky nav offset: section titles sit fully below the bar; previous
    // section tails do not peek in the gap (padding-top is inside the section).
    const nav=document.querySelector('nav');
    const setNavOffset=()=>{
      if(!nav) return;
      const h=Math.ceil(nav.getBoundingClientRect().height||56);
      document.documentElement.style.setProperty('--nav-offset', (h+2)+'px');
    };
    setNavOffset();
    window.addEventListener('resize', setNavOffset);

    // Rebalance first visible incident rows to fill 12 columns evenly
    (function(){
      const inc=document.getElementById('inc');
      if(!inc) return;
      const bento=inc.querySelector('.bento');
      if(!bento) return;
      const vis=[...bento.children].filter(c=>c.classList.contains('card') && !c.classList.contains('is-empty-hidden'));
      const spanOf=el=>{
        const m=(el.className||'').match(/\bc(\d+)\b/);
        return m?+m[1]:12;
      };
      const setSpan=(el,n)=>{
        el.className=(el.className||'').replace(/\bc\d+\b/g,'').trim()+' c'+n;
      };
      let i=0;
      while(i<vis.length){
        const a=vis[i], b=vis[i+1];
        if(b && spanOf(a)+spanOf(b)<12){
          setSpan(a,6); setSpan(b,6);
          i+=2;
        }else{
          i+=1;
        }
      }
    })();

    // Non-breaking hyphens on device / host / serial tokens; never mid-break serials
    const nbDev=s=>String(s||'').replace(/-/g,'\u2011');
    const isDevName=s=>{
      const t=String(s||'').trim();
      if(!t || t.length>80) return false;
      if(/\s/.test(t) && !/^Forti|^HOST-|^SIEM\./.test(t)) return false;
      return /^(HOST-|Forti|FDCVM|FPAV|FGVM|SIEM\.|Workshop-)/i.test(t)
        || /^[A-Z]{3,}[A-Z0-9]{8,}$/.test(t)
        || (/[A-Za-z]/.test(t) && /-/.test(t) && t.length<=48);
    };
    document.querySelectorAll('.kv dt, [data-dev], #cmdb td:first-child, #cmdb td.code, #overview .kv dt').forEach(el=>{
      if(el.querySelector && el.querySelector('*')) return;
      const raw=(el.textContent||'').trim();
      if(!raw || !isDevName(raw)) return;
      el.textContent=nbDev(raw);
      el.setAttribute('title', raw);
      el.classList.add('host-name');
    });
    document.querySelectorAll('#cmdb th, #inc th').forEach(th=>{
      th.style.whiteSpace='nowrap';
    });
    document.querySelectorAll('.card table td, .card table th').forEach(el=>{
      const raw=(el.getAttribute('title')||el.textContent||'').trim();
      if(!raw) return;
      if(el.scrollWidth>el.clientWidth+1 || (el.classList.contains('host-name') && raw.length>16)){
        if(!el.getAttribute('title')) el.setAttribute('title', raw);
      }
    });

  }catch(e){ console.warn('layout-fix', e); }
})();
"""


def apply_layout_fixes(html: str, payload: dict) -> str:
    """Hide empty SIEM leftover charts, fix calendar month, tables, nav wrap, typography."""
    # Calendar: leftover "十月" range from the 7-day SIEM shell
    month_en = '2026-11'
    month_zh = '十一月'
    try:
        start_s = str(((payload.get('data') or {}).get('derived') or {}).get('win_start') or (payload.get('meta') or {}).get('start_hkt') or '')
        import re as _re
        m = _re.search(r'(20\d{2})-(\d{2})', start_s)
        if m:
            month_en = f'{m.group(1)}-{m.group(2)}'
            months = '正二三四五六七八九十十一十二'
            # simpler map
            zh_months = {1:'一',2:'二',3:'三',4:'四',5:'五',6:'六',7:'七',8:'八',9:'九',10:'十',11:'十一',12:'十二'}
            month_zh = zh_months[int(m.group(2))] + '月'
    except Exception:
        pass
    html = html.replace("calendar:{range:'2026-10'", f"calendar:{{range:'{month_en}'")
    html = html.replace('calendar:{range:"2026-10"', f'calendar:{{range:"{month_en}"')
    html = html.replace("'十月事件日曆'", f"'{month_zh}事件日曆（本視窗）'")
    html = html.replace('"十月事件日曆"', f'"{month_zh}事件日曆（本視窗）"')
    html = html.replace(
        "'SIEM 輸入 EPS（每小時平均）','PH_SYSTEM_EPS_GLOBAL · incomingEventsPerSec'",
        "'OT 事件速率（每小時平均）','由本視窗 OT/IoT 事件量換算'",
    )
    html = html.replace('虛線為完整日平均；首尾兩日只有部分時段', '虛線為完整日平均；最後一日為不完整時段')
    html = html.replace('phRecvTime &gt; now() − 7×86400', f'phRecvTime 視窗：{SPAN_ZH}（HKT）')
    html = html.replace('phRecvTime > now() − 7×86400', f'phRecvTime 視窗：{SPAN_ZH}（HKT）')
    html = html.replace('now() − 7×86400', f'本{SPAN_ZH}視窗')
    # EPS peak/min badges were integer-rounded (0.33 → 0)
    html = html.replace(
        "plan('c_eps',O({tooltip:Object.assign({trigger:'axis',valueFormatter:v=>v==null?'—':v.toFixed(1)+' EPS'},TT)",
        "plan('c_eps',O({tooltip:Object.assign({trigger:'axis',valueFormatter:v=>v==null?'—':v.toFixed(2)+' EPS'},TT)",
        1,
    )
    html = html.replace(
        "areaStyle:{color:fade('#2f7bff','55','05')},markPoint:{symbolSize:46,itemStyle:{color:'#8a5cff'},label:{fontSize:10,formatter:p=>p.value.toFixed(0)}",
        "areaStyle:{color:fade('#2f7bff','55','05')},markPoint:{symbolSize:46,itemStyle:{color:'#8a5cff'},label:{fontSize:10,formatter:p=>Number(p.value).toFixed(2)}",
        1,
    )

    # First/last day average: Monday is a complete calendar day (starts 00:00)
    html = html.replace(
        "const fullDays=evDay.slice(1,-1);",
        "const fullDays=(X.full_days&&X.full_days.length)?evDay.filter(r=>X.full_days.includes(r.day)):evDay.slice(0,-1);",
    )
    # Give the overview peak badge room so it is not clipped
    html = html.replace(
        "grid:{left:6,right:20,top:30,bottom:4,containLabel:true}",
        "grid:{left:6,right:48,top:36,bottom:8,containLabel:true}",
    )
    win = (payload.get('data') or {}).get('derived', {}).get('win_label') or payload.get('meta', {}).get('window') or ''
    html = html.replace('__WIN_LABEL__', win.replace('HKT', '').strip() + ' HKT' if win else win)

    # Hero: drop the fsm.query ticker and the repeating window line under the title.
    # Capture time already appears in the footer ("生成於 …").
    ticker_html = (
        '<div class="ticker" data-text="${esc(`> fsm.query --window "${firstT} → ${lastT} HKT" --sources ${RAW.sources.length} --ok ${RAW.sources.filter(x=>x.ok).length} --mode pulse`)}"></div>'
        '<div class="hero-meta">資料時段 ${esc(firstT)} → ${esc(lastT)} HKT · 擷取於 ${esc(M.generated_hkt)} · FortiSIEM MCP</div>'
    )
    if ticker_html not in html:
        raise SystemExit('hero ticker/meta template not found')
    html = html.replace(ticker_html, '')

    # Incident row: after the empty hourly card is hidden, fill the first row evenly
    inc_status = "${card('c4','事故狀態','incident_status',ch('c_inc_status','m'))}"
    inc_daily = "${card('c5','每日事故（按嚴重度）','by last_seen',ch('c_inc_daily','m'))}"
    inc_new = "${card('c4','新開事故（按嚴重度）','by orig_first_seen_time',ch('c_inc_new','m'))}"
    inc_sankey = "${card('c7','規則 → 嚴重度流向','Top 10 規則 Sankey',ch('c_rule_sankey','l'))}"
    for old, new in (
        (inc_status, inc_status.replace("card('c4'", "card('c6'")),
        (inc_daily, inc_daily.replace("card('c5'", "card('c6'")),
        (inc_new, inc_new.replace("card('c4'", "card('c6'")),
        (inc_sankey, inc_sankey.replace("card('c7'", "card('c6'")),
    ):
        if old not in html:
            raise SystemExit('incident card template not found: ' + old[:40])
        html = html.replace(old, new)

    # Taller scroll area so more incident rows are fully visible
    html = html.replace(
        "table([{h:'規則',k:'rule'},{h:'類別',k:'category'},{h:'HIGH',k:'high'},{h:'MED',k:'medium'},{h:'LOW',k:'low'},{h:'合共',k:'c'},{h:'Open',k:'open'}],D.inc_top_rules,{max:380})",
        "table([{h:'規則',k:'rule'},{h:'類別',k:'category'},{h:'HIGH',k:'high'},{h:'MED',k:'medium'},{h:'LOW',k:'low'},{h:'合共',k:'c'},{h:'Open',k:'open'}],D.inc_top_rules,{max:460})",
    )
    html = html.replace(
        "table([{h:'標題',k:'incident_title'},{h:'嚴重度',k:'severity_cat',f:v=>sevB(v)},{h:'次數',k:'c'}],D.inc_top_titles,{max:380})",
        "table([{h:'標題',k:'incident_title'},{h:'嚴重度',k:'severity_cat',f:v=>sevB(v)},{h:'次數',k:'c'}],D.inc_top_titles,{max:460})",
    )

    # Sunburst / treemap: keep labels inside the card
    old_sun = "series:[{type:'sunburst',data,radius:['12%','94%'],sort:null,itemStyle:{borderRadius:1,borderWidth:2,borderColor:'#F4F6F8'},levels:[{},{r0:'12%',r:'44%',label:{rotate:'tangential',fontSize:11,color:'#041016',minAngle:12}},{r0:'44%',r:'94%',label:{align:'right',fontSize:10,color:'#2A323C',minAngle:4,formatter:p=>p.name.replace('FortiGate-','FGT-')},itemStyle:{opacity:.85}}]}]"
    new_sun = "series:[{type:'sunburst',data,radius:['16%','70%'],sort:null,itemStyle:{borderRadius:1,borderWidth:2,borderColor:'#F4F6F8'},label:{width:78,overflow:'truncate',ellipsis:'…'},levels:[{},{r0:'16%',r:'40%',label:{rotate:'tangential',fontSize:10,color:'#041016',minAngle:12,width:64,overflow:'truncate'}},{r0:'40%',r:'70%',label:{align:'center',fontSize:9,color:'#2A323C',minAngle:6,width:72,overflow:'truncate',ellipsis:'…',formatter:p=>{const n=p.name.replace('FortiGate-','FGT-');return n.length>20?n.slice(0,18)+'…':n}},itemStyle:{opacity:.85}}]}]"
    old_sun_dark = "series:[{type:'sunburst',data,radius:['12%','94%'],sort:null,itemStyle:{borderRadius:1,borderWidth:2,borderColor:'#070a0e'},levels:[{},{r0:'12%',r:'44%',label:{rotate:'tangential',fontSize:11,color:'#041016',minAngle:12}},{r0:'44%',r:'94%',label:{align:'right',fontSize:10,color:'#b4c2d3',minAngle:4,formatter:p=>p.name.replace('FortiGate-','FGT-')},itemStyle:{opacity:.85}}]}]"
    new_sun_dark = "series:[{type:'sunburst',data,radius:['16%','70%'],sort:null,itemStyle:{borderRadius:1,borderWidth:2,borderColor:'#070a0e'},label:{width:78,overflow:'truncate',ellipsis:'…'},levels:[{},{r0:'16%',r:'40%',label:{rotate:'tangential',fontSize:10,color:'#041016',minAngle:12,width:64,overflow:'truncate'}},{r0:'40%',r:'70%',label:{align:'center',fontSize:9,color:'#b4c2d3',minAngle:6,width:72,overflow:'truncate',ellipsis:'…',formatter:p=>{const n=p.name.replace('FortiGate-','FGT-');return n.length>20?n.slice(0,18)+'…':n}},itemStyle:{opacity:.85}}]}]"
    if old_sun in html:
        html = html.replace(old_sun, new_sun)
    elif old_sun_dark in html:
        html = html.replace(old_sun_dark, new_sun_dark)
    else:
        raise SystemExit('c_sun series template not found')

    old_cmsun = "series:[{type:'sunburst',data,radius:['10%','90%'],center:['50%','48%'],itemStyle:{borderColor:'#F4F6F8',borderWidth:2,borderRadius:1},levels:[{},{r0:'10%',r:'28%',label:{color:'#041016',fontSize:10.5}},{r0:'28%',r:'56%',label:{color:'#041016',fontSize:10,rotate:'tangential'}},{r0:'56%',r:'90%',label:{color:'#0E1216',fontSize:10}}]}]"
    new_cmsun = "series:[{type:'sunburst',data,radius:['14%','66%'],center:['50%','50%'],itemStyle:{borderColor:'#F4F6F8',borderWidth:2,borderRadius:1},label:{width:70,overflow:'truncate',ellipsis:'…'},levels:[{},{r0:'14%',r:'32%',label:{color:'#041016',fontSize:10,overflow:'truncate',width:52}},{r0:'32%',r:'48%',label:{color:'#041016',fontSize:9,rotate:'tangential',overflow:'truncate'}},{r0:'48%',r:'66%',label:{color:'#0E1216',fontSize:9,minAngle:8,overflow:'truncate',width:68,ellipsis:'…',formatter:p=>p.name&&p.name.length>16?p.name.slice(0,14)+'…':p.name}}]}]"
    old_cmsun_dark = "series:[{type:'sunburst',data,radius:['10%','90%'],center:['50%','48%'],itemStyle:{borderColor:'#070a0e',borderWidth:2,borderRadius:1},levels:[{},{r0:'10%',r:'28%',label:{color:'#041016',fontSize:10.5}},{r0:'28%',r:'56%',label:{color:'#041016',fontSize:10,rotate:'tangential'}},{r0:'56%',r:'90%',label:{color:'#e6f1ff',fontSize:10}}]}]"
    new_cmsun_dark = "series:[{type:'sunburst',data,radius:['14%','66%'],center:['50%','50%'],itemStyle:{borderColor:'#070a0e',borderWidth:2,borderRadius:1},label:{width:70,overflow:'truncate',ellipsis:'…'},levels:[{},{r0:'14%',r:'32%',label:{color:'#041016',fontSize:10,overflow:'truncate',width:52}},{r0:'32%',r:'48%',label:{color:'#041016',fontSize:9,rotate:'tangential',overflow:'truncate'}},{r0:'48%',r:'66%',label:{color:'#e6f1ff',fontSize:9,minAngle:8,overflow:'truncate',width:68,ellipsis:'…',formatter:p=>p.name&&p.name.length>16?p.name.slice(0,14)+'…':p.name}}]}]"
    if old_cmsun in html:
        html = html.replace(old_cmsun, new_cmsun)
    elif old_cmsun_dark in html:
        html = html.replace(old_cmsun_dark, new_cmsun_dark)
    else:
        raise SystemExit('c_cm_sun series template not found')

    old_tree = "series:[{type:'treemap',roam:false,nodeClick:false,breadcrumb:{show:false},left:0,right:0,top:0,bottom:0,itemStyle:{borderColor:'#C4CCD6',borderWidth:2,gapWidth:2,borderRadius:1},label:{fontSize:11.5,color:'#041016',formatter:p=>`${p.name}\\n${pct(p.value,T.events)}`}"
    new_tree = "series:[{type:'treemap',roam:false,nodeClick:false,breadcrumb:{show:false},left:4,right:4,top:4,bottom:4,itemStyle:{borderColor:'#C4CCD6',borderWidth:2,gapWidth:2,borderRadius:1},label:{fontSize:11,color:'#041016',overflow:'truncate',ellipsis:'…',formatter:p=>`${p.name}\\n${pct(p.value,T.events)}`}"
    old_tree_dark = "series:[{type:'treemap',roam:false,nodeClick:false,breadcrumb:{show:false},left:0,right:0,top:0,bottom:0,itemStyle:{borderColor:'#070a0e',borderWidth:3,gapWidth:3,borderRadius:1},label:{fontSize:11.5,color:'#041016',formatter:p=>`${p.name}\\n${pct(p.value,T.events)}`}"
    new_tree_dark = "series:[{type:'treemap',roam:false,nodeClick:false,breadcrumb:{show:false},left:4,right:4,top:4,bottom:4,itemStyle:{borderColor:'#070a0e',borderWidth:3,gapWidth:3,borderRadius:1},label:{fontSize:11,color:'#041016',overflow:'truncate',ellipsis:'…',formatter:p=>`${p.name}\\n${pct(p.value,T.events)}`}"
    if old_tree in html:
        html = html.replace(old_tree, new_tree)
    elif old_tree_dark in html:
        html = html.replace(old_tree_dark, new_tree_dark)
    else:
        raise SystemExit('c_tree series template not found')


    if 'layout-fix' not in html:
        html = html.replace('</style>', LAYOUT_CSS + '\n</style>', 1)
        inj = '<script>\n' + LAYOUT_JS.replace('</script>', '<\\/script>') + '\n</script>\n'
        i = html.rfind('</body>')
        if i < 0:
            html += inj
        else:
            html = html[:i] + inj + html[i:]
    return html



def main() -> int:
    if not BASE.exists():
        raise SystemExit(f'missing base {BASE}')
    raw = json.loads(COLLECT.read_text(encoding='utf-8'))
    payload, flows = build_payload_data(raw, hkci_src=str(HKCI_SRC))
    global FLOWS
    FLOWS = flows
    OUT_DATA.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding='utf-8')

    html = BASE.read_text(encoding='utf-8')
    html = replace_data(html, payload)
    html = patch_shell(html)
    html = inject_flows_and_art(html)

    # Global IP / attribution scrub (do not leave Supervisor IP anywhere)
    html = html.replace('165.84.173.36', '')
    html = html.replace('https:///', 'https://')  # just in case
    html = re.sub(r',?\s*"supervisor"\s*:\s*"[^"]*"', '', html)

    sys.path.insert(0, str(V15))
    import build_v15_variants as v  # noqa: E402

    html = v.scrub_lawrence(html)
    if THEME == 'light':
        html = v.apply_light(html)
    html = re.sub(r'<title>[^<]*</title>', f'<title>{TITLE_DOC}</title>', html, count=1)
    loc = 'en' if LANG == 'en' else 'zh-HK'
    html = re.sub(r'<html\b([^>]*)lang="[^"]*"', f'<html\\1lang="{loc}"', html, count=1)
    if f'lang="{loc}"' not in html[:400]:
        html = re.sub(r'<html\b', f'<html lang="{loc}"', html, count=1)
    html = v.inject_tail(html, 'en' if LANG == 'en' else 'zh', THEME if THEME in ('light', 'dark') else 'light')
    html = patch_overlay_3d(html)
    html = v.scrub_lawrence(html)
    # strip user-supplied host if present
    _host = (os.environ.get('FORTISIEM_HOST') or '').strip()
    if _host:
        bare = re.sub(r'^https?://', '', _host, flags=re.I).split('/')[0]
        if bare:
            html = html.replace(bare, '')
        html = html.replace(_host, '')
        html = html.replace('https:///', 'https://')

    html = apply_layout_fixes(html, payload)
    # Runtime JS may set document.title from derived.title — already TITLE_DOC
    OUT.write_text(html, encoding='utf-8')
    smoke(OUT)

    # Outputs stay under FORTISIEM_REPORT_ROOT (studio work/). Never write to historical report paths.
    print('report root', ROOT)
    print('engine', ENGINE)

    md5 = hashlib.md5(OUT.read_bytes()).hexdigest()
    data_md5 = hashlib.md5(OUT_DATA.read_bytes()).hexdigest()
    summary = {
        'report': str(OUT),
        'bytes': OUT.stat().st_size,
        'md5': md5,
        'embed': str(OUT_DATA),
        'embed_bytes': OUT_DATA.stat().st_size,
        'embed_md5': data_md5,
        'title': TITLE,
        'doc_title': TITLE_DOC,
        'window': payload['meta']['window'],
        'queried_at_hkt': payload['meta']['queried_at_hkt'],
        'kpis': payload.get('extras'),
        'findings': [
            {'lvl': f['lvl'], 'title': f['title']} for f in payload['findings']
        ],
        'flows': [
            {'name': f['name'], 'title': f['title'], 'sev': f['sev'], 'count': f['count']}
            for f in FLOWS
        ],
        'inc_ot_n': payload['extras']['inc_ot_n'],
        'cmdb_ot_n': payload['extras']['cmdb_ot_n'],
        'fdc_modbus': payload['extras'].get('fdc_modbus'),
    }
    OUT_SUM.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'WROTE {OUT} size={OUT.stat().st_size} md5={md5}')
    print(f'WROTE {OUT_DATA} size={OUT_DATA.stat().st_size} md5={data_md5}')
    print('Findings:')
    for f in summary['findings']:
        print(' -', f['lvl'], f['title'])
    print('Flows:')
    for f in summary['flows']:
        print(' -', f['sev'], f['name'], 'count=', f['count'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
