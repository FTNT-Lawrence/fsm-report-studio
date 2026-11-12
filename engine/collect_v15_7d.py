#!/usr/bin/env python3
"""Collect FortiSIEM 7-day pulse for v1.5 (+ attack-chain oriented extras)."""
import json, time, sys, os
from pathlib import Path
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor
from mcp import MCP, q

ROOT = Path(os.environ.get('FORTISIEM_REPORT_ROOT') or Path(__file__).resolve().parent)
os.chdir(ROOT)
DAYS = float(os.environ.get('FORTISIEM_REPORT_DAYS', '7'))
W = f"phRecvTime > now() - {DAYS:g}*86400"
D = "toDate(phRecvTime,'Asia/Hong_Kong')"
def grp(g):
    return f"dictHas('fsiem.dict_cmdb_group', (toUInt32(0), toString(fsiem.events.eventType), '{g}'))"

IW = f"last_seen_time > (extract(epoch from now())*1000 - {DAYS:g}*86400000)"
STATUS = "CASE i.incident_status WHEN 0 THEN 'Open' WHEN 1 THEN 'Cleared (FortiSIEM)' WHEN 2 THEN 'Cleared (User)' WHEN 3 THEN 'Cleared (Rule)' ELSE 'Unknown' END"

CH = {
 'ev_total': f"SELECT count(*) AS events, uniqExact(reptDevIpAddr) AS rept_ips, uniqExact(reptDevName) AS rept_names, uniqExact(eventType) AS event_types, min(phRecvTime) AS first, max(phRecvTime) AS last FROM fsiem.events WHERE {W}",
 'ev_per_day': f"SELECT {D} AS day, count(*) AS c FROM fsiem.events WHERE {W} GROUP BY day ORDER BY day",
 'ev_top_types': f"SELECT eventType, any(eventName) AS eventName, any(eventTypeGrp) AS grp, count(*) AS c FROM fsiem.events WHERE {W} GROUP BY eventType ORDER BY c DESC LIMIT 15",
 'ev_by_sev': f"SELECT eventSeverityCat AS sev, count(*) AS c FROM fsiem.events WHERE {W} GROUP BY sev ORDER BY c DESC",
 'ev_top_rept': f"SELECT reptDevName, toString(reptDevIpAddr) AS ip, any(reptModel) AS model, count(*) AS c FROM fsiem.events WHERE {W} GROUP BY reptDevName, ip ORDER BY c DESC LIMIT 12",
 'ev_by_vendor': f"SELECT reptVendor, reptModel, count(*) AS c FROM fsiem.events WHERE {W} GROUP BY reptVendor, reptModel ORDER BY c DESC LIMIT 12",
 'auth_daily': f"SELECT {D} AS day, countIf({grp('PH_SYS_EVENT_Logon')}) AS success, countIf({grp('PH_SYS_EVENT_LogonFailure')}) AS failure FROM fsiem.events WHERE {W} GROUP BY day ORDER BY day",
 'auth_fail_top': f"SELECT user, toString(srcIpAddrV4) AS src, reptDevName, eventType, count(*) AS c FROM fsiem.events WHERE {W} AND {grp('PH_SYS_EVENT_LogonFailure')} GROUP BY user, src, reptDevName, eventType ORDER BY c DESC LIMIT 10",
 'traffic_daily': f"SELECT {D} AS day, countIf({grp('PH_SYS_EVENT_PermitTraffic')}) AS permit, countIf({grp('PH_SYS_EVENT_DenyTraffic')}) AS deny FROM fsiem.events WHERE {W} GROUP BY day ORDER BY day",
 'traffic_deny_top_src': f"SELECT toString(srcIpAddrV4) AS ip, count(*) AS c FROM fsiem.events WHERE {W} AND {grp('PH_SYS_EVENT_DenyTraffic')} GROUP BY ip ORDER BY c DESC LIMIT 8",
 # attack / malware oriented (events)
 'malware_top': f"SELECT virusName, eventSeverityCat AS sev, count(*) AS c, any(toString(srcIpAddrV4)) AS src, any(toString(destIpAddrV4)) AS dst, any(reptDevName) AS host FROM fsiem.events WHERE {W} AND virusName != '' GROUP BY virusName, sev ORDER BY c DESC LIMIT 25",
 'attack_event_types': f"SELECT eventType, any(eventName) AS eventName, eventSeverityCat AS sev, count(*) AS c FROM fsiem.events WHERE {W} AND (positionCaseInsensitive(eventType,'Attack')>0 OR positionCaseInsensitive(eventType,'Malware')>0 OR positionCaseInsensitive(eventType,'IPS')>0 OR positionCaseInsensitive(eventName,'Exploit')>0) GROUP BY eventType, sev ORDER BY c DESC LIMIT 25",
}
PG = {
 'inc_by_sev': f"SELECT severity_cat, COUNT(*) AS c FROM ph_incident WHERE {IW} GROUP BY severity_cat ORDER BY c DESC",
 'inc_by_status': f"SELECT {STATUS} AS status, COUNT(*) AS c FROM ph_incident i WHERE {IW} GROUP BY 1 ORDER BY c DESC",
 'inc_top_rules': f"SELECT r.name AS rule, CASE r.category WHEN 1 THEN 'Availability' WHEN 2 THEN 'Performance' WHEN 3 THEN 'Change' WHEN 4 THEN 'Security' ELSE 'Other' END AS category, MAX(i.severity_cat) AS sev, COUNT(*) AS c, SUM(CASE WHEN i.incident_status=0 THEN 1 ELSE 0 END) AS open FROM ph_incident i JOIN ph_drq_rule r ON r.id=i.rule_id WHERE i.{IW} GROUP BY 1,2 ORDER BY c DESC LIMIT 20",
 'inc_top_titles': f"SELECT incident_title, severity_cat, COUNT(*) AS c FROM ph_incident WHERE {IW} GROUP BY 1,2 ORDER BY c DESC LIMIT 30",
 'inc_attack_chain': f"SELECT incident_title, severity_cat, COUNT(*) AS c, MAX(last_seen_time) AS last_seen FROM ph_incident WHERE {IW} AND (incident_title ILIKE '%Attack Chain%' OR incident_title ILIKE '%attack chain%') GROUP BY 1,2 ORDER BY c DESC LIMIT 20",
 'inc_high_diverse': f"SELECT incident_title, severity_cat, COUNT(*) AS c, MAX(last_seen_time) AS last_seen FROM ph_incident WHERE {IW} AND severity_cat IN ('HIGH','CRITICAL') AND incident_title NOT ILIKE '%Low Severity%' GROUP BY 1,2 ORDER BY c DESC LIMIT 40",
 'inc_ndr_malware_flows': f"""SELECT
   COALESCE(NULLIF(trim(incident_detail->>'virusName'),''), NULLIF(trim(incident_src->>'virusName'),''), split_part(incident_title,' ',1)) AS malware,
   severity_cat,
   COALESCE(NULLIF(trim(incident_src->>'srcIpAddr'),''), NULLIF(trim(incident_src->>'srcip'),'')) AS src,
   COALESCE(NULLIF(trim(incident_target->>'destIpAddr'),''), NULLIF(trim(incident_target->>'dstIp'),''), NULLIF(trim(incident_target->>'hostIpAddr'),'')) AS dst,
   COUNT(*) AS c,
   MAX(last_seen_time) AS last_seen
 FROM ph_incident
 WHERE {IW} AND (incident_title ILIKE '%FortiNDR%' OR incident_title ILIKE '%Attack%' OR severity_cat IN ('HIGH','CRITICAL'))
 GROUP BY 1,2,3,4
 HAVING COUNT(*) >= 3
 ORDER BY c DESC LIMIT 40""",
 'inc_non_permit': f"SELECT incident_title, severity_cat, COUNT(*) AS c, MAX(last_seen_time) AS last_seen FROM ph_incident WHERE {IW} AND incident_title NOT ILIKE '%Permitted%' AND incident_title NOT ILIKE '%Permit%' GROUP BY 1,2 ORDER BY c DESC LIMIT 25",
 'inc_vpn_auth': f"SELECT incident_title, severity_cat, COUNT(*) AS c, MAX(last_seen_time) AS last_seen FROM ph_incident WHERE {IW} AND (incident_title ILIKE '%VPN%' OR incident_title ILIKE '%SSO%' OR incident_title ILIKE '%login%' OR incident_title ILIKE '%Logon%' OR incident_title ILIKE '%bruteforce%' OR incident_title ILIKE '%Brute%' OR incident_title ILIKE '%Auth%') GROUP BY 1,2 ORDER BY c DESC LIMIT 20",
 'cmdb_count': "SELECT COUNT(*) AS c FROM ph_device",
 'cmdb_vendor_model': "SELECT dt.vendor, dt.model, COUNT(*) AS c FROM ph_device d JOIN ph_device_type dt ON dt.id=d.device_type_id GROUP BY 1,2 ORDER BY c DESC",
 'cmdb_devices': "SELECT d.name, d.access_ip, dt.vendor, dt.model, d.discover_method FROM ph_device d JOIN ph_device_type dt ON dt.id=d.device_type_id ORDER BY d.name",
 'health': "SELECT host_name, host_ip, CASE nodetype WHEN 0 THEN 'Supervisor' WHEN 1 THEN 'Worker' WHEN 2 THEN 'Collector' WHEN 3 THEN 'FortiSIEM Manager' WHEN 4 THEN 'DB Server' ELSE 'Unknown' END AS role, version, summary, eps_3min FROM ph_health_status WHERE host_ip IS NOT NULL",
}
TOOLS = {
 'risky_devices': ('get_top_10_risky_devices_incidents', {}),
 'risky_users': ('get_top_10_risky_users_incidents', {}),
}

items = {
  **{k: ('query_fsm_clickhouse', {'sql': v}) for k, v in CH.items()},
  **{k: ('query_fsm_postgres', {'sql': v}) for k, v in PG.items()},
  **TOOLS,
}

import threading
tl = threading.local()
def run(item):
    k, (tool, args) = item
    if not hasattr(tl, 'm'):
        tl.m = MCP()
    t0 = time.time()
    try:
        r = q(tl.m, tool, args)
    except Exception as e:
        r = {'ok': False, 'error': str(e)[:400]}
    r['tool'] = tool
    print(f"{k}\tok={r.get('ok')}\t{round(time.time()-t0,1)}s\t{(r.get('error') or '')[:160]}", flush=True)
    return k, r

raw = {}
with ThreadPoolExecutor(4) as ex:
    for k, r in ex.map(run, items.items()):
        raw[k] = r

HKT = timezone(timedelta(hours=8))
queried = datetime.now(HKT).strftime('%Y-%m-%d %H:%M:%S HKT')

data = {}
sources = []
errors = []
for k, r in raw.items():
    sources.append({
        'key': k,
        'tool': r.get('tool'),
        'ok': bool(r.get('ok')),
        'secs': r.get('secs'),
        'error': (r.get('error') or '')[:500],
    })
    if r.get('ok'):
        data[k] = r.get('data')
    else:
        data[k] = None
        errors.append({'key': k, 'error': r.get('error')})

kpis = {}
et = data.get('ev_total')
if isinstance(et, list) and et:
    row = et[0]
    kpis['total_events'] = row.get('events')
    kpis['rept_ips'] = row.get('rept_ips')
    kpis['rept_names'] = row.get('rept_names')
    kpis['event_types'] = row.get('event_types')
    kpis['first'] = str(row.get('first'))
    kpis['last'] = str(row.get('last'))

days = data.get('ev_per_day') or []
if isinstance(days, list) and days:
    kpis['daily'] = [{'day': str(d.get('day')), 'c': d.get('c')} for d in days]
    peak = max(days, key=lambda x: x.get('c') or 0)
    kpis['peak_day'] = str(peak.get('day'))
    kpis['peak_events'] = peak.get('c')

inc_sev = data.get('inc_by_sev') or []
if isinstance(inc_sev, list):
    kpis['incidents_by_sev'] = {str(r.get('severity_cat')): r.get('c') for r in inc_sev}
    kpis['incidents_total'] = sum((r.get('c') or 0) for r in inc_sev)

inc_st = data.get('inc_by_status') or []
if isinstance(inc_st, list):
    kpis['incidents_by_status'] = {str(r.get('status')): r.get('c') for r in inc_st}
    kpis['incidents_open'] = next((r.get('c') for r in inc_st if r.get('status') == 'Open'), None)

auth = data.get('auth_daily') or []
if isinstance(auth, list):
    kpis['auth_fail_total'] = sum((r.get('failure') or 0) for r in auth)
    kpis['auth_success_total'] = sum((r.get('success') or 0) for r in auth)

traf = data.get('traffic_daily') or []
if isinstance(traf, list):
    kpis['traffic_permit'] = sum((r.get('permit') or 0) for r in traf)
    kpis['traffic_deny'] = sum((r.get('deny') or 0) for r in traf)

cc = data.get('cmdb_count')
if isinstance(cc, list) and cc:
    kpis['cmdb_devices'] = cc[0].get('c')

rd = data.get('risky_devices')
if isinstance(rd, dict):
    tops = sorted(
        ((ip, (info.get('score') if isinstance(info, dict) else None)) for ip, info in rd.items()),
        key=lambda x: float(x[1] or 0), reverse=True
    )[:5]
    kpis['top_risky_devices'] = [{'ip': ip, 'score': sc} for ip, sc in tops]

ru = data.get('risky_users')
if isinstance(ru, dict):
    tops = sorted(
        ((u, (info.get('score') if isinstance(info, dict) else None)) for u, info in ru.items()),
        key=lambda x: float(x[1] or 0), reverse=True
    )[:5]
    kpis['top_risky_users'] = [{'user': u, 'score': sc} for u, sc in tops]

out = {
    'meta': {
        'version': '1.5',
        'queried_at_hkt': queried,
        'window': f'Last {DAYS:g} days (phRecvTime > now()-{DAYS:g}*86400 / last_seen_time > now-{DAYS:g}d)',
        'scope': 'full SIEM (not OT-only)',
    },
    'kpis': kpis,
    'data': data,
    'sources': sources,
    'errors': errors,
}
path = os.environ.get('FORTISIEM_PULSE_JSON') or str(ROOT / 'fsm-v15-7d-data.json')
with open(path, 'w') as f:
    json.dump(out, f, indent=1, default=str, ensure_ascii=False)
print('WROTE', path, 'ok=', sum(1 for s in sources if s['ok']), '/', len(sources), 'errors=', len(errors))
print('KPIs', json.dumps(kpis, default=str)[:1200])
