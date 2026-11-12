#!/usr/bin/env python3
"""Collect FortiSIEM OT/IoT overview for a parameterized HKT window.

Window comes from env (set by generate.py):
  FORTISIEM_WINDOW_START, FORTISIEM_WINDOW_END  (YYYY-MM-DD or YYYY-MM-DD HH:MM)
  or FORTISIEM_REPORT_DAYS (last N days ending now; default 3)

SQL pitfalls baked in:
- no host() on varchar (use access_ip::text / ip::text)
- no CASE/TO_CHAR in incident SELECTs (enrich in Python)
- ClickHouse any(eventName) AS evtName (never AS eventName)
- Postgres incidents use Python epoch-ms bounds
"""
import os, sys, json, time
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone, timedelta
sys.path.insert(0, str(Path(__file__).resolve().parent))
from mcp import MCP, q
from studio_lib import parse_hkt, now_hkt, calendar_span_days

HKT = timezone(timedelta(hours=8))
NOW = now_hkt()

def _resolve_window():
    start_s = (os.environ.get("FORTISIEM_WINDOW_START") or "").strip()
    end_s = (os.environ.get("FORTISIEM_WINDOW_END") or "").strip()
    days_s = (os.environ.get("FORTISIEM_REPORT_DAYS") or "").strip()
    end = parse_hkt(end_s) if end_s else NOW
    if start_s:
        start = parse_hkt(start_s)
    else:
        days = float(days_s or "3")
        start = end - timedelta(days=days)
    if start >= end:
        raise SystemExit("OT 視窗的開始時間必須早於結束時間")
    return start, end

START, END = _resolve_window()
START_S = START.strftime("%Y-%m-%d %H:%M:%S")
END_S = END.strftime("%Y-%m-%d %H:%M:%S")
START_ISO = START.isoformat(timespec="seconds")
END_ISO = END.isoformat(timespec="seconds")
START_MS = int(START.timestamp() * 1000)
END_MS = int(END.timestamp() * 1000)
WINDOW_DAYS = calendar_span_days(START, END)
ENTITY_DAYS = max(1, int(round(WINDOW_DAYS)))

WIN = (
    f"phRecvTime >= toDateTime('{START_S}', 'Asia/Hong_Kong') "
    f"AND phRecvTime < toDateTime('{END_S}', 'Asia/Hong_Kong')"
)
PG_WIN = f"last_seen_time >= {START_MS} AND last_seen_time < {END_MS}"
PG_WIN_I = f"i.last_seen_time >= {START_MS} AND i.last_seen_time < {END_MS}"

OT_MATCH = f"""{WIN} AND eventType NOT ILIKE 'PH_AUDIT%' AND (
  match(ifNull(eventType,''), '(?i)(^|[^A-Za-z0-9])(OT|ICS|SCADA|PLC|RTU|OPC|S7|Modbus|DNP3|BACnet|IoT|IIoT|MQTT|Zigbee|CoAP)([^A-Za-z0-9]|$)')
  OR match(ifNull(eventName,''), '(?i)(^|[^A-Za-z0-9])(OT|ICS|SCADA|PLC|RTU|OPC|S7|Modbus|DNP3|BACnet|IoT|IIoT|MQTT|Zigbee|CoAP)([^A-Za-z0-9]|$)')
  OR match(ifNull(rawEventMsg,''), '(?i)(^|[^A-Za-z0-9])(IoT|IIoT)([^A-Za-z0-9]|$)')
  OR multiSearchAnyCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')), ['SCADA','Modbus','DNP3','BACnet','IEC104','IEC-104','Profinet','EtherNet/IP','EtherNetIP','S7comm','OPC-UA','OPCUA','FortiGuardOT','ICS-CERT','OTSecurity','industrial control','IIoT','Zigbee','Z-Wave','ZWave','CoAP','Veeder-Root','Modbus-device','MQTT'])
)"""
OT_NET = (
    "(toString(srcIpAddr) LIKE '172.16.0.%' OR toString(destIpAddr) LIKE '172.16.0.%' "
    "OR toString(srcIpAddr) LIKE '192.168.27.%' OR toString(destIpAddr) LIKE '192.168.27.%')"
)

errors = {}
sql_used = {}
out = {
    "title": f"FortiSIEM OT/IoT network overview ({START_S} to {END_S} HKT)",
    "queried_at_hkt": NOW.isoformat(timespec="seconds"),
    "timezone": "Asia/Hong_Kong (HKT, UTC+8)",
    "window": {
        "start_hkt": START_ISO,
        "end_hkt": END_ISO,
        "start_ms": START_MS,
        "end_ms": END_MS,
        "sql_predicate": WIN,
        "pg_predicate": PG_WIN,
        "note": f"Absolute HKT window {START_S} to {END_S} (exclusive upper bound). Calendar {ENTITY_DAYS} day(s).",
    },
    "match_scope": "narrow (token-safe) + IoT word-boundary",
    "match_note": "Word-boundary OT/ICS/SCADA/PLC/... on eventType/eventName; word-boundary IoT/IIoT on rawEventMsg; multiSearch for distinctive protocol strings. Exclude PH_AUDIT%.",
    "mcp_failures": [],
}

print(f"Window {START_S} .. {END_S} HKT  ms={START_MS}..{END_MS}", flush=True)
print("Connecting MCP...", flush=True)
m = MCP()
print("Connected.", flush=True)


def normalize(d):
    if isinstance(d, dict) and d.get("status") == "error":
        return None, d.get("message") or str(d)
    if isinstance(d, dict) and "columns" in d and "rows" in d:
        return [dict(zip(d["columns"], r)) for r in d["rows"]], None
    if isinstance(d, list):
        return d, None
    if isinstance(d, dict) and len(d) == 1 and isinstance(next(iter(d.values())), (int, float, str)):
        return [d], None
    if isinstance(d, dict):
        return [d], None
    return d, None


def rows_of(d):
    return normalize(d)


def cell(row, *keys, default=0):
    if not row:
        return default
    if isinstance(row, list):
        row = row[0] if row else {}
    if not isinstance(row, dict):
        return default
    for k in keys:
        if k in row:
            try:
                return int(row[k])
            except Exception:
                try:
                    return int(float(row[k]))
                except Exception:
                    return row[k]
    try:
        return int(next(iter(row.values())))
    except Exception:
        return default


def ch(name, sql):
    sql_used[name] = sql
    print(f"  CH[{name}]...", flush=True)
    r = q(m, "query_fsm_clickhouse", {"sql": sql})
    if not r.get("ok"):
        err = r.get("error", "unknown")
        print(f"    FAIL: {str(err)[:200]}", flush=True)
        errors[name] = err
        out["mcp_failures"].append({"tool": "query_fsm_clickhouse", "query": name, "error": str(err)[:500]})
        return None
    data, err = rows_of(r["data"])
    if err is not None or data is None:
        err = err or "bad shape"
        print(f"    FAIL: {str(err)[:200]}", flush=True)
        errors[name] = err
        out["mcp_failures"].append({"tool": "query_fsm_clickhouse", "query": name, "error": str(err)[:500]})
        return None
    print(f"    ok ({r.get('secs')}s) n={len(data) if isinstance(data, list) else '?'}", flush=True)
    return data


def pg(name, sql):
    sql_used[name] = sql
    print(f"  PG[{name}]...", flush=True)
    r = q(m, "query_fsm_postgres", {"sql": sql})
    if not r.get("ok"):
        err = r.get("error", "unknown")
        print(f"    FAIL: {str(err)[:200]}", flush=True)
        errors[name] = err
        out["mcp_failures"].append({"tool": "query_fsm_postgres", "query": name, "error": str(err)[:500]})
        return None
    data, err = rows_of(r["data"])
    if err is not None:
        print(f"    FAIL: {str(err)[:200]}", flush=True)
        errors[name] = err
        out["mcp_failures"].append({"tool": "query_fsm_postgres", "query": name, "error": str(err)[:500]})
        return None
    print(f"    ok ({r.get('secs')}s) n={len(data) if isinstance(data, list) else '?'}", flush=True)
    return data


def tool(name, args):
    print(f"  TOOL[{name}]...", flush=True)
    r = q(m, name, args)
    if not r.get("ok"):
        err = r.get("error", "unknown")
        print(f"    FAIL: {str(err)[:200]}", flush=True)
        errors[name] = err
        out["mcp_failures"].append({"tool": name, "error": str(err)[:500]})
        return None
    print(f"    ok ({r.get('secs')}s)", flush=True)
    return r["data"]


STATUS = {0: "Open", 1: "Cleared (FortiSIEM)", 2: "Cleared (User)", 3: "Cleared (Rule)"}


def ts_hkt(ms):
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=HKT).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return None


def enrich_inc(rows):
    outr = []
    for r in rows or []:
        outr.append({
            **r,
            "status": STATUS.get(r.get("incident_status"), r.get("status") or "Unknown"),
            "first_seen": r.get("first_seen") or ts_hkt(r.get("orig_first_seen_time")),
            "last_seen": r.get("last_seen") or ts_hkt(r.get("last_seen_time")),
        })
    return outr


def enrich_status_counts(rows):
    outr = []
    for r in rows or []:
        st = r.get("status")
        if st is None:
            st = STATUS.get(r.get("incident_status"), "Unknown")
        outr.append({**r, "status": st, "c": int(r.get("c") or r.get("count") or 0)})
    return outr


def fmt_ct(rows):
    outr = []
    for r in rows or []:
        ct = r.get("creation_time")
        rec = dict(r)
        try:
            ms = int(ct)
            if ms <= 100000000000:
                ms = ms * 1000
            rec["created_hkt"] = datetime.fromtimestamp(ms / 1000, tz=HKT).strftime("%Y-%m-%d %H:%M")
        except Exception:
            pass
        outr.append(rec)
    return outr


# ---- 1. Totals / daily / hourly ----
print("\n== Totals / daily ==", flush=True)
total = ch("total", f"SELECT count(*) AS c FROM fsiem.events WHERE {OT_MATCH}")
out["total_ot_iot_related_events"] = cell(total, "c")

daily = ch("daily", f"""SELECT toString(toDate(toTimezone(toDateTime(phRecvTime),'Asia/Hong_Kong'))) AS day, count(*) AS c
FROM fsiem.events WHERE {OT_MATCH} GROUP BY day ORDER BY day""")
out["daily_trend_hkt"] = [{"day": r["day"], "count": int(r["c"])} for r in (daily or [])]

hourly_all = ch("hourly_all", f"""SELECT
  toString(toDate(toTimezone(toDateTime(phRecvTime),'Asia/Hong_Kong'))) AS day,
  toHour(toTimezone(toDateTime(phRecvTime),'Asia/Hong_Kong')) AS hr,
  count(*) AS c
FROM fsiem.events WHERE {OT_MATCH}
GROUP BY day, hr ORDER BY day, hr""")
out["hourly_all_hkt"] = [{"day": r["day"], "hour": int(r["hr"]), "count": int(r["c"])} for r in (hourly_all or [])]
today = NOW.strftime("%Y-%m-%d")
out["hourly_today_hkt"] = [{"hour": r["hour"], "count": r["count"]} for r in out["hourly_all_hkt"] if r["day"] == today]

# ---- 2. Tops / needles ----
print("\n== Tops / needles ==", flush=True)
types = ch("top_types", f"""SELECT eventType, any(eventName) AS evtName, count(*) AS c
FROM fsiem.events WHERE {OT_MATCH} GROUP BY eventType ORDER BY c DESC LIMIT 30""")
out["top_event_types"] = [{"eventType": r["eventType"], "eventName": r.get("evtName") or r.get("eventName"), "count": int(r["c"])} for r in (types or [])]

rept = ch("top_rept", f"""SELECT reptDevName, toString(reptDevIpAddr) AS ip, count(*) AS c
FROM fsiem.events WHERE {OT_MATCH} GROUP BY reptDevName, ip ORDER BY c DESC LIMIT 20""")
out["top_reporting_devices"] = [{"reptDevName": r["reptDevName"], "reptDevIpAddr": r["ip"], "count": int(r["c"])} for r in (rept or [])]

needles = ch("needles", f"""SELECT
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'Modbus')>0) AS Modbus,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'DNP3')>0) AS DNP3,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'BACnet')>0) AS BACnet,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'SCADA')>0) AS SCADA,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'Profinet')>0) AS Profinet,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'IEC104')>0 OR positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'IEC-104')>0) AS IEC104,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'S7comm')>0) AS S7comm,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'OPC-UA')>0 OR positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'OPCUA')>0) AS OPCUA,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'EtherNet/IP')>0 OR positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'EtherNetIP')>0) AS EtherNetIP,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'FortiGuardOT')>0) AS FortiGuardOT,
    countIf(match(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')), '(?i)(^|[^A-Za-z0-9])IoT([^A-Za-z0-9]|$)')) AS IoT,
    countIf(match(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')), '(?i)(^|[^A-Za-z0-9])IIoT([^A-Za-z0-9]|$)')) AS IIoT,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'MQTT')>0) AS MQTT,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'Zigbee')>0) AS Zigbee,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'Z-Wave')>0 OR positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'ZWave')>0) AS ZWave,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'CoAP')>0) AS CoAP,
    countIf(match(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')), '(?i)(^|[^A-Za-z0-9])ICS([^A-Za-z0-9]|$)')) AS ICS,
    countIf(match(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')), '(?i)(^|[^A-Za-z0-9])PLC([^A-Za-z0-9]|$)')) AS PLC,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'S7')>0 OR positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'Siemens')>0) AS Siemens_S7,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'Purdue')>0) AS Purdue,
    countIf(positionCaseInsensitive(concat(ifNull(eventType,''),' ',ifNull(eventName,''),' ',ifNull(rawEventMsg,'')),'FTNT-IOT')>0) AS FTNT_IOT
  FROM fsiem.events WHERE {OT_MATCH}""")
out["protocol_needle_breakdown"] = {k: int(v) for k, v in (needles[0].items() if needles else {})}

sev = ch("severity", f"""SELECT ifNull(toString(eventSeverityCat),'UNKNOWN') AS sev, count(*) AS c
FROM fsiem.events WHERE {OT_MATCH} GROUP BY sev ORDER BY c DESC""")
out["severity_breakdown"] = [{"severity": r["sev"], "count": int(r["c"])} for r in (sev or [])]

dport = ch("top_dport", f"""SELECT destIpPort AS port, ifNull(ipProto,0) AS ipProto, count(*) AS c
FROM fsiem.events WHERE {OT_MATCH} AND destIpPort IS NOT NULL
GROUP BY port, ipProto ORDER BY c DESC LIMIT 15""")
out["top_dport"] = [{"port": int(r["port"]), "ipProto": int(r.get("ipProto") or 0), "c": int(r["c"])} for r in (dport or [])]

# ---- 3. Notable rules ----
print("\n== Notable rules ==", flush=True)
rules = ch("notable_rules", f"""SELECT eventType, any(eventName) AS evtName, count(*) AS c
FROM fsiem.events WHERE {OT_MATCH} AND (
  eventType ILIKE '%OT%' OR eventType ILIKE '%Purdue%' OR eventType ILIKE '%MOBUS%' OR eventType ILIKE '%Modbus%'
  OR eventType ILIKE '%PLC%' OR eventType ILIKE '%SCADA%' OR eventType ILIKE '%Siemens%'
  OR eventType ILIKE '%Port_Scan%' OR eventType ILIKE '%Unusual%' OR eventType ILIKE '%Unusal%'
  OR eventName ILIKE '%Purdue%' OR eventName ILIKE '%OT %' OR eventName ILIKE '%OT\\_%' OR eventName ILIKE 'OT %'
  OR eventType ILIKE 'PH_RULE_%OT%' OR eventType ILIKE 'PH_RULE_TRAFFIC_NOT_L%' OR eventType ILIKE 'PH_RULE_MOBUS%'
  OR eventType ILIKE 'PH_RULE_HIGH_SEV_SEC_IPS%'
  OR eventType ILIKE '%wireless-rogue%'
)
GROUP BY eventType ORDER BY c DESC LIMIT 40""")
out["notable_rule_hits"] = [{"eventType": r["eventType"], "eventName": r.get("evtName") or r.get("eventName"), "count": int(r["c"])} for r in (rules or [])]

# ---- 4. Talkers ----
print("\n== Talkers ==", flush=True)
talkers = ch("talkers_modbus", f"""SELECT toString(srcIpAddr) AS src, toString(destIpAddr) AS dst, count(*) AS c
FROM fsiem.events WHERE {OT_MATCH}
AND (destIpPort = 502 OR srcIpPort = 502
  OR destIpPort = 102 OR srcIpPort = 102
  OR positionCaseInsensitive(ifNull(rawEventMsg,''),'Modbus')>0
  OR positionCaseInsensitive(ifNull(appName,''),'Modbus')>0
  OR positionCaseInsensitive(ifNull(rawEventMsg,''),'SCADA')>0
  OR positionCaseInsensitive(ifNull(rawEventMsg,''),'Intra-SCADA')>0)
GROUP BY src, dst ORDER BY c DESC LIMIT 25""")
out["top_talker_pairs"] = [{"src": r["src"], "dst": r["dst"], "count": int(r["c"])} for r in (talkers or [])]

s7_pairs = ch("s7_pairs", f"""SELECT toString(srcIpAddr) AS src, toString(destIpAddr) AS dst, destIpPort AS dport, reptDevName, count(*) AS c
FROM fsiem.events WHERE {WIN} AND eventType NOT ILIKE 'PH_AUDIT%'
  AND destIpPort IN (102, 502)
GROUP BY src, dst, dport, reptDevName
ORDER BY c DESC LIMIT 20""")
out["ics_port_pairs"] = [{"src": r["src"], "dst": r["dst"], "dport": int(r["dport"]) if r.get("dport") is not None else None, "reptDevName": r.get("reptDevName"), "count": int(r["c"])} for r in (s7_pairs or [])]

src_top = ch("top_src", f"""SELECT toString(srcIpAddr) AS src, count(*) AS c
FROM fsiem.events WHERE {OT_MATCH} AND srcIpAddr IS NOT NULL
GROUP BY src ORDER BY c DESC LIMIT 15""")
out["top_src"] = [{"ip": r["src"], "count": int(r["c"])} for r in (src_top or [])]

dst_top = ch("top_dst", f"""SELECT toString(destIpAddr) AS dst, count(*) AS c
FROM fsiem.events WHERE {OT_MATCH} AND destIpAddr IS NOT NULL
GROUP BY dst ORDER BY c DESC LIMIT 15""")
out["top_dst"] = [{"ip": r["dst"], "count": int(r["c"])} for r in (dst_top or [])]

policies = ch("policies", f"""SELECT
  if(positionCaseInsensitive(rawEventMsg,'Intra-SCADA')>0,'Intra-SCADA-Network-Monitor',
    if(positionCaseInsensitive(rawEventMsg,'SCADA')>0,'SCADA-related-policy',
      if(positionCaseInsensitive(rawEventMsg,'Modbus')>0,'Modbus-related-policy','other'))) AS policy,
  count(*) AS c
FROM fsiem.events WHERE {OT_MATCH}
AND positionCaseInsensitive(ifNull(rawEventMsg,''),'policyname')>0
AND (positionCaseInsensitive(ifNull(rawEventMsg,''),'SCADA')>0
  OR positionCaseInsensitive(ifNull(rawEventMsg,''),'Modbus')>0)
GROUP BY policy ORDER BY c DESC LIMIT 15""")
out["ot_related_policies"] = [{"policy": r["policy"], "count": int(r["c"])} for r in (policies or [])]

policies2 = ch("policies_detail", f"""SELECT
  substring(rawEventMsg, positionCaseInsensitive(rawEventMsg,'policyname="')+12, 60) AS policy_raw,
  count(*) AS c
FROM fsiem.events WHERE {OT_MATCH}
AND positionCaseInsensitive(ifNull(rawEventMsg,''),'policyname="')>0
AND (positionCaseInsensitive(ifNull(rawEventMsg,''),'SCADA')>0
  OR positionCaseInsensitive(ifNull(rawEventMsg,''),'Modbus')>0
  OR positionCaseInsensitive(ifNull(rawEventMsg,''),'Intra-SCADA')>0)
GROUP BY policy_raw ORDER BY c DESC LIMIT 20""")
merged = {}
for r in (policies2 or []):
    pr = str(r.get("policy_raw") or "")
    pr = pr.split('"')[0].split(" ")[0]
    if pr:
        merged[pr] = merged.get(pr, 0) + int(r["c"])
out["ot_related_policies_detail"] = [{"policy": k, "count": v} for k, v in sorted(merged.items(), key=lambda kv: -kv[1])[:15]]

# ---- 5. Samples ----
print("\n== Samples ==", flush=True)
sample_queries = [
    ("Siemens_PLC", "eventType ILIKE '%Siemens%' OR eventType ILIKE '%PLC%'"),
    ("Modbus_appctrl", "eventType ILIKE '%appctrl%' AND positionCaseInsensitive(ifNull(rawEventMsg,''),'Modbus')>0"),
    ("FDC_Modbus", "eventType ILIKE '%FortiDeceptor%' AND positionCaseInsensitive(ifNull(rawEventMsg,''),'Modbus')>0"),
    ("OT_rules", "eventType ILIKE '%OT%' OR eventType ILIKE '%Purdue%' OR eventType ILIKE '%MOBUS%' OR eventName ILIKE '%Purdue%' OR eventName ILIKE '%OT %'"),
    ("IoT_SSID", "positionCaseInsensitive(ifNull(rawEventMsg,''),'FTNT-IOT')>0 OR (eventType ILIKE '%wireless-rogue%' AND match(ifNull(rawEventMsg,''), '(?i)(^|[^A-Za-z0-9])IoT([^A-Za-z0-9]|$)'))"),
    ("IPS_OT", "eventType ILIKE '%ips%' AND (positionCaseInsensitive(ifNull(rawEventMsg,''),'Modbus')>0 OR positionCaseInsensitive(ifNull(rawEventMsg,''),'SCADA')>0 OR positionCaseInsensitive(ifNull(rawEventMsg,''),'Siemens')>0)"),
    ("Port_scan", "eventType ILIKE '%Port_Scan%' OR eventType ILIKE '%port_scanning%'"),
]
samples = []
for tag, cond in sample_queries:
    rows = ch(f"sample_{tag}", f"""SELECT
      toString(toTimezone(toDateTime(phRecvTime),'Asia/Hong_Kong')) AS t,
      eventType, eventName, reptDevName,
      substring(ifNull(rawEventMsg,''),1,280) AS msg
    FROM fsiem.events WHERE {OT_MATCH} AND ({cond})
    ORDER BY phRecvTime DESC LIMIT 3""")
    for r in (rows or []):
        samples.append({**r, "sample_tag": tag})
out["samples"] = samples

wireless = ch("wireless_rogue", f"""SELECT eventType, any(eventName) AS evtName, reptDevName, count(*) AS c
FROM fsiem.events WHERE {OT_MATCH} AND (eventType ILIKE '%wireless-rogue%' OR positionCaseInsensitive(ifNull(rawEventMsg,''),'FTNT-IOT')>0)
GROUP BY eventType, reptDevName ORDER BY c DESC LIMIT 20""")
out["wireless_rogue_breakdown"] = [{"eventType": r["eventType"], "eventName": r.get("evtName") or r.get("eventName"), "reptDevName": r.get("reptDevName"), "count": int(r["c"])} for r in (wireless or [])]

# ---- 6. CMDB ----
print("\n== CMDB ==", flush=True)
cmdb_ot = pg("cmdb_otish", """
SELECT d.name, d.access_ip::text AS access_ip, dt.vendor, dt.model, d.discover_method, d.creation_time
FROM ph_device d
INNER JOIN ph_device_type dt ON dt.id = d.device_type_id
WHERE dt.vendor ILIKE '%FortiDeceptor%'
   OR dt.model ILIKE '%Deceptor%'
   OR dt.vendor ILIKE '%Siemens%'
   OR dt.model ILIKE '%PLC%'
   OR dt.model ILIKE '%Rugged%'
   OR d.name ILIKE '%Rugged%'
   OR d.name ILIKE '%Deceptor%'
   OR d.name ILIKE '%FDC%'
   OR d.name ILIKE '%PLC%'
   OR d.name ILIKE '%SCADA%'
   OR d.name ILIKE '%OT%'
   OR d.name ILIKE '%Modbus%'
   OR dt.model ILIKE '%OT%'
ORDER BY d.name
LIMIT 100
""")
out["cmdb_ot_ish"] = fmt_ct(cmdb_ot or [])

cmdb_fortios = pg("cmdb_fortios", """
SELECT d.name, d.access_ip::text AS access_ip, dt.vendor, dt.model, d.discover_method
FROM ph_device d
INNER JOIN ph_device_type dt ON dt.id = d.device_type_id
WHERE dt.vendor ILIKE '%Fortinet%' AND (dt.model ILIKE '%FortiOS%' OR dt.model ILIKE '%FortiGate%' OR d.name ILIKE '%FortiGate%')
ORDER BY d.name LIMIT 50
""")
out["cmdb_fortios"] = cmdb_fortios or []

cmdb_vendors = pg("cmdb_vendors", """
SELECT dt.vendor, dt.model, COUNT(*) AS c
FROM ph_device d
INNER JOIN ph_device_type dt ON dt.id = d.device_type_id
GROUP BY dt.vendor, dt.model
ORDER BY c DESC LIMIT 40
""")
out["cmdb_vendor_model_top"] = cmdb_vendors or []

cmdb_by_name = pg("cmdb_by_event_hosts", """
SELECT d.name, d.access_ip::text AS access_ip, dt.vendor, dt.model
FROM ph_device d
INNER JOIN ph_device_type dt ON dt.id = d.device_type_id
WHERE d.name IN (
  'FortiGateRugged-70G-5G-Dual','FDCVM','FDCVMSTM26000372','FortiGate-700G-Backup','Workshop-27.2',
  'HOST-172.16.0.1','HOST-172.16.0.114','SIEM.fortinethk.com','FortiGate-Workshop',
  'FortiGate-121G','FGVMELTM26019309','FGVMELTM25016133','FPAVULTM26001793'
)
OR d.access_ip::text LIKE '%172.16.0.%'
OR d.access_ip::text LIKE '%192.168.27.%'
ORDER BY d.name
""")
out["cmdb_event_hosts"] = cmdb_by_name or []

out["memory_fortios"] = [
    {"name": "FGVMELTM26019309", "ip": "192.168.27.2"},
    {"name": "FortiGate-121G", "ip": "192.168.10.32"},
    {"name": "FortiGate-700G-Backup", "ip": "192.168.10.1"},
    {"name": "FortiGate-Workshop", "ip": "192.168.115.253"},
]

# ---- 7. Incidents / risk ----
print("\n== Incidents / risk ==", flush=True)
inc_pg = pg("incidents_ot", f"""
SELECT i.incident_id, i.incident_title, i.severity_cat, i.incident_status,
       i.src_ip_addr, i.dest_ip_addr, i.host_name, i.host_ip_addr,
       i.orig_first_seen_time, i.last_seen_time, r.name AS rule_name
FROM ph_incident i
LEFT JOIN ph_drq_rule r ON r.id=i.rule_id
WHERE {PG_WIN_I}
  AND (
    i.incident_title ILIKE '%OT%' OR i.incident_title ILIKE '%SCADA%' OR i.incident_title ILIKE '%Modbus%'
    OR i.incident_title ILIKE '%PLC%' OR i.incident_title ILIKE '%Purdue%' OR i.incident_title ILIKE '%Siemens%'
    OR i.incident_title ILIKE '%IoT%' OR i.incident_title ILIKE '%ICS%' OR i.incident_title ILIKE '%industrial%'
    OR i.incident_title ILIKE '%Deceptor%' OR i.incident_title ILIKE '%Unusual%' OR i.incident_title ILIKE '%Unusal%'
    OR r.name ILIKE '%OT%' OR r.name ILIKE '%SCADA%' OR r.name ILIKE '%Modbus%' OR r.name ILIKE '%Purdue%'
    OR r.name ILIKE '%PLC%' OR r.name ILIKE '%Siemens%'
  )
ORDER BY i.last_seen_time DESC NULLS LAST
LIMIT 80
""")
out["ot_related_incidents"] = enrich_inc(inc_pg or [])

inc_hi = pg("incidents_hi_window", f"""
SELECT i.incident_id, i.incident_title, i.severity_cat, i.incident_status,
       i.src_ip_addr, i.dest_ip_addr, i.host_name,
       i.orig_first_seen_time, i.last_seen_time
FROM ph_incident i
WHERE {PG_WIN_I.replace('i.last_seen_time', 'last_seen_time') if False else ''} i.last_seen_time >= {START_MS} AND i.last_seen_time < {END_MS}
  AND i.severity_cat ILIKE 'HIGH'
ORDER BY i.last_seen_time DESC NULLS LAST
LIMIT 40
""")
out["high_sev_incidents_window"] = enrich_inc(inc_hi or [])

risky_dev = tool("get_top_10_risky_devices_incidents", {})
out["top_10_risky_devices"] = risky_dev
risky_usr = tool("get_top_10_risky_users_incidents", {})
out["top_10_risky_users"] = risky_usr

out["incidents_by_ot_entity"] = {}
for ip in ["172.16.0.1", "172.16.0.254", "192.168.27.3", "172.16.0.114", "172.16.0.116", "172.16.0.112", "172.16.0.117"]:
    data = tool("get_incidents_by_entity", {"params": {"time_value": ENTITY_DAYS, "time_unit": "days", "ip": ip}})
    if data is not None:
        out["incidents_by_ot_entity"][ip] = data
for hn in ["FortiGateRugged-70G-5G-Dual", "FDCVM", "FDCVMSTM26000372", "FPAVULTM26001793"]:
    data = tool("get_incidents_by_entity", {"params": {"time_value": ENTITY_DAYS, "time_unit": "days", "hostname": hn}})
    if data is not None:
        out["incidents_by_ot_entity"][hn] = data

fdc = ch("fdc_modbus", f"""SELECT count(*) AS c FROM fsiem.events WHERE {OT_MATCH}
AND eventType ILIKE '%FortiDeceptor%' AND positionCaseInsensitive(ifNull(rawEventMsg,''),'Modbus')>0""")
out["fortideceptor_modbus_count"] = int(fdc[0]["c"]) if fdc else 0

# ---- 8. Attack flow candidates ----
print("\n== Attack flow samples ==", flush=True)
flow_defs = [
    ("protocol_abuse_modbus", "eventType ILIKE '%MOBUS%' OR eventType ILIKE '%Modbus%' OR (destIpPort=502 AND (eventType ILIKE '%appctrl%' OR eventType ILIKE '%ips%' OR eventType ILIKE '%PH_RULE%')) OR positionCaseInsensitive(ifNull(eventName,''),'Modbus')>0"),
    ("ot_port_scan", "eventType ILIKE '%Port_Scan%' OR eventType ILIKE '%port_scanning%' OR eventType ILIKE '%OT_Suspicious_Port%' OR eventName ILIKE '%Port Scan%' OR eventName ILIKE '%port scanning%'"),
    ("auth_or_wireless_iot", "eventType ILIKE '%wireless-rogue%' OR positionCaseInsensitive(ifNull(rawEventMsg,''),'FTNT-IOT')>0 OR eventType ILIKE '%auth%' OR eventType ILIKE '%login%' OR eventType ILIKE '%VPN%'"),
    ("malware_ndr_ot", "eventType ILIKE '%FortiDeceptor%' OR eventType ILIKE '%malware%' OR eventType ILIKE '%NDR%' OR eventType ILIKE '%botnet%' OR eventType ILIKE '%ips%' AND (positionCaseInsensitive(ifNull(rawEventMsg,''),'Modbus')>0 OR positionCaseInsensitive(ifNull(rawEventMsg,''),'SCADA')>0 OR positionCaseInsensitive(ifNull(rawEventMsg,''),'Siemens')>0 OR positionCaseInsensitive(ifNull(rawEventMsg,''),'OT')>0)"),
    ("config_change_plc", "eventType ILIKE '%Siemens_PLC_Logic%' OR eventType ILIKE '%PLC_Logic%' OR eventType ILIKE '%Config%' OR eventType ILIKE '%Start_Stop%' OR eventName ILIKE '%Logic_Modified%' OR eventType ILIKE '%Purdue%' OR eventType ILIKE '%Unusal_OT%' OR eventType ILIKE '%Unusual_OT%'"),
]
flows = []
for tag, cond in flow_defs:
    rows = ch(f"flow_{tag}", f"""SELECT
      toString(toTimezone(toDateTime(phRecvTime),'Asia/Hong_Kong')) AS t,
      eventType, eventName, reptDevName,
      toString(srcIpAddr) AS src, toString(destIpAddr) AS dst,
      ifNull(toString(srcIpPort),'') AS sport, ifNull(toString(destIpPort),'') AS dport,
      ifNull(toString(eventSeverityCat),'') AS sev,
      ifNull(user,'') AS userName,
      substring(ifNull(rawEventMsg,''),1,360) AS msg
    FROM fsiem.events WHERE {OT_MATCH} AND ({cond})
    ORDER BY phRecvTime DESC LIMIT 8""")
    cnt = ch(f"flowcnt_{tag}", f"SELECT count(*) AS c FROM fsiem.events WHERE {OT_MATCH} AND ({cond})")
    flows.append({"tag": tag, "count": int(cnt[0]["c"]) if cnt else 0, "samples": rows or []})
out["attack_flow_candidates"] = flows

# ---- 9. Extra investigation ----
print("\n== Extra investigation ==", flush=True)
fail_login = ch("fail_login_ot", f"""SELECT
  toString(toDate(toTimezone(toDateTime(phRecvTime),'Asia/Hong_Kong'))) AS day,
  ifNull(user,'') AS userName, toString(srcIpAddr) AS src, toString(destIpAddr) AS dst,
  reptDevName, eventType, any(eventName) AS evtName, count(*) AS c
FROM fsiem.events
WHERE {WIN} AND eventType NOT ILIKE 'PH_AUDIT%'
  AND (
    eventType ILIKE '%LogonFail%' OR eventType ILIKE '%LoginFail%' OR eventType ILIKE '%auth%fail%'
    OR eventType ILIKE '%Failed_Logon%' OR eventType ILIKE '%Authentication_Failure%'
    OR eventName ILIKE '%logon fail%' OR eventName ILIKE '%login fail%' OR eventName ILIKE '%authentication fail%'
  )
  AND {OT_NET}
GROUP BY day, userName, src, dst, reptDevName, eventType
ORDER BY c DESC LIMIT 30""")
out["failed_logins_ot"] = fail_login or []

remote = ch("remote_access_ot", f"""SELECT eventType, any(eventName) AS evtName,
  ifNull(toString(eventSeverityCat),'') AS sev,
  toString(srcIpAddr) AS src, toString(destIpAddr) AS dst,
  ifNull(toString(destIpPort),'') AS dport, reptDevName, count(*) AS c
FROM fsiem.events
WHERE {WIN} AND eventType NOT ILIKE 'PH_AUDIT%'
  AND (
    eventType ILIKE '%VPN%' OR eventType ILIKE '%SSLVPN%' OR eventType ILIKE '%ssl-vpn%'
    OR eventType ILIKE '%RDP%' OR eventType ILIKE '%SSH%' OR eventName ILIKE '%VPN%'
    OR eventName ILIKE '%RDP%' OR eventName ILIKE '%SSH%'
    OR destIpPort IN (22, 3389, 5900, 5901, 8291, 8443)
  )
  AND {OT_NET}
GROUP BY eventType, sev, src, dst, dport, reptDevName
ORDER BY c DESC LIMIT 30""")
out["remote_access_ot_net"] = remote or []

plc_comms = ch("plc_scada_comms", f"""SELECT eventType, any(eventName) AS evtName,
  ifNull(toString(eventSeverityCat),'') AS sev,
  toString(srcIpAddr) AS src, toString(destIpAddr) AS dst,
  ifNull(toString(destIpPort),'') AS dport, reptDevName, count(*) AS c
FROM fsiem.events WHERE {OT_MATCH}
  AND (
    destIpPort IN (502, 102, 20000, 44818, 47808, 2404, 4840, 2222)
    OR eventType ILIKE '%PLC%' OR eventType ILIKE '%SCADA%' OR eventType ILIKE '%Siemens%'
    OR eventType ILIKE '%Modbus%' OR eventType ILIKE '%MOBUS%' OR eventType ILIKE '%Purdue%'
    OR eventName ILIKE '%PLC%' OR eventName ILIKE '%SCADA%' OR eventName ILIKE '%Modbus%'
  )
GROUP BY eventType, sev, src, dst, dport, reptDevName
ORDER BY c DESC LIMIT 40""")
out["plc_scada_ics_comms"] = plc_comms or []

hi_ev = ch("high_events_ot", f"""SELECT
  toString(toTimezone(toDateTime(phRecvTime),'Asia/Hong_Kong')) AS t,
  eventType, eventName, ifNull(toString(eventSeverityCat),'') AS sev,
  reptDevName, toString(srcIpAddr) AS src, toString(destIpAddr) AS dst,
  substring(ifNull(rawEventMsg,''),1,280) AS msg
FROM fsiem.events WHERE {OT_MATCH}
  AND (eventSeverityCat IN ('HIGH','CRITICAL') OR eventType ILIKE '%PH_RULE%' OR eventType ILIKE '%IPS%'
       OR eventType ILIKE '%Unusual%' OR eventType ILIKE '%Unusal%' OR eventType ILIKE '%Purdue%'
       OR eventType ILIKE '%Logic_Modified%' OR eventType ILIKE '%Port_Scan%')
ORDER BY phRecvTime DESC LIMIT 40""")
out["high_or_rule_ot_events"] = hi_ev or []

inc_sum = pg("inc_summary", f"""
SELECT severity_cat, incident_status, COUNT(*) AS c
FROM ph_incident
WHERE last_seen_time >= {START_MS} AND last_seen_time < {END_MS}
GROUP BY 1, 2
ORDER BY 1, 2
""")
out["all_incidents_by_sev_status"] = enrich_status_counts(inc_sum or [])

inc_ot_sum = pg("inc_ot_summary", f"""
SELECT i.severity_cat, i.incident_status, COUNT(*) AS c
FROM ph_incident i
LEFT JOIN ph_drq_rule r ON r.id=i.rule_id
WHERE {PG_WIN_I}
  AND (
    i.incident_title ILIKE '%OT%' OR i.incident_title ILIKE '%SCADA%' OR i.incident_title ILIKE '%Modbus%'
    OR i.incident_title ILIKE '%PLC%' OR i.incident_title ILIKE '%Purdue%' OR i.incident_title ILIKE '%Siemens%'
    OR i.incident_title ILIKE '%IoT%' OR i.incident_title ILIKE '%ICS%' OR i.incident_title ILIKE '%industrial%'
    OR i.incident_title ILIKE '%Deceptor%' OR i.incident_title ILIKE '%Unusual%' OR i.incident_title ILIKE '%Unusal%'
    OR r.name ILIKE '%OT%' OR r.name ILIKE '%SCADA%' OR r.name ILIKE '%Modbus%' OR r.name ILIKE '%Purdue%'
    OR r.name ILIKE '%PLC%' OR r.name ILIKE '%Siemens%'
  )
GROUP BY 1, 2
ORDER BY 1, 2
""")
out["ot_incidents_by_sev_status"] = enrich_status_counts(inc_ot_sum or [])

cmdb_new = pg("cmdb_new", f"""
SELECT d.name, d.access_ip::text AS access_ip, dt.vendor, dt.model, d.discover_method, d.creation_time
FROM ph_device d
INNER JOIN ph_device_type dt ON dt.id = d.device_type_id
WHERE d.creation_time IS NOT NULL
  AND d.creation_time >= {START_MS}
  AND d.creation_time < {END_MS}
ORDER BY d.creation_time DESC NULLS LAST
LIMIT 80
""")
out["cmdb_new_in_window"] = fmt_ct(cmdb_new or [])

cmdb_new_otish = pg("cmdb_new_otish", f"""
SELECT d.name, d.access_ip::text AS access_ip, dt.vendor, dt.model, d.discover_method, d.creation_time
FROM ph_device d
INNER JOIN ph_device_type dt ON dt.id = d.device_type_id
WHERE d.creation_time IS NOT NULL
  AND d.creation_time >= {START_MS}
  AND d.creation_time < {END_MS}
  AND (
    dt.vendor ILIKE '%Siemens%' OR dt.model ILIKE '%PLC%' OR dt.model ILIKE '%Rugged%' OR dt.model ILIKE '%Deceptor%'
    OR dt.vendor ILIKE '%FortiDeceptor%' OR d.name ILIKE '%Rugged%' OR d.name ILIKE '%Deceptor%' OR d.name ILIKE '%FDC%'
    OR d.name ILIKE '%PLC%' OR d.name ILIKE '%SCADA%' OR d.name ILIKE '%OT%' OR d.name ILIKE '%Modbus%'
    OR d.access_ip::text LIKE '%172.16.0.%' OR d.access_ip::text LIKE '%192.168.27.%'
  )
ORDER BY d.creation_time DESC NULLS LAST
LIMIT 50
""")
out["cmdb_new_ot_ish"] = fmt_ct(cmdb_new_otish or [])

inc_ot_ip = pg("incidents_ot_ip", f"""
SELECT i.incident_id, i.incident_title, i.severity_cat, i.incident_status,
       i.src_ip_addr, i.dest_ip_addr, i.host_name, i.host_ip_addr,
       i.orig_first_seen_time, i.last_seen_time, r.name AS rule_name
FROM ph_incident i
LEFT JOIN ph_drq_rule r ON r.id=i.rule_id
WHERE {PG_WIN_I}
  AND (
    i.src_ip_addr::text LIKE '%172.16.0.%' OR i.dest_ip_addr::text LIKE '%172.16.0.%'
    OR i.host_ip_addr::text LIKE '%172.16.0.%'
    OR i.src_ip_addr::text LIKE '%192.168.27.%' OR i.dest_ip_addr::text LIKE '%192.168.27.%'
    OR i.host_ip_addr::text LIKE '%192.168.27.%'
    OR i.host_name ILIKE '%Rugged%' OR i.host_name ILIKE '%FDC%' OR i.host_name ILIKE '%SCADA%'
    OR i.host_name ILIKE '%PLC%' OR i.host_name ILIKE '%OT%'
  )
ORDER BY i.last_seen_time DESC NULLS LAST
LIMIT 50
""")
out["incidents_touching_ot_ips"] = enrich_inc(inc_ot_ip or [])

rules_inc = pg("ot_incident_rules", f"""
SELECT r.name, COUNT(*) AS c, MAX(i.severity_cat) AS sev
FROM ph_incident i
JOIN ph_drq_rule r ON r.id=i.rule_id
WHERE {PG_WIN_I}
  AND (r.name ILIKE '%OT%' OR r.name ILIKE '%SCADA%' OR r.name ILIKE '%Modbus%' OR r.name ILIKE '%Purdue%'
       OR r.name ILIKE '%PLC%' OR r.name ILIKE '%Siemens%' OR r.name ILIKE '%IoT%'
       OR i.incident_title ILIKE '%OT%' OR i.incident_title ILIKE '%SCADA%' OR i.incident_title ILIKE '%Siemens%'
       OR i.incident_title ILIKE '%PLC%' OR i.incident_title ILIKE '%Modbus%' OR i.incident_title ILIKE '%Purdue%')
GROUP BY r.name ORDER BY c DESC LIMIT 20
""")
out["ot_incident_rules"] = rules_inc or []

hi_ot = pg("incidents_ot_high", f"""
SELECT i.incident_id, i.incident_title, i.severity_cat, i.incident_status,
       i.src_ip_addr, i.dest_ip_addr, i.host_name, i.host_ip_addr,
       i.orig_first_seen_time, i.last_seen_time, r.name AS rule_name
FROM ph_incident i
LEFT JOIN ph_drq_rule r ON r.id=i.rule_id
WHERE {PG_WIN_I}
  AND i.severity_cat ILIKE 'HIGH'
  AND (
    i.incident_title ILIKE '%OT%' OR i.incident_title ILIKE '%SCADA%' OR i.incident_title ILIKE '%Modbus%'
    OR i.incident_title ILIKE '%PLC%' OR i.incident_title ILIKE '%Purdue%' OR i.incident_title ILIKE '%Siemens%'
    OR i.incident_title ILIKE '%IoT%' OR i.incident_title ILIKE '%ICS%' OR i.incident_title ILIKE '%industrial%'
    OR i.incident_title ILIKE '%Deceptor%' OR i.incident_title ILIKE '%Unusual%' OR i.incident_title ILIKE '%Unusal%'
    OR r.name ILIKE '%OT%' OR r.name ILIKE '%SCADA%' OR r.name ILIKE '%Modbus%' OR r.name ILIKE '%Purdue%'
    OR r.name ILIKE '%PLC%' OR r.name ILIKE '%Siemens%'
  )
ORDER BY i.last_seen_time DESC NULLS LAST
LIMIT 20
""")
out["ot_high_incidents"] = enrich_inc(hi_ot or [])

port_src = ch("port_scan_sources", f"""SELECT toString(srcIpAddr) AS src, toString(destIpAddr) AS dst,
  reptDevName, count(*) AS c, min(toString(toTimezone(toDateTime(phRecvTime),'Asia/Hong_Kong'))) AS first_t,
  max(toString(toTimezone(toDateTime(phRecvTime),'Asia/Hong_Kong'))) AS last_t
FROM fsiem.events
WHERE {OT_MATCH} AND (eventType ILIKE '%Port_Scan%' OR eventType ILIKE '%port_scanning%' OR eventName ILIKE '%Port Scan%')
GROUP BY src, dst, reptDevName
ORDER BY c DESC LIMIT 25""")
out["ot_port_scan_sources"] = port_src or []

ext = ch("ext_to_ot", f"""SELECT toString(srcIpAddr) AS src, toString(destIpAddr) AS dst,
  eventType, any(eventName) AS evtName, ifNull(toString(eventSeverityCat),'') AS sev, count(*) AS c
FROM fsiem.events
WHERE {WIN} AND eventType NOT ILIKE 'PH_AUDIT%'
  AND (toString(destIpAddr) LIKE '172.16.0.%' OR toString(destIpAddr) LIKE '192.168.27.%')
  AND NOT (toString(srcIpAddr) LIKE '172.16.%' OR toString(srcIpAddr) LIKE '192.168.%' OR toString(srcIpAddr) LIKE '10.%')
GROUP BY src, dst, eventType, sev
ORDER BY c DESC LIMIT 30""")
out["external_to_ot"] = ext or []

unk = ch("unknown_types", f"""SELECT eventType, any(eventName) AS evtName, reptDevName, count(*) AS c,
  any(substring(ifNull(rawEventMsg,''),1,220)) AS msg
FROM fsiem.events WHERE {OT_MATCH} AND eventType = 'Unknown_EventType'
GROUP BY eventType, reptDevName
ORDER BY c DESC LIMIT 10""")
out["unknown_eventtype_breakdown"] = unk or []

cfg_ev = ch("cfg_events_ot", f"""SELECT
  toString(toTimezone(toDateTime(phRecvTime),'Asia/Hong_Kong')) AS t,
  eventType, eventName, ifNull(user,'') AS userName, reptDevName,
  toString(srcIpAddr) AS src, toString(destIpAddr) AS dst,
  substring(ifNull(rawEventMsg,''),1,280) AS msg
FROM fsiem.events
WHERE {WIN} AND eventType NOT ILIKE 'PH_AUDIT%'
  AND (eventType ILIKE '%Config%' OR eventName ILIKE '%Config Change%' OR eventType ILIKE '%system-config%')
  AND ({OT_NET} OR reptDevName ILIKE '%Rugged%' OR reptDevName ILIKE '%FDC%' OR reptDevName ILIKE '%PAM%')
ORDER BY phRecvTime DESC LIMIT 25""")
out["config_events_ot"] = cfg_ev or []

out["sql_used"] = sql_used
out["query_errors"] = errors
out["false_positive_notes"] = {
    "bare_multiSearch_IoT": "Would match Cryptojacking via substring; excluded by word-boundary.",
    "PH_AUDIT": "Excluded all PH_AUDIT% (self-query / dashboard noise mentioning Modbus/OT).",
    "title_ilike_ot": "Incident title ILIKE '%OT%' is not genuine OT (matches protocol/Remote/Botnet/Protection). Use incidents_touching_ot_ips instead.",
}

# No leftover 5-day / previous-window findings templates.
out["findings_draft"] = []

path = os.environ.get("FORTISIEM_OT_JSON") or str(Path(os.environ.get("FORTISIEM_REPORT_ROOT") or Path(__file__).resolve().parent) / "ot-collect.json")
with open(path, "w") as f:
    json.dump(out, f, ensure_ascii=False, indent=2, default=str)
print(f"\nWrote {path}", flush=True)
print(f"TOTAL={out['total_ot_iot_related_events']} daily={out['daily_trend_hkt']}", flush=True)
print(f"window={START_S} .. {END_S} HKT queried_at={out['queried_at_hkt']}", flush=True)
print(f"failures={len(out['mcp_failures'])}", flush=True)
for e in out["mcp_failures"]:
    print("  ERR", e.get("query") or e.get("tool"), (e.get("error") or "")[:160], flush=True)
