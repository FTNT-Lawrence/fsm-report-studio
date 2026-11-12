#!/usr/bin/env python3
"""
fsm_report.py — FortiSIEM 安全報告產生器 (FortiSIEM security report generator)

Queries FortiSIEM through its MCP endpoint (JSON-RPC over HTTPS, OAuth2 client_credentials),
STRICTLY READ-ONLY, and renders a single self-contained offline HTML report
(ECharts + fonts inlined) in one of three themes: v1 (dark SOC), v1.1 (bright editorial), v1.2 (cyber HUD).

Python 3.9+, standard library only.
The client secret is read from env FORTISIEM_CLIENT_SECRET (or an interactive getpass prompt);
it is never printed, logged or written to any output.
"""
import argparse, ast, base64, datetime as dt, getpass, html, json, logging, os, re, ssl, sys, threading, time
import urllib.error, urllib.parse, urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import queue

VERSION = "1.2.0"
HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
HKT = dt.timezone(dt.timedelta(hours=8))
THEMES = ("v1", "v1.1", "v1.2", "v1.3")
# Only these MCP tools are ever called. Anything that writes (update_*, clear_*, append_*) is refused.
READ_ONLY_TOOLS = {
    "query_fsm_clickhouse", "query_fsm_postgres", "get_top_10_risky_devices_incidents", "get_top_10_risky_users_incidents",
    "get_incident_by_id", "get_trigger_events_by_incident_id", "get_related_incidents_by_id", "get_iocs_by_incident_ids",
    "get_context_by_entity", "get_incidents_by_entity", "get_reputation_by_entity",
}
log = logging.getLogger("fsm_report")


class SecretFilter(logging.Filter):
    """Belt and braces: scrub the secret / bearer token from any log line."""
    def __init__(self):
        super().__init__(); self.secrets = []
    def filter(self, record):
        msg = record.getMessage()
        for s in self.secrets:
            if s and s in msg:
                msg = msg.replace(s, "***")
        msg = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+", r"\1***", msg)
        record.msg, record.args = msg, ()
        return True
SECRET_FILTER = SecretFilter()


def now_hkt():
    return dt.datetime.now(HKT)


def ms2hk(ms):
    try:
        return dt.datetime.fromtimestamp(float(ms) / 1000, HKT).strftime("%Y-%m-%d %H:%M") if ms else None
    except Exception:
        return None


# ----------------------------------------------------------------------------- time window
class Window:
    """Builds WHERE fragments. Relative mode (--days) uses the server clock (now()), exactly like the
    original report; absolute mode (--start/--end, HKT) uses epoch literals."""
    def __init__(self, days=7, start=None, end=None):
        self.relative = not (start or end)
        if self.relative:
            self.days = float(days)
            self.end = now_hkt(); self.start = self.end - dt.timedelta(days=self.days)
        else:
            self.end = end or now_hkt()
            self.start = start or (self.end - dt.timedelta(days=float(days)))
            if self.start >= self.end:
                raise SystemExit("--start must be earlier than --end")
            self.days = (self.end - self.start).total_seconds() / 86400
        self.s0, self.s1 = int(self.start.timestamp()), int(self.end.timestamp())

    def ch(self, pad_days=0):
        if self.relative:
            return f"phRecvTime > now() - {self.days + pad_days:g}*86400"
        return f"phRecvTime >= toDateTime({self.s0 - int(pad_days * 86400)}) AND phRecvTime < toDateTime({self.s1})"

    def pg(self, col="last_seen_time", alias=""):
        c = alias + col
        if self.relative:
            return f"{c} > (extract(epoch from now())*1000 - {self.days:g}*86400000)"
        return f"{c} >= {self.s0 * 1000} AND {c} < {self.s1 * 1000}"

    def label(self):
        if self.relative:
            return f"Last {self.days:g} days (phRecvTime > now()-{self.days:g}*86400 / last_seen_time > now-{self.days:g}d)"
        return f"{self.start:%Y-%m-%d %H:%M} → {self.end:%Y-%m-%d %H:%M} HKT (absolute)"


def parse_hkt(s):
    if not s:
        return None
    for f in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(s, f).replace(tzinfo=HKT)
        except ValueError:
            pass
    raise SystemExit(f"Cannot parse time '{s}' (use YYYY-MM-DD or 'YYYY-MM-DD HH:MM', HKT)")


# ----------------------------------------------------------------------------- MCP client (stdlib)
def _mask_secrets(text, *secrets):
    """Scrub secrets / bearer tokens from error snippets before logging."""
    s = "" if text is None else str(text)
    for sec in secrets:
        if sec and len(str(sec)) > 4:
            s = s.replace(str(sec), "***")
    s = re.sub(r"(?i)(client_secret|access_token)\s*[:=]\s*[^,&\s\"']+", r"\1=***", s)
    s = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+", r"\1***", s)
    return s


class MCP:
    """JSON-RPC MCP client over FortiSIEM HTTPS.

    OAuth + initialize are serialized with a class-level lock so parallel workers
    cannot stampede the token endpoint (a common cause of HTTP 400 on smaller FSMs).
    Each instance also has an RPC lock so one session is never used concurrently.
    """
    _oauth_lock = threading.Lock()

    def __init__(self, host, client_id, secret, insecure=True, cafile=None, timeout=120):
        self.base = "https://" + host.replace("https://", "").rstrip("/")
        self.client_id, self._secret, self.timeout = client_id, secret, timeout
        if insecure:
            self.ctx = ssl.create_default_context(); self.ctx.check_hostname = False; self.ctx.verify_mode = ssl.CERT_NONE
        else:
            self.ctx = ssl.create_default_context(cafile=cafile)
        self.tok = None; self.sid = None; self.n = 0
        self._rpc_lock = threading.Lock()
        self._authed_once = False
        self.connect()

    def _http(self, url, data, headers):
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as r:
                return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers or {}), (e.read() or b"").decode("utf-8", "replace")

    def _remember_token(self, tok):
        self.tok = tok
        secs = list(SECRET_FILTER.secrets or [])
        for x in (self._secret, self.tok):
            if x and x not in secs:
                secs.append(x)
        SECRET_FILTER.secrets = secs

    def _oauth_fail(self, st, txt):
        snippet = _mask_secrets((txt or "").replace("\n", " ")[:200], self._secret, self.tok)
        hint = ""
        if self._authed_once:
            hint = (" Previously connected OK — parallel re-auth often causes OAuth HTTP 400 "
                    "on some FortiSIEM hosts. Retry with --workers 1.")
        return RuntimeError(
            f"OAuth token request failed (HTTP {st}): {snippet or '(empty body)'}. "
            f"Check client id / secret / host.{hint}")

    def token(self):
        """Fetch a new access token. Always call under _oauth_lock (or via connect())."""
        body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": self.client_id,
                                       "client_secret": self._secret}).encode()
        st, _, txt = self._http(self.base + "/phoenix/rest/pub/security/oauth/token", body,
                                {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
        if st != 200:
            raise self._oauth_fail(st, txt)
        try:
            tok = json.loads(txt)["access_token"]
        except Exception:
            snippet = _mask_secrets((txt or "").replace("\n", " ")[:200], self._secret)
            raise RuntimeError(f"OAuth token response did not contain an access token: {snippet}")
        self._remember_token(tok)

    def _hdr(self):
        h = {"Authorization": "Bearer " + self.tok, "Content-Type": "application/json",
             "Accept": "application/json, text/event-stream"}
        if self.sid:
            h["mcp-session-id"] = self.sid
        return h

    def _post(self, body):
        return self._http(self.base + "/phoenix/mcp", json.dumps(body).encode(), self._hdr())

    def connect(self):
        """OAuth + MCP initialize. Serialized class-wide."""
        with MCP._oauth_lock:
            self.token()
            self.sid = None
            st, hd, txt = self._post({"jsonrpc": "2.0", "id": self._id(), "method": "initialize",
                                      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                                 "clientInfo": {"name": "fsm_report", "version": VERSION}}})
            if st >= 400:
                snippet = _mask_secrets((txt or "").replace("\n", " ")[:200], self._secret, self.tok)
                raise RuntimeError(f"MCP initialize failed (HTTP {st}): {snippet or '(empty body)'}")
            self.sid = {k.lower(): v for k, v in hd.items()}.get("mcp-session-id")
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
            self._authed_once = True

    def _id(self):
        self.n += 1
        return self.n

    @staticmethod
    def _parse(txt):
        for line in txt.splitlines():
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except Exception:
                    pass
        try:
            return json.loads(txt)
        except Exception:
            return {"error": {"message": txt[:500]}}

    def rpc(self, method, params, retry=True):
        # Re-auth ONLY on 401/403 (and 404 session loss). MCP HTTP 400 is a query/tool
        # failure — reconnecting used to stampede OAuth under --workers > 1.
        with self._rpc_lock:
            st, _, txt = self._post({"jsonrpc": "2.0", "id": self._id(), "method": method, "params": params})
            need = retry and st in (401, 403, 404)
            if st == 400:
                log.debug("MCP HTTP 400 for %s (not re-authing): %s", method,
                          _mask_secrets((txt or "").replace("\n", " ")[:160], self._secret, self.tok))
            if not need:
                return self._parse(txt)
        # Drop RPC lock before OAuth so we never hold rpc+oauth together.
        log.warning("MCP HTTP %s for %s — re-authenticating once", st, method)
        self.connect()
        with self._rpc_lock:
            st, _, txt = self._post({"jsonrpc": "2.0", "id": self._id(), "method": method, "params": params})
            return self._parse(txt)

    def call(self, name, args):
        if name not in READ_ONLY_TOOLS:
            raise RuntimeError(f"refusing to call non-whitelisted tool {name}")
        t0 = time.time()
        res = self.rpc("tools/call", {"name": name, "arguments": args})
        if "error" in res:
            return {"error": res["error"], "secs": round(time.time() - t0, 1)}
        r = res.get("result", {})
        out = [_loads(c.get("text", "")) for c in r.get("content", [])]
        return {"isError": r.get("isError", False), "data": out[0] if len(out) == 1 else out, "secs": round(time.time() - t0, 1)}



def _loads(tx):
    try:
        return json.loads(tx)
    except Exception:
        try:
            return ast.literal_eval(tx)
        except Exception:
            pass
    # IOC tool returns a python repr with datetime(...) objects
    if isinstance(tx, str) and "datetime.datetime(" in tx:
        t2 = re.sub(r"datetime\.datetime\(((?:[^()]|\([^()]*(?:\([^()]*\))?[^()]*\))*)\)", lambda m: repr(_dtrepr(m.group(1))), tx)
        try:
            return ast.literal_eval(t2)
        except Exception:
            pass
    return tx


def _dtrepr(args):
    try:
        n = [int(x) for x in re.findall(r"(?<![\w.'\"])-?\d+(?![\w.'\"])", args.split("tzinfo")[0])][:6]
        t = dt.datetime(*n)
        if "tzinfo" in args:  # server returns UTC-aware datetimes → HKT
            t = t.replace(tzinfo=dt.timezone.utc).astimezone(HKT)
        return t.strftime("%Y-%m-%d %H:%M:%S") + " HKT"
    except Exception:
        return args


def unwrap(v):
    for _ in range(4):
        if isinstance(v, dict) and isinstance(v.get("content"), list):
            outs = [_loads(c.get("text", "")) for c in v["content"] if isinstance(c, dict)]
            v = outs[0] if len(outs) == 1 else outs
        else:
            break
    if isinstance(v, dict) and "columns" in v and "rows" in v:
        v = [dict(zip(v["columns"], r)) for r in v["rows"]]
    return v


def q(m, tool, args):
    r = m.call(tool, args)
    if "error" in r:
        return {"ok": False, "error": str(r["error"])[:500], "secs": r.get("secs")}
    d = unwrap(r["data"])
    err = r.get("isError") or (isinstance(r["data"], dict) and r["data"].get("isError"))
    if isinstance(d, dict) and set(d.keys()) == {"error"}:
        err = True; d = d["error"]
    if isinstance(d, dict) and d.get("status") == "error":
        err = True; d = d.get("message", d)
    if err or (isinstance(d, str) and re.search(r"error|not allowed|denied", d, re.I)):
        return {"ok": False, "error": (d if isinstance(d, str) else json.dumps(d, default=str))[:800], "secs": r.get("secs")}
    return {"ok": True, "data": d, "secs": r.get("secs")}


# ----------------------------------------------------------------------------- query catalog
def sqlq(s):
    return str(s).replace("'", "''")


def is_private(ip):
    return bool(re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|0\.)", str(ip or "")))


def is_ip(s):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(s or "")))


CAT = "CASE r.category WHEN 1 THEN 'Availability' WHEN 2 THEN 'Performance' WHEN 3 THEN 'Change' WHEN 4 THEN 'Security' ELSE 'Other' END"
STATUS = "CASE i.incident_status WHEN 0 THEN 'Open' WHEN 1 THEN 'Cleared (FortiSIEM)' WHEN 2 THEN 'Cleared (User)' WHEN 3 THEN 'Cleared (Rule)' ELSE 'Unknown' END"


def phase1(w):
    W = w.ch(); D = "toDate(phRecvTime,'Asia/Hong_Kong')"
    IW, FW = w.pg(), w.pg("orig_first_seen_time")
    IWi = w.pg(alias="i.")
    g = lambda n: f"dictHas('fsiem.dict_cmdb_group', (toUInt32(0), toString(fsiem.events.eventType), '{n}'))"
    CH = {
        "ev_total": f"SELECT count(*) AS events, uniqExact(reptDevIpAddr) AS rept_ips, uniqExact(reptDevName) AS rept_names, uniqExact(eventType) AS event_types, min(phRecvTime) AS first, max(phRecvTime) AS last FROM fsiem.events WHERE {W}",
        "ev_per_day": f"SELECT {D} AS day, count(*) AS c FROM fsiem.events WHERE {W} GROUP BY day ORDER BY day",
        "ev_heatmap": f"SELECT {D} AS day, toHour(phRecvTime,'Asia/Hong_Kong') AS hr, count(*) AS c FROM fsiem.events WHERE {W} GROUP BY day, hr ORDER BY day, hr",
        "ev_top_types": f"SELECT eventType, any(eventName) AS eventName, any(eventTypeGrp) AS grp, count(*) AS c FROM fsiem.events WHERE {W} GROUP BY eventType ORDER BY c DESC LIMIT 25",
        "ev_by_sev": f"SELECT eventSeverityCat AS sev, count(*) AS c FROM fsiem.events WHERE {W} GROUP BY sev ORDER BY c DESC",
        "ev_by_cat": f"SELECT phEventCategory AS cat, count(*) AS c FROM fsiem.events WHERE {W} GROUP BY cat ORDER BY c DESC",
        "ev_by_vendor": f"SELECT reptVendor, reptModel, count(*) AS c FROM fsiem.events WHERE {W} GROUP BY reptVendor, reptModel ORDER BY c DESC LIMIT 20",
        "ev_top_rept": f"SELECT reptDevName, toString(reptDevIpAddr) AS ip, any(reptModel) AS model, count(*) AS c FROM fsiem.events WHERE {W} GROUP BY reptDevName, ip ORDER BY c DESC LIMIT 20",
        "ev_rept_list": f"SELECT reptDevName, toString(reptDevIpAddr) AS ip, any(reptVendor) AS vendor, any(reptModel) AS model, count(*) AS c, max(phRecvTime) AS last FROM fsiem.events WHERE {W} GROUP BY reptDevName, ip ORDER BY c DESC",
        "ev_top_src": f"SELECT toString(srcIpAddrV4) AS ip, count(*) AS c FROM fsiem.events WHERE {W} AND srcIpAddrV4 IS NOT NULL AND toString(srcIpAddrV4) NOT IN ('0.0.0.0','') GROUP BY ip ORDER BY c DESC LIMIT 15",
        "ev_top_dst": f"SELECT toString(destIpAddrV4) AS ip, count(*) AS c FROM fsiem.events WHERE {W} AND destIpAddrV4 IS NOT NULL AND toString(destIpAddrV4) NOT IN ('0.0.0.0','') GROUP BY ip ORDER BY c DESC LIMIT 15",
        "ev_top_users": f"SELECT user, count(*) AS c FROM fsiem.events WHERE {W} AND user != '' GROUP BY user ORDER BY c DESC LIMIT 15",
        "ev_top_dport": f"SELECT destIpPort AS port, ipProto, count(*) AS c FROM fsiem.events WHERE {W} AND destIpPort > 0 GROUP BY port, ipProto ORDER BY c DESC LIMIT 15",
        "ev_src_country": f"SELECT srcGeoCountry AS country, count(*) AS c FROM fsiem.events WHERE {W} AND srcGeoCountry != '' GROUP BY country ORDER BY c DESC LIMIT 15",
        "ev_dst_country": f"SELECT destGeoCountry AS country, count(*) AS c FROM fsiem.events WHERE {W} AND destGeoCountry != '' GROUP BY country ORDER BY c DESC LIMIT 15",
        "ev_rept_daily": f"SELECT {D} AS day, reptDevName, count(*) AS c FROM fsiem.events WHERE {W} GROUP BY day, reptDevName ORDER BY day",
        "ev_sev_daily": f"SELECT {D} AS day, eventSeverityCat AS sev, count(*) AS c FROM fsiem.events WHERE {W} GROUP BY day, sev ORDER BY day",
        "traffic_daily": f"SELECT {D} AS day, countIf({g('PH_SYS_EVENT_PermitTraffic')}) AS permit, countIf({g('PH_SYS_EVENT_DenyTraffic')}) AS deny FROM fsiem.events WHERE {W} GROUP BY day ORDER BY day",
        "traffic_fgt_action": f"SELECT reptDevName, countIf(eventAction=0) AS permitted, countIf(eventAction=1) AS blocked FROM fsiem.events WHERE {W} AND reptVendor ILIKE 'Fortinet' AND eventType ILIKE 'FortiGate-traffic%' GROUP BY reptDevName ORDER BY permitted+blocked DESC LIMIT 10",
        "traffic_deny_top_src": f"SELECT toString(srcIpAddrV4) AS ip, count(*) AS c FROM fsiem.events WHERE {W} AND {g('PH_SYS_EVENT_DenyTraffic')} GROUP BY ip ORDER BY c DESC LIMIT 10",
        "traffic_deny_top_dport": f"SELECT destIpPort AS port, count(*) AS c FROM fsiem.events WHERE {W} AND {g('PH_SYS_EVENT_DenyTraffic')} GROUP BY port ORDER BY c DESC LIMIT 10",
        "auth_daily": f"SELECT {D} AS day, countIf({g('PH_SYS_EVENT_Logon')}) AS success, countIf({g('PH_SYS_EVENT_LogonFailure')}) AS failure FROM fsiem.events WHERE {W} GROUP BY day ORDER BY day",
        "auth_fail_top": f"SELECT user, toString(srcIpAddrV4) AS src, reptDevName, eventType, count(*) AS c FROM fsiem.events WHERE {W} AND {g('PH_SYS_EVENT_LogonFailure')} GROUP BY user, src, reptDevName, eventType ORDER BY c DESC LIMIT 15",
        "auth_success_top": f"SELECT user, toString(srcIpAddrV4) AS src, reptDevName, eventType, count(*) AS c FROM fsiem.events WHERE {W} AND {g('PH_SYS_EVENT_Logon')} GROUP BY user, src, reptDevName, eventType ORDER BY c DESC LIMIT 15",
        "auth_types": f"SELECT eventType, countIf({g('PH_SYS_EVENT_Logon')}) AS success, countIf({g('PH_SYS_EVENT_LogonFailure')}) AS failure FROM fsiem.events WHERE {W} AND ({g('PH_SYS_EVENT_Logon')} OR {g('PH_SYS_EVENT_LogonFailure')}) GROUP BY eventType ORDER BY success+failure DESC LIMIT 15",
        "vpn_events": f"SELECT eventType, user, toString(srcIpAddrV4) AS src, srcGeoCountry, reptDevName, count(*) AS c FROM fsiem.events WHERE {W} AND (eventType ILIKE '%vpn%' OR eventType ILIKE '%ssl%tunnel%') GROUP BY eventType, user, src, srcGeoCountry, reptDevName ORDER BY c DESC LIMIT 20",
        "admin_logins": f"SELECT eventType, user, toString(srcIpAddrV4) AS src, reptDevName, count(*) AS c FROM fsiem.events WHERE {W} AND eventType ILIKE 'FortiGate-event-admin-log%' GROUP BY eventType, user, src, reptDevName ORDER BY c DESC LIMIT 20",
        "dns_groups": f"SELECT countIf({g('PH_SYS_EVENT_CommonDNSTraffic')}) AS common_dns, countIf({g('PH_SYS_EVENT_UncommonDNSTraffic')}) AS uncommon_dns, countIf({g('PH_SYS_EVENT_DenyDNSTraffic')}) AS denied_dns FROM fsiem.events WHERE {W}",
        "dns_types": f"SELECT eventType, count(*) AS c FROM fsiem.events WHERE {W} AND (eventType ILIKE '%dns%' OR destIpPort = 53) GROUP BY eventType ORDER BY c DESC LIMIT 15",
        "dns_top_src": f"SELECT toString(srcIpAddrV4) AS ip, toString(destIpAddrV4) AS dns_server, count(*) AS c FROM fsiem.events WHERE {W} AND destIpPort = 53 GROUP BY ip, dns_server ORDER BY c DESC LIMIT 10",
        "cfg_types": f"SELECT eventType, any(eventName) AS eventName, count(*) AS c FROM fsiem.events WHERE {W} AND (eventType ILIKE '%chg%' OR eventType ILIKE '%config%' OR eventType ILIKE '%change%') GROUP BY eventType ORDER BY c DESC LIMIT 20",
        "cfg_by_dev_user": f"SELECT reptDevName, user, count(*) AS c FROM fsiem.events WHERE {W} AND (eventType ILIKE 'FortiGate-event-chg%' OR eventType ILIKE '%config%change%' OR eventType ILIKE 'FortiGate-event-%config%') GROUP BY reptDevName, user ORDER BY c DESC LIMIT 15",
        "cfg_recent": f"SELECT phRecvTime, reptDevName, user, eventType, substring(rawEventMsg,1,400) AS raw FROM fsiem.events WHERE {W} AND (eventType ILIKE 'FortiGate-event-chg%' OR eventType ILIKE 'FortiGate-event-%config%') ORDER BY phRecvTime DESC LIMIT 20",
        # metrics_float64.value[...] subscript breaks the MCP SQL validator → arrayElement()
        "eps_hourly": f"SELECT toStartOfHour(phRecvTime) AS h, avg(arrayElement(metrics_float64.value, indexOf(metrics_float64.name, 'incomingEventsPerSec'))) AS eps FROM fsiem.events WHERE {W} AND eventType = 'PH_SYSTEM_EPS_GLOBAL' GROUP BY h ORDER BY h",
        "unparsed": f"SELECT reptDevName, count(*) AS c FROM fsiem.events WHERE {W} AND eventType = 'Unknown_EventType' GROUP BY reptDevName ORDER BY c DESC LIMIT 10",
        "security_attacks": f"SELECT eventType, any(eventName) AS eventName, eventSeverityCat AS sev, count(*) AS c FROM fsiem.events WHERE {W} AND eventSeverity >= 7 GROUP BY eventType, sev ORDER BY c DESC LIMIT 15",
        "malware": f"SELECT eventType, count(*) AS c FROM fsiem.events WHERE {W} AND {g('PH_SYS_EVENT_Malware')} GROUP BY eventType ORDER BY c DESC LIMIT 10",
    }
    # Postgres: TO_CHAR/AT TIME ZONE is rejected by the validator → epoch values, converted to HKT locally.
    PG = {
        "inc_by_sev": f"SELECT severity_cat, COUNT(*) AS c FROM ph_incident WHERE {IW} GROUP BY severity_cat ORDER BY c DESC",
        "inc_new_by_sev": f"SELECT severity_cat, COUNT(*) AS c FROM ph_incident WHERE {FW} GROUP BY severity_cat ORDER BY c DESC",
        "inc_by_status": f"SELECT {STATUS} AS status, COUNT(*) AS c FROM ph_incident i WHERE {IWi} GROUP BY 1 ORDER BY c DESC",
        "inc_by_reso": f"SELECT CASE incident_reso WHEN 1 THEN 'Open' WHEN 2 THEN 'True Positive' WHEN 3 THEN 'False Positive' WHEN 4 THEN 'In Progress' ELSE 'Unset' END AS reso, COUNT(*) AS c FROM ph_incident WHERE {IW} GROUP BY 1 ORDER BY c DESC",
        "inc_daily_sev": f"SELECT FLOOR((last_seen_time/1000 + 28800)/86400) AS dayn, severity_cat, COUNT(*) AS c FROM ph_incident WHERE {IW} GROUP BY 1,2 ORDER BY 1",
        "inc_new_daily_sev": f"SELECT FLOOR((orig_first_seen_time/1000 + 28800)/86400) AS dayn, severity_cat, COUNT(*) AS c FROM ph_incident WHERE {FW} GROUP BY 1,2 ORDER BY 1",
        "inc_hourly": f"SELECT FLOOR((last_seen_time/1000 + 28800)/3600) AS hn, COUNT(*) AS c FROM ph_incident WHERE {IW} GROUP BY 1 ORDER BY 1",
        "inc_top_rules": f"SELECT r.name AS rule, {CAT} AS category, SUM(CASE WHEN i.severity_cat='HIGH' THEN 1 ELSE 0 END) AS high, SUM(CASE WHEN i.severity_cat='MEDIUM' THEN 1 ELSE 0 END) AS medium, SUM(CASE WHEN i.severity_cat='LOW' THEN 1 ELSE 0 END) AS low, COUNT(*) AS c, SUM(CASE WHEN i.incident_status=0 THEN 1 ELSE 0 END) AS open FROM ph_incident i JOIN ph_drq_rule r ON r.id=i.rule_id WHERE {IWi} GROUP BY 1,2 ORDER BY c DESC LIMIT 25",
        "inc_by_category": f"SELECT {CAT} AS category, i.severity_cat, COUNT(*) AS c FROM ph_incident i LEFT JOIN ph_drq_rule r ON r.id=i.rule_id WHERE {IWi} GROUP BY 1,2 ORDER BY 1",
        "inc_top_titles": f"SELECT incident_title, severity_cat, COUNT(*) AS c FROM ph_incident WHERE {IW} GROUP BY 1,2 ORDER BY c DESC LIMIT 20",
        "inc_top_hosts": f"SELECT COALESCE(NULLIF(host_name,''),NULLIF(src_name,''),NULLIF(dest_name,'')) AS entity, COALESCE(NULLIF(host_ip_addr,''),NULLIF(src_ip_addr,''),NULLIF(dest_ip_addr,'')) AS ip, COUNT(*) AS c, SUM(CASE WHEN severity_cat='HIGH' THEN 1 ELSE 0 END) AS high FROM ph_incident WHERE {IW} GROUP BY 1,2 ORDER BY c DESC LIMIT 20",
        "inc_top_src_ip": f"SELECT src_ip_addr AS ip, COUNT(*) AS c FROM ph_incident WHERE {IW} AND src_ip_addr IS NOT NULL AND src_ip_addr<>'' GROUP BY 1 ORDER BY c DESC LIMIT 15",
        "inc_top_dest_ip": f"SELECT dest_ip_addr AS ip, COUNT(*) AS c FROM ph_incident WHERE {IW} AND dest_ip_addr IS NOT NULL AND dest_ip_addr<>'' GROUP BY 1 ORDER BY c DESC LIMIT 15",
        "inc_top_users": f"SELECT COALESCE(NULLIF(user_attr,''),NULLIF(src_user_attr,''),NULLIF(target_user_attr,'')) AS usr, COUNT(*) AS c FROM ph_incident WHERE {IW} GROUP BY 1 HAVING COALESCE(NULLIF(user_attr,''),NULLIF(src_user_attr,''),NULLIF(target_user_attr,'')) IS NOT NULL ORDER BY c DESC LIMIT 15",
        "inc_latest_high": f"SELECT i.incident_id, i.incident_title, i.severity_cat, {STATUS} AS status, i.src_ip_addr, i.dest_ip_addr, i.host_name, i.host_ip_addr, i.user_attr, i.orig_first_seen_time, i.last_seen_time, i.incident_count FROM ph_incident i WHERE {IWi} AND i.severity_cat ILIKE 'HIGH' ORDER BY i.last_seen_time DESC LIMIT 40",
        # unnest(string_to_array()) breaks the MCP validator (sqlglot) → group raw strings, split locally
        "inc_tactics_raw": f"SELECT tactics, COUNT(*) AS c FROM ph_incident WHERE {IW} AND tactics IS NOT NULL GROUP BY tactics ORDER BY c DESC LIMIT 50",
        "inc_techniques_raw": f"SELECT technique_ids, COUNT(*) AS c FROM ph_incident WHERE {IW} AND technique_ids IS NOT NULL GROUP BY technique_ids ORDER BY c DESC LIMIT 50",
        "inc_by_org": f"SELECT o.name, COUNT(*) AS c FROM ph_incident i JOIN ph_sys_domain o ON o.domain_id=i.cust_org_id WHERE {IWi} GROUP BY 1 ORDER BY c DESC",
        "inc_top_count_high": f"SELECT i.incident_id, i.incident_title, i.severity_cat, {STATUS} AS status, i.incident_count, r.name AS rule FROM ph_incident i LEFT JOIN ph_drq_rule r ON r.id=i.rule_id WHERE {IWi} AND i.severity_cat='HIGH' ORDER BY i.incident_count DESC NULLS LAST LIMIT 15",
        "cmdb_count": "SELECT COUNT(*) AS c FROM ph_device",
        "cmdb_vendor_model": "SELECT dt.vendor, dt.model, COUNT(*) AS c FROM ph_device d JOIN ph_device_type dt ON dt.id=d.device_type_id GROUP BY 1,2 ORDER BY c DESC",
        "cmdb_discover": "SELECT discover_method, COUNT(*) AS c FROM ph_device GROUP BY 1 ORDER BY c DESC",
        "cmdb_orgs": "SELECT org.name AS org, COUNT(*) AS c FROM ph_device d JOIN ph_sys_domain org ON org.domain_id=d.cust_org_id GROUP BY 1 ORDER BY c DESC",
        "cmdb_all_orgs": "SELECT domain_id, name FROM ph_sys_domain WHERE domain_id NOT IN (0,2)",
        "cmdb_devices": "SELECT d.id, d.name, d.access_ip, dt.vendor, dt.model, dt.version, d.discover_method, d.asset_weight, d.hw_serial_no, d.discover_time, d.creation_time FROM ph_device d JOIN ph_device_type dt ON dt.id=d.device_type_id ORDER BY d.name",
        "cmdb_fortios": "SELECT d.name, d.access_ip, dt.vendor, dt.model, dt.version, d.hw_serial_no, d.discover_method FROM ph_device d JOIN ph_device_type dt ON dt.id=d.device_type_id WHERE dt.model ILIKE '%FortiOS%' ORDER BY d.name",
        "cmdb_status": "SELECT dev.name, dev.access_ip, s.monitor_status, s.event_status FROM ph_device dev JOIN ph_device_status s ON dev.id=s.device_id",
        "cmdb_intf_count": "SELECT d.name, COUNT(*) AS intfs FROM ph_device_intf di JOIN ph_device d ON d.id=di.device_id GROUP BY 1 ORDER BY 2 DESC",
        "cmdb_sw_count": "SELECT d.name, COUNT(*) AS sw FROM ph_installed_software s JOIN ph_device d ON d.id=s.device_id GROUP BY 1 ORDER BY 2 DESC",
        # diskusage_used_pct does not exist on 7.6 → not selected
        "health": "SELECT host_name, host_ip, nodetype, version, content_version, hardware_vcpu, hardware_memory_gb, summary, reason, eps_3min, loadaverage, cpuusage_used_pct, memoryusage_used_pct, swapusage_used_pct, last_update_time FROM ph_health_status WHERE host_ip IS NOT NULL",
        "storage_type": "SELECT property, value FROM ph_sys_conf_view WHERE property = 'storage_type'",
        "fsm_users": "SELECT u.name AS usr, d.name AS org, u.rbac_profile_name AS profile FROM ph_user u JOIN ph_sys_domain d ON d.domain_id=u.cust_org_id WHERE prime_profile_id IS NOT NULL",
        "malware_ip_count": "SELECT COUNT(*) AS c FROM ph_malware_ip",
        "ext_rep_count": "SELECT reputation, COUNT(*) AS c FROM ph_external_reputation GROUP BY 1 ORDER BY 2 DESC LIMIT 10",
    }
    items = {k: ("query_fsm_clickhouse", {"sql": v}) for k, v in CH.items()}
    items.update({k: ("query_fsm_postgres", {"sql": v}) for k, v in PG.items()})
    items["risky_devices"] = ("get_top_10_risky_devices_incidents", {})
    items["risky_users"] = ("get_top_10_risky_users_incidents", {})
    return items


def rule_family(rule):
    rule = rule or ""
    return rule.split(":")[0].strip() if ":" in rule else (rule.split(" ")[0] if rule else "")


def top_family(rules, total):
    c = Counter()
    for r in rules or []:
        c[rule_family(r.get("rule"))] += r.get("c") or 0
    if not c:
        return None, 0, 0.0
    fam, n = c.most_common(1)[0]
    return fam, n, (n / total * 100 if total else 0.0)


def risk_rows(o):
    rows = []
    for k, v in (o or {}).items():
        if not isinstance(v, dict):
            continue
        inc = v.get("incidents") or {}
        ids = [int(i) for x in inc.values() for i in (x.get("incidentIds") or []) if str(i).isdigit()]
        try:
            score = float(v.get("score") or 0)
        except Exception:
            score = 0.0
        rows.append({"entity": k, "score": score, "rules": list(inc.keys()), "ids": ids})
    return sorted(rows, key=lambda r: -r["score"])


def choose_picks(R):
    """Deep-dive selection, all from data: Top risky device's latest incident, most repeated HIGH incident,
    top risky user's latest incident, next risky device's latest incident."""
    get = lambda k: R.get(k, {}).get("data") if R.get(k, {}).get("ok") else None
    rd, ru = risk_rows(get("risky_devices")), risk_rows(get("risky_users"))
    picks, seen = [], set()
    def add(i, role, **kw):
        if i and i not in seen:
            seen.add(i); picks.append(dict(id=int(i), role=role, **kw))
    devs = [r for r in rd if r["ids"]]
    if devs:
        add(max(devs[0]["ids"]), "device", ent=devs[0]["entity"], rank=1)
    th = get("inc_top_count_high") or []
    if th:
        add(th[0].get("incident_id"), "count", n=th[0].get("incident_count"))
    us = [r for r in ru if r["ids"] and r["entity"] not in ("N/A", "", "None")]
    if us:
        add(max(us[0]["ids"]), "user", ent=us[0]["entity"], rank=1)
    for i, r in enumerate(devs[1:], start=2):
        before = len(picks); add(max(r["ids"]), "device", ent=r["entity"], rank=rd.index(r) + 1)
        if len(picks) > before:
            break
    return picks


def _d(R, k):
    v = R.get(k) or {}
    return v.get("data") if v.get("ok") else None


def detail_of(v):
    if isinstance(v, dict) and isinstance(v.get("data"), list) and v["data"]:
        return v["data"][0]
    if isinstance(v, list) and v and isinstance(v[0], dict):
        return v[0]
    return v if isinstance(v, dict) else None


def kvfield(s, key):
    m = re.search(re.escape(key) + r":\s*([^,]+)", str(s or ""))
    return m.group(1).strip() if m else None


def find_exposure(picks, details):
    """First risky-device pick whose incident is an external source hitting an internal ip:port."""
    for p in picks:
        if p.get("role") != "device":
            continue
        d = details.get(p["id"]) or {}
        src = kvfield(d.get("incidentSrc"), "srcIpAddr")
        ip, port = kvfield(d.get("incidentTarget"), "destIpAddr"), kvfield(d.get("incidentTarget"), "destIpPort")
        if is_ip(ip) and port and port.isdigit() and int(port) > 0 and is_ip(src) and not is_private(src):
            return {"id": p["id"], "ip": ip, "port": int(port)}
    return None


def phase2(R, w):
    W, IW = w.ch(), w.pg(alias="i.")
    tot = sum((r.get("c") or 0) for r in (_d(R, "inc_by_sev") or []))
    fam, _, _ = top_family(_d(R, "inc_top_rules"), tot)
    items = {}
    if fam:
        f = sqlq(fam)
        cond = f"(i.incident_title ILIKE '{f}%' OR r.name ILIKE '{f}:%')"
        items["ndr_virus_top"] = ("query_fsm_postgres", {"sql": f"SELECT i.incident_detail_json::json->>'virusName' AS virus, i.severity_cat, COUNT(*) AS c FROM ph_incident i LEFT JOIN ph_drq_rule r ON r.id=i.rule_id WHERE {IW} AND {cond} GROUP BY 1,2 ORDER BY c DESC LIMIT 20"})
        items["ndr_pairs"] = ("query_fsm_postgres", {"sql": f"SELECT i.src_ip_addr, i.dest_ip_addr, COUNT(*) AS c FROM ph_incident i LEFT JOIN ph_drq_rule r ON r.id=i.rule_id WHERE {IW} AND {cond} GROUP BY 1,2 ORDER BY c DESC LIMIT 10"})
    picks = choose_picks(R)
    for p in picks:
        i = p["id"]; prm = {"params": {"incident_id": i}}
        items[f"inc_{i}_detail"] = ("get_incident_by_id", prm)
        items[f"inc_{i}_trigger"] = ("get_trigger_events_by_incident_id", prm)
        items[f"inc_{i}_related"] = ("get_related_incidents_by_id", prm)
        # fallback for trigger events (tool fails server-side with ClickHouse Code 48 on 7.6)
        items[f"trig_pg_{i}"] = ("query_fsm_postgres", {"sql": f"SELECT incident_id, trigger_events FROM ph_incident_detail WHERE incident_id = {i}"})
        items[f"trig_ch_{i}"] = ("query_fsm_clickhouse", {"sql": f"SELECT phRecvTime, eventType, incidentId, inIncidentEventIdList, reptDevName FROM fsiem.events WHERE {W} AND phEventCategory = 1 AND incidentId = {i} ORDER BY phRecvTime DESC LIMIT 10"})
    if picks:
        items["iocs"] = ("get_iocs_by_incident_ids", {"params": {"incident_ids": [p["id"] for p in picks]}})
    return items, picks, fam


def phase3(R, w, picks):
    W, IW = w.ch(), w.pg()
    items, ctx_ips, exposure = {}, [], None
    details = {p["id"]: detail_of(_d(R, f"inc_{p['id']}_detail")) for p in picks}
    for p in picks:
        d = details.get(p["id"]) or {}
        if p["role"] == "device" and is_ip(p.get("ent")):
            ctx_ips.append(p["ent"])
        elif p["role"] == "count":
            s = kvfield(d.get("incidentSrc"), "srcIpAddr")
            if is_ip(s) and is_private(s):
                ctx_ips.append(s)
    pairs = _d(R, "ndr_pairs") or []
    if pairs:
        for ip in (pairs[0].get("src_ip_addr"), pairs[0].get("dest_ip_addr")):
            if is_ip(ip):
                ctx_ips.append(ip)
    for ip in dict.fromkeys(ctx_ips):
        items[f"ctx_{ip}"] = ("get_context_by_entity", {"params": {"ip": ip}})
    for u in risk_rows(_d(R, "risky_users")):
        if not is_ip(u["entity"]) and u["entity"] not in ("N/A", ""):
            items[f"ctx_user_{u['entity']}"] = ("get_context_by_entity", {"params": {"user": u["entity"]}}); break
    tv = max(1, int(round(w.days)))
    for ip in list(dict.fromkeys(([p["ent"] for p in picks if p["role"] == "device" and is_ip(p.get("ent"))][:1]) +
                                 ([pairs[0]["src_ip_addr"]] if pairs and is_ip(pairs[0].get("src_ip_addr")) else []))):
        items[f"ent_{ip}"] = ("get_incidents_by_entity", {"params": {"ip": ip, "time_value": tv, "time_unit": "days"}})
    for p in picks:
        ids = []
        for row in _d(R, f"trig_pg_{p['id']}") or []:
            ids += re.findall(r"\b\d{15,20}\b", str(row.get("trigger_events") or ""))
        ids = list(dict.fromkeys(ids))[:10]
        if ids:
            items[f"trig_raw_{p['id']}"] = ("query_fsm_clickhouse", {"sql": f"SELECT eventId, phRecvTime, eventType, eventSeverityCat, reptDevName, toString(srcIpAddrV4) AS src, toString(destIpAddrV4) AS dst, destIpPort, user, substring(rawEventMsg,1,700) AS raw FROM fsiem.events WHERE {w.ch(pad_days=1)} AND eventId IN ({','.join(ids)}) LIMIT 10"})
    exposure = find_exposure(picks, details)
    if exposure:
        ip, port = exposure["ip"], exposure["port"]
        items["cleartext_ch"] = ("query_fsm_clickhouse", {"sql": f"SELECT 'x' AS k, uniqExact(srcIpAddrV4) AS srcs, count(*) AS c FROM fsiem.events WHERE {W} AND destIpPort = {int(port)} AND toString(destIpAddrV4) = '{ip}'"})
        items["cleartext_srcs"] = ("query_fsm_postgres", {"sql": f"SELECT src_ip_addr, src_geo_country, COUNT(*) AS c, MIN(orig_first_seen_time) AS first, MAX(last_seen_time) AS last FROM ph_incident WHERE {IW} AND dest_ip_addr='{ip}' GROUP BY 1,2 ORDER BY c DESC LIMIT 50"})
    pub = []
    for x in _d(R, "iocs") or []:
        if isinstance(x, dict):
            pub += [x.get("src_ip_addr"), x.get("dest_ip_addr")]
    for d in details.values():
        d = d or {}
        pub += [kvfield(d.get("incidentSrc"), "srcIpAddr"), kvfield(d.get("incidentTarget"), "destIpAddr")]
    pub = [ip for ip in dict.fromkeys(pub) if is_ip(ip) and not is_private(ip)][:8]
    if pub:
        items["rep_ips"] = ("get_reputation_by_entity", {"params": {"ip": pub}})
        items["rep_pg"] = ("query_fsm_postgres", {"sql": "SELECT value, source, reputation, creation_time FROM ph_external_reputation WHERE value IN (" + ",".join(f"'{ip}'" for ip in pub) + ")"})
    return items, exposure


def run_items(items, sessions, label):
    """Run MCP queries. `sessions` is a non-empty list of MCP clients created serially.
    Workers borrow a session from a pool (one RPC at a time per session via MCP._rpc_lock)."""
    if not sessions:
        raise RuntimeError("no MCP sessions")
    pool = queue.Queue()
    for m in sessions:
        pool.put(m)
    out = {}
    n_workers = max(1, min(len(sessions), len(items) or 1))

    def one(it):
        k, (tool, args) = it
        t0 = time.time()
        m = pool.get()
        try:
            r = q(m, tool, args)
        except Exception as e:
            r = {"ok": False, "error": str(e)[:400]}
        finally:
            pool.put(m)
        r["tool"], r["args"] = tool, args
        r.setdefault("secs", round(time.time() - t0, 1))
        if r["ok"]:
            log.info("  ✓ %-28s %5.1fs", k, r["secs"] or 0)
        else:
            log.warning("  ✗ %-28s %s", k, (r.get("error") or "")[:160].replace("\n", " "))
        return k, r

    log.info("%s: %d queries (%d session%s)", label, len(items), len(sessions), "" if len(sessions) == 1 else "s")
    with ThreadPoolExecutor(n_workers) as ex:
        for k, r in ex.map(one, items.items()):
            out[k] = r
    return out


def open_sessions(args, secret):
    """Create 1..N MCP sessions serially (OAuth is class-locked). Never open them in parallel."""
    n = max(1, int(args.workers or 1))
    sessions = []
    for i in range(n):
        log.info("Opening MCP session %d/%d …", i + 1, n)
        sessions.append(MCP(args.host, args.client_id, secret, insecure=args.insecure,
                            cafile=args.cafile, timeout=args.timeout))
    log.info("Connected to https://%s (%d MCP session%s OK)",
             args.host.replace("https://", ""), n, "" if n == 1 else "s")
    if n > 1:
        log.info("Tip: if you see OAuth HTTP 400 after connect, re-run with --workers 1")
    return sessions


def collect(args, secret, w):
    sessions = open_sessions(args, secret)
    R = run_items(phase1(w), sessions, "Phase 1 (aggregates)")
    it2, picks, fam = phase2(R, w)
    R.update(run_items(it2, sessions, "Phase 2 (deep dive)"))
    it3, exposure = phase3(R, w, picks)
    R.update(run_items(it3, sessions, "Phase 3 (context / trigger events / reputation)"))
    return R, picks, exposure



# ----------------------------------------------------------------------------- post-processing (raw → data.json)
def strip_v6(o):
    if isinstance(o, dict):
        return {k: strip_v6(v) for k, v in o.items()}
    if isinstance(o, list):
        return [strip_v6(x) for x in o]
    if isinstance(o, str) and o.startswith("::ffff:"):
        return o[7:]
    return o


DICT_KEYS = ("risky_devices", "risky_users")


def sanitize(S):
    """Make every dataset the shape the report JS expects; anything unusable is dropped (→ 'No data')."""
    out = {}
    for k, v in S.items():
        if isinstance(v, str):
            v = _loads(v)
        want_dict = k in DICT_KEYS or k.startswith(("ctx_", "inc_"))
        if k.startswith("ent_"):
            out[k] = v; continue
        if want_dict and isinstance(v, (dict, list)):
            out[k] = v
        elif not want_dict and isinstance(v, list) and all(isinstance(x, dict) for x in v):
            out[k] = v
        elif not want_dict and isinstance(v, dict) and isinstance(v.get("data"), list):
            out[k] = v["data"]
        else:
            log.warning("  dataset %s has an unexpected shape (%s) → shown as 'No data'", k, type(v).__name__)
    return out


def postprocess(R, picks, exposure, meta):
    S = {}
    for k, v in R.items():
        if v.get("ok") and not (k.startswith("inc_") and k.endswith(("_related", "_trigger"))):
            S[k] = v["data"]
    dayn = lambda n: (dt.date(1970, 1, 1) + dt.timedelta(days=int(float(n)))).isoformat()
    for k in ("inc_daily_sev", "inc_new_daily_sev"):
        for r in S.get(k) or []:
            if "dayn" in r:
                r["day"] = dayn(r.pop("dayn"))
    for r in S.get("inc_hourly") or []:
        if "hn" in r:
            r["hour"] = (dt.datetime(1970, 1, 1) + dt.timedelta(hours=int(float(r.pop("hn"))))).strftime("%Y-%m-%d %H:00")
    for r in S.get("inc_latest_high") or []:
        r["first_seen"] = ms2hk(r.pop("orig_first_seen_time", None)); r["last_seen"] = ms2hk(r.pop("last_seen_time", None))
    for r in S.get("cmdb_devices") or []:
        r["discovered"] = ms2hk(r.pop("discover_time", None)); r["created"] = ms2hk(r.pop("creation_time", None))
    for r in S.get("health") or []:
        try:
            r["updated"] = dt.datetime.fromtimestamp(float(r.pop("last_update_time")), HKT).strftime("%Y-%m-%d %H:%M")
        except Exception:
            r["updated"] = None
        r["role"] = {0: "Supervisor", 1: "Worker", 2: "Collector", 3: "FortiSIEM Manager", 4: "DB Server"}.get(r.get("nodetype"), "Unknown")
        try:
            r["reason"] = json.loads(r["reason"])
        except Exception:
            pass
    for r in S.get("cleartext_srcs") or []:
        r["first"], r["last"] = ms2hk(r.get("first")), ms2hk(r.get("last"))
    S = strip_v6(sanitize(S))
    rel, terr = {}, {}
    for p in picks:
        i = p["id"]; v = R.get(f"inc_{i}_related") or {}
        if not v.get("ok"):
            rel[i] = {"error": v.get("error") or "n/a"}
        else:
            L = v["data"] if isinstance(v["data"], list) else []
            rel[i] = {"count": len(L), "by_rule": Counter(x.get("ruleName") for x in L if isinstance(x, dict)).most_common(10),
                      "sample": [{k: x.get(k) for k in ("incidentId", "ruleName", "incidentTitle", "incidentSrc", "incidentTarget")} for x in L[:15] if isinstance(x, dict)]}
        t = R.get(f"inc_{i}_trigger") or {}
        if not t.get("ok"):
            terr[i] = {"status": "error", "message": t.get("error") or "n/a"}
        d = detail_of(S.get(f"inc_{i}_detail"))
        if d:
            for f in ("incidentFirstSeen", "incidentLastSeen", "origFirstSeenTime"):
                if d.get(f):
                    d[f + "_hkt"] = ms2hk(d[f])
            S[f"inc_{i}_detail"] = d
    S["related_summary"], S["trigger_tool_errors"] = rel, terr
    if isinstance(S.get("rep_ips"), list):
        prov = lambda vv: (vv[0] if isinstance(vv, list) and vv else vv)
        S["rep_ips"] = [{"ip": x.get("ip"), "country": (x.get("location") or {}).get("countryName"), "city": (x.get("location") or {}).get("city"),
                         "watchlists": [f"{w.get('name')} ({w.get('ruleName')})" for w in x.get("watchlists", [])],
                         "incidents": [i.get("incidentId") for i in x.get("incidents", [])],
                         "ti_status": "; ".join(sorted({f"{kk}: {(prov(vv) or {}).get('message') if isinstance(prov(vv), dict) else prov(vv)}" for kk, vv in x.items() if kk.endswith("Fail")}))}
                        for x in S["rep_ips"] if isinstance(x, dict)]
    S["picks_raw"], S["exposure_raw"] = picks, exposure
    src = []
    for k, v in R.items():
        a = v.get("args", {})
        src.append({"key": k, "tool": v.get("tool"), "query": a.get("sql") if "sql" in a else json.dumps(a, ensure_ascii=False),
                    "ok": bool(v.get("ok")), "secs": v.get("secs"), "error": "" if v.get("ok") else (v.get("error") or "")[:400]})
    return {"meta": meta, "data": S, "sources": src}


# ----------------------------------------------------------------------------- narrative / findings (computed from data only)
E = lambda x: html.escape("" if x is None else str(x))
MONO = lambda x: f'<span class="mono">{E(x)}</span>'
ZH = "零一二三四五六七八九"
PORT_SVC = {21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3", 143: "IMAP", 389: "LDAP", 445: "SMB", 1433: "MSSQL",
            3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-alt", 22: "SSH", 443: "HTTPS", 993: "IMAPS", 995: "POP3S"}
PORT_TODO_ZH = {143: "關閉對外 IMAP 143，只開 IMAPS 993", 110: "關閉對外 POP3 110，只開 POP3S 995", 23: "停用 Telnet，改用 SSH",
                21: "停用明文 FTP，改用 SFTP / FTPS", 80: "強制轉用 HTTPS", 3389: "唔好直接對外開放 RDP，改經 VPN 並加 MFA",
                445: "封鎖對外 SMB", 25: "限制 SMTP 只接受指定 relay", 389: "改用 LDAPS 636 並限制來源", 5900: "封鎖對外 VNC"}
PORT_TODO_EN = {143: "Close inbound IMAP 143; allow only IMAPS 993", 110: "Close inbound POP3 110; allow only POP3S 995",
                23: "Disable Telnet; use SSH", 21: "Disable cleartext FTP; use SFTP/FTPS", 80: "Force HTTPS",
                3389: "Do not expose RDP directly; require VPN + MFA", 445: "Block inbound SMB",
                25: "Restrict SMTP to approved relays", 389: "Use LDAPS 636 and restrict sources", 5900: "Block inbound VNC"}
PORT_TODO = PORT_TODO_ZH  # default; derive() selects by lang


def fmt(n):
    if isinstance(n, bool) or n is None:
        return "—"
    if isinstance(n, (int, float)):
        return f"{n:,.0f}" if float(n).is_integer() else f"{n:,.2f}"
    return str(n)


def wan(n, lang="zh"):
    n = n or 0
    if lang == "en":
        if n >= 1e9: return f"{n / 1e9:.2f}B"
        if n >= 1e6: return f"{n / 1e6:.2f}M"
        if n >= 1e3: return f"{n / 1e3:.1f}K"
        return fmt(n)
    if n >= 1e8:
        return f"{n / 1e8:.2f} 億"
    if n >= 1e4:
        return f"{n / 1e4:.0f} 萬" if n >= 1e6 else f"{n / 1e4:.1f} 萬"
    return fmt(n)


def pct(a, b):
    return f"{a / b * 100:.1f}%" if b else "—"


def zh_share(p):
    if p >= 99:
        return "九成九"
    if p >= 10:
        return ZH[int(p // 10)] + "成"
    return f"{p:.1f}%"


def en_share(p):
    return f"{p:.1f}%"


def derive(data, lang="zh"):
    lang = "en" if lang == "en" else "zh"
    en = lang == "en"
    M, D = data.setdefault("meta", {}), data.setdefault("data", {})
    days = float(M.get("days") or 7)
    if en:
        span = "7 days" if abs(days - 7) < 1e-9 else f"{days:g} days"
        wk = "this week" if abs(days - 7) < 1e-9 else "this period"
        join = ", "
        port_todo = PORT_TODO_EN
        share = en_share
    else:
        span = "七日" if abs(days - 7) < 1e-9 else f"{days:g} 日"
        wk = "本週" if abs(days - 7) < 1e-9 else "本期"
        join = "、"
        port_todo = PORT_TODO_ZH
        share = zh_share
    L = lambda k: D.get(k) if isinstance(D.get(k), list) else []
    first = lambda k: (L(k) or [{}])[0]
    inc_total = sum(r.get("c") or 0 for r in L("inc_by_sev"))
    inc_open = next((r.get("c") or 0 for r in L("inc_by_status") if r.get("status") == "Open"), 0)
    rules = L("inc_top_rules")
    fam, fam_n, fam_p = top_family(rules, inc_total)
    fam_rules = [r for r in rules if rule_family(r.get("rule")) == fam]
    fam_open = sum(r.get("open") or 0 for r in fam_rules)
    pairs = L("ndr_pairs")
    top_src = pairs[0].get("src_ip_addr") if pairs else None
    top_src_c = sum(r.get("c") or 0 for r in pairs if r.get("src_ip_addr") == top_src) if top_src else 0
    top_dst = Counter()
    for r in pairs:
        if r.get("src_ip_addr") == top_src:
            top_dst[r.get("dest_ip_addr")] += r.get("c") or 0
    top_dst = top_dst.most_common(1)[0][0] if top_dst else None
    rd, ru = risk_rows(D.get("risky_devices")), risk_rows(D.get("risky_users"))
    score = {r["entity"]: r["score"] for r in rd + ru}
    raw = D.get("picks_raw")
    if not raw:
        raw = []
        th = first("inc_top_count_high")
        for k in D:
            m = re.match(r"^inc_(\d+)_detail$", k)
            if not m:
                continue
            i = int(m.group(1))
            dv = next((r for r in rd if i in r["ids"]), None); uv = next((r for r in ru if i in r["ids"]), None)
            if th.get("incident_id") == i:
                raw.append({"id": i, "role": "count", "n": th.get("incident_count")})
            elif uv:
                raw.append({"id": i, "role": "user", "ent": uv["entity"], "rank": ru.index(uv) + 1})
            elif dv:
                raw.append({"id": i, "role": "device", "ent": dv["entity"], "rank": rd.index(dv) + 1})
            else:
                raw.append({"id": i, "role": "other"})
    exp = D.get("exposure_raw")
    if exp is None:
        exp = find_exposure(raw, {p["id"]: D.get(f"inc_{p['id']}_detail") for p in raw})
    if exp:
        rawtxt = " ".join(str(e.get("raw") or "") for e in L(f"trig_raw_{exp['id']}"))
        g = lambda k: (re.search(k + r'="([^"]+)"', rawtxt) or [None, None])[1]
        pol = " · ".join(f'{k}="{g(k)}"' for k in ("policyname", "service", "trandisp") if g(k))
        exp = dict(exp, svc=g("service") or PORT_SVC.get(exp["port"]), policy=pol or None, policyname=g("policyname"),
                   rpt=(D.get(f"inc_{exp['id']}_detail") or {}).get("incidentRptDevName"))
    picks = []
    for p in raw:
        d = D.get(f"inc_{p['id']}_detail") or {}
        rn = d.get("eventName") or d.get("incidentTitle") or ""
        sc = score.get(p.get("ent"), 0)
        if p["role"] == "device":
            why = (f"Latest incident for top-{p.get('rank', 1)} risky device {p.get('ent')} ({sc:g}): {rn}" if en
                   else f"Top {p.get('rank', 1)} 風險設備 {p.get('ent')}（{sc:g} 分）嘅最新事故：{rn}")
            ctx = f"ctx_{p.get('ent')}"
        elif p["role"] == "count":
            n = p.get("n") if p.get("n") is not None else d.get("count")
            why = (f"Highest-count HIGH incident (incident_count = {n}): {rn}" if en
                   else f"出現次數最多（incident_count = {n}）嘅 HIGH 事故：{rn}")
            s = kvfield(d.get("incidentSrc"), "srcIpAddr"); ctx = f"ctx_{s}"
        elif p["role"] == "user":
            why = (f"Top-{p.get('rank', 1)} risky user {p.get('ent')} ({sc:g}): {rn}" if en
                   else f"Top {p.get('rank', 1)} 風險使用者 {p.get('ent')}（{sc:g} 分）：{rn}")
            ctx = None
        else:
            why = (f"Spotlight incident: {rn}" if en else f"重點事故：{rn}"); ctx = None
        picks.append({"id": p["id"], "why": why, "ctx": ctx if ctx and ctx in D else None,
                      "extra": "exposure" if exp and exp["id"] == p["id"] else None})
    ti = " ".join(r.get("ti_status") or "" for r in L("rep_ips"))
    tinames = [n for k, n in (("virusTotalFail", "VirusTotal"), ("riskIQFail", "RiskIQ"), ("ctsServiceFail", "FortiGuard IOC")) if re.search(k + r"[^;]*not configured", ti)]
    if en:
        deep = f"Selected {len(picks)} incidents that most warrant follow-up." if picks else "No incidents available for deep dive."
        if exp:
            deep += (f" Of these, <b>#{exp['id']}</b> shows an external IP "
                     + (f"via FortiGate policy {MONO(exp['policyname'])} " if exp.get("policyname") else "")
                     + f"reaching {MONO(exp['ip'] + ':' + str(exp['port']))}"
                     + (f" ({E(exp['svc'])})" if exp.get("svc") else "") + "; ")
        if tinames:
            deep += f"external IP reputation returns only geo/watchlist because {join.join(tinames)} are not configured."
    else:
        deep = f"揀咗 {len(picks)} 宗最值得跟進嘅事故。" if picks else "冇可供深入分析嘅事故。"
        if exp:
            deep += f"其中 <b>#{exp['id']}</b> 顯示外部 IP {('經 FortiGate 政策 ' + MONO(exp['policyname']) + ' ') if exp.get('policyname') else ''}連入 {MONO(exp['ip'] + ':' + str(exp['port']))}{'（' + E(exp['svc']) + '）' if exp.get('svc') else ''}；"
        if tinames:
            deep += f"外部 IP 信譽查詢只得地理位置及 watchlist，因為 {join.join(tinames)} 未有設定。"
    rept = L("ev_rept_list"); total_ev = first("ev_total").get("events") or 0
    devs, st = L("cmdb_devices"), {r.get("name"): r for r in L("cmdb_status")}
    names = {d.get("name") for d in devs}
    not_in = [r for r in rept if r.get("reptDevName") not in names]
    crit = [r.get("name") for r in L("cmdb_status") if r.get("event_status") == "Critical"]
    alias = [{"serial": d["hw_serial_no"], "name": d["name"]} for d in devs
             if d.get("hw_serial_no") and d["hw_serial_no"] != d.get("name") and any(r.get("reptDevName") == d["hw_serial_no"] for r in rept)]
    evd = L("ev_per_day"); peak = max(evd, key=lambda r: r.get("c") or 0) if evd else None
    full = evd[1:-1]; avg_full = (sum(r["c"] for r in full) / len(full)) if full else 0
    health = first("health")
    F = []
    def add(lvl, title, body, todo):
        F.append({"lvl": lvl, "title": title, "body": body, "todo": todo})
    if fam and fam_p >= 30:
        vir = [v.get("virus") for v in L("ndr_virus_top") if v.get("virus")][:5]
        if en:
            b = f"Of {fmt(inc_total)} incidents in {span}, {E(fam)} rules account for <b>{fmt(fam_n)}</b> ({fam_p:.1f}%)"
            if top_src:
                b += f"; <b>{fmt(top_src_c)}</b> of them source from {MONO(top_src)}" + (f", mainly targeting {MONO(top_dst)}" if top_dst else "")
            b += "." + (f" Most common names: {join.join(MONO(v) for v in vir)}." if vir else "") + (f" {pct(fam_open, fam_n)} are still Open." if fam_n else "")
            add("high", f"{E(fam)} alerts are flooding the incident queue", b,
                (f"Confirm whether {E(top_src)} is a lab / sample-replay host. If not, isolate and validate samples immediately; if it is a test host, "
                 if top_src else "Review the main triggering sources; if the activity is expected, ")
                + "add FortiSIEM exceptions or aggregation to reduce alert fatigue.")
        else:
            b = f"{span} {fmt(inc_total)} 宗事故中，{E(fam)} 規則佔 <b>{fmt(fam_n)}</b> 宗（{fam_p:.1f}%）"
            if top_src:
                b += f"；其中 <b>{fmt(top_src_c)}</b> 宗來源係 {MONO(top_src)}" + (f"，主要目的係 {MONO(top_dst)}" if top_dst else "")
            b += "。" + (f"最常見名稱：{join.join(MONO(v) for v in vir)}。" if vir else "") + (f"當中 {pct(fam_open, fam_n)} 仍然 Open。" if fam_n else "")
            add("high", f"{E(fam)} 告警淹沒咗事故隊列", b,
                (f"確認 {E(top_src)} 係咪測試 / 樣本重播主機。如果唔係測試，即時隔離並核實樣本；如果係測試，" if top_src else "檢視主要觸發來源；如屬預期活動，")
                + "喺 FortiSIEM 加例外或 aggregation，減少告警疲勞。")
    if rd and rd[0]["score"] >= 40:
        r0 = rd[0]
        if exp:
            r0 = next((r for r in rd if r["entity"] == exp.get("ip") and r["score"] >= rd[0]["score"]), r0)
        if en:
            t = f"Top-1 risky device {E(r0['entity'])} ({r0['score']:g})"
            drivers = join.join('"' + E(x) + '"' for x in r0['rules']) or '—'
            b = f"Risk drivers: {drivers} ({fmt(len(r0['ids']))} related incidents)."
            todo = "Review this device's exposure and policies; confirm whether the service should be internet-facing and apply least privilege."
            if exp and exp.get("ip") == r0["entity"] or (exp and r0["entity"] in (exp.get("ip"),)):
                c = first("cleartext_ch")
                t += f": internet-facing {E(exp.get('svc') or 'port')} ({exp['port']})"
                b += f" In {span}, <b>{fmt(c.get('c'))}</b> events from <b>{fmt(c.get('srcs'))}</b> distinct sources hit {MONO(exp['ip'] + ':' + str(exp['port']))}"
                b += (f" via {E(exp.get('rpt'))} policy {MONO(exp['policyname'])}" if exp.get("policyname") else "") + "."
                todo = (port_todo.get(exp["port"], "Restrict the internet-facing service")
                        + "; or limit sources with Local-in / ISDB; also check related accounts for brute-force.")
            add("high", t, b, todo)
        else:
            t = f"Top 1 風險設備 {E(r0['entity'])}（{r0['score']:g} 分）"
            b = f"風險原因：{join.join('「' + E(x) + '」' for x in r0['rules']) or '—'}（相關事故 {fmt(len(r0['ids']))} 宗）。"
            todo = "檢查呢部設備嘅曝露面同政策，確認係咪應該對外開放，並套用最少權限。"
            if exp and exp.get("ip") == r0["entity"] or (exp and r0["entity"] in (exp.get("ip"),)):
                c = first("cleartext_ch")
                t += f"：對外開放 {E(exp.get('svc') or 'port')}（{exp['port']}）"
                b += f"{span}內 <b>{fmt(c.get('c'))}</b> 筆事件、<b>{fmt(c.get('srcs'))}</b> 個不同來源連入 {MONO(exp['ip'] + ':' + str(exp['port']))}"
                b += (f"，經 {E(exp.get('rpt'))} 政策 {MONO(exp['policyname'])}" if exp.get("policyname") else "") + "。"
                todo = (port_todo.get(exp["port"], "限制對外開放嘅服務") + "；或者用 Local-in / ISDB 限制來源；同時檢查相關帳戶有冇被暴力破解。")
            add("high", t, b, todo)
    unauth = next((r.get("c") for r in L("dns_types") if r.get("eventType") == "PH_RULE_UNAUTH_DNS_QUERY"), 0) or 0
    p53 = sum(r.get("c") or 0 for r in L("ev_top_dport") if r.get("port") == 53)
    d53 = next((r.get("c") for r in L("traffic_deny_top_dport") if r.get("port") == 53), 0) or 0
    dtop = first("dns_top_src")
    if unauth or (dtop.get("dns_server") and not is_private(dtop.get("dns_server"))):
        if en:
            b = f"{MONO('PH_RULE_UNAUTH_DNS_QUERY')} {fmt(unauth)} hits; port-53 events {wan(p53, lang)}, denied {wan(d53, lang)}."
            if dtop:
                b += f" Top client {MONO(str(dtop.get('ip')) + ' → ' + str(dtop.get('dns_server')))} ({wan(dtop.get('c'), lang)})."
            wl = [w.get("name") for w in (((D.get(f"ctx_{dtop.get('ip')}") or {}).get("contexts") or [{}])[0].get("watchlists") or [])]
            add("medium", "Clients querying public DNS directly", b,
                "Enforce internal DNS / FortiGuard DNS filter and block direct public DNS"
                + (f"; follow up {E(dtop.get('ip'))}" if dtop.get("ip") else "")
                + (f" (already on watchlist {E(join.join(wl))})" if wl else "") + ".")
        else:
            b = f"{MONO('PH_RULE_UNAUTH_DNS_QUERY')} {fmt(unauth)} 次；53 埠事件 {wan(p53)}，被拒絕 {wan(d53)}。"
            if dtop:
                b += f"最大客戶端 {MONO(str(dtop.get('ip')) + ' → ' + str(dtop.get('dns_server')))}（{wan(dtop.get('c'))}）。"
            wl = [w.get("name") for w in (((D.get(f"ctx_{dtop.get('ip')}") or {}).get("contexts") or [{}])[0].get("watchlists") or [])]
            add("medium", "用戶直接問公共 DNS", b, "強制使用內部 DNS / FortiGuard DNS filter，封鎖直連公共 DNS"
                + (f"；跟進 {E(dtop.get('ip'))}" if dtop.get("ip") else "") + (f"（已在 {E(join.join(wl))} watchlist）" if wl else "") + "。")
    vr = next((r for r in rules if re.search(r"VPN", r.get("rule") or "") and re.search(r"outside my country", r.get("rule") or "", re.I)), None)
    if vr:
        if en:
            b = f"Rule \"{E(vr['rule'])}\" fired {fmt(vr.get('c'))} times"
            u0 = ru[0] if ru else None
            if u0:
                b += f"; top risky user {MONO(u0['entity'])} ({u0['score']:g})"
                up = next((p for p in raw if p.get("role") == "user"), None)
                if up:
                    tt = (D.get(f"inc_{up['id']}_detail") or {}).get("incidentTitle")
                    geo = next((x.get("src_geo_country") for x in L("iocs") if x.get("incident_title") == tt and x.get("src_geo_country")), None)
                    if geo:
                        b += f". Triggering IP geo shows {E(geo)}"
            add("medium", "\"Outside my country\" VPN rule may be mis-tuned", b + ".",
                "Review FortiSIEM \"My Country\" settings to cut false positives"
                + ("; VPN user field is an IP rather than an account — adjust the parser for user behaviour analytics" if u0 and is_ip(u0["entity"]) else "") + ".")
        else:
            b = f"規則「{E(vr['rule'])}」{fmt(vr.get('c'))} 宗"
            u0 = ru[0] if ru else None
            if u0:
                b += f"；最高風險使用者 {MONO(u0['entity'])}（{u0['score']:g} 分）"
                up = next((p for p in raw if p.get("role") == "user"), None)
                if up:
                    tt = (D.get(f"inc_{up['id']}_detail") or {}).get("incidentTitle")
                    geo = next((x.get("src_geo_country") for x in L("iocs") if x.get("incident_title") == tt and x.get("src_geo_country")), None)
                    if geo:
                        b += f"。觸發 IP 嘅 geo 顯示為 {E(geo)}"
            add("medium", "「境外」VPN 登入規則可能設定唔準", b + "。", "檢查 FortiSIEM「My Country」設定以減少誤報"
                + ("；VPN 使用者欄位係 IP 而唔係帳戶名，建議調整 parser，方便做使用者行為分析" if u0 and is_ip(u0["entity"]) else "") + "。")
    if inc_total and inc_open / inc_total >= 0.5:
        tp = next((r.get("c") for r in L("inc_by_reso") if r.get("reso") == "True Positive"), 0) or 0
        soar = any("soar" in str(u.get("usr", "")).lower() for u in L("fsm_users"))
        if en:
            add("medium", "Incident backlog",
                f"<b>{fmt(inc_open)}</b> / {fmt(inc_total)} ({pct(inc_open, inc_total)}) still Open; only {fmt(tp)} marked True Positive.",
                (f"Auto-clear or notify-only for low-severity {E(fam)} rules; " if fam else "Auto-clear low-severity rules; ")
                + "open Cases / SOAR playbooks for HIGH"
                + (" (fortisoar account already active)" if soar else "") + ".")
        else:
            add("medium", "事故積壓", f"<b>{fmt(inc_open)}</b> / {fmt(inc_total)} 宗（{pct(inc_open, inc_total)}）仍然 Open；只有 {fmt(tp)} 宗標記為 True Positive。",
                (f"為 {E(fam)} 低嚴重度規則設定 auto-clear 或改為只通知；" if fam else "為低嚴重度規則設定 auto-clear；") + "高嚴重度事故開 Case / SOAR playbook" + ("（fortisoar 帳戶已經活躍）" if soar else "") + "。")
    unp = first("unparsed")
    if crit or not_in or unp:
        b = ""
        if en:
            if crit:
                lasts = [f"{E(n)} (last event {(next((r for r in rept if r.get('reptDevName') == n), {}).get('last') or '—').replace('T', ' ')[:16]})" for n in crit]
                b += f"{fmt(len(crit))} devices Critical for collection: {join.join(lasts)}. "
            if not_in:
                b += f"{fmt(len(not_in))} reporting names not in CMDB (e.g. {join.join(MONO(r.get('reptDevName')) for r in not_in[:4])}). "
            if unp:
                b += f"Also {fmt(unp.get('c'))} Unknown_EventType from {E(unp.get('reptDevName'))}."
            add("info", "Gaps in log collection", b,
                "Check syslog delivery for Critical devices"
                + (f"; add reporting device {E(not_in[0].get('reptDevName'))} etc. to CMDB" if not_in else "")
                + ("; apply a parser for unparsed sources" if unp else "") + ".")
        else:
            if crit:
                lasts = [f"{E(n)}（最後事件 {E((next((r for r in rept if r.get('reptDevName') == n), {}).get('last') or '—').replace('T', ' ')[:16])}）" for n in crit]
                b += f"{fmt(len(crit))} 部設備收集狀態 Critical：{join.join(lasts)}。"
            if not_in:
                b += f"{fmt(len(not_in))} 個報告名稱唔喺 CMDB（例如 {join.join(MONO(r.get('reptDevName')) for r in not_in[:4])}）。"
            if unp:
                b += f"另有 {fmt(unp.get('c'))} 筆 Unknown_EventType 來自 {E(unp.get('reptDevName'))}。"
            add("info", "日誌收集有缺口", b, "檢查 Critical 設備嘅 syslog 送達" + (f"；將 {E(not_in[0].get('reptDevName'))} 等報告設備加入 CMDB" if not_in else "") + ("；為未解析來源套用 parser" if unp else "") + "。")
    if peak and full and evd[-2].get("c", 0) < 0.75 * avg_full:
        dd = evd[-2]; r0 = rept[0] if rept else {}
        if en:
            b = (f"Peak {E(peak.get('day'))} ({wan(peak.get('c'), lang)}); {E(dd.get('day'))} fell to {wan(dd.get('c'), lang)} (full-day avg {wan(avg_full, lang)}). "
                 + (f"{E(r0.get('reptDevName'))} is {pct(r0.get('c') or 0, total_ev)} of volume; " if r0 else "")
                 + (f"SIEM EPS {E(health.get('eps_3min'))}, node health {E(health.get('summary'))}." if health else ""))
            ha = sorted({re.sub(r"[-_ ]?(Primary|Backup)$", "", r.get("reptDevName") or "") for r in rept if re.search(r"(Primary|Backup)$", r.get("reptDevName") or "")})
            add("info", f"Event volume dropped clearly on {E((dd.get('day') or '')[5:])}", b,
                f"Confirm whether the {E(dd.get('day'))} drop ties to a logging source stopping or a traffic-policy change"
                + (f"; HA pair ({E(ha[0])} Primary/Backup) should share one logging source to avoid duplicates" if ha else "") + ".")
        else:
            b = (f"高峰 {E(peak.get('day'))}（{wan(peak.get('c'))}）；{E(dd.get('day'))} 跌至 {wan(dd.get('c'))}（完整日平均 {wan(avg_full)}）。"
                 + (f"{E(r0.get('reptDevName'))} 佔 {pct(r0.get('c') or 0, total_ev)} 事件量；" if r0 else "")
                 + (f"SIEM EPS {E(health.get('eps_3min'))}，節點健康 {E(health.get('summary'))}。" if health else ""))
            ha = sorted({re.sub(r"[-_ ]?(Primary|Backup)$", "", r.get("reptDevName") or "") for r in rept if re.search(r"(Primary|Backup)$", r.get("reptDevName") or "")})
            add("info", f"事件量於 {E((dd.get('day') or '')[5:])} 明顯回落", b,
                f"確認 {E(dd.get('day'))} 下降係咪同日誌來源停止送日誌或者流量政策變更有關" + (f"；HA 一對（{E(ha[0])} Primary / Backup）建議統一日誌來源，避免重覆" if ha else "") + "。")
    cfg_tot = sum(r.get("c") or 0 for r in L("cfg_types"))
    if cfg_tot:
        cu = Counter()
        for r in L("cfg_by_dev_user"):
            cu[r.get("user") or "(blank)"] += r.get("c") or 0
        top = cu.most_common(3)
        cc = next((r.get("c") for r in rules if re.search(r"Config Change", r.get("rule") or "")), None)
        shared = [u for u, _ in top if str(u).lower() in ("admin", "root", "administrator", "fortinet")]
        if en:
            add("info", "Config changes concentrated on shared accounts" if shared else "Configuration-change activity",
                f"{fmt(cfg_tot)} config-related events" + (f"; \"FortiGate: Config Change Detected\" {fmt(cc)}" if cc else "")
                + f". Top operators: {join.join(MONO(u) + ' (' + fmt(c) + ')' for u, c in top) or '—'}.",
                ("Move to personal admin accounts with MFA, " if shared else "") + "and tie changes to change tickets.")
        else:
            add("info", "設定變更集中喺共用帳戶" if shared else "設定變更活動",
                f"{fmt(cfg_tot)} 筆設定相關事件" + (f"；「FortiGate: Config Change Detected」{fmt(cc)} 宗" if cc else "") + f"。主要操作者：{join.join(MONO(u) + '（' + fmt(c) + '）' for u, c in top) or '—'}。",
                ("改用個人化管理員帳戶並啟用 MFA，" if shared else "") + "變更與變更單對數。")
    lim = []
    if en:
        if D.get("trigger_tool_errors"):
            lim.append(f"{MONO('get_trigger_events_by_incident_id')} failed server-side (e.g. ClickHouse Code 48); fell back to {MONO('ph_incident_detail')} + {MONO('eventId IN (...)')}.")
        lim.append(f"Postgres validator rejects {MONO('TO_CHAR(... AT TIME ZONE ...)')}; epoch milliseconds are converted to HKT locally.")
        lim.append(f"{MONO('unnest(string_to_array())')} and {MONO('metrics_float64.value[...]')} trip MCP sqlglot errors; raw grouping / {MONO('arrayElement()')} used instead.")
        lim.append(f"{MONO('ph_health_status.diskusage_used_pct')} does not exist; not queried.")
        dg = first("dns_groups")
        if dg and not any(dg.get(k) for k in ("common_dns", "uncommon_dns", "denied_dns")):
            lim.append("DNS event groups counted 0; port-53 analysis used instead.")
        if not L("cmdb_intf_count") and not L("cmdb_sw_count"):
            lim.append("MCP does not expose full device config; ph_device_intf / ph_installed_software returned empty.")
        if tinames:
            lim.append(f"{join.join(tinames)} not configured" + ("; ph_external_reputation has no rows" if not L("rep_pg") else "") + ".")
        lim.append(f"Incidents counted by last_seen_time within {span}; first/last days are partial.")
        lim.append(f"risky-users tool returned {len(ru)} entities; risky-devices returned {len(rd)}.")
        lim.append("The event-to-disposition funnel stages are independent counts with log-scaled widths; MITRE Tactics treemap areas also use log scale with real counts on labels.")
        if fam and fam != "FortiNDR":
            lim.append(f"Charts labelled \"FortiNDR\" (virusName, source → dest) actually follow the top rule family {E(fam)}.")
    else:
        if D.get("trigger_tool_errors"):
            lim.append(f"{MONO('get_trigger_events_by_incident_id')} 伺服器端出錯（例如 ClickHouse Code 48），改用 {MONO('ph_incident_detail')} + {MONO('eventId IN (...)')}。")
        lim.append(f"Postgres validator 拒絕 {MONO('TO_CHAR(... AT TIME ZONE ...)')}，改取 epoch 毫秒再喺本地轉 HKT。")
        lim.append(f"{MONO('unnest(string_to_array())')} 及 {MONO('metrics_float64.value[...]')} 觸發 MCP 端 sqlglot 錯誤，改用 raw 欄位分組 / {MONO('arrayElement()')}。")
        lim.append(f"{MONO('ph_health_status.diskusage_used_pct')} 欄位不存在，冇查詢。")
        dg = first("dns_groups")
        if dg and not any(dg.get(k) for k in ("common_dns", "uncommon_dns", "denied_dns")):
            lim.append("DNS event groups 計數為 0，改用 53 埠分析。")
        if not L("cmdb_intf_count") and not L("cmdb_sw_count"):
            lim.append("MCP 唔提供完整設備設定；ph_device_intf / ph_installed_software 查詢為空。")
        if tinames:
            lim.append(f"{join.join(tinames)} 未設定" + ("；ph_external_reputation 冇記錄" if not L("rep_pg") else "") + "。")
        lim.append(f"事故以 last_seen_time 落在{span}內計算；首尾兩日為不完整日。")
        lim.append(f"risky users 工具回傳 {len(ru)} 個實體；risky devices 回傳 {len(rd)} 個。")
        lim.append("「由事件到處置」漏斗各階段為獨立計數，闊度用對數比例；MITRE Tactics treemap 面積亦用對數比例，標籤為實數。")
        if fam and fam != "FortiNDR":
            lim.append(f"標示為「FortiNDR」嘅圖表（virusName、來源 → 目的）實際按佔比最高嘅規則家族 {E(fam)} 計算。")
    st_ = M.get("start_hkt") or str(first("ev_total").get("first") or "").replace("T", " ")
    en_ = M.get("end_hkt") or str(first("ev_total").get("last") or "").replace("T", " ")
    if en:
        title = f"FortiSIEM Security Review · {st_[:10]} to {en_[5:10]}" if st_ and en_ else "FortiSIEM Security Review"
    else:
        title = f"FortiSIEM 安全回顧 · {st_[:10]} 至 {en_[5:10]}" if st_ and en_ else "FortiSIEM 安全回顧"

    # ISO 27001 Annex A style recommendations — grounded only in collected data
    COMP = []
    def cadd(lvl, ctrl, ctrl_title, title, body, todo):
        COMP.append({"lvl": lvl, "ctrl": ctrl, "ctrl_title": ctrl_title, "title": title, "body": body, "todo": todo})
    if crit or not_in:
        if en:
            b = ""
            if crit:
                b += f"{fmt(len(crit))} CMDB device(s) have Critical collection status ({join.join(E(n) for n in crit)}). "
            if not_in:
                b += f"{fmt(len(not_in))} reporting name(s) send logs but are not in CMDB (e.g. {join.join(MONO(r.get('reptDevName')) for r in not_in[:4])}). "
            b += f"CMDB lists {fmt(len(devs))} device(s); {fmt(len(rept))} reporting names observed in {span}."
            cadd("high", "A.8.15", "Logging", "Log-source inventory incomplete vs CMDB", b,
                 "Reconcile reporting names with CMDB; restore syslog for Critical devices; document discover_method=LOG assets.")
        else:
            b = ""
            if crit:
                b += f"{fmt(len(crit))} 部 CMDB 設備日誌收集狀態 Critical（{join.join(E(n) for n in crit)}）。"
            if not_in:
                b += f"{fmt(len(not_in))} 個報告名稱有送日誌但未入 CMDB（例如 {join.join(MONO(r.get('reptDevName')) for r in not_in[:4])}）。"
            b += f"CMDB 登錄 {fmt(len(devs))} 部；{span}內觀察到 {fmt(len(rept))} 個報告名稱。"
            cadd("high", "A.8.15", "日誌記錄 Logging", "日誌來源盤點同 CMDB 唔齊", b,
                 "對齊報告名稱同 CMDB；修復 Critical 設備 syslog；為 discover_method=LOG 資產補齊記錄。")
    if inc_total and inc_open / inc_total >= 0.5:
        if en:
            cadd("high", "A.8.16", "Monitoring activities", "Incident monitoring backlog",
                 f"<b>{fmt(inc_open)}</b> of {fmt(inc_total)} incidents ({pct(inc_open, inc_total)}) remain Open in {span}.",
                 "Define triage SLAs; auto-clear or aggregate noisy low-severity rules; escalate HIGH via Cases/SOAR.")
        else:
            cadd("high", "A.8.16", "監控活動 Monitoring", "事故監控積壓",
                 f"{span}內 <b>{fmt(inc_open)}</b> / {fmt(inc_total)} 宗事故（{pct(inc_open, inc_total)}）仍然 Open。",
                 "訂立分流 SLA；為低嚴重度嘈雜規則設 auto-clear / aggregation；HIGH 經 Case / SOAR 升級。")
    ct = first("cleartext_ch")
    if ct and (ct.get("c") or 0) > 0:
        if en:
            cadd("medium", "A.8.22", "Network segregation / services", "Cleartext / exposed service activity observed",
                 f"<b>{fmt(ct.get('c'))}</b> events from <b>{fmt(ct.get('srcs'))}</b> distinct sources hit an exposed cleartext-related channel in {span}"
                 + (f" (spotlight device {MONO(exp.get('ip'))}:{exp.get('port')})" if exp else "") + ".",
                 "Restrict internet-facing cleartext services; prefer encrypted alternatives; tighten Local-in / ISDB source controls.")
        else:
            cadd("medium", "A.8.22", "網絡分隔 / 服務", "觀察到明文或對外服務活動",
                 f"{span}內 <b>{fmt(ct.get('c'))}</b> 筆事件、<b>{fmt(ct.get('srcs'))}</b> 個來源命中對外明文相關通道"
                 + (f"（焦點設備 {MONO(exp.get('ip'))}:{exp.get('port')}）" if exp else "") + "。",
                 "限制對外明文服務；改用加密替代；用 Local-in / ISDB 收緊來源。")
    d53 = next((r.get("c") for r in L("traffic_deny_top_dport") if r.get("port") == 53), 0) or 0
    unauth = next((r.get("c") for r in L("dns_types") if r.get("eventType") == "PH_RULE_UNAUTH_DNS_QUERY"), 0) or 0
    if d53 or unauth:
        if en:
            cadd("medium", "A.8.23", "Web filtering / DNS controls", "DNS deny / unauthorised DNS activity",
                 f"Port-53 denies: {wan(d53, lang)}" + (f"; PH_RULE_UNAUTH_DNS_QUERY: {fmt(unauth)}" if unauth else "") + f" in {span}.",
                 "Enforce internal DNS / FortiGuard DNS filter; block direct public DNS where policy requires.")
        else:
            cadd("medium", "A.8.23", "網頁過濾 / DNS 控制", "DNS 拒絕 / 未授權 DNS 活動",
                 f"{span}內 53 埠拒絕 {wan(d53)}" + (f"；PH_RULE_UNAUTH_DNS_QUERY {fmt(unauth)} 次" if unauth else "") + "。",
                 "強制內部 DNS / FortiGuard DNS filter；按政策封鎖直連公共 DNS。")
    if vr:
        if en:
            cadd("medium", "A.5.15 / A.8.5", "Access control / Secure authentication", "VPN logons from outside configured country",
                 f"Rule \"{E(vr.get('rule'))}\" fired {fmt(vr.get('c'))} times ({fmt(vr.get('open') or 0)} still Open).",
                 "Review \"My Country\" / geo policy; verify legitimate roamers; strengthen MFA and unusual-login review.")
        else:
            cadd("medium", "A.5.15 / A.8.5", "存取控制 / 安全認證", "境外 VPN 登入告警",
                 f"規則「{E(vr.get('rule'))}」觸發 {fmt(vr.get('c'))} 次（仍然 Open {fmt(vr.get('open') or 0)}）。",
                 "檢視「My Country」/ 地理政策；核實合法漫遊；強化 MFA 同異常登入覆核。")
    if cfg_tot:
        if en:
            cadd("info", "A.8.9", "Configuration management", "Configuration changes under monitoring",
                 f"{fmt(cfg_tot)} config-related events recorded in {span}.",
                 "Link changes to tickets; prefer named admin accounts with MFA over shared admin/root.")
        else:
            cadd("info", "A.8.9", "組態管理", "設定變更受監控",
                 f"{span}內錄得 {fmt(cfg_tot)} 筆設定相關事件。",
                 "變更與變更單對數；優先個人化管理員 + MFA，減少共用 admin/root。")
    if rd and rd[0]["score"] >= 40:
        r0 = rd[0]
        if en:
            cadd("medium", "A.8.8", "Management of technical vulnerabilities", f"Elevated risk score on {E(r0['entity'])}",
                 f"Top risky device score {r0['score']:g} with {fmt(len(r0['ids']))} related incidents.",
                 "Prioritise investigation of this entity; validate exposure, patching, and compensating controls.")
        else:
            cadd("medium", "A.8.8", "技術弱點管理", f"{E(r0['entity'])} 風險分數偏高",
                 f"最高風險設備分數 {r0['score']:g}，相關事故 {fmt(len(r0['ids']))} 宗。",
                 "優先調查此實體；核實曝露面、修補及補償控制。")
    fortios = L("cmdb_fortios")
    if fortios or rept:
        vendors = Counter((r.get("vendor") or "unknown") for r in rept)
        top_v = join.join(f"{E(v)} ({fmt(c)})" for v, c in vendors.most_common(5))
        if en:
            cadd("info", "A.5.9 / A.8.1", "Inventory of information / user endpoint assets", "Asset & reporting-device coverage snapshot",
                 f"Reporting vendors in {span}: {top_v}. FortiOS devices in CMDB: {fmt(len(fortios))}. Devices in CMDB: {fmt(len(devs))}; reporting-only (not in CMDB): {fmt(len(not_in))}.",
                 "Keep CMDB as the system of record for log sources; review vendor/model coverage against the logging architecture.")
        else:
            cadd("info", "A.5.9 / A.8.1", "資訊資產盤點", "資產同報告設備覆蓋速覽",
                 f"{span}報告廠商：{top_v}。CMDB 內 FortiOS 設備 {fmt(len(fortios))} 部；CMDB 共 {fmt(len(devs))} 部；只報告未入 CMDB {fmt(len(not_in))} 個。",
                 "以 CMDB 作為日誌來源系統記錄；對照日誌架構檢視廠商 / 型號覆蓋。")

    D["derived"] = {
        "days": days, "span_zh": span, "wk": wk, "lang": lang, "fam": fam, "fam_n": fam_n, "fam_pct": fam_p,
        "fam_pct_zh": share(fam_p) if fam else "—",
        "fam_re": "^" + re.escape(fam) if fam else None, "fam_top_src": top_src, "fam_top_src_c": top_src_c,
        "picks": picks, "exposure": exp, "deep_story": deep, "alias_notes": alias, "findings": F, "compliance": COMP, "limits": lim,
        "title": title,
    }
    return data



# ----------------------------------------------------------------------------- rendering
FONTS = [("Orbitron", "orbitron", "400 900"), ("Rajdhani", "rajdhani600", "600"), ("Rajdhani", "rajdhani700", "700"),
         ("Chakra Petch", "chakra400", "400"), ("Chakra Petch", "chakra600", "600 700"), ("JetBrains Mono", "jbmono", "100 800")]
FORBIDDEN = ("client_secret", "access_token", "Bearer ")


def render(data, theme, out_path, secret=None, lang="zh"):
    lang = "en" if lang == "en" else "zh"
    tdir = os.path.join(ASSETS, "themes", theme, lang)
    if not os.path.isdir(tdir):  # back-compat: theme root = zh
        tdir = os.path.join(ASSETS, "themes", theme)
    rd = lambda p: open(p, encoding="utf-8").read()
    tpl, app = rd(os.path.join(tdir, "template.html")), rd(os.path.join(tdir, "app.js"))
    echarts = rd(os.path.join(ASSETS, "echarts.min.js"))
    data = json.loads(json.dumps(data, default=str))
    data["meta"]["theme"] = theme
    data["meta"]["lang"] = lang
    payload = json.dumps(data, ensure_ascii=False, default=str).replace("</", "<\\/")
    check_secrets(payload, secret, "report")
    if "/*FONTS*/" in tpl:
        ff = []
        for fam, f, wgt in FONTS:
            p = os.path.join(ASSETS, "fonts", f + ".woff2")
            if os.path.exists(p):
                b64 = base64.b64encode(open(p, "rb").read()).decode()
                ff.append(f"@font-face{{font-family:'{fam}';src:url(data:font/woff2;base64,{b64}) format('woff2');font-weight:{wgt};font-display:swap}}")
        tpl = tpl.replace("/*FONTS*/", "\n".join(ff))
    html_ = tpl.replace("<script>/*ECHARTS*/</script>", lambda_safe("<script>" + echarts + "</script>")) \
               .replace("/*DATA*/", payload).replace("/*APP*/", app)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_)
    return len(html_.encode("utf-8"))


def lambda_safe(s):
    return s


def check_secrets(text, secret, what):
    toks = [x for x in (SECRET_FILTER.secrets or []) + [secret] if x and len(x) > 8]
    if any(t in text for t in toks):
        raise RuntimeError(f"refusing to write {what}: it would contain the client secret / access token")
    for w in FORBIDDEN:
        if w in text:
            log.warning("%s contains the word %r (from FortiSIEM log content, not a credential of this tool)", what, w.strip())


def write_json(obj, path, secret=None):
    s = json.dumps(obj, ensure_ascii=False, default=str, indent=1)
    check_secrets(s, secret, "data file")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(s)


# ----------------------------------------------------------------------------- CLI
def build_parser():
    p = argparse.ArgumentParser(prog="fsm_report.py", description="FortiSIEM security report generator (read-only MCP → offline HTML)",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog="Examples:\n  python fsm_report.py --days 7 --theme v1.2\n"
                                       "  python fsm_report.py --start 2026-10-01 --end 2026-10-08 --theme v1.1 --out oct-wk1.html\n"
                                       "  python fsm_report.py --data-only --data-out week.json\n"
                                       "  python fsm_report.py --from-data week.json --theme v1 --out week-v1.html")
    p.add_argument("--days", type=float, default=7, help="look-back window in days (default 7)")
    p.add_argument("--start", help="absolute window start, HKT (YYYY-MM-DD or 'YYYY-MM-DD HH:MM')")
    p.add_argument("--end", help="absolute window end, HKT (default: now)")
    p.add_argument("--theme", choices=THEMES, default="v1.2", help="v1 = dark SOC, v1.1 = bright editorial, v1.2 = cyber HUD, v1.3 = cyber HUD + CMDB/compliance/click (default v1.2)")
    p.add_argument("--lang", choices=("zh", "en"), default="zh", help="report language: zh (zh-HK, default) or en")
    p.add_argument("--out", help="output HTML path (default ./fortisiem-report-<theme>-<YYYYmmdd-HHMM>.html)")
    p.add_argument("--data-out", help="where to save collected data JSON (default: next to --out, *.data.json)")
    p.add_argument("--host", default=os.environ.get("FORTISIEM_HOST") or None,
                   help="FortiSIEM supervisor host (required unless --from-data; or env FORTISIEM_HOST)")
    p.add_argument("--client-id", default=os.environ.get("FORTISIEM_CLIENT_ID") or None,
                   help="OAuth2 client id (required unless --from-data; or env FORTISIEM_CLIENT_ID)")
    p.add_argument("--insecure", action=argparse.BooleanOptionalAction, default=True,
                   help="skip TLS certificate verification for self-signed certs (default ON; use --no-insecure to verify)")
    p.add_argument("--cafile", help="CA bundle for TLS verification (with --no-insecure)")
    p.add_argument("--data-only", action="store_true", help="query FortiSIEM and save data JSON only (no HTML)")
    p.add_argument("--from-data", metavar="DATA_JSON", help="rebuild HTML from a saved data JSON without querying FortiSIEM")
    p.add_argument("--workers", type=int, default=2,
                   help="number of MCP sessions (default 2; use 1 if OAuth HTTP 400 after connect — sessions are opened serially, queries run in parallel across them)")
    p.add_argument("--timeout", type=int, default=120, help="per-request timeout seconds (default 120)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=VERSION)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    for h in logging.getLogger().handlers:
        h.addFilter(SECRET_FILTER)
    stamp = now_hkt().strftime("%Y%m%d-%H%M")
    out = a.out or (f"fortisiem-report-{a.theme}-{a.lang}-{stamp}.html" if a.lang != "zh" else f"fortisiem-report-{a.theme}-{stamp}.html")
    if a.from_data:
        if a.data_only:
            raise SystemExit("--from-data and --data-only are mutually exclusive")
        data = json.load(open(a.from_data, encoding="utf-8"))
        keep = {k: v for k, v in data.get("data", {}).items() if k in ("related_summary", "trigger_tool_errors", "picks_raw", "exposure_raw", "derived")}
        data["data"] = dict(sanitize({k: v for k, v in data.get("data", {}).items() if k not in keep}), **keep)
        derive(data, a.lang)
        n = render(data, a.theme, out, lang=a.lang)
        log.info("Rebuilt %s (%s/%s, %.1f MB) from %s", out, a.theme, a.lang, n / 1e6, a.from_data)
        return 0
    if not a.from_data:
        if not a.host:
            raise SystemExit("請提供 --host（或環境變數 FORTISIEM_HOST），此工具沒有內建 Supervisor 預設值。")
        if not a.client_id:
            raise SystemExit("請提供 --client-id（或環境變數 FORTISIEM_CLIENT_ID），此工具沒有內建 OAuth client id 預設值。")
    secret = os.environ.get("FORTISIEM_CLIENT_SECRET")
    if not secret:
        if not sys.stdin.isatty():
            raise SystemExit("FORTISIEM_CLIENT_SECRET is not set and no terminal is available for a prompt")
        secret = getpass.getpass("FortiSIEM client secret: ")
    SECRET_FILTER.secrets = [secret]
    if a.insecure:
        log.warning("TLS certificate verification is OFF (--insecure, default) — use --no-insecure [--cafile ca.pem] to verify")
    w = Window(a.days, parse_hkt(a.start), parse_hkt(a.end))
    log.info("Window: %s", w.label())
    t0 = time.time()
    try:
        R, picks, exposure = collect(a, secret, w)
    except Exception as e:
        log.error("Cannot collect from FortiSIEM: %s", e)
        return 2
    ver = ((_d(R, "health") or [{}])[0] or {}).get("version")
    meta = {"generated_hkt": now_hkt().strftime("%Y-%m-%d %H:%M:%S HKT"), "window": w.label(),
            "supervisor": f"https://{a.host.replace('https://', '')}" + (f" (FortiSIEM {ver})" if ver else ""),
            "days": round(w.days, 4), "start_hkt": w.start.strftime("%Y-%m-%d %H:%M"), "end_hkt": w.end.strftime("%Y-%m-%d %H:%M"),
            "tool_version": VERSION}
    data = derive(postprocess(R, picks, exposure, meta), a.lang)
    ok = sum(1 for s in data["sources"] if s["ok"]); bad = len(data["sources"]) - ok
    dpath = a.data_out or (os.path.splitext(out)[0] + ".data.json")
    write_json(data, dpath, secret)
    log.info("Collected %d datasets (%d ok, %d failed) in %.0fs → %s", ok + bad, ok, bad, time.time() - t0, dpath)
    if not a.data_only:
        n = render(data, a.theme, out, secret, lang=a.lang)
        log.info("Wrote %s (%s/%s, %.1f MB)", out, a.theme, a.lang, n / 1e6)
    return 0


if __name__ == "__main__":
    sys.exit(main())
