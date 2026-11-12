#!/usr/bin/env python3
"""FortiSIEM MCP client (read-only). Host and client id come from the environment; no lab defaults."""
import os, json, requests, ast, time, urllib3

urllib3.disable_warnings()

HOST = (os.environ.get("FORTISIEM_HOST") or "").strip().rstrip("/")
CLIENT_ID = (os.environ.get("FORTISIEM_CLIENT_ID") or "").strip()
if not HOST:
    raise SystemExit("未設定 FORTISIEM_HOST（Supervisor IP 或主機名稱）。")
if not CLIENT_ID:
    raise SystemExit("未設定 FORTISIEM_CLIENT_ID（FortiSIEM MCP OAuth client id）。")
if not os.environ.get("FORTISIEM_CLIENT_SECRET"):
    raise SystemExit("未設定 FORTISIEM_CLIENT_SECRET（API Access Key／Client Secret）。")

BASE = HOST if HOST.startswith("http") else "https://" + HOST
VERIFY = os.environ.get("FORTISIEM_VERIFY_TLS", "0").strip().lower() in ("1", "true", "yes", "on")

# Only query / get tools. Anything that writes is refused.
READ_ONLY_TOOLS = {
    "query_fsm_clickhouse", "query_fsm_postgres",
    "get_top_10_risky_devices_incidents", "get_top_10_risky_users_incidents",
    "get_incident_by_id", "get_trigger_events_by_incident_id",
    "get_related_incidents_by_id", "get_iocs_by_incident_ids",
    "get_context_by_entity", "get_incidents_by_entity", "get_reputation_by_entity",
}


class MCP:
    def __init__(self):
        self.tok = None
        self.sid = None
        self.id = 0
        self.connect()

    def token(self):
        r = requests.post(
            BASE + "/phoenix/rest/pub/security/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
                "client_secret": os.environ["FORTISIEM_CLIENT_SECRET"],
            },
            verify=VERIFY,
            timeout=60,
        )
        r.raise_for_status()
        self.tok = r.json()["access_token"]

    def hdr(self):
        h = {
            "Authorization": "Bearer " + self.tok,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.sid:
            h["mcp-session-id"] = self.sid
        return h

    def connect(self):
        self.token()
        self.sid = None
        r = self._post({
            "jsonrpc": "2.0",
            "id": self._nid(),
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "fsm-report-studio", "version": "1"},
            },
        })
        self.sid = r.headers.get("mcp-session-id")
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _nid(self):
        self.id += 1
        return self.id

    def _post(self, body):
        return requests.post(BASE + "/phoenix/mcp", json=body, headers=self.hdr(), verify=VERIFY, timeout=90)

    def parse(self, r):
        t = r.text
        for line in t.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip())
        try:
            return r.json()
        except Exception:
            return {"raw": t[:2000]}

    def rpc(self, method, params, retry=True):
        r = self._post({"jsonrpc": "2.0", "id": self._nid(), "method": method, "params": params})
        if r.status_code in (401, 404, 400) and retry:
            self.connect()
            return self.rpc(method, params, False)
        return self.parse(r)

    def call(self, name, args):
        if name not in READ_ONLY_TOOLS:
            return {"error": f"refusing to call non-whitelisted tool {name}"}
        t0 = time.time()
        try:
            res = self.rpc("tools/call", {"name": name, "arguments": args})
        except Exception as e:
            return {"error": str(e)}
        if "error" in res:
            return {"error": res["error"]}
        r = res.get("result", {})
        texts = [c.get("text", "") for c in r.get("content", [])]
        out = []
        for tx in texts:
            v = tx
            try:
                v = json.loads(tx)
            except Exception:
                try:
                    v = ast.literal_eval(tx)
                except Exception:
                    pass
            out.append(v)
        val = out[0] if len(out) == 1 else out
        return {"isError": r.get("isError", False), "data": val, "secs": round(time.time() - t0, 1)}


def unwrap(v):
    for _ in range(4):
        if isinstance(v, dict) and "content" in v and isinstance(v["content"], list):
            texts = [c.get("text", "") for c in v["content"] if isinstance(c, dict)]
            outs = []
            for tx in texts:
                try:
                    outs.append(json.loads(tx))
                except Exception:
                    try:
                        outs.append(ast.literal_eval(tx))
                    except Exception:
                        outs.append(tx)
            v = outs[0] if len(outs) == 1 else outs
        else:
            break
    if isinstance(v, dict) and "columns" in v and "rows" in v:
        v = [dict(zip(v["columns"], r)) for r in v["rows"]]
    return v


def q(m, tool, args):
    r = m.call(tool, args)
    if "error" in r:
        return {"ok": False, "error": str(r["error"])[:500]}
    d = unwrap(r["data"])
    err = r.get("isError") or (isinstance(r["data"], dict) and r["data"].get("isError"))
    if isinstance(d, dict) and set(d.keys()) == {"error"}:
        err = True
        d = d["error"]
    if err or (isinstance(d, str) and ("error" in d.lower() or "not allowed" in d.lower() or "denied" in d.lower())):
        return {"ok": False, "error": (d if isinstance(d, str) else json.dumps(d, default=str))[:800], "secs": r.get("secs")}
    return {"ok": True, "data": d, "secs": r.get("secs")}
