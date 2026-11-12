#!/usr/bin/env python3
"""Build FortiSIEM 5-day SIEM report v1.5 locale × theme variants.

Variants (default --only-new writes the 3 new files; --all also refreshes ZH-dark):
  zh + dark  → fortisiem-5day-report-v1.5.html          (canonical ZH-dark)
  en + dark  → fortisiem-5day-report-v1.5-en.html
  zh + light → fortisiem-5day-report-v1.5-zh-light.html
  en + light → fortisiem-5day-report-v1.5-en-light.html

Starts from the already-built ZH-dark HTML. Never uses html.replace('</body>') —
only rfind. Never embeds raw </script> in inline JS.
"""
from __future__ import annotations

import hashlib
import os
import json
import pathlib
import re
import sys

ENGINE = pathlib.Path(os.environ.get('FORTISIEM_ENGINE_DIR') or pathlib.Path(__file__).resolve().parents[1])
ROOT = pathlib.Path(os.environ.get('FORTISIEM_REPORT_ROOT') or ENGINE)
V15 = ENGINE / 'v15'
SRC = ROOT / 'fortisiem-5day-report-v1.5.html'
LINK = ROOT / 'fortisiem-7day-report-v1.5.html'
EN_MAP_PATH = V15 / 'en_ui_map.json'

OUTS = {
    ('zh', 'dark'): ROOT / 'fortisiem-5day-report-v1.5.html',
    ('en', 'dark'): ROOT / 'fortisiem-5day-report-v1.5-en.html',
    ('zh', 'light'): ROOT / 'fortisiem-5day-report-v1.5-zh-light.html',
    ('en', 'light'): ROOT / 'fortisiem-5day-report-v1.5-en-light.html',
}

TITLES = {
    ('zh', 'dark'): ('zh-HK', 'FortiSIEM 五日安全報告 · v1.5'),
    ('en', 'dark'): ('en', 'FortiSIEM 5-Day Security Report · v1.5'),
    ('zh', 'light'): ('zh-HK', 'FortiSIEM 五日安全報告 · v1.5 · Light'),
    ('en', 'light'): ('en', 'FortiSIEM 5-Day Security Report · v1.5 · Light'),
}

# ---------- Flow EN (why / meta / last_seen Chinese) ----------
FLOW_EN = {
    '五日內最高量 HIGH IoT/botnet 家族；src→dst 路徑清晰，屬可行動威脅簇。':
        'Highest-volume HIGH IoT/botnet family in the 5-day window; clear src→dst path; actionable threat cluster.',
    '規則 FortiNDR High Severity Attack Permitted · 主路徑 192.168.127.161 → 192.168.27.4':
        'Rule FortiNDR High Severity Attack Permitted · primary path 192.168.127.161 → 192.168.27.4',
    'HIGH flooder 家族，容量僅次 Mirai；反映可能被利用作濫發／放大攻擊。':
        'HIGH flooder family, volume second only to Mirai; suggests possible abuse for flood / amplification.',
    'NDR virus HIGH 計數 · 同組 NDR 感測器路徑 192.168.127.161 → 192.168.27.4':
        'NDR virus HIGH count · same NDR sensor path 192.168.127.161 → 192.168.27.4',
    'WannaCry 家族特徵，HIGH 且具勒索影響語義；優先於純 Permit 噪音。':
        'WannaCry-family signature; HIGH with ransomware impact semantics — prioritize over pure Permit noise.',
    'NDR HIGH · 192.168.127.161 → 192.168.27.4 · 需核對是否測試流量':
        'NDR HIGH · 192.168.127.161 → 192.168.27.4 · verify whether this is test traffic',
    '明確 Attack Chain Permitted（非純 volume title）；多階段鏈路語意，適合畫 kill-chain。':
        'Clear Attack Chain Permitted (not a pure volume title); multi-stage semantics — good kill-chain candidate.',
    '規則 Attack Chain Permitted 五日合計 72 宗 · 本鏈 W32/Agent.VO!tr':
        'Rule Attack Chain Permitted · 72 incidents over 5 days · this chain W32/Agent.VO!tr',
    '非 FortiNDR Permit 噪音；NIPS 偵測到代碼注入，屬 exploit 階段，來源分散於風險主機。':
        'Not FortiNDR Permit noise; NIPS detected code injection (exploit stage); sources tied to risky hosts.',
    '規則 Code Injection Attack detected by NIPS · 例：10.50.3.88（風險分 90）· 另見 SQL Injection 多樣 dst':
        'Rule Code Injection Attack detected by NIPS · e.g. 10.50.3.88 (risk score 90) · also see SQL Injection diverse dst',
    '近期（風險設備 10.50.3.88 相關）':
        'Recent (related to risky device 10.50.3.88)',
}

FLOW_SECTION_EN = {
    '攻擊流程': 'Attack Flows',
    '五日內 5 個具保安意義嘅攻擊／鏈路。虛線節點 = 數據未直接觀測到嘅階段。節點色：':
        'Five security-relevant attacks / chains in the 5-day window. Dashed nodes = stages not directly observed. Node colours: ',
    '篩選': 'Filter',
    '全部嚴重度': 'All severities',
    '窗口 · 近 5 日 · HKT': 'Window · last 5 days · HKT',
    'Attack flows · 5 day': 'Attack flows · 5 day',
}

# ---------- Derived narrative EN ----------
FINDINGS_EN = [
    {
        'lvl': 'high',
        'title': 'FortiNDR alerts are flooding the incident queue',
        'body': 'Of 90,809 incidents in 5 days, FortiNDR rules account for <b>88,979</b> (98.0%); <b>88,539</b> of them source from <span class="mono">192.168.127.161</span>, mainly targeting <span class="mono">192.168.27.4</span>. Top names: <span class="mono">Malware_Generic.P0</span>, <span class="mono">W32/Agent.XS!tr</span>, <span class="mono">W32/Agent.VO!tr</span>, <span class="mono">ELF/Mirai.AT!tr</span>, <span class="mono">ELF/Flooder.ADS!tr</span>. 100.0% remain Open.',
        'todo': 'Confirm whether 192.168.127.161 is a test / sample-replay host. If not, isolate immediately and validate samples; if it is test traffic, add FortiSIEM exceptions or aggregation to reduce alert fatigue.',
    },
    {
        'lvl': 'high',
        'title': 'Top risky device 172.16.8.44 (score 90)',
        'body': 'Risk drivers: "CyberArk Vault CPM Password Disabled", "Website access policy violation: Same Source and Multiple Categories", "Code Injection Attack detected by NIPS", "Website access policy violation: Same Source and Destination" (119 related incidents).',
        'todo': 'Review this device\'s exposure and policy; confirm it should be reachable externally and apply least privilege.',
    },
    {
        'lvl': 'medium',
        'title': 'Users querying public DNS directly',
        'body': '<span class="mono">PH_RULE_UNAUTH_DNS_QUERY</span> 30,165 hits; 8.33M port-53 events, 2.31M denied. Largest client <span class="mono">192.168.108.16 → 8.8.8.8</span> (3.20M).',
        'todo': 'Enforce internal DNS / FortiGuard DNS filter; block direct public DNS; follow up on 192.168.108.16.',
    },
    {
        'lvl': 'medium',
        'title': '"Outside my country" VPN logon rule may be mis-tuned',
        'body': 'Rule "Successful VPN Logon From Outside My Country" 41 incidents; top risky user <span class="mono">admin</span> (score 90).',
        'todo': 'Review FortiSIEM "My Country" settings to reduce false positives.',
    },
    {
        'lvl': 'medium',
        'title': 'Incident backlog',
        'body': '<b>90,466</b> / 90,809 incidents (99.6%) still Open; only 343 marked True Positive.',
        'todo': 'Set auto-clear or notify-only for noisy low-severity FortiNDR rules; open Case / SOAR playbooks for HIGH (fortisoar account already active).',
    },
    {
        'lvl': 'info',
        'title': 'Gaps in log collection',
        'body': '12 devices in Critical collection status: FDCVMSTM26000372 (last event 2026-11-02 12:34), cp-fw-01 (last event 2026-11-02 11:40), FortiGateRugged-70G-5G-Dual (last event 2026-11-02 12:34), FPAVULTM26001793 (last event 2026-11-02 12:34), FortiGate-900G (last event 2026-10-29 12:18), HOST-172.16.0.114 (last event 2026-11-02 11:52), FDCVM (last event 2026-11-02 12:34), FGT-61F-RKJZFF (last event 2026-11-02 12:34), FortiNDR (last event 2026-11-02 12:34), cp-fw-01 (last event 2026-11-02 11:40), pa-fw-02 (last event —), pa-fw-01 (last event 2026-11-02 12:34). 16 reporting names not in CMDB (e.g. <span class="mono">HOST-172.16.0.1</span>, <span class="mono">FortiNDR-VM</span>, <span class="mono">cs-falcon-01</span>, <span class="mono">HOST-172.16.0.254</span>). Also 91,375 Unknown_EventType events from HOST-172.16.0.1.',
        'todo': 'Check syslog delivery for Critical devices; add HOST-172.16.0.1 and peers to CMDB; apply parsers for unresolved sources.',
    },
    {
        'lvl': 'info',
        'title': 'Config changes concentrated on shared accounts',
        'body': '58,533 config-related events; "FortiGate: Config Change Detected" 220 incidents. Top operators: <span class="mono">FGT_ha_admin</span> (1,861), <span class="mono">admin</span> (429), <span class="mono">MCPBB</span> (36).',
        'todo': 'Move to personalized admin accounts with MFA; tie changes to change tickets.',
    },
]

COMPLIANCE_EN = [
    {
        'lvl': 'high', 'ctrl': 'A.8.15', 'ctrl_title': 'Logging',
        'title': 'Log-source inventory out of sync with CMDB',
        'body': '12 CMDB devices in Critical log-collection status (FDCVMSTM26000372, cp-fw-01, FortiGateRugged-70G-5G-Dual, FPAVULTM26001793, FortiGate-900G, HOST-172.16.0.114, FDCVM, FGT-61F-RKJZFF, FortiNDR, cp-fw-01, pa-fw-02, pa-fw-01). 16 reporting names send logs but are not in CMDB (e.g. <span class="mono">HOST-172.16.0.1</span>, <span class="mono">FortiNDR-VM</span>, <span class="mono">cs-falcon-01</span>, <span class="mono">HOST-172.16.0.254</span>). CMDB lists 21 devices; 40 reporting names observed in 5 days.',
        'todo': 'Align reporting names with CMDB; repair Critical-device syslog; complete records for discover_method=LOG assets.',
    },
    {
        'lvl': 'high', 'ctrl': 'A.8.16', 'ctrl_title': 'Monitoring activities',
        'title': 'Incident-monitoring backlog',
        'body': 'In 5 days <b>90,466</b> / 90,809 incidents (99.6%) remain Open.',
        'todo': 'Define triage SLAs; auto-clear / aggregate noisy low-severity rules; escalate HIGH via Case / SOAR.',
    },
    {
        'lvl': 'medium', 'ctrl': 'A.8.23', 'ctrl_title': 'Web filtering / DNS controls',
        'title': 'DNS denials / unauthorized DNS activity',
        'body': 'In 5 days 2.31M port-53 denials; PH_RULE_UNAUTH_DNS_QUERY 30,165 hits.',
        'todo': 'Enforce internal DNS / FortiGuard DNS filter; block direct public DNS per policy.',
    },
    {
        'lvl': 'medium', 'ctrl': 'A.5.15 / A.8.5', 'ctrl_title': 'Access control / secure authentication',
        'title': 'Outside-country VPN logon alerts',
        'body': 'Rule "Successful VPN Logon From Outside My Country" fired 41 times (still Open 41).',
        'todo': 'Review "My Country" / geo policy; validate legitimate roaming; strengthen MFA and anomaly logon review.',
    },
    {
        'lvl': 'info', 'ctrl': 'A.8.9', 'ctrl_title': 'Configuration management',
        'title': 'Configuration changes are monitored',
        'body': '58,533 config-related events recorded in 5 days.',
        'todo': 'Tie changes to tickets; prefer personalized admins + MFA; reduce shared admin/root use.',
    },
    {
        'lvl': 'medium', 'ctrl': 'A.8.8', 'ctrl_title': 'Technical vulnerability management',
        'title': '172.16.8.44 risk score elevated',
        'body': 'Top risky device score 90 with 119 related incidents.',
        'todo': 'Investigate this entity first; validate exposure, patching, and compensating controls.',
    },
    {
        'lvl': 'info', 'ctrl': 'A.5.9 / A.8.1', 'ctrl_title': 'Inventory of information assets',
        'title': 'Asset vs reporting-device coverage snapshot',
        'body': '5-day reporting vendors: Fortinet (36), Checkpoint (2), Generic (1), CrowdStrike (1). CMDB FortiOS devices: 7; CMDB total 21; report-only not in CMDB: 16.',
        'todo': 'Use CMDB as the system of record for log sources; review vendor/model coverage against the logging architecture.',
    },
]

LIMITS_EN = [
    '<span class="mono">get_trigger_events_by_incident_id</span> failed server-side (e.g. ClickHouse Code 48); fell back to <span class="mono">ph_incident_detail</span> + <span class="mono">eventId IN (...)</span>.',
    'Postgres validator rejected <span class="mono">TO_CHAR(... AT TIME ZONE ...)</span>; used epoch milliseconds and converted to HKT locally.',
    '<span class="mono">unnest(string_to_array())</span> and <span class="mono">metrics_float64.value[...]</span> triggered MCP sqlglot errors; used raw-field grouping / <span class="mono">arrayElement()</span>.',
    '<span class="mono">ph_health_status.diskusage_used_pct</span> column does not exist — not queried.',
    'DNS event groups counted 0; used port-53 analysis instead.',
    'MCP does not expose full device config; ph_device_intf / ph_installed_software queries were empty.',
    'VirusTotal, RiskIQ, FortiGuard IOC not configured; ph_external_reputation has no rows.',
    'Incidents counted where last_seen_time falls in the 5-day window; first/last days are partial.',
    'risky-users tool returned 10 entities; risky-devices returned 10.',
    '"Event to disposition" funnel stages are independent counts with log-scale widths; MITRE Tactics treemap also uses log-scale area with real-number labels.',
]

DEEP_STORY_EN = (
    'Selected 4 incidents most worth following up. External IP reputation only returned geo + watchlist '
    'because VirusTotal, RiskIQ, and FortiGuard IOC are not configured.'
)

# Extra UI phrases not reliably recovered from v1.3 diff (v1.5 + critical chrome)
EXTRA_EN = [
    # Titles / brand / nav (order matters — longest first handled by sorter)
    ('FortiSIEM 五日安全報告 · v1.5', 'FortiSIEM 5-Day Security Report · v1.5'),
    ('FortiSIEM 五日安全報告', 'FortiSIEM 5-Day Security Report'),
    ('FORTI<em>SIEM</em> // 五日 · v1.5', 'FORTI<em>SIEM</em> // 5-Day · v1.5'),
    ('五日 · v1.5', '5-Day · v1.5'),
    ('<a href="#overview">總覽</a>', '<a href="#overview">Overview</a>'),
    ('<a href="#cmdb">資產</a>', '<a href="#cmdb">Assets</a>'),
    ('<a href="#events">事件</a>', '<a href="#events">Events</a>'),
    ('<a href="#traffic">流量</a>', '<a href="#traffic">Traffic</a>'),
    ('<a href="#auth">登入</a>', '<a href="#auth">Auth</a>'),
    ('<a href="#cfg">設定變更</a>', '<a href="#cfg">Config changes</a>'),
    ('<a href="#inc">事故</a>', '<a href="#inc">Incidents</a>'),
    ('<a href="#risk">風險</a>', '<a href="#risk">Risk</a>'),
    ('<a href="#deep">個案追蹤</a>', '<a href="#deep">Case tracking</a>'),
    ('<a href="#flows">攻擊流程</a>', '<a href="#flows">Attack Flows</a>'),
    ('<a href="#findings">發現與建議</a>', '<a href="#findings">Findings</a>'),
    ('<a href="#compliance">合規</a>', '<a href="#compliance">Compliance</a>'),
    ('<a href="#appendix">附錄</a>', '<a href="#appendix">Appendix</a>'),
    # Hero / footer (v1.5 patterns)
    ('FortiSIEM ${SPAN}安全回顧 · Super 組織 · 香港時間 HKT',
     'FortiSIEM ${SPAN} Security Review · Super org · Hong Kong Time (HKT)'),
    ('<h1>FortiSIEM ${SPAN}安全報告</h1>',
     '<h1>FortiSIEM ${SPAN} Security Report</h1>'),
    ("X.span_zh||'五日'", "'5-Day'"),
    ("X.span_zh||'5 日'", "'5-Day'"),
    ("X.wk||'本週'", "'This period'"),
    ("X.wk||'本期'", "'This period'"),
    (' 係${WK}最忙嘅一日（', ' was the busiest day of ${WK} ('),
    (' 筆）。期內共開出 ', ' events). In the period there were '),
    (' 宗事故，', ' incidents, '),
    (' 仍然未處理；其中 ', ' still open; of which '),
    (' 由 ${esc(X.fam||"—")} 規則觸發。', ' triggered by ${esc(X.fam||"—")} rules.'),
    ('<span>事件 Events</span>', '<span>Events</span>'),
    ('<span>事故 Incidents</span>', '<span>Incidents</span>'),
    ('<span>高嚴重度 HIGH</span>', '<span>HIGH</span>'),
    ('<span>流量被拒絕</span>', '<span>Traffic denied</span>'),
    ('資料時段 ', 'Window '),
    (' · 擷取於 ', ' · Collected '),
    ('即時數據 Live via MCP', 'Live via MCP'),
    (' 部 CMDB 設備', ' CMDB devices'),
    ("FortiSIEM ${SPAN}安全回顧 · ${esc(M.theme||\"\")} · 生成於 ${esc(M.generated_hkt)} · 數據來源 FortiSIEM MCP（唯讀）· 圖表 Apache ECharts（已內嵌）",
     "FortiSIEM ${SPAN} Security Report · ${esc(M.theme||\"\")} · generated ${esc(M.generated_hkt)} · source FortiSIEM MCP (read-only) · charts Apache ECharts (inlined)"),
    # Section heads — use EN primary labels matching user nav wording where useful
    ("head('cmdb','01',G.cyan,'資產與日誌來源','Assets, CMDB & log sources'",
     "head('cmdb','01',G.cyan,'Assets & log sources','Assets, CMDB & log sources'"),
    ("head('events','02',G.blue,'事件流量','Event analytics'",
     "head('events','02',G.blue,'Event analytics','Event analytics'"),
    ("head('traffic','03',G.teal,'防火牆流量','FortiGate allowed vs denied'",
     "head('traffic','03',G.teal,'Firewall traffic','FortiGate allowed vs denied'"),
    ("head('auth','04',G.violet,'登入與認證','Authentication'",
     "head('auth','04',G.violet,'Auth','Authentication'"),
    ("head('dns','05',G.sky,'DNS 活動','DNS activity'",
     "head('dns','05',G.sky,'DNS activity','DNS activity'"),
    ("head('cfg','06',G.amber,'設定變更','Configuration changes'",
     "head('cfg','06',G.amber,'Config changes','Configuration changes'"),
    ("head('inc','07',G.rose,'事故','Incidents'",
     "head('inc','07',G.rose,'Incidents','Incidents'"),
    ("head('risk','08',G.orange,'風險實體','Top risky devices & users'",
     "head('risk','08',G.orange,'Risk','Top risky devices & users'"),
    ("head('deep','10',G.grape,'個案追蹤','Incident deep dive'",
     "head('deep','10',G.grape,'Case tracking','Incident deep dive'"),
    ("head('findings','11',G.rose,'發現與建議','Findings & recommendations'",
     "head('findings','11',G.rose,'Findings','Findings & recommendations'"),
    ("head('compliance','12',G.lime,'合規建議 ISO 27001','Compliance recommendations'",
     "head('compliance','12',G.lime,'Compliance','Compliance recommendations'"),
    ("head('appendix','13',G.mut,'附錄','Data sources & limitations'",
     "head('appendix','13',G.mut,'Appendix','Data sources & limitations'"),
    # Misc chrome
    ('建議：', 'Action: '),
    ("{high:'優先處理',medium:'中等',info:'留意'}",
     "{high:'Priority',medium:'Medium',info:'Watch'}"),
    ('有</span>', 'yes</span>'),
    ('冇</span>', 'no</span>'),
    ('經 FortiSIEM MCP 唯讀查詢', 'via FortiSIEM MCP'),
    (' · FortiSIEM MCP', ' · FortiSIEM MCP'),
    # Flows chrome
    ('<h2 class="flows-title">攻擊流程</h2>', '<h2 class="flows-title">Attack Flows</h2>'),
    ('五日內 5 個具保安意義嘅攻擊／鏈路。虛線節點 = 數據未直接觀測到嘅階段。節點色：',
     'Five security-relevant attacks / chains in the 5-day window. Dashed nodes = stages not directly observed. Node colours: '),
    ('<label>篩選</label>', '<label>Filter</label>'),
    ('<option value="ALL">全部嚴重度</option>', '<option value="ALL">All severities</option>'),
    ('窗口 · 近 5 日 · HKT', 'Window · last 5 days · HKT'),
    # Table headers / chart series / common JS chrome
    ("{h:'規則',k:'rule'}", "{h:'Rule',k:'rule'}"),
    ("{h:'類別',k:'category'}", "{h:'Category',k:'category'}"),
    ("{h:'標題',k:'incident_title'}", "{h:'Title',k:'incident_title'}"),
    ("{h:'實體',k:'entity'", "{h:'Entity',k:'entity'"),
    ("{h:'名稱',k:'name'}", "{h:'Name',k:'name'}"),
    ("{h:'序號',k:'hw_serial_no'", "{h:'Serial',k:'hw_serial_no'"),
    ("{h:'版本',k:'version'}", "{h:'Version',k:'version'}"),
    ("{h:'廠商',k:'vendor'}", "{h:'Vendor',k:'vendor'}"),
    ("{h:'型號',k:'model'}", "{h:'Model',k:'model'}"),
    ("subtext:center?center[1]:'合共'", "subtext:center?center[1]:'Total'"),
    ("{name:'成功',type:'bar'", "{name:'Success',type:'bar'"),
    ("{name:'失敗',type:'scatter'", "{name:'Failure',type:'scatter'"),
    ("'報告設備 vs CMDB'", "'Reporting devices vs CMDB'"),
    ("'報告中嘅設備'", "'Reporting devices'"),
    (" 個來源 IP · ", " source IPs · "),
    (" 種Events類型`", " event types`"),
    (" 個報告名稱 · CMDB ", " reporting names · CMDB "),
    (" 部 · 未入 CMDB ", " · not in CMDB "),
    ("SIEM 節點 ", "SIEM node "),
    (" 狀態 ", " status "),
    (" · 健康 ", " · health "),
    ("規則觸發記錄共取得 ", "Trigger event records fetched: "),
    ("<dt>版本</dt>", "<dt>Version</dt>"),
    ("<dt>模式</dt>", "<dt>Mode</dt>"),
    ("<dt>主題</dt>", "<dt>Theme</dt>"),
    ("<dd>唯讀：冇呼叫任何 update / clear / append 工具</dd>",
     "<dd>Read-only: no update / clear / append tools called</dd>"),
    (" 筆Events · ", " events · "),
    (" 個不同來源 IP（ClickHouse）</dd>", " distinct source IPs (ClickHouse)</dd>"),
    ("<dt>相關Incidents來源</dt>", "<dt>Related incident sources</dt>"),
    ("['全部Events',", "['All events',"),
    ("['被拒絕流量Events',", "['Denied traffic events',"),
    ("['Incidents Incidents',", "['Incidents',"),
    ("['高Severity", "['HIGH severity"),
    (" 部。", " devices."),
    ("出現次數最多", "Most frequent"),
    ("Top 1 風險設備 ", "Top 1 risky device "),
    ("（90 分）嘅最新Incidents：", " (score 90) latest incident: "),
    ("嘅最新Incidents：", " latest incident: "),
    ("風險設備 ", "risky device "),
    # Derived meta keys (string replace inside JSON)
    ('"span_zh": "5 日"', '"span_zh": "5-Day"'),
    ('"span_zh":"5 日"', '"span_zh":"5-Day"'),
    ('"wk": "本期"', '"wk": "This period"'),
    ('"wk":"本期"', '"wk":"This period"'),
    ('"wk": "本週"', '"wk": "This period"'),
    ('"fam_pct_zh": "九成"', '"fam_pct_zh": "~90%"'),
    ('"fam_pct_zh":"九成"', '"fam_pct_zh":"~90%"'),
    ('"lang": "zh"', '"lang": "en"'),
    ('"lang":"zh"', '"lang":"en"'),
    ('FortiSIEM 安全回顧 · 2026-10-28 至 11-02',
     'FortiSIEM Security Report · 2026-10-28 to 11-02'),
    ('安全回顧', 'Security Review'),
]

LIGHT_CSS = r'''
/* === v1.5 LIGHT — industrial metal / concrete (not pastel) === */
html.theme-light, html.theme-light body, body.theme-light{
  --bg:#F4F6F8; --panel:#FFFFFF; --panel2:#E8ECF0; --line:#C4CCD6; --line2:#A8B0BA;
  --ink:#0E1216; --ink2:#2A323C; --mut:#4A5562;
  --cyan:#00E5FF; --violet:#7B61FF; --amber:#FFB020; --red:#FF4D6A; --ok:#2AA86E;
  --acid:#00E5FF;
}
html.theme-light body, body.theme-light{
  background:
    radial-gradient(1100px 520px at 90% -8%,rgba(255,77,106,.07),transparent 55%),
    radial-gradient(900px 500px at -5% 15%,rgba(0,229,255,.10),transparent 55%),
    radial-gradient(700px 400px at 50% 100%,rgba(123,97,255,.06),transparent 50%),
    linear-gradient(135deg,rgba(255,255,255,.55) 0%,transparent 42%,rgba(0,0,0,.03) 100%),
    linear-gradient(rgba(0,229,255,.045) 1px,transparent 1px) 0 0/48px 48px,
    linear-gradient(90deg,rgba(0,229,255,.045) 1px,transparent 1px) 0 0/48px 48px,
    var(--bg)!important;
  color:var(--ink);
}
html.theme-light body:after, body.theme-light:after{opacity:.22}
html.theme-light nav, body.theme-light nav{
  background:linear-gradient(180deg,rgba(255,255,255,.96),rgba(232,236,240,.94))!important;
  border-bottom-color:var(--line)!important;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.8),inset 0 -1px 0 rgba(0,0,0,.06);
}
html.theme-light nav a, body.theme-light nav a{color:var(--ink2)!important}
html.theme-light nav a:hover, body.theme-light nav a:hover{color:var(--ink)!important;background:rgba(0,229,255,.08)!important}
html.theme-light nav a.active, body.theme-light nav a.active{
  background:linear-gradient(90deg,#00E5FF,#2a7fff)!important;color:#041018!important;
  box-shadow:0 0 0 1px #00E5FF55, inset 0 -2px 0 #FFB020!important;
}
html.theme-light .brand, body.theme-light .brand{color:var(--ink)!important}
html.theme-light .hero-main, body.theme-light .hero-main{
  background:
    linear-gradient(180deg,rgba(255,255,255,.75),transparent 28%),
    linear-gradient(rgba(0,229,255,.06) 1px,transparent 1px) 0 0/20px 20px,
    linear-gradient(90deg,rgba(0,229,255,.06) 1px,transparent 1px) 0 0/20px 20px,
    linear-gradient(135deg,#FFFFFF,#EEF2F6 55%,#E8ECF0)!important;
  border-left-color:#00E5FF!important;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.9),inset 0 -1px 0 rgba(0,0,0,.06);
}
html.theme-light .hero-main h1, body.theme-light .hero-main h1{color:var(--ink)!important}
html.theme-light .hero-main h1 .hl, body.theme-light .hero-main h1 .hl{
  background:linear-gradient(90deg,#007a94,#7B61FF,#FFB020);
  -webkit-background-clip:text;background-clip:text;color:transparent;
}
html.theme-light .hero-main .eyebrow, body.theme-light .hero-main .eyebrow{color:#007a94!important}
html.theme-light .hero-main p.lead, body.theme-light .hero-main p.lead{color:var(--ink2)!important}
html.theme-light .hero-big div b, body.theme-light .hero-big div b{color:var(--ink)!important}
html.theme-light .hero-big div:nth-child(1) b, body.theme-light .hero-big div:nth-child(1) b{color:#007a94!important}
html.theme-light .hero-meta, body.theme-light .hero-meta{color:var(--mut)!important}
html.theme-light .card, html.theme-light .stat, html.theme-light .find, html.theme-light .case,
body.theme-light .card, body.theme-light .stat, body.theme-light .find, body.theme-light .case{
  background:linear-gradient(180deg,#FFFFFF,#E8ECF0)!important;
  border:1px solid var(--line)!important;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.9),0 4px 16px rgba(14,18,22,.06)!important;
  color:var(--ink);
}
html.theme-light .card:before, html.theme-light .stat:before, html.theme-light .find:before, html.theme-light .case:before,
body.theme-light .card:before, body.theme-light .stat:before, body.theme-light .find:before, body.theme-light .case:before{
  background:linear-gradient(180deg,#FFFFFF 0%,#F4F6F8 100%)!important;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.9)!important;
}
html.theme-light .stat .v, body.theme-light .stat .v{color:var(--ink)!important}
html.theme-light .stat .d, body.theme-light .stat .d{color:var(--mut)!important}
html.theme-light .stat .t, body.theme-light .stat .t{color:var(--ink2)!important}
html.theme-light th, body.theme-light th{
  background:linear-gradient(180deg,#EEF2F6,#E2E8EE)!important;color:#007a94!important;
}
html.theme-light td, body.theme-light td{border-bottom-color:#D8DEE6!important;color:var(--ink2)!important}
html.theme-light tbody tr:hover td, body.theme-light tbody tr:hover td{background:rgba(0,229,255,.08)!important;color:var(--ink)!important}
html.theme-light .tbl, body.theme-light .tbl{
  background:linear-gradient(180deg,rgba(255,255,255,.85),rgba(232,236,240,.55))!important;
  border-color:var(--line)!important;
}
html.theme-light .story, body.theme-light .story{
  background:linear-gradient(90deg,rgba(0,229,255,.08),rgba(244,246,248,.95) 42%)!important;
  border-color:var(--line)!important;color:var(--ink2)!important;
}
html.theme-light .chip, body.theme-light .chip{
  background:linear-gradient(180deg,#FFFFFF,#E8ECF0)!important;border-color:var(--line)!important;color:var(--ink2)!important;
}
html.theme-light .mono, body.theme-light .mono{color:#007a94!important}
html.theme-light .sec-head, body.theme-light .sec-head{color:var(--ink)!important}
html.theme-light .sec-head h2, body.theme-light .sec-head h2{color:var(--ink)!important}
html.theme-light .hint, body.theme-light .hint, html.theme-light .note, body.theme-light .note{color:#8A5A00!important}
html.theme-light .find h3, body.theme-light .find h3{color:var(--ink)!important}
html.theme-light .find p, body.theme-light .find p{color:var(--ink2)!important}
html.theme-light .find .todo, body.theme-light .find .todo{
  background:rgba(42,168,110,.08)!important;border-color:rgba(42,168,110,.3)!important;color:#1a5c3a!important;
}
html.theme-light .drawer-panel, body.theme-light .drawer-panel{
  background:linear-gradient(180deg,#FFFFFF,#EEF2F6)!important;border-left:1px solid #00E5FF!important;color:var(--ink)!important;
}
html.theme-light .drawer-backdrop, body.theme-light .drawer-backdrop{background:rgba(14,18,22,.35)!important}
html.theme-light .raw, body.theme-light .raw{background:#EEF2F6!important;border-color:var(--line)!important;color:#1a5c3a!important}
html.theme-light #flows .flows-head, body.theme-light #flows .flows-head,
html.theme-light .flow-filters, body.theme-light .flow-filters,
html.theme-light .flow-card, body.theme-light .flow-card{
  background:linear-gradient(180deg,#FFFFFF,#EEF2F6)!important;
  border:1px solid var(--line)!important;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.9)!important;
}
html.theme-light #flows .flows-title, body.theme-light #flows .flows-title{color:var(--ink)!important}
html.theme-light #flows .flows-lead, body.theme-light #flows .flows-lead{color:var(--ink2)!important}
html.theme-light #flows .flows-lead .leg, body.theme-light #flows .flows-lead .leg{
  background:#E8ECF0!important;border-color:var(--line)!important;color:var(--ink)!important;
}
html.theme-light .flow-filters label, body.theme-light .flow-filters label{color:var(--ink2)!important}
html.theme-light .flow-filters select, body.theme-light .flow-filters select{
  background:#FFFFFF!important;border:1px solid var(--line)!important;color:var(--ink)!important;
}
html.theme-light .flow-titles h3, body.theme-light .flow-titles h3{color:var(--ink)!important}
html.theme-light .flow-sub, body.theme-light .flow-sub{color:var(--mut)!important}
html.theme-light .flow-meta, body.theme-light .flow-meta{color:var(--mut)!important;border-top-color:var(--line)!important}
html.theme-light .sev-chip .mono, body.theme-light .sev-chip .mono{color:var(--ink)!important}
html.theme-light .industrial, body.theme-light .industrial{color:var(--ink2)!important}
html.theme-light footer, body.theme-light footer{color:var(--mut)!important}
html.theme-light .ticker, body.theme-light .ticker{color:#007a94!important}
html.theme-light .ok, body.theme-light .ok{color:#1a6b45!important}
html.theme-light .bad, body.theme-light .bad{color:#D42038!important}
html.theme-light .vtag, body.theme-light .eyebrow .vtag{
  border-color:var(--line)!important;color:#007a94!important;background:rgba(0,229,255,.08)!important;
}

/* Force readable text — dark theme uses b{color:#fff} which vanishes on light */
html.theme-light b, body.theme-light b{color:var(--ink)!important}
html.theme-light .story b, body.theme-light .story b{color:#007a94!important}
html.theme-light .story p, body.theme-light .story p{color:var(--ink2)!important}
html.theme-light .story .mono, body.theme-light .story .mono{color:#007a94!important}
html.theme-light .mono, body.theme-light .mono{color:#007a94!important}
html.theme-light .hl, body.theme-light .hl,
html.theme-light .hero-main h1 .hl, body.theme-light .hero-main h1 .hl{
  background:none!important;-webkit-background-clip:border-box!important;background-clip:border-box!important;
  color:#007a94!important;
}
html.theme-light .sec-head small, body.theme-light .sec-head small,
html.theme-light .hint, body.theme-light .hint{color:#5A6570!important}
html.theme-light .card h3, body.theme-light .card h3,
html.theme-light .card .hint, body.theme-light .card .hint{color:var(--ink2)!important}
html.theme-light .mark, body.theme-light mark{color:#B84210!important;background:rgba(255,176,0,.18)!important}
html.theme-light .pill, body.theme-light .pill{color:#007a94!important}

/* Nuclear panel surfaces */
html.theme-light .wrap, body.theme-light .wrap,
html.theme-light section, body.theme-light section{color:var(--ink)!important}
html.theme-light .card, html.theme-light .stat, html.theme-light .find, html.theme-light .case,
html.theme-light .story, html.theme-light .tbl, html.theme-light .chip,
html.theme-light .drawer-panel, html.theme-light .flow-card, html.theme-light .flow-filters,
html.theme-light #flows .flows-head, html.theme-light .hero-main, html.theme-light .hero-side,
body.theme-light .card, body.theme-light .stat, body.theme-light .find, body.theme-light .case,
body.theme-light .story, body.theme-light .tbl, body.theme-light .chip,
body.theme-light .drawer-panel, body.theme-light .flow-card, body.theme-light .flow-filters,
body.theme-light #flows .flows-head, body.theme-light .hero-main, body.theme-light .hero-side{
  background:#FFFFFF!important;
  background-image:linear-gradient(180deg,#FFFFFF 0%,#EEF2F6 100%)!important;
  color:var(--ink)!important;
  border-color:#C4CCD6!important;
}
html.theme-light .card:before, html.theme-light .stat:before, html.theme-light .find:before, html.theme-light .case:before,
body.theme-light .card:before, body.theme-light .stat:before, body.theme-light .find:before, body.theme-light .case:before{
  background:linear-gradient(180deg,#FFFFFF 0%,#F4F6F8 100%)!important;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.95)!important;
}
html.theme-light h1, html.theme-light h2, html.theme-light h3, html.theme-light h4,
html.theme-light .find h3, html.theme-light .card h3, html.theme-light .sec-head h2,
html.theme-light .drawer-panel h2, html.theme-light .flows-title,
body.theme-light h1, body.theme-light h2, body.theme-light h3, body.theme-light h4,
body.theme-light .find h3, body.theme-light .card h3, body.theme-light .sec-head h2,
body.theme-light .drawer-panel h2, body.theme-light .flows-title{color:#0E1216!important}
html.theme-light p, html.theme-light li, html.theme-light td, html.theme-light label,
html.theme-light .hint, html.theme-light .note, html.theme-light .flow-meta, html.theme-light .flow-sub,
body.theme-light p, body.theme-light li, body.theme-light td, body.theme-light label,
body.theme-light .hint, body.theme-light .note, body.theme-light .flow-meta, body.theme-light .flow-sub{color:#2A323C!important}
html.theme-light b, body.theme-light b{color:#0E1216!important}
html.theme-light .story b, body.theme-light .story b{color:#007a94!important}
html.theme-light .mono, body.theme-light .mono{color:#007a94!important}
html.theme-light th, body.theme-light th{color:#007a94!important;background:#EEF2F6!important}
html.theme-light tbody tr:hover td, body.theme-light tbody tr:hover td{color:#0E1216!important;background:rgba(0,229,255,.10)!important}
html.theme-light .chart, body.theme-light .chart{background:transparent!important}
html.theme-light nav a:hover, body.theme-light nav a:hover{color:#0E1216!important;background:#E2E8EE!important}

/* ECharts tooltips — light bubble + dark ink (never black-on-dark) */
html.theme-light div[class*="echarts-tooltip"],
body.theme-light div[class*="echarts-tooltip"],
html.theme-light .echarts-tooltip,
body.theme-light .echarts-tooltip{
  background:rgba(255,255,255,.97)!important;
  border:1px solid rgba(0,168,200,.5)!important;
  color:#0E1216!important;
  box-shadow:0 4px 20px rgba(14,18,22,.12)!important;
}
html.theme-light div[class*="echarts-tooltip"] b,
body.theme-light div[class*="echarts-tooltip"] b,
html.theme-light .echarts-tooltip b,
body.theme-light .echarts-tooltip b,
html.theme-light div[class*="echarts-tooltip"] span,
body.theme-light div[class*="echarts-tooltip"] span{color:#0E1216!important}
'''

OVERLAY_JS = r'''
(function(){
  var cfg = Object.assign({locale:'zh', theme:'dark'}, window.__V15__ || {});
  document.documentElement.setAttribute('data-v15-locale', cfg.locale);
  document.documentElement.setAttribute('data-v15-theme', cfg.theme);

  // Light: patch ECharts surfaces / labels / tooltips after charts init
  if (cfg.theme === 'light' && typeof echarts !== 'undefined') {
    var LIGHT_TXT = '#2A323C';
    var LIGHT_MUTED = '#4A5562';
    var LIGHT_LINE = '#C4CCD6';
    var LIGHT_SPLIT = '#D8DEE6';
    var LIGHT_CELL = '#e8eef5';
    var LIGHT_TT_BG = 'rgba(255,255,255,.97)';
    var LIGHT_TT_FG = '#0E1216';
    var HEAT_LIGHT = ['#e8eef5','#9ad4e0','#00b8d4','#ffb000','#ff2e4d'];
    function patchAxis(ax){
      if(!ax) return;
      var list = Array.isArray(ax) ? ax : [ax];
      list.forEach(function(a){
        if(!a || typeof a !== 'object') return;
        a.axisLabel = Object.assign({}, a.axisLabel||{}, {color: LIGHT_MUTED});
        a.nameTextStyle = Object.assign({}, a.nameTextStyle||{}, {color: LIGHT_MUTED});
        if(a.axisLine) a.axisLine = Object.assign({}, a.axisLine, {lineStyle:Object.assign({},(a.axisLine.lineStyle)||{},{color:LIGHT_LINE})});
        if(a.splitLine) a.splitLine = Object.assign({}, a.splitLine, {lineStyle:Object.assign({},(a.splitLine.lineStyle)||{},{color:LIGHT_SPLIT})});
        if(a.splitArea && a.splitArea.areaStyle){
          a.splitArea = Object.assign({}, a.splitArea, {areaStyle:Object.assign({}, a.splitArea.areaStyle, {color:[LIGHT_CELL,'#f0f4f8']})});
        }
      });
    }
    function patchAll(){
      try{
        document.querySelectorAll('[_echarts_instance_], div[id^="c_"], div[id^="ch"]').forEach(function(dom){
          var inst = echarts.getInstanceByDom(dom);
          if(!inst) return;
          var o2 = inst.getOption()||{};
          var so = {
            backgroundColor:'transparent',
            textStyle:{color:LIGHT_TXT},
            tooltip:{
              backgroundColor:LIGHT_TT_BG,
              borderColor:'rgba(0,168,200,.5)',
              borderWidth:1,
              textStyle:{color:LIGHT_TT_FG, fontSize:12.5}
            },
            legend:{textStyle:{color:LIGHT_TXT}, pageTextStyle:{color:LIGHT_MUTED}, pageIconInactiveColor:'#A8B0BA'},
            title:{textStyle:{color:'#0E1216'}, subtextStyle:{color:LIGHT_MUTED}}
          };
          // axes
          if(o2.xAxis) so.xAxis = (Array.isArray(o2.xAxis)?o2.xAxis:[o2.xAxis]).map(function(a){
            return Object.assign({}, a||{}, {
              axisLabel:Object.assign({},(a&&a.axisLabel)||{},{color:LIGHT_MUTED}),
              nameTextStyle:Object.assign({},(a&&a.nameTextStyle)||{},{color:LIGHT_MUTED}),
              axisLine:Object.assign({},(a&&a.axisLine)||{},{lineStyle:Object.assign({},(a&&a.axisLine&&a.axisLine.lineStyle)||{},{color:LIGHT_LINE})}),
              splitLine:Object.assign({},(a&&a.splitLine)||{},{lineStyle:Object.assign({},(a&&a.splitLine&&a.splitLine.lineStyle)||{},{color:LIGHT_SPLIT})})
            });
          });
          if(o2.yAxis) so.yAxis = (Array.isArray(o2.yAxis)?o2.yAxis:[o2.yAxis]).map(function(a){
            return Object.assign({}, a||{}, {
              axisLabel:Object.assign({},(a&&a.axisLabel)||{},{color:LIGHT_MUTED}),
              nameTextStyle:Object.assign({},(a&&a.nameTextStyle)||{},{color:LIGHT_MUTED}),
              axisLine:Object.assign({},(a&&a.axisLine)||{},{lineStyle:Object.assign({},(a&&a.axisLine&&a.axisLine.lineStyle)||{},{color:LIGHT_LINE})}),
              splitLine:Object.assign({},(a&&a.splitLine)||{},{lineStyle:Object.assign({},(a&&a.splitLine&&a.splitLine.lineStyle)||{},{color:LIGHT_SPLIT})})
            });
          });
          // calendar + visualMap (heatmap empty cells + weekday labels)
          if(o2.calendar){
            so.calendar = (Array.isArray(o2.calendar)?o2.calendar:[o2.calendar]).map(function(c){
              return Object.assign({}, c||{}, {
                splitLine:Object.assign({},(c&&c.splitLine)||{},{lineStyle:Object.assign({},(c&&c.splitLine&&c.splitLine.lineStyle)||{},{color:LIGHT_LINE,width:2})}),
                itemStyle:Object.assign({},(c&&c.itemStyle)||{},{borderColor:LIGHT_LINE,borderWidth:2,color:LIGHT_CELL}),
                dayLabel:Object.assign({},(c&&c.dayLabel)||{},{color:LIGHT_MUTED}),
                monthLabel:Object.assign({},(c&&c.monthLabel)||{},{color:LIGHT_MUTED}),
                yearLabel:Object.assign({},(c&&c.yearLabel)||{},{color:LIGHT_MUTED})
              });
            });
          }
          if(o2.visualMap){
            so.visualMap = (Array.isArray(o2.visualMap)?o2.visualMap:[o2.visualMap]).map(function(v){
              var vm = Object.assign({}, v||{}, {textStyle:Object.assign({},(v&&v.textStyle)||{},{color:LIGHT_MUTED})});
              var colors = (v && v.inRange && v.inRange.color) || [];
              var first = colors[0] ? String(colors[0]).toLowerCase() : '';
              if(!colors.length || first==='#0b1a22' || first==='#0a1218' || first==='#0a2f3c' || first==='#0c1218' || first.indexOf('#0')===0 && first.length===7){
                vm.inRange = Object.assign({}, (v&&v.inRange)||{}, {color: HEAT_LIGHT.slice()});
              }
              return vm;
            });
          }
          // series: bars tracks, pie borders, gauge tracks, labels
          if(o2.series){
            so.series = (Array.isArray(o2.series)?o2.series:[o2.series]).map(function(s){
              if(!s) return s;
              var ss = Object.assign({}, s);
              if(ss.type==='bar'){
                if(ss.showBackground || ss.backgroundStyle){
                  ss.backgroundStyle = Object.assign({}, ss.backgroundStyle||{}, {color:'#E8ECF0'});
                }
                if(ss.label) ss.label = Object.assign({}, ss.label, {color:LIGHT_MUTED});
              }
              if(ss.type==='pie' || ss.type==='doughnut' || ss.type==='sunburst' || ss.type==='treemap'){
                ss.label = Object.assign({}, ss.label||{}, {color:LIGHT_TXT});
                ss.itemStyle = Object.assign({}, ss.itemStyle||{}, {borderColor:'#F4F6F8'});
              }
              if(ss.type==='heatmap' && ss.label){
                ss.label = Object.assign({}, ss.label, {color:'#0E1216'});
              }
              if(ss.type==='gauge' && ss.axisLine && ss.axisLine.lineStyle){
                var lc = ss.axisLine.lineStyle.color;
                if(Array.isArray(lc)){
                  ss.axisLine = Object.assign({}, ss.axisLine, {lineStyle:Object.assign({}, ss.axisLine.lineStyle, {color: lc.map(function(pair){
                    if(Array.isArray(pair) && typeof pair[1]==='string' && /#16202b|#0[0-9a-f]{5}/i.test(pair[1])) return [pair[0],'#D8DEE6'];
                    return pair;
                  })})});
                }
              }
              if(ss.type==='sankey' && ss.label){
                ss.label = Object.assign({}, ss.label, {color:LIGHT_TXT});
              }
              if(ss.type==='graph' && ss.label){
                ss.label = Object.assign({}, ss.label, {color:LIGHT_TXT});
              }
              if(ss.markPoint){
                ss.markPoint = Object.assign({}, ss.markPoint, {
                  itemStyle:Object.assign({},(ss.markPoint.itemStyle)||{},{color:'#0E1216'}),
                  label:Object.assign({},(ss.markPoint.label)||{},{color:'#FFFFFF'})
                });
              }
              return ss;
            });
          }
          // radar
          if(o2.radar){
            so.radar = (Array.isArray(o2.radar)?o2.radar:[o2.radar]).map(function(r){
              return Object.assign({}, r||{}, {
                axisName:Object.assign({},(r&&r.axisName)||{},{color:LIGHT_MUTED}),
                name:Object.assign({},(r&&r.name)||{},{color:LIGHT_MUTED}),
                axisLine:Object.assign({},(r&&r.axisLine)||{},{lineStyle:Object.assign({},(r&&r.axisLine&&r.axisLine.lineStyle)||{},{color:LIGHT_LINE})}),
                splitLine:Object.assign({},(r&&r.splitLine)||{},{lineStyle:Object.assign({},(r&&r.splitLine&&r.splitLine.lineStyle)||{},{color:LIGHT_SPLIT})}),
                splitArea:Object.assign({},(r&&r.splitArea)||{},{areaStyle:Object.assign({},(r&&r.splitArea&&r.splitArea.areaStyle)||{},{color:[LIGHT_CELL,'#f4f6f8']})})
              });
            });
          }
          inst.setOption(so, false);
        });
      }catch(e){}
    }
    setTimeout(patchAll, 80);
    setTimeout(patchAll, 400);
    setTimeout(patchAll, 1200);
    setTimeout(patchAll, 2800);
  }

  // EN: rewrite remaining key chrome

  // EN: rewrite remaining key chrome if any Chinese left in known slots
  if (cfg.locale === 'en') {
    var MAP = {
      '總覽':'Overview','資產':'Assets','事件':'Events','流量':'Traffic','登入':'Auth',
      '設定變更':'Config changes','事故':'Incidents','風險':'Risk','個案追蹤':'Case tracking',
      '攻擊流程':'Attack Flows','發現與建議':'Findings','合規':'Compliance','附錄':'Appendix',
      '篩選':'Filter','全部嚴重度':'All severities','建議：':'Action: ','優先處理':'Priority',
      '中等':'Medium','留意':'Watch','有':'yes','冇':'no',
      '輸入關鍵字篩選…':'Filter by keyword…','資料時段':'Window','擷取於':'Collected',
      '生成於':'generated','數據來源':'source','唯讀':'read-only','已內嵌':'inlined',
      '五日安全報告':'5-Day Security Report','安全報告':'Security Report','安全回顧':'Security Review',
      '規則':'Rule','類別':'Category','標題':'Title','實體':'Entity','名稱':'Name',
      '序號':'Serial','版本':'Version','廠商':'Vendor','型號':'Model','合共':'Total',
      '成功':'Success','失敗':'Failure','來源':'Source','次數':'Count','設備':'Device',
      '狀態':'Status','健康':'health','節點':'node','報告設備':'Reporting devices',
      '模式':'Mode','主題':'Theme','相關':'Related','留意':'Watch'
    };
    function walk(node){
      if(!node) return;
      if(node.nodeType===3){
        var t=node.nodeValue, n=t;
        Object.keys(MAP).forEach(function(k){ if(n.indexOf(k)>=0) n=n.split(k).join(MAP[k]); });
        if(n!==t) node.nodeValue=n;
        return;
      }
      if(node.nodeType!==1) return;
      var tag=(node.tagName||'').toLowerCase();
      if(tag==='script'||tag==='style'||tag==='code'||tag==='pre') return;
      for(var i=0;i<node.childNodes.length;i++) walk(node.childNodes[i]);
    }
    setTimeout(function(){ walk(document.body); }, 60);
    setTimeout(function(){ walk(document.body); }, 500);
  }
})();
'''


def load_en_map() -> list[tuple[str, str]]:
    pairs: dict[str, str] = {}
    BAD_EXACT = {' 宗', '屬 ', '合共', '設備', '秒', '宗事故'}
    BAD_EN_SUB = ('incidentsIncidents', 'EventsEvents', 'reptDevName')
    if EN_MAP_PATH.exists():
        for row in json.loads(EN_MAP_PATH.read_text(encoding='utf-8')):
            zh, en = row.get('zh') or '', row.get('en') or ''
            if not zh or zh == en:
                continue
            if not re.search(r'[\u4e00-\u9fff]', zh):
                continue
            # drop echarts / junk / dangerous shorts
            if 'dimensions' in zh or 'hash' in zh or len(zh) > 500:
                continue
            if zh in BAD_EXACT:
                continue
            if any(b in en for b in BAD_EN_SUB):
                continue
            cjk_n = len(re.findall(r'[\u4e00-\u9fff]', zh))
            if cjk_n <= 1 and len(zh) < 4:
                continue
            if len(zh) <= 2 and zh not in ('附錄', '合規', '總覽', '資產', '流量', '登入', '風險', '事故', '事件'):
                continue
            pairs[zh] = en
    for zh, en in EXTRA_EN:
        pairs[zh] = en
    for zh, en in FLOW_EN.items():
        pairs[zh] = en
    for zh, en in FLOW_SECTION_EN.items():
        pairs[zh] = en
    # User-preferred nav wording overrides (Auth / Config changes / Case tracking)
    pairs['登入與認證'] = 'Auth'
    pairs['設定變更'] = 'Config changes'
    pairs['個案追蹤'] = 'Case tracking'
    pairs['發現與建議'] = 'Findings'
    pairs['合規建議 ISO 27001'] = 'Compliance'
    pairs['附錄'] = 'Appendix'
    pairs['資產與日誌來源'] = 'Assets & log sources'
    pairs['風險實體'] = 'Risk'
    # Sort longest-first
    return sorted(pairs.items(), key=lambda x: -len(x[0]))


def js_unicode_escape(s: str) -> str:
    """Match json.dumps(..., ensure_ascii=True) body escaping used in FLOW_SECTION inject."""
    return json.dumps(s, ensure_ascii=True)[1:-1]


def apply_en(html: str, pairs: list[tuple[str, str]]) -> str:
    for zh, en in pairs:
        if zh in html:
            html = html.replace(zh, en)
        esc_zh = js_unicode_escape(zh)
        if esc_zh != zh and esc_zh in html:
            html = html.replace(esc_zh, js_unicode_escape(en))
    # Replace findings / compliance / limits / deep_story blocks in embedded JSON
    html = patch_derived_narrative(html)
    return html


def patch_derived_narrative(html: str) -> str:
    """Swap Chinese findings/compliance/limits/deep_story inside #data JSON."""
    m = re.search(r'(<script id="data"[^>]*>)(.*?)(</script>)', html, re.S)
    if not m:
        return html
    try:
        data = json.loads(m.group(2))
    except Exception:
        return html
    der = (((data.get('data') or {}).get('derived')) or {})
    if not isinstance(der, dict):
        return html
    if der.get('findings'):
        der['findings'] = FINDINGS_EN
    if der.get('compliance'):
        # preserve ctrl ids from ZH if lengths match
        zh_c = der['compliance']
        merged = []
        for i, row in enumerate(COMPLIANCE_EN):
            base = dict(row)
            if i < len(zh_c) and isinstance(zh_c[i], dict):
                base['ctrl'] = zh_c[i].get('ctrl', base.get('ctrl'))
            merged.append(base)
        der['compliance'] = merged
    if der.get('limits'):
        der['limits'] = LIMITS_EN
    if 'deep_story' in der:
        der['deep_story'] = DEEP_STORY_EN
    der['title'] = 'FortiSIEM Security Report · 2026-10-28 to 11-02'
    der['span_zh'] = '5-Day'
    der['wk'] = 'This period'
    if 'fam_pct_zh' in der:
        der['fam_pct_zh'] = '~90%'
    der['lang'] = 'en'
    data['data']['derived'] = der
    new_json = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
    return html[:m.start()] + m.group(1) + new_json + m.group(3) + html[m.end():]




def apply_light(html: str) -> str:
    html = re.sub(r'<html\b([^>]*)>', lambda m: _html_tag_with_theme(m.group(0)), html, count=1)
    html = re.sub(r'<body\b([^>]*)>', lambda m: _body_tag_with_theme(m.group(0)), html, count=1)

    # --- Rewrite dark stylesheet tokens inside <style> blocks (not in JSON data) ---
    def restyle(css: str) -> str:
        reps = [
            # core surfaces
            ('#06080b', '#F4F6F8'), ('#0B0F14', '#F4F6F8'), ('#0b0f14', '#F4F6F8'),
            ('#0c1117', '#FFFFFF'), ('#0C1117', '#FFFFFF'),
            ('#0a1016', '#EEF2F6'), ('#0A1016', '#EEF2F6'),
            ('#0f161d', '#EEF2F6'), ('#0F161D', '#EEF2F6'),
            ('#0F141C', '#F4F6F8'), ('#0f141c', '#F4F6F8'),
            ('#121820', '#FFFFFF'), ('#161E28', '#FFFFFF'), ('#161e28', '#FFFFFF'),
            ('#1A2330', '#E8ECF0'), ('#1a2330', '#E8ECF0'),
            ('#111b24', '#E2E8EE'), ('#16202b', '#E8ECF0'),
            ('#070a0e', '#F4F6F8'), ('#05070a', '#F4F6F8'),
            # lines / steel
            ('#243041', '#C4CCD6'), ('#1c2833', '#C4CCD6'), ('#24384a', '#A8B0BA'),
            # near-white text → ink (do NOT touch tooltip JS outside style)
            ('color:#fff}', 'color:#0E1216}'),
            ('color:#fff;', 'color:#0E1216;'),
            ('color:#ffffff', 'color:#0E1216'),
            ('color:#E8EEF6', 'color:#0E1216'),
            ('color:#e8eef6', 'color:#0E1216'),
            ('color:#e6f1ff', 'color:#0E1216'),
            ('color:#E6F1FF', 'color:#0E1216'),
            ('color:#b4c2d3', 'color:#2A323C'),
            ('color:#B4C2D3', 'color:#2A323C'),
            ('color:#9aa8bc', 'color:#4A5562'),
            ('color:#9AA8BC', 'color:#4A5562'),
            ('color:#7d8fa5', 'color:#4A5562'),
            ('color:#6B7A8F', 'color:#4A5562'),
            ('color:#6b7a8f', 'color:#4A5562'),
            # :root dark vars if still present in same block
            ('--bg:#06080b', '--bg:#F4F6F8'),
            ('--bg:#0B0F14', '--bg:#F4F6F8'),
            ('--panel:#0c1117', '--panel:#FFFFFF'),
            ('--panel:#121820', '--panel:#FFFFFF'),
            ('--panel2:#0f161d', '--panel2:#E8ECF0'),
            ('--panel2:#1A2330', '--panel2:#E8ECF0'),
            ('--ink:#e6f1ff', '--ink:#0E1216'),
            ('--ink:#E8EEF6', '--ink:#0E1216'),
            ('--ink2:#b4c2d3', '--ink2:#2A323C'),
            ('--ink2:#9AA8BC', '--ink2:#2A323C'),
            ('--mut:#7d8fa5', '--mut:#4A5562'),
            ('--mut:#6B7A8F', '--mut:#4A5562'),
            ('--line:#1c2833', '--line:#C4CCD6'),
            ('--line:#243041', '--line:#C4CCD6'),
        ]
        for a, b in reps:
            css = css.replace(a, b)
        # keep cyan accents vivid but readable on light for nav active text
        css = css.replace('nav a:hover{background:#E2E8EE;color:#0E1216}', 'nav a:hover{background:#E2E8EE;color:#0E1216}')
        return css

    def style_sub(mobj):
        return mobj.group(1) + restyle(mobj.group(2)) + mobj.group(3)

    html = re.sub(r'(<style[^>]*>)([\s\S]*?)(</style>)', style_sub, html, count=2)

    # Flow SVG + chart JS tokens outside first styles
    html = html.replace(r'fill=\"#1A2330\" stroke=\"#243041\"', r'fill=\"#E8ECF0\" stroke=\"#C4CCD6\"')
    html = html.replace(r'fill=\"#E8EEF6\" font-size=\"11\"', r'fill=\"#0E1216\" font-size=\"11\"')
    html = html.replace('fill="#1A2330" stroke="#243041"', 'fill="#E8ECF0" stroke="#C4CCD6"')
    html = html.replace('fill="#E8EEF6" font-size="11"', 'fill="#0E1216" font-size="11"')

    # Chart option tokens — ONLY rewrite app JS (from const TT=), never the inlined echarts lib
    marker = 'const TT='
    cut = html.find(marker)
    if cut < 0:
        return html
    head, app = html[:cut], html[cut:]

    # Light tooltip (dark ink text) — avoids black-on-dark from theme-light b{} CSS
    app = app.replace(
        "const TT={backgroundColor:'rgba(7,11,15,.96)',borderColor:'rgba(0,229,255,.45)',borderWidth:1,padding:[9,13],appendToBody:true,textStyle:{color:'#e6f1ff'",
        "const TT={backgroundColor:'rgba(255,255,255,.97)',borderColor:'rgba(0,168,200,.5)',borderWidth:1,padding:[9,13],appendToBody:true,textStyle:{color:'#0E1216'",
    )

    chart_reps = [
        # titles / strong ink
        ("fontWeight:700,color:'#e6f1ff'}", "fontWeight:700,color:'#0E1216'}"),
        ('fontWeight:700,color:"#e6f1ff"}', 'fontWeight:700,color:"#0E1216"}'),
        ("color:'#e6f1ff'", "color:'#0E1216'"),
        ('color:"#e6f1ff"', 'color:"#0E1216"'),
        # muted / axis / category labels (hbar used #b4c2d3)
        ("color:'#b4c2d3'", "color:'#2A323C'"),
        ('color:"#b4c2d3"', 'color:"#2A323C"'),
        ("color:'#7d8fa5'", "color:'#4A5562'"),
        ('color:"#7d8fa5"', 'color:"#4A5562"'),
        ("fill:'#7d8fa5'", "fill:'#4A5562'"),
        ("textStyle:{color:'#7d8fa5'", "textStyle:{color:'#4A5562'"),
        ("pageTextStyle:{color:'#7d8fa5'", "pageTextStyle:{color:'#4A5562'"),
        ("subtextStyle:{color:'#7d8fa5'", "subtextStyle:{color:'#4A5562'"),
        ("axisLabel:{color:'#7d8fa5'", "axisLabel:{color:'#4A5562'"),
        # pie / sunburst borders & bar tracks
        ("borderColor:'#070a0e',borderWidth:2", "borderColor:'#F4F6F8',borderWidth:2"),
        ("borderWidth:2,borderColor:'#070a0e'", "borderWidth:2,borderColor:'#F4F6F8'"),
        ("borderColor:'#070a0e',borderWidth:3,color:'#0c1218'", "borderColor:'#C4CCD6',borderWidth:2,color:'#e8eef5'"),
        ("borderColor:'#070a0e',borderWidth:3,gapWidth:3", "borderColor:'#C4CCD6',borderWidth:2,gapWidth:2"),
        ("borderColor:'#070a0e'", "borderColor:'#C4CCD6'"),
        ("backgroundStyle:{color:'#16202b'", "backgroundStyle:{color:'#E8ECF0'"),
        ("backgroundColor:'#16202b'", "backgroundColor:'#E8ECF0'"),
        ("color:[[1,'#16202b']]", "color:[[1,'#D8DEE6']]"),
        ("lineStyle:{color:'#16202b'}", "lineStyle:{color:'#D8DEE6'}"),
        ("splitLine:{lineStyle:{color:'#16202b'", "splitLine:{lineStyle:{color:'#D8DEE6'"),
        # calendar / heatmap empty cells + visualMap
        ("inRange:{color:['#0b1a22','#00708a','#00e5ff','#ffb000','#ff2e4d']}",
         "inRange:{color:['#e8eef5','#9ad4e0','#00b8d4','#ffb000','#ff2e4d']}"),
        ("inRange:{color:['#0a2f3c','#00a6c7','#00e5ff','#a3ff12','#ffb000','#ff2e4d']}",
         "inRange:{color:['#e8eef5','#9ad4e0','#00b8d4','#b6ff00','#ffb000','#ff2e4d']}"),
        ("splitLine:{lineStyle:{color:'#06080b',width:3}}",
         "splitLine:{lineStyle:{color:'#C4CCD6',width:2}}"),
        ("splitArea:{areaStyle:{color:['#0c1218','#090d12']}}",
         "splitArea:{areaStyle:{color:['#e8eef5','#f0f4f8']}}"),
        ("color:'#0c1218'", "color:'#e8eef5'"),
        # axes chrome
        ("axisLine:{lineStyle:{color:'#24384a'}}", "axisLine:{lineStyle:{color:'#C4CCD6'}}"),
        ("pageIconInactiveColor:'#24384a'", "pageIconInactiveColor:'#A8B0BA'"),
        ("splitLine:{lineStyle:{color:'#141f29',type:[2,4]}}",
         "splitLine:{lineStyle:{color:'#D8DEE6',type:[2,4]}}"),
        ("axisLine:{lineStyle:{color:'#1f2c38'}}", "axisLine:{lineStyle:{color:'#C4CCD6'}}"),
        # donut / pie label already handled via #b4c2d3; ensure light pie border
        ("label:{show:!!o.label,color:'#2A323C'", "label:{show:!!o.label,color:'#2A323C'"),
        # peak markPoint: cyan badge + white label (readable on light)
        ("itemStyle:{color:'#0E1216'},label:{color:'#041016',fontSize:11,formatter:p=>'高峰 '+sh(p.value)}",
         "itemStyle:{color:'#00A8C8'},label:{color:'#FFFFFF',fontSize:11,formatter:p=>'高峰 '+sh(p.value)}"),
        ("itemStyle:{color:'#0E1216'},label:{color:'#041016',fontSize:11,formatter:p=>'Peak '+sh(p.value)}",
         "itemStyle:{color:'#00A8C8'},label:{color:'#FFFFFF',fontSize:11,formatter:p=>'Peak '+sh(p.value)}"),
        ("itemStyle:{color:'#0E1216'},label:{color:'#041016',fontSize:11,formatter:p=>'最高 '+fmt(p.value)}",
         "itemStyle:{color:'#00A8C8'},label:{color:'#FFFFFF',fontSize:11,formatter:p=>'最高 '+fmt(p.value)}"),
        ("itemStyle:{color:'#0E1216'},label:{color:'#041016',fontSize:11,formatter:p=>'Max '+fmt(p.value)}",
         "itemStyle:{color:'#00A8C8'},label:{color:'#FFFFFF',fontSize:11,formatter:p=>'Max '+fmt(p.value)}"),
        ("itemStyle:{color:'#0E1216'},label:{fontSize:10",
         "itemStyle:{color:'#00A8C8'},label:{color:'#FFFFFF',fontSize:10"),
        ("splitLine:{lineStyle:{color:'#1f2c38'}}",
         "splitLine:{lineStyle:{color:'#C4CCD6'}}"),
    ]
    for a, b in chart_reps:
        app = app.replace(a, b)

    html = head + app
    return html



def _html_tag_with_theme(tag: str) -> str:
    if 'theme-light' in tag:
        return tag
    if 'class="' in tag:
        return re.sub(r'class="([^"]*)"', r'class="\1 theme-light"', tag, count=1)
    return tag[:-1] + ' class="theme-light">'


def _body_tag_with_theme(tag: str) -> str:
    if 'theme-light' in tag:
        return tag
    if 'class="' in tag:
        return re.sub(r'class="([^"]*)"', r'class="\1 theme-light"', tag, count=1)
    return tag[:-1] + ' class="theme-light">'


def strip_variants(html: str) -> str:
    """Remove a prior v15 variants tail so rebuilds stay idempotent."""
    i = html.rfind('</body>')
    if i < 0:
        return html
    head = html[:i]
    cut = -1
    j_css = head.rfind('/* === v1.5 LIGHT')
    if j_css >= 0:
        k = head.rfind('<style', 0, j_css)
        if k >= 0:
            cut = k
    j_v = head.rfind('<script>window.__V15__')
    if j_v >= 0 and (cut < 0 or j_v < cut):
        cut = j_v
    if cut >= 0:
        head = head[:cut].rstrip() + '\n'
    return head + html[i:]


def inject_tail(html: str, locale: str, theme: str) -> str:
    html = strip_variants(html)
    cfg = json.dumps({'locale': locale, 'theme': theme}, separators=(',', ':'))
    css_block = ''
    if theme == 'light':
        css_block = '<style>\n' + LIGHT_CSS + '\n</style>\n'
    js = OVERLAY_JS.replace('</script>', '<\\/script>')
    if '</script>' in js:
        raise SystemExit('raw </script> in overlay JS')
    block = (
        css_block
        + f'<script>window.__V15__={cfg};</script>\n'
        + '<script>\n' + js + '\n</script>\n'
    )
    i = html.rfind('</body>')
    if i < 0:
        raise SystemExit('no </body>')
    return html[:i] + block + html[i:]

def set_lang_title(html: str, locale: str, theme: str) -> str:
    lang, title = TITLES[(locale, theme)]
    html = re.sub(r'<html\b([^>]*)lang="[^"]*"', f'<html\\1lang="{lang}"', html, count=1)
    if f'lang="{lang}"' not in html[:200]:
        html = re.sub(r'<html\b', f'<html lang="{lang}"', html, count=1)
    html = re.sub(r'<title>[^<]*</title>', f'<title>{title}</title>', html, count=1)
    return html


def scrub_lawrence(html: str) -> str:
    # Ensure no user-attribution chrome (should already be absent)
    for bad in (
        'LAWRENCE LAU', '為 LAWRENCE LAU', 'For LAWRENCE LAU',
        'Compiled for LAWRENCE', '為 LAWRENCE', 'For LAWRENCE',
    ):
        html = html.replace(bad, '')
    return html


def build(locale: str, theme: str, src_html: str, pairs: list[tuple[str, str]]) -> pathlib.Path:
    html = strip_variants(src_html)
    if locale == 'en':
        html = apply_en(html, pairs)
    html = set_lang_title(html, locale, theme)
    if theme == 'light':
        html = apply_light(html)
    html = scrub_lawrence(html)
    html = inject_tail(html, locale, theme)
    # Re-assert title after other replaces
    _, title = TITLES[(locale, theme)]
    html = re.sub(r'<title>[^<]*</title>', f'<title>{title}</title>', html, count=1)
    out = OUTS[(locale, theme)]
    # For ZH-dark rebuild into SRC — only when explicitly requested
    out.write_text(html, encoding='utf-8')
    return out


def smoke(path: pathlib.Path, locale: str, theme: str) -> None:
    t = path.read_text(encoding='utf-8')
    lang, title = TITLES[(locale, theme)]
    assert f'lang="{lang}"' in t[:300] or f"lang='{lang}'" in t[:300], (path, t[:200])
    assert title in t, (path, title)
    assert 'v1.5 · 5D' in t or 'v1.5' in t
    assert 'window.__V15__' in t
    assert 'ELF/Mirai.AT!tr' in t
    assert 'LAWRENCE LAU' not in t
    assert '為 LAWRENCE' not in t
    assert 'For LAWRENCE' not in t
    assert 'Compiled for LAWRENCE' not in t
    if theme == 'light':
        assert 'theme-light' in t
        assert 'industrial metal' in t or '--bg:#F4F6F8' in t
    if locale == 'en':
        assert 'FortiSIEM 5-Day Security Report' in t
        assert 'Attack Flows' in t
        assert '>Overview<' in t or 'Overview</a>' in t
        # Should not keep Chinese nav brand
        assert '五日 · v1.5' not in t
    else:
        assert 'FortiSIEM 五日安全報告' in t
        assert '攻擊流程' in t or theme == 'light'  # still Chinese
    size = path.stat().st_size
    assert size > 1_000_000, f'{path} too small: {size}'
    # no raw </script> inside our overlay (escaped)
    print(f'OK {path.name}  {size:,} bytes  lang={lang} theme={theme}')


def main(argv=None):
    argv = list(argv or sys.argv[1:])
    if not SRC.exists():
        raise SystemExit(f'missing source {SRC} — run build_v15.py first')
    src_html = SRC.read_text(encoding='utf-8')
    src_md5 = hashlib.md5(src_html.encode('utf-8')).hexdigest()
    pairs = load_en_map()
    print(f'Source {SRC} md5={src_md5} size={SRC.stat().st_size:,}  EN pairs={len(pairs)}')

    only = {('en', 'dark'), ('zh', 'light'), ('en', 'light')}
    if '--all' in argv:
        only = None
    variants = [('zh', 'dark'), ('en', 'dark'), ('zh', 'light'), ('en', 'light')]
    results = []
    for loc, th in variants:
        if only and (loc, th) not in only:
            # leave canonical untouched
            continue
        # Always start from original ZH-dark bytes (not from a previously localized file)
        out = build(loc, th, src_html, pairs)
        smoke(out, loc, th)
        results.append((out, out.stat().st_size, hashlib.md5(out.read_bytes()).hexdigest()))

    # Keep 7day symlink pointing at ZH-dark
    if LINK.exists() or LINK.is_symlink():
        LINK.unlink()
    try:
        LINK.symlink_to(SRC.name)
    except OSError:
        LINK.write_bytes(SRC.read_bytes())

    # Confirm canonical unchanged when not --all
    if only:
        now = hashlib.md5(SRC.read_bytes()).hexdigest()
        assert now == src_md5, 'canonical ZH-dark was modified unexpectedly'
        print(f'Canonical ZH-dark unchanged md5={now}')

    for out, size, md5 in results:
        print(f'{out}  size={size}  md5={md5}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
