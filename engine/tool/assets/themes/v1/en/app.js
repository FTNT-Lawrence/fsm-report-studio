const RAW=JSON.parse(document.getElementById('data').textContent);const X=(RAW.data||{}).derived||{};const SPAN=X.span_zh||'7 days';
const D=RAW.data, M=RAW.meta;
const C={cy:'#22d3ee',gr:'#34d399',am:'#fbbf24',rd:'#f87171',pu:'#a78bfa',bl:'#60a5fa',pk:'#f472b6',mut:'#7f93b5',line:'#1d3357'};
const PAL=['#22d3ee','#34d399','#fbbf24','#f87171','#a78bfa','#60a5fa','#f472b6','#2dd4bf','#facc15','#fb923c','#818cf8','#4ade80'];
const SEVC={HIGH:C.rd,MEDIUM:C.am,LOW:C.gr,'':C.mut};
const esc=s=>s==null?'':String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=n=>n==null||n===''?'—':(typeof n==='number'?n.toLocaleString('en-US',{maximumFractionDigits:2}):n);
const sh=n=>n>=1e9?(n/1e9).toFixed(2)+'B':n>=1e6?(n/1e6).toFixed(2)+'M':n>=1e3?(n/1e3).toFixed(1)+'K':String(n);
const has=k=>Array.isArray(D[k])?D[k].length>0:(D[k]!=null&&typeof D[k]==='object'&&Object.keys(D[k]).length>0);
const sum=(a,f)=>a.reduce((s,x)=>s+(+f(x)||0),0);
const NA=(m)=>`<div class="na">No data / not available via MCP${m?'<br>'+esc(m):''}</div>`;
const charts=[];
function card(title,body,sub,cls){return `<div class="card ${cls||''}"><h3>${title}${sub?`<small>${sub}</small>`:''}</h3>${body}</div>`}
function chartDiv(id,cls){return `<div id="${id}" class="chart ${cls||''}"></div>`}
function plan(id,opt){charts.push([id,opt])}
let TB=0;const TABLES=[];
function table(cols,rows,opt){opt=opt||{};if(!rows||!rows.length)return NA(opt.na);const id='t'+(TB++);TABLES.push({id,cols,rows});
 return `${opt.filter!==false&&rows.length>8?`<input class="filter" placeholder="🔍 filter…" data-t="${id}">`:''}<div class="tbl-wrap" style="${opt.max?`max-height:${opt.max}px`:''}"><table id="${id}"><thead><tr>${cols.map((c,i)=>`<th data-i="${i}">${esc(c.h)}</th>`).join('')}</tr></thead><tbody></tbody></table></div>`}
function renderRows(t){const tb=document.querySelector('#'+t.id+' tbody');tb.innerHTML=t.rows.map(r=>`<tr>${t.cols.map(c=>{let v=typeof c.k==='function'?c.k(r):r[c.k];const isn=typeof v==='number';let h=c.f?c.f(v,r):(isn?fmt(v):esc(v==null?'':v));const nw=c.code&&typeof v==='string'&&v.length<=42;return `<td class="${isn||c.n?'n':''} ${c.code?'code':''} ${nw?'nw':''}">${h}</td>`}).join('')}</tr>`).join('')}
function sevB(s){return s?`<span class="sev sev-${esc(s)}">${esc(s)}</span>`:''}
const base={backgroundColor:'transparent',textStyle:{color:'#c7d5ee',fontFamily:'-apple-system,Segoe UI,Noto Sans TC,sans-serif'},grid:{left:56,right:18,top:34,bottom:38,containLabel:true},tooltip:{trigger:'axis',backgroundColor:'#0b1530',borderColor:'#22406e',textStyle:{color:'#e2ecff'}},legend:{textStyle:{color:'#9fb6da'},top:0,type:'scroll'}};
const ax={axisLine:{lineStyle:{color:C.line}},axisLabel:{color:'#8ea3c7'},splitLine:{lineStyle:{color:'#13254a'}}};
function hbar(id,labels,vals,color,extra){plan(id,Object.assign({},base,{grid:{left:10,right:40,top:10,bottom:10,containLabel:true},tooltip:{trigger:'axis',axisPointer:{type:'shadow'},backgroundColor:'#0b1530',borderColor:'#22406e',textStyle:{color:'#e2ecff'}},xAxis:Object.assign({type:'value',axisLabel:{color:'#8ea3c7',formatter:v=>sh(v)}},{splitLine:ax.splitLine,axisLine:ax.axisLine}),yAxis:{type:'category',data:labels.slice().reverse(),axisLabel:{color:'#c7d5ee',fontFamily:'monospace',fontSize:11,width:220,overflow:'truncate'},axisLine:ax.axisLine},series:[{type:'bar',data:vals.slice().reverse(),itemStyle:{color:new echarts.graphic.LinearGradient(0,0,1,0,[{offset:0,color:(color||C.cy)+'55'},{offset:1,color:color||C.cy}]),borderRadius:[0,3,3,0]},label:{show:true,position:'right',color:'#9fb6da',fontSize:10,formatter:p=>sh(p.value)}}]},extra||{}))}
function donut(id,items,colors){plan(id,Object.assign({},base,{tooltip:{trigger:'item',formatter:p=>`${esc(p.name)}<br><b>${fmt(p.value)}</b> (${p.percent}%)`},legend:{orient:'vertical',right:0,top:'middle',textStyle:{color:'#9fb6da',fontSize:11}},series:[{type:'pie',radius:['45%','72%'],center:['38%','52%'],itemStyle:{borderColor:'#0e1a30',borderWidth:2},label:{color:'#c7d5ee',formatter:'{d}%',fontSize:11},data:items.map((x,i)=>({name:x[0],value:x[1],itemStyle:{color:(colors&&colors[i])||PAL[i%PAL.length]}}))}]}))}
const S=[];// html chunks
const dayLbl=d=>d.slice(5);
// ---------- data prep
const T=(D.ev_total||[{}])[0];
const evDay=D.ev_per_day||[];
const incSev=Object.fromEntries((D.inc_by_sev||[]).map(r=>[r.severity_cat,r.c]));
const incTotal=sum(D.inc_by_sev||[],r=>r.c);
const incOpen=((D.inc_by_status||[]).find(r=>r.status==='Open')||{}).c||0;
const incCleared=incTotal-incOpen;
const cmdbN=((D.cmdb_count||[])[0]||{}).c;
const rept=D.ev_rept_list||[];
const health=(D.health||[])[0];
const firstT=(T.first||'').replace('T',' ').slice(0,16), lastT=(T.last||'').replace('T',' ').slice(0,16);
document.getElementById('heroSub').innerHTML=`Supervisor ${esc(M.supervisor)} · Window: ${esc(firstT)} → ${esc(lastT)} HKT · Collected: ${esc(M.generated_hkt)}`;
// ---------- 1 EXEC
const denyTot=sum(D.traffic_daily||[],r=>r.deny), permTot=sum(D.traffic_daily||[],r=>r.permit);
const authS=sum(D.auth_daily||[],r=>r.success), authF=sum(D.auth_daily||[],r=>r.failure);
const kp=[
 ['Total Events',sh(T.events||0),fmt(T.events)+' events',C.cy],
 ['Avg / day',sh(Math.round((T.events||0)/(X.days||7))),(X.days||7)+'-day window',C.bl],
 ['Event Types',fmt(T.event_types),'distinct eventType',C.pu],
 ['Reporting Devices',fmt(rept.length),`${fmt(T.rept_ips)} distinct IPs`,C.gr],
 ['CMDB Devices',fmt(cmdbN),'ph_device',C.gr],
 ['Incidents',sh(incTotal),fmt(incTotal)+' (last_seen '+(X.days||7)+'d)',C.am],
 ['HIGH',sh(incSev.HIGH||0),fmt(incSev.HIGH)+' incidents',C.rd],
 ['MEDIUM',sh(incSev.MEDIUM||0),fmt(incSev.MEDIUM),C.am],
 ['LOW',sh(incSev.LOW||0),fmt(incSev.LOW),C.gr],
 ['Open',sh(incOpen),(incTotal?(incOpen/incTotal*100).toFixed(1):0)+'% of incidents',C.rd],
 ['Cleared',fmt(incCleared),'Rule/System cleared',C.gr],
 ['Denied Traffic',sh(denyTot),(denyTot/(denyTot+permTot)*100).toFixed(1)+'% of traffic events',C.rd],
 ['Logon S/F',`${sh(authS)} / ${authF}`,'PH_SYS_EVENT_Logon / LogonFailure',C.cy],
 ['SIEM EPS (3min)',health?fmt(health.eps_3min):'—',health?`${esc(health.host_name)} · ${esc(health.summary)}`:'',C.pu],
];
S.push(`<section id="exec"><h2><span class="num">01</span>Executive Overview</h2><p class="desc">Key FortiSIEM metrics for the last ${SPAN}; all figures queried live via FortiSIEM MCP (ClickHouse <span class="mono">fsiem.events</span>  and Postgres CMDB).</p>
<div class="kpis">${kp.map(k=>`<div class="kpi" style="--c:${k[3]}"><div class="l">${k[0]}</div><div class="v">${k[1]}</div><div class="s">${k[2]}</div></div>`).join('')}</div>
<div class="grid g3" style="margin-top:14px">
${card('Events / Day',chartDiv('c_exec_ev','short'),'HKT')}
${card('Incidents / Day (by severity)',chartDiv('c_exec_inc','short'),'by last_seen')}
${card('Incident Severity',chartDiv('c_exec_sev','short'),'7d')}
</div></section>`);
plan('c_exec_ev',Object.assign({},base,{xAxis:Object.assign({type:'category',data:evDay.map(r=>dayLbl(r.day))},ax),yAxis:Object.assign({type:'value',axisLabel:{color:'#8ea3c7',formatter:v=>sh(v)}},{splitLine:ax.splitLine}),series:[{type:'line',smooth:true,data:evDay.map(r=>r.c),areaStyle:{color:new echarts.graphic.LinearGradient(0,0,0,1,[{offset:0,color:'#22d3ee66'},{offset:1,color:'#22d3ee00'}])},lineStyle:{color:C.cy,width:2},itemStyle:{color:C.cy}}]}));
function incDailyOpt(rows){const days=[...new Set(rows.map(r=>r.day))].sort();const sevs=['HIGH','MEDIUM','LOW'];return Object.assign({},base,{tooltip:Object.assign({},base.tooltip,{axisPointer:{type:'shadow'}}),xAxis:Object.assign({type:'category',data:days.map(dayLbl)},ax),yAxis:Object.assign({type:'value',axisLabel:{color:'#8ea3c7',formatter:v=>sh(v)}},{splitLine:ax.splitLine}),series:sevs.map(s=>({name:s,type:'bar',stack:'a',itemStyle:{color:SEVC[s]},data:days.map(d=>{const x=rows.find(r=>r.day===d&&r.severity_cat===s);return x?x.c:0})}))})}
if(has('inc_daily_sev'))plan('c_exec_inc',incDailyOpt(D.inc_daily_sev));
donut('c_exec_sev',(D.inc_by_sev||[]).map(r=>[r.severity_cat,r.c]),(D.inc_by_sev||[]).map(r=>SEVC[r.severity_cat]));
// ---------- 2 EVENTS
const hm=D.ev_heatmap||[];const hmDays=[...new Set(hm.map(r=>r.day))].sort();
S.push(`<section id="events"><h2><span class="num">02</span>Event Analytics</h2><p class="desc">Source: <span class="mono">query_fsm_clickhouse</span> → <span class="mono">fsiem.events</span>(phRecvTime &gt; now() − ${X.days||7}×86400). First/last days (${esc(evDay[0]&&evDay[0].day)} · ${esc(evDay.length&&evDay[evDay.length-1].day)}) are partial).</p>
<div class="grid g2">
${card('Events Heatmap (Day × Hour, HKT)',chartDiv('c_heat','tall'))}
${card('FortiSIEM ingest EPS (hourly avg)',has('eps_hourly')?chartDiv('c_eps','tall'):NA(),'PH_SYSTEM_EPS_GLOBAL')}
${card('Events by Severity / Day',chartDiv('c_evsev'),'eventSeverityCat')}
${card('phEventCategory',chartDiv('c_evcat'),'7d')}
</div>
<div class="grid g2" style="margin-top:14px">
${card('Top 15 Event Types',chartDiv('c_types','tall'))}
${card('Top Reporting Devices',chartDiv('c_rept','tall'))}
${card('Top 15 Source IPs',chartDiv('c_src','tall'),'srcIpAddrV4')}
${card('Top 15 Destination IPs',chartDiv('c_dst','tall'),'destIpAddrV4')}
${card('Top 15 Users',chartDiv('c_users','tall'),'user')}
${card('Top Destination Ports',chartDiv('c_ports','tall'),'destIpPort/ipProto')}
${card('Source Country (Top 15)',chartDiv('c_sgeo'),'srcGeoCountry')}
${card('Destination Country (Top 15)',chartDiv('c_dgeo'),'destGeoCountry')}
</div>
<div class="grid g2" style="margin-top:14px">
${card('Event Type Detail (Top 25)',table([{h:'eventType',k:'eventType',code:1},{h:'eventName',k:'eventName'},{h:'Group',k:'grp'},{h:'Count',k:'c'}],D.ev_top_types))}
${card('Vendor / Model',table([{h:'reptVendor',k:'reptVendor'},{h:'reptModel',k:'reptModel'},{h:'Events',k:'c'},{h:'%',k:r=>+(r.c/T.events*100).toFixed(2)}],D.ev_by_vendor))}
</div></section>`);
const hmMax=Math.max(1,...hm.map(r=>r.c));
plan('c_heat',Object.assign({},base,{tooltip:{position:'top',formatter:p=>`${hmDays[p.value[1]]} ${p.value[0]}:00 HKT<br><b>${fmt(p.value[2])}</b> events`},grid:{left:10,right:20,top:10,bottom:60,containLabel:true},xAxis:{type:'category',data:[...Array(24).keys()].map(h=>h+''),axisLabel:{color:'#8ea3c7'},splitArea:{show:false}},yAxis:{type:'category',data:hmDays.map(dayLbl),axisLabel:{color:'#8ea3c7'}},visualMap:{min:0,max:hmMax,calculable:true,orient:'horizontal',left:'center',bottom:0,textStyle:{color:'#8ea3c7'},inRange:{color:['#0b1a33','#0e4a6b','#0891b2','#22d3ee','#fbbf24','#f87171']}},series:[{type:'heatmap',data:hm.map(r=>[r.hr,hmDays.indexOf(r.day),r.c]),itemStyle:{borderColor:'#060b16',borderWidth:1}}]}));
if(has('eps_hourly'))plan('c_eps',Object.assign({},base,{xAxis:Object.assign({type:'category',data:D.eps_hourly.map(r=>r.h.slice(5,13).replace('T',' '))},ax),yAxis:Object.assign({type:'value',name:'EPS',nameTextStyle:{color:'#8ea3c7'}},ax),dataZoom:[{type:'inside'}],series:[{type:'line',showSymbol:false,data:D.eps_hourly.map(r=>+r.eps.toFixed(2)),lineStyle:{color:C.pu},areaStyle:{color:'#a78bfa22'},itemStyle:{color:C.pu}}]}));
(function(){const r=D.ev_sev_daily||[];const days=[...new Set(r.map(x=>x.day))].sort();const sv=['HIGH','MEDIUM','LOW',''];plan('c_evsev',Object.assign({},base,{tooltip:Object.assign({},base.tooltip,{axisPointer:{type:'shadow'}}),xAxis:Object.assign({type:'category',data:days.map(dayLbl)},ax),yAxis:Object.assign({type:'value',axisLabel:{color:'#8ea3c7',formatter:v=>sh(v)}},{splitLine:ax.splitLine}),series:sv.map(s=>({name:s||'(none)',type:'bar',stack:'e',itemStyle:{color:SEVC[s]},data:days.map(d=>{const x=r.find(y=>y.day===d&&y.sev===s);return x?x.c:0})}))}))})();
const CATN={0:'External',1:'Incidents',2:'Audit',3:'System',4:'Traffic Flow',5:'Health',6:'Performance'};
donut('c_evcat',(D.ev_by_cat||[]).map(r=>[`${r.cat} · ${CATN[r.cat]||'?'}`,r.c]));
hbar('c_types',(D.ev_top_types||[]).slice(0,15).map(r=>r.eventType),(D.ev_top_types||[]).slice(0,15).map(r=>r.c),C.cy);
hbar('c_rept',rept.map(r=>`${r.reptDevName} (${r.ip})`),rept.map(r=>r.c),C.gr,{xAxis:{type:'log',axisLabel:{color:'#8ea3c7',formatter:v=>sh(v)},splitLine:ax.splitLine}});
hbar('c_src',(D.ev_top_src||[]).map(r=>r.ip),(D.ev_top_src||[]).map(r=>r.c),C.bl);
hbar('c_dst',(D.ev_top_dst||[]).map(r=>r.ip),(D.ev_top_dst||[]).map(r=>r.c),C.pu);
hbar('c_users',(D.ev_top_users||[]).map(r=>r.user),(D.ev_top_users||[]).map(r=>r.c),C.am);
const PROTO={6:'tcp',17:'udp',1:'icmp'};
hbar('c_ports',(D.ev_top_dport||[]).map(r=>`${r.port}/${PROTO[r.ipProto]||r.ipProto}`),(D.ev_top_dport||[]).map(r=>r.c),C.pk);
hbar('c_sgeo',(D.ev_src_country||[]).map(r=>r.country),(D.ev_src_country||[]).map(r=>r.c),C.am);
hbar('c_dgeo',(D.ev_dst_country||[]).map(r=>r.country),(D.ev_dst_country||[]).map(r=>r.c),C.cy);
// ---------- 3 TRAFFIC
const td=D.traffic_daily||[];
S.push(`<section id="traffic"><h2><span class="num">03</span>FortiGate Traffic: Allowed vs Denied</h2><p class="desc">using FortiSIEM event type group <span class="mono">PH_SYS_EVENT_PermitTraffic</span> / <span class="mono">PH_SYS_EVENT_DenyTraffic</span> classification; Per-device stats use  <span class="mono">eventAction</span>(0=permit, 1=block) counted as <span class="mono">FortiGate-traffic*</span> Events。</p>
<div class="kpis"><div class="kpi" style="--c:${C.gr}"><div class="l">Permitted (${X.days||7}d)</div><div class="v">${sh(permTot)}</div><div class="s">${fmt(permTot)}</div></div><div class="kpi" style="--c:${C.rd}"><div class="l">Denied (${X.days||7}d)</div><div class="v">${sh(denyTot)}</div><div class="s">${fmt(denyTot)}</div></div><div class="kpi" style="--c:${C.am}"><div class="l">Deny rate</div><div class="v">${(denyTot/(denyTot+permTot)*100).toFixed(1)}%</div><div class="s">deny / (permit+deny)</div></div></div>
<div class="grid g2" style="margin-top:14px">
${card('Permit vs Deny / Day',chartDiv('c_tr_daily'))}
${card('Per-FortiGate Action',chartDiv('c_tr_fgt'),'eventAction')}
${card('Top Denied Sources',chartDiv('c_tr_dsrc'))}
${card('Top Denied Dest Ports',chartDiv('c_tr_dport'))}
</div></section>`);
plan('c_tr_daily',Object.assign({},base,{tooltip:Object.assign({},base.tooltip,{axisPointer:{type:'shadow'}}),xAxis:Object.assign({type:'category',data:td.map(r=>dayLbl(r.day))},ax),yAxis:Object.assign({type:'value',axisLabel:{color:'#8ea3c7',formatter:v=>sh(v)}},{splitLine:ax.splitLine}),series:[{name:'Permit',type:'bar',stack:'t',data:td.map(r=>r.permit),itemStyle:{color:C.gr}},{name:'Deny',type:'bar',stack:'t',data:td.map(r=>r.deny),itemStyle:{color:C.rd}}]}));
(function(){const r=D.traffic_fgt_action||[];plan('c_tr_fgt',Object.assign({},base,{tooltip:Object.assign({},base.tooltip,{axisPointer:{type:'shadow'}}),grid:{left:10,right:30,top:30,bottom:10,containLabel:true},yAxis:{type:'category',data:r.map(x=>x.reptDevName).reverse(),axisLabel:{color:'#c7d5ee',fontFamily:'monospace',fontSize:11}},xAxis:{type:'log',axisLabel:{color:'#8ea3c7',formatter:v=>sh(v)},splitLine:ax.splitLine},series:[{name:'Permitted',type:'bar',data:r.map(x=>x.permitted||null).reverse(),itemStyle:{color:C.gr}},{name:'Blocked',type:'bar',data:r.map(x=>x.blocked||null).reverse(),itemStyle:{color:C.rd}}]}))})();
hbar('c_tr_dsrc',(D.traffic_deny_top_src||[]).map(r=>r.ip),(D.traffic_deny_top_src||[]).map(r=>r.c),C.rd);
hbar('c_tr_dport',(D.traffic_deny_top_dport||[]).map(r=>r.port==null?'(none/ICMP)':String(r.port)),(D.traffic_deny_top_dport||[]).map(r=>r.c),C.am);
// ---------- 4 AUTH
const ad=D.auth_daily||[];
S.push(`<section id="auth"><h2><span class="num">04</span>Authentication</h2><p class="desc">Success: <span class="mono">PH_SYS_EVENT_Logon</span>；Failure: <span class="mono">PH_SYS_EVENT_LogonFailure</span>(FortiSIEM CMDB event type groups)。${SPAN} recorded only <b>${authF}</b>  logon failures.</p>
<div class="grid g2">
${card('Logon Success vs Failure',chartDiv('c_auth'))}
${card('Auth Event Types',table([{h:'eventType',k:'eventType',code:1},{h:'Success',k:'success'},{h:'Failure',k:'failure'}],D.auth_types,{max:300}))}
${card('Logon Failures',table([{h:'user',k:'user'},{h:'src',k:'src',code:1},{h:'reptDevName',k:'reptDevName'},{h:'eventType',k:'eventType',code:1},{h:'Count',k:'c'}],D.auth_fail_top))}
${card('FortiGate Admin Login/Logout',table([{h:'eventType',k:'eventType',code:1},{h:'user',k:'user'},{h:'src',k:'src',code:1},{h:'Device',k:'reptDevName'},{h:'Count',k:'c'}],D.admin_logins))}
${card('Top successful logons (user/src/device)',table([{h:'user',k:'user'},{h:'src',k:'src',code:1},{h:'reptDevName',k:'reptDevName'},{h:'eventType',k:'eventType',code:1},{h:'Count',k:'c'}],D.auth_success_top))}
${card('VPN VPN Events',table([{h:'eventType',k:'eventType',code:1},{h:'user',k:'user'},{h:'src',k:'src',code:1},{h:'srcGeoCountry',k:'srcGeoCountry'},{h:'Device',k:'reptDevName'},{h:'Count',k:'c'}],D.vpn_events))}
</div></section>`);
plan('c_auth',Object.assign({},base,{xAxis:Object.assign({type:'category',data:ad.map(r=>dayLbl(r.day))},ax),yAxis:[Object.assign({type:'value',name:'success'},ax),Object.assign({type:'value',name:'failure',minInterval:1},ax,{splitLine:{show:false}})],series:[{name:'Success',type:'bar',data:ad.map(r=>r.success),itemStyle:{color:C.gr}},{name:'Failure',type:'line',yAxisIndex:1,data:ad.map(r=>r.failure),itemStyle:{color:C.rd},lineStyle:{color:C.rd,width:2}}]}));
// ---------- 5 DNS
const dg=(D.dns_groups||[{}])[0];
const p53=(D.ev_top_dport||[]).filter(r=>r.port===53).reduce((s,r)=>s+r.c,0);
const p853=(D.ev_top_dport||[]).filter(r=>r.port===853).reduce((s,r)=>s+r.c,0);
const dnsRule=(D.dns_types||[]).filter(r=>/DNS/i.test(r.eventType));
S.push(`<section id="dns"><h2><span class="num">05</span>DNS Activity</h2><p class="desc">FortiSIEM DNS event groups(CommonDNS/UncommonDNS/DenyDNS) count  <b>${fmt((dg.common_dns||0)+(dg.uncommon_dns||0)+(dg.denied_dns||0))}</b>(i.e. groups not populated from FortiGate traffic logs), so using  <span class="mono">destIpPort = 53</span>  and DNS-related rule events.</p>
<div class="kpis"><div class="kpi"><div class="l">DNS 53/udp+tcp Events</div><div class="v">${sh(p53)}</div><div class="s">${fmt(p53)}</div></div><div class="kpi" style="--c:${C.pu}"><div class="l">DoT 853/tcp Events</div><div class="v">${sh(p853)}</div><div class="s">${fmt(p853)}</div></div><div class="kpi" style="--c:${C.rd}"><div class="l">Denied port-53 traffic</div><div class="v">${sh(((D.traffic_deny_top_dport||[]).find(r=>r.port===53)||{}).c||0)}</div><div class="s">Deny group, port 53</div></div>${dnsRule.map(r=>`<div class="kpi" style="--c:${C.am}"><div class="l mono" style="font-size:11px">${esc(r.eventType)}</div><div class="v">${sh(r.c)}</div><div class="s">${fmt(r.c)}</div></div>`).join('')}</div>
<div class="grid g2" style="margin-top:14px">
${card('DNS-related event types (port 53 or name contains dns)',chartDiv('c_dns_types','tall'))}
${card('Top DNS client → DNS server',table([{h:'Client IP',k:'ip',code:1},{h:'DNS Server',k:'dns_server',code:1},{h:'Count',k:'c'}],D.dns_top_src))}
</div></section>`);
hbar('c_dns_types',(D.dns_types||[]).map(r=>r.eventType),(D.dns_types||[]).map(r=>r.c),C.cy);
// ---------- 6 CONFIG
const cfgUsr={};(D.cfg_by_dev_user||[]).forEach(r=>{cfgUsr[r.user]=(cfgUsr[r.user]||0)+r.c});
S.push(`<section id="cfg"><h2><span class="num">06</span>Configuration Changes</h2><p class="desc">eventType contains  <span class="mono">chg / config / change</span>；including <span class="mono">FortiGate-event-chg-config</span> · <span class="mono">FortiGate-event-config-objattr</span>  and FortiSIEM rules <span class="mono">PH_RULE_FGT_Config_Change</span>。</p>
<div class="grid g3">
${card('Change Event Types',chartDiv('c_cfg_types','tall'))}
${card('By device × user By Device × User',chartDiv('c_cfg_du','tall'))}
${card('By User',chartDiv('c_cfg_u','tall'))}
</div>
<div style="margin-top:14px">${card('Recent FortiGate Config Events (raw)',table([{h:'Time (HKT)',k:r=>(r.phRecvTime||'').replace('T',' ').slice(0,19),code:1},{h:'Device',k:'reptDevName'},{h:'user',k:'user'},{h:'eventType',k:'eventType',code:1},{h:'Raw (truncated)',k:'raw',code:1}],D.cfg_recent))}</div></section>`);
hbar('c_cfg_types',(D.cfg_types||[]).map(r=>r.eventType),(D.cfg_types||[]).map(r=>r.c),C.am);
hbar('c_cfg_du',(D.cfg_by_dev_user||[]).map(r=>`${r.reptDevName} · ${r.user}`),(D.cfg_by_dev_user||[]).map(r=>r.c),C.pu);
donut('c_cfg_u',Object.entries(cfgUsr).sort((a,b)=>b[1]-a[1]));
// ---------- 7 INCIDENTS
const cat=D.inc_by_category||[];const cats=[...new Set(cat.map(r=>r.category))];
const tac=D.inc_tactics_raw||[];const tacM={};tac.forEach(r=>(r.tactics||'').split(',').forEach(t=>{t=t.trim();if(t)tacM[t]=(tacM[t]||0)+r.c}));
const tec=D.inc_techniques_raw||[];const tecM={};tec.forEach(r=>(r.technique_ids||'').split(',').forEach(t=>{t=t.trim();if(t)tecM[t]=(tecM[t]||0)+r.c}));
S.push(`<section id="inc"><h2><span class="num">07</span>Incident Analytics</h2><p class="desc">Source: Postgres <span class="mono">ph_incident JOIN ph_drq_rule</span>, filter <span class="mono">last_seen_time &gt; now − ${X.days||7}d</span>。total <b>${fmt(incTotal)}</b>  total, Open <b>${fmt(incOpen)}</b>。</p>
<div class="grid g3">
${card('Incidents / Day (stacked by last_seen)',chartDiv('c_inc_daily'))}
${card('New Incidents / Day (by first_seen)',chartDiv('c_inc_new'))}
${card('Incidents / Hour',chartDiv('c_inc_hour'),'HKT')}
${card('Category × Severity',chartDiv('c_inc_cat'))}
${card('Status',chartDiv('c_inc_status'))}
${card('MITRE ATT&CK Tactics',chartDiv('c_tac'))}
</div>
<div class="grid g2" style="margin-top:14px">
${card('Top Rules (with severity split)',table([{h:'Rule',k:'rule'},{h:'Category',k:'category'},{h:'HIGH',k:'high'},{h:'MED',k:'medium'},{h:'LOW',k:'low'},{h:'Total',k:'c'},{h:'Open',k:'open'}],D.inc_top_rules))}
${card('Top Incident Titles',table([{h:'Title',k:'incident_title'},{h:'Sev',k:'severity_cat',f:v=>sevB(v)},{h:'Count',k:'c'}],D.inc_top_titles))}
${card('Top Affected IPs (host/src/dest)',chartDiv('c_inc_hosts','tall'))}
${card('FortiNDR Malware detections Top Malware (virusName)',chartDiv('c_ndr_virus','tall'))}
${card('Top Incident source IP',chartDiv('c_inc_src'))}
${card('Top incident destination IPs',chartDiv('c_inc_dst'))}
${card('MITRE Techniques',chartDiv('c_tec'))}
${card('Incident users Incident Users',chartDiv('c_inc_users'))}
</div>
<div style="margin-top:14px">${card('Latest HIGH Incidents (40)',table([{h:'ID',k:'incident_id'},{h:'Title',k:'incident_title'},{h:'Status',k:'status'},{h:'src',k:'src_ip_addr',code:1},{h:'dest',k:'dest_ip_addr',code:1},{h:'First (HKT)',k:'first_seen',code:1},{h:'Last (HKT)',k:'last_seen',code:1},{h:'Count',k:'incident_count'}],D.inc_latest_high))}</div>
<div style="margin-top:14px">${card('Top HIGH by incident_count',table([{h:'ID',k:'incident_id'},{h:'Title',k:'incident_title'},{h:'Rule',k:'rule'},{h:'Status',k:'status'},{h:'incident_count',k:'incident_count'}],D.inc_top_count_high))}</div></section>`);
if(has('inc_daily_sev'))plan('c_inc_daily',incDailyOpt(D.inc_daily_sev));
if(has('inc_new_daily_sev'))plan('c_inc_new',incDailyOpt(D.inc_new_daily_sev));
plan('c_inc_hour',Object.assign({},base,{xAxis:Object.assign({type:'category',data:(D.inc_hourly||[]).map(r=>r.hour.slice(5))},ax),yAxis:Object.assign({type:'value'},ax),dataZoom:[{type:'inside'}],series:[{type:'line',showSymbol:false,data:(D.inc_hourly||[]).map(r=>r.c),lineStyle:{color:C.am},areaStyle:{color:'#fbbf2422'},itemStyle:{color:C.am}}]}));
plan('c_inc_cat',Object.assign({},base,{tooltip:Object.assign({},base.tooltip,{axisPointer:{type:'shadow'}}),xAxis:Object.assign({type:'category',data:cats},ax),yAxis:Object.assign({type:'log',axisLabel:{color:'#8ea3c7',formatter:v=>sh(v)}},{splitLine:ax.splitLine}),series:['HIGH','MEDIUM','LOW'].map(s=>({name:s,type:'bar',itemStyle:{color:SEVC[s]},data:cats.map(c=>{const x=cat.find(r=>r.category===c&&r.severity_cat===s);return x?x.c:null})}))}));
donut('c_inc_status',(D.inc_by_status||[]).map(r=>[r.status,r.c]),[C.rd,C.gr,C.cy]);
hbar('c_tac',Object.keys(tacM).sort((a,b)=>tacM[b]-tacM[a]),Object.keys(tacM).sort((a,b)=>tacM[b]-tacM[a]).map(k=>tacM[k]),C.rd,{xAxis:{type:'log',axisLabel:{color:'#8ea3c7',formatter:v=>sh(v)},splitLine:ax.splitLine}});
hbar('c_tec',Object.keys(tecM).sort((a,b)=>tecM[b]-tecM[a]),Object.keys(tecM).sort((a,b)=>tecM[b]-tecM[a]).map(k=>tecM[k]),C.pu,{xAxis:{type:'log',axisLabel:{color:'#8ea3c7',formatter:v=>sh(v)},splitLine:ax.splitLine}});
hbar('c_inc_hosts',(D.inc_top_hosts||[]).filter(r=>r.ip).map(r=>r.ip),(D.inc_top_hosts||[]).filter(r=>r.ip).map(r=>r.c),C.rd,{xAxis:{type:'log',axisLabel:{color:'#8ea3c7',formatter:v=>sh(v)},splitLine:ax.splitLine}});
(function(){const v=(D.ndr_virus_top||[]).slice(0,15);hbar('c_ndr_virus',v.map(r=>`${r.virus} [${r.severity_cat[0]}]`),v.map(r=>r.c),C.pk)})();
hbar('c_inc_src',(D.inc_top_src_ip||[]).map(r=>r.ip),(D.inc_top_src_ip||[]).map(r=>r.c),C.am,{xAxis:{type:'log',axisLabel:{color:'#8ea3c7',formatter:v=>sh(v)},splitLine:ax.splitLine}});
hbar('c_inc_dst',(D.inc_top_dest_ip||[]).map(r=>r.ip),(D.inc_top_dest_ip||[]).map(r=>r.c),C.bl,{xAxis:{type:'log',axisLabel:{color:'#8ea3c7',formatter:v=>sh(v)},splitLine:ax.splitLine}});
hbar('c_inc_users',(D.inc_top_users||[]).map(r=>r.usr),(D.inc_top_users||[]).map(r=>r.c),C.cy);
// ---------- 8 RISK
function riskRows(o){return Object.entries(o||{}).map(([k,v])=>({entity:k,score:parseFloat(v.score),rules:Object.keys(v.incidents||{}),sev:[...new Set(Object.values(v.incidents||{}).map(x=>x.severity))].join(','),n:Object.values(v.incidents||{}).reduce((s,x)=>s+(x.incidentIds||[]).length,0),ids:Object.values(v.incidents||{}).flatMap(x=>x.incidentIds||[])})).sort((a,b)=>b.score-a.score)}
const rd=riskRows(D.risky_devices), ru=riskRows(D.risky_users);
const riskCols=[{h:'Entity',k:'entity',code:1},{h:'Risk Score',k:'score'},{h:'# Incidents',k:'n'},{h:'Rules / Incident summary',k:r=>r.rules.join(' | ')||'(no incident attached)'},{h:'Sev (tool)',k:'sev',f:v=>v.split(',').filter(Boolean).map(sevB).join(' ')},{h:'Sample IDs',k:r=>r.ids.slice(0,6).join(', ')+(r.ids.length>6?' …':''),code:1}];
S.push(`<section id="risk"><h2><span class="num">08</span>Risk — Top 10 Devices &amp; Users</h2><p class="desc">Source: MCP tools <span class="mono">get_top_10_risky_devices_incidents</span> / <span class="mono">get_top_10_risky_users_incidents</span>(FortiSIEM built-in risk score). Note: the risky-users tool returned  ${ru.length}  entities, mostly IPs/hostnames (VPN user field )。</p>
<div class="grid g2">
${card('Top 10 Device risk score',chartDiv('c_rdev'))}
${card(`Top User risk score (${ru.length})`,chartDiv('c_rusr'))}
</div>
<div class="grid g2" style="margin-top:14px">
${card('Risky Devices',table(riskCols,rd,{filter:false}))}
${card('Risky Users',table(riskCols,ru,{filter:false}))}
</div></section>`);
const rcol=v=>v>=60?C.rd:v>=30?C.am:C.gr;
plan('c_rdev',Object.assign({},base,{grid:{left:10,right:40,top:10,bottom:10,containLabel:true},tooltip:{trigger:'axis',axisPointer:{type:'shadow'}},xAxis:{type:'value',max:100,axisLabel:{color:'#8ea3c7'},splitLine:ax.splitLine},yAxis:{type:'category',data:rd.map(r=>r.entity).reverse(),axisLabel:{color:'#c7d5ee',fontFamily:'monospace'}},series:[{type:'bar',data:rd.map(r=>({value:r.score,itemStyle:{color:rcol(r.score)}})).reverse(),label:{show:true,position:'right',color:'#c7d5ee'}}]}));
plan('c_rusr',Object.assign({},base,{grid:{left:10,right:40,top:10,bottom:10,containLabel:true},tooltip:{trigger:'axis',axisPointer:{type:'shadow'}},xAxis:{type:'value',max:100,axisLabel:{color:'#8ea3c7'},splitLine:ax.splitLine},yAxis:{type:'category',data:ru.map(r=>r.entity).reverse(),axisLabel:{color:'#c7d5ee',fontFamily:'monospace'}},series:[{type:'bar',data:ru.map(r=>({value:r.score,itemStyle:{color:rcol(r.score)}})).reverse(),label:{show:true,position:'right',color:'#c7d5ee'}}]}));
// ---------- 9 DEEP DIVE
const DD=(X.picks||[]);
const iocs=Array.isArray(D.iocs)?D.iocs:[];const rep=Array.isArray(D.rep_ips)?D.rep_ips:[];
function ddHtml(x){const d=D['inc_'+x.id+'_detail'];if(!d)return `<div class="dd">${NA('incident '+x.id)}</div>`;
 const rel=(D.related_summary||{})[x.id]||{};const trigErr=(D.trigger_tool_errors||{})[x.id];const tr=D['trig_raw_'+x.id]||[];const trc=D['trig_ch_'+x.id]||[];
 const ioc=iocs.find(i=>i.incident_title===d.incidentTitle);const ips=[];if(ioc){[ioc.src_ip_addr,ioc.dest_ip_addr].forEach(ip=>ip&&ips.push(ip))}
 const reps=rep.filter(r=>ips.includes(r.ip));
 return `<div class="dd"><h3><span class="mono" style="color:var(--cy)">#${x.id}</span> ${esc(d.incidentTitle)} ${sevB(d.eventSeverityCat)}</h3><p class="desc" style="color:var(--mut);margin:0 0 8px">Why selected: ${esc(x.why)}</p>
 <div class="grid g2"><div><div class="kv">
 <div>Rule / eventType</div><div>${esc(d.eventName)} / ${esc(d.eventType)}</div>
 <div>Severity</div><div>${esc(d.eventSeverityCat)} (${esc(d.eventSeverity)})</div>
 <div>Status / Resolution</div><div>${d.incidentStatus===0?'Open (0)':esc(d.incidentStatus)} / ${d.incidentReso===1?'Open (1)':esc(d.incidentReso)}</div>
 <div>First / Last seen</div><div>${esc(d.incidentFirstSeen_hkt)} → ${esc(d.incidentLastSeen_hkt)} HKT</div>
 <div>Count</div><div>${esc(d.count)}</div>
 <div>Source</div><div>${esc(d.incidentSrc)}</div>
 <div>Target</div><div>${esc(d.incidentTarget)}</div>
 <div>Reporting device</div><div>${esc(d.incidentRptDevName)} (${esc(d.incidentRptIp)})</div>
 <div>Tactic / Technique</div><div>${esc(d.attackTactic)} / ${esc(d.attackTechnique)}</div>
 <div>Tag</div><div>${esc(d.incidentTagName)}</div>
 <div>Detail</div><div>${esc(d.incidentDetail)}</div>
 </div></div><div>
 <div class="kv"><div>Related incidents</div><div>${rel.count!=null?fmt(rel.count)+' (get_related_incidents_by_id)':'—'}</div></div>
 ${(rel.by_rule||[]).length?`<div style="margin:6px 0">${rel.by_rule.map(b=>`<span class="pill">${esc(b[0])}: ${fmt(b[1])}</span>`).join('')}</div>`:''}
 <div class="kv" style="margin-top:6px"><div>IOC (get_iocs_by_incident_ids)</div><div>${ioc?Object.entries(ioc).filter(([k,v])=>v&&k!=='incident_title').map(([k,v])=>`${esc(k)}=${esc(v)}`).join('<br>'):'—'}</div></div>
 ${reps.length?`<div style="margin-top:6px">${table([{h:'IOC IP',k:'ip',code:1},{h:'Geo',k:r=>[r.city,r.country].filter(Boolean).join(', ')},{h:'Watchlists',k:r=>r.watchlists.join('; ')||'—'},{h:'TI providers',k:'ti_status'}],reps,{filter:false})}</div>`:`<div class="kv" style="margin-top:6px"><div>Reputation</div><div>Internal IP — external reputation not queried</div></div>`}
 </div></div>
 <div style="margin-top:8px"><b style="font-size:12.5px">Trigger events</b> ${trigErr?`<span class="mono" style="color:var(--am);font-size:11px">get_trigger_events_by_incident_id failed: ${esc(String(trigErr&&trigErr.message||trigErr||'').slice(0,140))}… → falling back to Postgres ph_incident_detail + ClickHouse eventId</span>`:''}
 ${tr.length?tr.slice(0,3).map(e=>`<pre class="raw">[${esc((e.phRecvTime||'').replace('T',' ').slice(0,19))} HKT] ${esc(e.eventType)} ${esc(e.src)} → ${esc(e.dst)}:${esc(e.destIpPort)} (${esc(e.reptDevName)})\n${esc(e.raw)}</pre>`).join(''):NA('trigger raw events')}
 <div class="mono" style="font-size:11px;color:var(--mut)">FortiSIEM Trigger records (ClickHouse phEventCategory=1): ${trc.length}  recent records · latest ${esc((trc[0]||{}).phRecvTime||'')}</div></div>
 ${x.ctx&&D[x.ctx]?`<div style="margin-top:8px">${ctxHtml(D[x.ctx])}</div>`:''}
 ${x.extra==='exposure'?cleartextHtml():''}
 </div>`}
function ctxHtml(c){const x=(c.contexts||[])[0]||{};return `<div class="kv"><div>Context (get_context_by_entity)</div><div>${esc(x.parameter)}=${esc(x.value)} · risk ${esc(x.risk?(+x.risk.score).toFixed(2):'—')} · ${x.hostName?esc(x.hostName)+' · ':''}incidents ${(x.incidents||[]).length}</div><div>Watchlists</div><div>${(x.watchlists||[]).map(w=>esc(w.name+' ← '+w.ruleName)).join('<br>')||'—'}</div>${(x.topEventTypes||[]).length?`<div>Top event types</div><div>${x.topEventTypes.slice(0,6).map(e=>esc(e.eventType)+' ('+fmt(e.count)+')').join('<br>')}</div>`:''}</div>`}
function cleartextHtml(){const e=X.exposure;if(!e)return '';const c=(D.cleartext_ch||[{}])[0]||{};const s=D.cleartext_srcs||[];return `<div style="margin-top:8px"><b style="font-size:12.5px">External exposure Exposure ${esc(e.ip)}:${esc(e.port)}${e.svc?' ('+esc(e.svc)+')':''}</b><div class="kv"><div>${SPAN} events</div><div>${fmt(c.c)} events · ${fmt(c.srcs)} distinct source IPs (ClickHouse)</div><div>Related incident source IPs</div><div>${fmt(s.length)}${s.length>=50?'+ (limit 50)':''} distinct src in ph_incident (dest=${esc(e.ip)})</div>${e.policy?`<div>Policy / service</div><div>trigger raw: ${esc(e.policy)}</div>`:''}</div></div>`}
S.push(`<section id="deep"><h2><span class="num">09</span>Incident Deep Dive</h2><p class="desc">Using <span class="mono">get_incident_by_id</span> · <span class="mono">get_related_incidents_by_id</span> · <span class="mono">get_iocs_by_incident_ids</span> · <span class="mono">get_reputation_by_entity</span> · <span class="mono">get_context_by_entity</span>；Trigger-events tool failed server-side; replaced with read-only SQL.</p>${DD.map(ddHtml).join('')}
${card('IOC Reputation (get_reputation_by_entity)',table([{h:'IP',k:'ip',code:1},{h:'Geo',k:r=>[r.city,r.country].filter(Boolean).join(', ')},{h:'Watchlists',k:r=>r.watchlists.join('; ')||'—'},{h:'Incidents',k:r=>r.incidents.join(', '),code:1},{h:'TI providers',k:'ti_status'}],rep,{filter:false}))}</section>`);
// ---------- 10 CMDB
const devs=D.cmdb_devices||[];const st=Object.fromEntries((D.cmdb_status||[]).map(r=>[r.name,r]));
const cmdbNames=new Set(devs.map(d=>d.name));
const reptNotInCmdb=rept.filter(r=>!cmdbNames.has(r.reptDevName));
const evStat={};(D.cmdb_status||[]).forEach(r=>evStat[r.event_status]=(evStat[r.event_status]||0)+1);
S.push(`<section id="cmdb"><h2><span class="num">10</span>Assets &amp; FortiSIEM Health</h2><p class="desc">Source: Postgres <span class="mono">ph_device / ph_device_type / ph_device_status / ph_sys_domain / ph_health_status / ph_sys_conf_view</span>。</p>
<div class="kpis"><div class="kpi" style="--c:${C.gr}"><div class="l">CMDB devices</div><div class="v">${fmt(cmdbN)}</div><div class="s">all discover_method=${esc(((D.cmdb_discover||[])[0]||{}).discover_method)}</div></div><div class="kpi"><div class="l">FortiOS devices</div><div class="v">${fmt((D.cmdb_fortios||[]).length)}</div><div class="s">model ILIKE FortiOS</div></div><div class="kpi" style="--c:${C.rd}"><div class="l">Event status Critical</div><div class="v">${fmt(evStat.Critical||0)}</div><div class="s">ph_device_status.event_status</div></div><div class="kpi" style="--c:${C.am}"><div class="l">In report but not in CMDB</div><div class="v">${fmt(reptNotInCmdb.length)}</div><div class="s">reptDevName not in ph_device</div></div><div class="kpi" style="--c:${C.pu}"><div class="l">Organizations</div><div class="v">${fmt((D.cmdb_all_orgs||[]).length)}</div><div class="s">${(D.cmdb_all_orgs||[]).map(o=>esc(o.name)).join(', ')}</div></div><div class="kpi" style="--c:${C.cy}"><div class="l">Event storage</div><div class="v" style="font-size:18px">${esc(((D.storage_type||[])[0]||{}).value||'—')}</div><div class="s">ph_sys_conf_view</div></div></div>
<div class="grid g3" style="margin-top:14px">
${card('Vendor / Model',chartDiv('c_cm_vm','short'))}
${card('Event Collection Status',chartDiv('c_cm_st','short'),'ph_device_status')}
${card('Discovery Method',chartDiv('c_cm_dm','short'))}
</div>
<div class="grid g2" style="margin-top:14px">
${card('Device Inventory',table([{h:'Name',k:'name'},{h:'access_ip',k:'access_ip',code:1},{h:'Vendor',k:'vendor'},{h:'Model',k:'model'},{h:'Serial',k:'hw_serial_no',code:1},{h:'Method',k:'discover_method'},{h:'Weight',k:'asset_weight'},{h:'Discovered (HKT)',k:'discovered',code:1},{h:'Event status',k:r=>(st[r.name]||{}).event_status,f:v=>sevB(v)}],devs,{filter:false}))}
${card('FortiOS FortiOS Devices',table([{h:'Name',k:'name'},{h:'access_ip',k:'access_ip',code:1},{h:'Serial',k:'hw_serial_no',code:1},{h:'Version',k:'version'},{h:'Method',k:'discover_method'},{h:SPAN+' events (as reptDevName)',k:r=>{const x=rept.find(y=>y.reptDevName===r.name);return x?x.c:0}},{h:'Event status',k:r=>(st[r.name]||{}).event_status,f:v=>sevB(v)}],D.cmdb_fortios,{filter:false})+(X.alias_notes||[]).map(a=>`<p style="font-size:12px;color:var(--mut);margin:8px 0 0">Note: serial  <span class="mono">${esc(a.serial)}</span>  is named in CMDB as  <span class="mono">${esc(a.name)}</span>；logs also arrive as  ${esc(a.name)}(${fmt((rept.find(r=>r.reptDevName===a.name)||{}).c)} and ${esc(a.serial)}(${fmt((rept.find(r=>r.reptDevName===a.serial)||{}).c)}).</p>`).join(''))}
${card('Reporting Devices vs CMDB ('+SPAN+')',table([{h:'reptDevName',k:'reptDevName'},{h:'IP',k:'ip',code:1},{h:'Vendor/Model',k:r=>r.vendor+' / '+r.model},{h:'Events',k:'c'},{h:'Last (HKT)',k:r=>(r.last||'').replace('T',' ').slice(0,16),code:1},{h:'In CMDB',k:r=>cmdbNames.has(r.reptDevName)?'✔':'✘',f:v=>v==='✔'?'<span class="ok">✔</span>':'<span class="bad">✘</span>'}],rept,{filter:false}))}
${card('FortiSIEM Node Health',health?`<div class="kv"><div>Node</div><div>${esc(health.host_name)} (${esc(health.host_ip)}) · ${esc(health.role)}</div><div>Version / Content</div><div>${esc(health.version)} / ${esc(health.content_version)}</div><div>HW</div><div>${esc(health.hardware_vcpu)} vCPU · ${esc(health.hardware_memory_gb)} GB</div><div>Summary</div><div>${sevB(health.summary)}</div><div>EPS (3min)</div><div>${esc(health.eps_3min)}</div><div>Load avg</div><div>${esc(health.loadaverage)}</div><div>CPU / Mem / Swap %</div><div>${esc(health.cpuusage_used_pct)} / ${esc(health.memoryusage_used_pct)} / ${esc(health.swapusage_used_pct)}</div><div>Updated</div><div>${esc(health.updated)} HKT</div></div><div style="margin-top:8px">${chartDiv('c_health','short')}</div>${table([{h:'Attribute',k:'attribute'},{h:'Value',k:'value',f:v=>sevB(v)},{h:'Reason',k:'reason'}],Array.isArray(health.reason)?health.reason:[],{filter:false,max:260})}`:NA())}
${card('FortiSIEM Users (RBAC)',table([{h:'User',k:'usr'},{h:'Org',k:'org'},{h:'Profile',k:'profile'}],D.fsm_users,{filter:false}))}
</div></section>`);
donut('c_cm_vm',(D.cmdb_vendor_model||[]).map(r=>[r.vendor+' '+r.model,r.c]));
donut('c_cm_st',Object.entries(evStat),Object.keys(evStat).map(k=>k==='Critical'?C.rd:k==='Warning'?C.am:C.gr));
donut('c_cm_dm',(D.cmdb_discover||[]).map(r=>[r.discover_method,r.c]));
if(health)plan('c_health',Object.assign({},base,{tooltip:{},series:[['CPU',health.cpuusage_used_pct,'25%'],['Memory',health.memoryusage_used_pct,'50%'],['Swap',health.swapusage_used_pct,'75%']].map(g=>({type:'gauge',center:[g[2],'60%'],radius:'80%',min:0,max:100,progress:{show:true,width:8},axisLine:{lineStyle:{width:8,color:[[1,'#1d3357']]}},itemStyle:{color:g[1]>85?C.rd:g[1]>70?C.am:C.cy},pointer:{show:false},axisTick:{show:false},splitLine:{show:false},axisLabel:{show:false},title:{color:'#9fb6da',offsetCenter:[0,'45%'],fontSize:11},detail:{valueAnimation:false,formatter:'{value}%',color:'#e2ecff',fontSize:15,offsetCenter:[0,'5%']},data:[{value:g[1],name:g[0]}]}))}));
// ---------- 11 FINDINGS
const ndrPair=(D.ndr_pairs||[]);
const ndrRules=(D.inc_top_rules||[]).filter(r=>(X.fam_re?new RegExp(X.fam_re):/FortiNDR/).test(r.rule));const ndrInc=sum(ndrRules,r=>r.c);
const cl=(D.cleartext_ch||[{}])[0]||{};
const unauthDns=((D.dns_types||[]).find(r=>r.eventType==='PH_RULE_UNAUTH_DNS_QUERY')||{}).c;
const unp=(D.unparsed||[])[0];
const evDrop=evDay.length>2?evDay[evDay.length-2]:null;const evPeak=evDay.reduce((a,b)=>b.c>(a?a.c:0)?b:a,null);
const F=(X.findings||[]).map(f=>[{high:C.rd,medium:C.am,info:C.cy}[f.lvl]||C.cy,{high:'HIGH',medium:'MEDIUM',info:'INFO'}[f.lvl]||'INFO',f.title,f.body,f.todo]);
S.push(`<section id="findings"><h2><span class="num">11</span>Findings &amp; Recommendations</h2><p class="desc">Based only on data collected for this report; no speculative figures.</p>${F.map(f=>`<div class="finding" style="--c:${f[0]}"><div><span class="tag">[${f[1]}]</span><b>${f[2]}</b></div><div style="margin-top:4px">${f[3]}</div><div style="margin-top:6px;color:#9fe3c9">➜ Action: ${f[4]}</div></div>`).join('')}</section>`);
// ---------- 12 APPENDIX
const src=RAW.sources||[];const fails=src.filter(s=>!s.ok);
S.push(`<section id="appendix"><h2><span class="num">12</span>Appendix — Data Sources &amp; Limitations</h2>
<div class="grid g2">${card('Collection',`<div class="kv"><div>Collected</div><div>${esc(M.generated_hkt)}</div><div>Window</div><div>${esc(M.window)}</div><div>Supervisor</div><div>${esc(M.supervisor)}</div><div>Transport</div><div>MCP over HTTPS (JSON-RPC, SSE) · OAuth2 client_credentials(credentials are not written into this report)</div><div>Calls</div><div>${src.length}(${src.length-fails.length} Success / ${fails.length} failed)</div><div>Mode</div><div>Read-only: no update_* / clear_* / append_* tools</div></div>`)}
${card('Limitations',`<ul style="margin:0;padding-left:18px;font-size:12.5px">${(X.limits||[]).map(l=>'<li>'+l+'</li>').join('')}</ul>`)}</div>
<div style="margin-top:14px">${card('Failed or Blocked Calls',table([{h:'Key',k:'key',code:1},{h:'Tool',k:'tool',code:1},{h:'Error',k:'error',code:1}],fails,{filter:false}))}</div>
<div style="margin-top:14px">${card('All Data Sources (tool / SQL per dataset)',table([{h:'Dataset key',k:'key',code:1},{h:'Tool',k:'tool',code:1},{h:'OK',k:r=>r.ok?'✔':'✘',f:v=>v==='✔'?'<span class="ok">✔</span>':'<span class="bad">✘</span>'},{h:'secs',k:'secs'},{h:'SQL / arguments',k:'query',code:1}],src,{max:600}))}</div></section>`);
document.getElementById('main').innerHTML=S.join('');{const hs=document.getElementById('heroSpan');if(hs)hs.textContent='// Last '+SPAN;}if(X.title)document.title=X.title;
document.getElementById('foot').textContent=`FortiSIEM ${X.days||7}-Day SOC Report · ${M.theme||''} · generated ${M.generated_hkt} · data: FortiSIEM MCP (read-only) · charts: Apache ECharts (inlined)`;
// tables
TABLES.forEach(t=>{renderRows(t);const el=document.getElementById(t.id);el.querySelectorAll('th').forEach(th=>th.addEventListener('click',()=>{const i=+th.dataset.i;const c=t.cols[i];const dir=th.classList.contains('sorted-desc')?1:-1;el.querySelectorAll('th').forEach(x=>x.classList.remove('sorted-asc','sorted-desc'));th.classList.add(dir===1?'sorted-asc':'sorted-desc');const g=r=>typeof c.k==='function'?c.k(r):r[c.k];t.rows.sort((a,b)=>{const x=g(a),y=g(b);if(typeof x==='number'&&typeof y==='number')return (x-y)*dir;return String(x??'').localeCompare(String(y??''))*dir});renderRows(t);applyFilter(t.id)}))});
function applyFilter(id){const inp=document.querySelector(`input[data-t="${id}"]`);if(!inp)return;const q=inp.value.toLowerCase();document.querySelectorAll('#'+id+' tbody tr').forEach(tr=>tr.style.display=tr.textContent.toLowerCase().includes(q)?'':'none')}
document.querySelectorAll('input.filter').forEach(i=>i.addEventListener('input',()=>applyFilter(i.dataset.t)));
// charts
const inst=[];charts.forEach(([id,opt])=>{const el=document.getElementById(id);if(!el)return;try{const c=echarts.init(el,null,{renderer:'canvas'});c.setOption(opt);inst.push(c)}catch(e){el.innerHTML=NA('chart error: '+e.message)}});
document.querySelectorAll('.chart').forEach(el=>{if(!el.innerHTML.trim())el.outerHTML=NA()});
window.addEventListener('resize',()=>inst.forEach(c=>c.resize()));
window.__CHARTS=inst.length;
// nav active
const secs=[...document.querySelectorAll('section')];const links=[...document.querySelectorAll('nav a')];
window.addEventListener('scroll',()=>{let cur=secs[0].id;secs.forEach(s=>{if(s.getBoundingClientRect().top<90)cur=s.id});links.forEach(a=>a.classList.toggle('active',a.getAttribute('href')==='#'+cur))});
