/* Control-panel tools that used to live in the classic interface:
   ⚙ Settings: linking, activation, iPhone, and monitored apps.
   Activity: continuous phone activity and the operations box with its decisions.
   Permissions: phone permissions center (location, motion, and tracking).
   Smart review is added to the Review window. All are small windows under the bar, like the rest of the panel. */

const TRAY_KEY = "privacy-protector-operation-tray-v3";   // The same key, so the saved operations box is not lost
const RISK_WORD = {red:"Red",orange:"Orange",green:"Green",unclassified:"Not studied","":"Not studied"};
const ACTION_WORD = {allow:"Allow",monitor:"Monitor",block:"Block"};
const tools = {logs:null, attributions:[], stats:{}, policyFull:null, privacy:null, ai:null, risks:[], dev:null, actShown:200,
  act:{app:"",filter:"all",sort:"time"}, perm:{id:"",desired:null}, aiPoll:0, devBusy:false};

function loadTray(){try{const v=JSON.parse(localStorage.getItem(TRAY_KEY)||"[]");return new Set(Array.isArray(v)?v:[])}catch(e){return new Set()}}
let tray = loadTray();
function saveTray(){try{localStorage.setItem(TRAY_KEY,JSON.stringify([...tray].sort()))}catch(e){}}
const cleanDomain = v => String(v||"").trim().toLowerCase().replace(/\.$/,"");
function download(name,text,type){const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([text],{type}));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
function armed(b,label){if(b.classList.contains("arm"))return true;const t=b.textContent;b.classList.add("arm");b.textContent=label;
  setTimeout(()=>{b.classList.remove("arm");b.textContent=t},4000);return false}
async function send(method,url,body){const r=await fetch(url,{method,headers:await authHeaders(),body:body===undefined?undefined:JSON.stringify(body)});
  const j=await r.json().catch(()=>({}));if(!r.ok||j.error)throw new Error(j.error||("HTTP "+r.status));return j}
const opts=(list,cur)=>list.map(([v,l])=>`<option value="${esc(v)}"${v===cur?" selected":""}>${esc(l)}</option>`).join("");
const riskOf=d=>{const r=(classes[d]||{}).risk;return r==="unclassified"?"":(r||"")};

/* ------------------------------------------------------------ ⚙ Settings */
const REMIND={connected:"connected",lost:"disconnected recently: reconnect it to the modem",disconnected:"not connected",waiting:"waiting for the phone"};
function drawSettings(){
  const s=st.status||{}, rem=s.connectionReminder||{}, pc=st.pc||{}, hist=((tools.caps||{}).status?.sources||[]).find(x=>x.id==="windows-history")||{};
  const test=s.dnsEngine?.lastSelfTest;
  const detected=phoneApps, monitored=new Set(profiles.map(p=>String(p.bundleID||"").toLowerCase()));
  const q=String($("#det-q")?.value||"").toLowerCase(), focus=document.activeElement?.id==="det-q";
  const shown=detected.filter(a=>`${a.name} ${a.bundleID}`.toLowerCase().includes(q));
  const dev=tools.dev;
  show(`<h2>Settings</h2>${choicesHtml()}
    <div class="sec"><h3>Connections</h3>
    <div class="rows">
      <span>Local service</span><span>${s.ok?"running":"<b class=\"st-red\">stopped</b>"}</span>
      <span>Phone</span>${!choice("phone")?"<span>off</span>":""}<span class="${!choice("phone")?"hide":rem.state==="connected"?"":"st-orange"}">${esc(REMIND[rem.state]||rem.state||"—")} · DNS ${esc(rem.dnsAddress||"—")}${rem.state==="connected"?"":` · ${Math.max(1,Math.round((rem.silentForSeconds||rem.disconnectedForSeconds||0)/60))}m`}</span>
      <span>PC</span>${!choice("pc")?"<span>off</span>":""}<span class="${!choice("pc")?"hide":pc.routing?.routed?"":"st-red"}">${pc.routing?.routed?"protected: traffic goes through the engine":"not protected: traffic bypasses the engine"}</span>
      <span>Windows history</span><span class="${hist.state==="live"?"":"st-orange"}">${esc(hist.state||"—")}${hist.lastCopyAt?" · copied "+ago(hist.lastCopyAt):""}</span>
      <span>DNS self-test</span><span>${test?`${esc(test.state)} · ${ago(test.finishedAt||test.at||test.time)}`:"not run"}</span>
    </div>
    <div class="btns"><button data-t="dns-test">Test DNS</button>
      ${hist.state&&hist.state!=="live"&&choice("capabilities")?`<button data-t="hist-setup">Enable Windows history</button>`:""}</div>
    <div class="mut gap6">If the engine stops, the PC's internet comes back by itself within a minute.</div></div>
    ${choicesExtraHtml()}
    <div class="sec"><h3>iPhone</h3>
      <div class="btns"><label class="filebtn">Import Apple privacy report<input type="file" id="report-file" accept=".ndjson,application/x-ndjson"></label>
        <button data-t="scan-iphone">Read apps from the iPhone</button><button data-t="dev-check">${tools.devBusy?"Checking…":"Check developer mode"}</button></div>
      ${dev?`<div class="dom ${dev.kind}"><div class="t">${esc(dev.title)}</div><div class="l">${esc(dev.detail)}</div></div>`:""}
      <div class="mut gap6">Developer mode is truly hidden only when it's off on the iPhone: Settings → Privacy &amp; Security → Developer Mode → Off. The app never injects code or bypasses app checks.</div>
    </div>
    <div class="sec"><h3>Detected apps · ${detected.length} · ${profiles.length} monitored</h3>
      <div class="tool-bar"><input id="det-q" placeholder="Search by name or bundle ID" value="${esc(q)}"></div>
      <div class="lg"><table><colgroup><col><col class="w40p"><col class="w56px"><col class="w84px"></colgroup><tbody>
        ${shown.slice(0,150).map(a=>{const on=monitored.has(String(a.bundleID||"").toLowerCase());
          return `<tr title="${esc(a.bundleID)}"><td>${esc(a.purposeDisplayName||a.name||a.bundleID)}</td><td>${esc(a.bundleID)}</td><td class="m">${(a.domains||[]).length}</td>
            <td class="m">${on?`<span class="mut">monitored</span>`:`<button data-t="monitor-app" data-bundle="${esc(a.bundleID)}">Monitor</button>`}</td></tr>`}).join("")}
      </tbody></table>${shown.length>150?`<div class="mut gap6">${shown.length-150} more: narrow the search</div>`:""}${detected.length?"":`<div class="empty">Import an Apple report or read the iPhone first</div>`}</div>
      <h3>Add an app by hand</h3>
      <div class="tool-bar"><input id="add-name" placeholder="Name"><input id="add-bundle" placeholder="com.example.app"><input id="add-proc" placeholder="Process name (optional)"><button data-t="add-app">Add</button></div>
    </div>`);
  if(focus){const i=$("#det-q");i.focus();i.setSelectionRange(i.value.length,i.value.length)}
}
async function devCheck(){
  tools.devBusy=true; drawSettings();
  try{const r=await getJson("/api/developer-mode/status",null); if(!r||!r.ok)throw new Error(r?.error||"Couldn't read developer mode");
    tools.dev=r.enabled?{kind:"red",title:"Developer mode is visible to apps",detail:"Turn it off on the iPhone, then check again."}
      :{kind:"green",title:"Developer mode is hidden from apps",detail:`It's off on the iPhone${r.productVersion?" · iOS "+r.productVersion:""}. Nothing else to do.`}}
  catch(err){tools.dev={kind:"orange",title:"Couldn't reach the iPhone",detail:err.message+". Make sure it's unlocked, paired, and on the local network."}}
  tools.devBusy=false; if(view==="open-settings")drawSettings();
}
/* Import Apple report: sends the apps and domains it contains to the engine in batches, and links them to the monitored apps */
const IMPORT_LIMIT=96*1024, CHUNK=100;
function sizedBatches(items,key){const out=[];let cur=[];const pack=c=>({apps:key==="apps"?c:[],attributions:key==="attributions"?c:[]});
  for(const it of items){const cand=[...cur,it];if(cur.length&&new TextEncoder().encode(JSON.stringify(pack(cand))).length>IMPORT_LIMIT){out.push(pack(cur));cur=[it]}else cur=cand}
  if(cur.length)out.push(pack(cur));return out}
async function importReport(file){
  const rows=[];let bad=0;
  for(const line of (await file.text()).split(/\r?\n/)){if(!line.trim())continue;try{rows.push(JSON.parse(line))}catch(e){bad++}}
  const net=rows.filter(r=>r.type==="networkActivity"), found=new Map(), attr=new Map();
  let latest="";
  for(const r of net){const b=String(r.bundleID||"").trim(), d=cleanDomain(r.domain);if(!b||!d)continue;
    const name=String(r.appName||r.displayName||r.applicationName||"").trim()||b, k=b.toLowerCase();
    if(!found.has(k))found.set(k,{bundleID:b,name,domains:new Set()});found.get(k).domains.add(d);
    if(String(r.timeStamp||"")>latest)latest=r.timeStamp;
    const ak=k+"|"+d, cur=attr.get(ak);
    if(!cur||(Date.parse(r.timeStamp)||0)>(Date.parse(cur.observedAt)||0))attr.set(ak,{domain:d,bundleID:b,appName:name,processName:"",observedAt:r.timeStamp||new Date().toISOString()})}
  const parts=[];
  for(const a of found.values()){const ds=[...a.domains].sort(),base={bundleID:a.bundleID,name:a.name,lastSeen:latest||new Date().toISOString()};
    if(!ds.length)parts.push({...base,domains:[]});for(let i=0;i<ds.length;i+=CHUNK)parts.push({...base,domains:ds.slice(i,i+CHUNK)})}
  for(const batch of [...sizedBatches(parts,"apps"),...sizedBatches([...attr.values()],"attributions")])await send("POST","/api/apps/discovered",batch);
  let linked=0;
  for(const p of profiles){const f=found.get(String(p.bundleID||"").toLowerCase());if(!f)continue;
    try{await send("POST",`/api/apps/${encodeURIComponent(p.id)}/domains`,{source:"confirmed",domains:[...f.domains]});linked++}catch(e){}}
  note(`${rows.length} records · ${found.size} apps found${linked?` · linked to ${linked} monitored`:""}${bad?` · ${bad} bad lines skipped`:""}`,6000);
  await reloadSlow();
}
async function monitorApp(bundle){
  const a=phoneApps.find(x=>x.bundleID===bundle); if(!a)return;
  const r=await send("POST","/api/apps",{name:a.purposeDisplayName||a.name||a.bundleID,bundleID:a.bundleID,processName:a.processName||""});
  if((a.domains||[]).length)await send("POST",`/api/apps/${encodeURIComponent(r.profile.id)}/domains`,{source:"confirmed",domains:a.domains});
  note(`${r.profile.name} is monitored`); await reloadSlow();
}


/* ------------------------------------------------------------ Your choices: what is watched and protected */
const SWITCH_ROWS=[["phone","Phone protection","DNS protection for a phone that uses this computer as its DNS server"],
  ["pc","PC protection","DNS protection for this computer itself"],
  ["capabilities","Device access","Which programs use the microphone, camera, location and contacts"],
  ["outlook","Outlook mail","Checks new mail in classic Outlook and removes dangerous messages"],
  ["defender","Windows Defender","Shows Defender's state and asks it to scan new downloads; never changes its settings"],
  ["tempCleanup","Temp cleanup","Deletes old temporary files daily at 9 pm, after you approve the first run"],
  ["models","AI review","A second reading of unclear domains by AI providers you add below, with your own keys"]];
const KIND_ROWS=[["microphone","Microphone"],["webcam","Camera"],["location","Location"],["contacts","Contacts"]];
function choice(key){const c=tools.settings?.settings;if(!c)return false;return key==="capabilities"?!!c.capabilities?.enabled:!!c[key]}
function switchBtn(key,on,label){return `<button class="sw${on?" on":""}" data-t="set" data-k="${esc(key)}" aria-pressed="${on}">${esc(label)}: ${on?"On":"Off"}</button>`}
function choicesHtml(){
  const v=tools.settings; if(!v)return `<div class="empty">…</div>`;
  const c=v.settings||{}, caps=c.capabilities||{};
  return `<div class="lg-key">Everything is off until you turn it on. Each switch works at once; turning one off removes what it changed in Windows.</div>
    ${v.lastError?`<div class="dom orange"><div class="t">${esc(v.lastError)}</div><div class="l">Windows asks for approval once; try the switch again and approve it.</div></div>`:""}
    ${v.dns?.error?`<div class="dom red"><div class="t">${esc(v.dns.error)}</div></div>`:""}
    ${SWITCH_ROWS.map(([k,l,d])=>`<div class="dom"><div class="btns">${switchBtn(k,choice(k),l)}</div><div class="l mut">${esc(d)}</div>
      ${k==="capabilities"&&caps.enabled?`<div class="btns">${KIND_ROWS.map(([kk,ll])=>switchBtn(kk,!!caps[kk],ll)).join("")}</div>`:""}</div>`).join("")}
    <h3>Language</h3><div class="btns">${[["en","English"],["ar","العربية"]].map(([code,label])=>`<button class="sw${(c.language||"en")===code?" on":""}" data-t="lang" data-v="${code}">${label}</button>`).join("")}</div>`;
}
function linesOf(id){return String($("#"+id)?.value||"").split(/\r?\n/).map(x=>x.trim()).filter(Boolean)}
function choicesExtraHtml(){
  const ex=tools.exceptions||{hosts:{},programs:[],apps:[]};
  const hosts=Object.entries(ex.hosts||{}).map(([h,n])=>n?`${h} ${n}`:h).join("\n");
  const prov=tools.providers||{providers:[]};
  return `<div class="sec"><h3>Trusted by you</h3><div class="lg-key">Never blocked or flagged. One per line.</div>
      <label class="fld">Hosts (a full host name, then an optional note)<textarea id="ex-hosts" rows="3">${esc(hosts)}</textarea></label>
      <label class="fld">Program folders (under Program Files, AppData\\Local\\Programs or Documents)<textarea id="ex-programs" rows="2">${esc((ex.programs||[]).join("\n"))}</textarea></label>
      <label class="fld">Apps (a phone bundle ID or a PC program name)<textarea id="ex-apps" rows="2">${esc((ex.apps||[]).join("\n"))}</textarea></label>
      <div class="btns"><button data-t="ex-save">Save trusted lists</button></div></div>
    ${choice("models")?`<div class="sec"><h3>AI providers</h3><div class="lg-key">Your keys stay on this computer and go only to the provider you name. Roles: the writer reads first, jurors decide, the judge confirms. One provider may hold all three.</div>
      ${(prov.providers||[]).map((p,i)=>providerHtml(p,i)).join("")}${providerHtml({kind:"openai",roles:["writer","juror","judge"],enabled:true},(prov.providers||[]).length,true)}
      <div class="btns"><button data-t="prov-save">Save providers</button><button data-t="ai-exam">Test them</button></div></div>`:""}`;
}
function providerHtml(p,i,blank){
  const roles=new Set(p.roles||[]);
  return `<div class="dom prov" data-i="${i}"><div class="t">${blank?"Add a provider":esc(p.name)}</div>
    <div class="tool-bar"><input data-f="name" placeholder="Name" value="${esc(p.name||"")}">
      <select data-f="kind">${opts([["openai","OpenAI-compatible"],["anthropic","Anthropic"]],p.kind||"openai")}</select></div>
    <div class="tool-bar"><input data-f="baseUrl" placeholder="https://api.example.com/v1" value="${esc(p.baseUrl||"")}"><input data-f="model" placeholder="Model" value="${esc(p.model||"")}"></div>
    <div class="tool-bar"><input data-f="apiKey" type="password" autocomplete="off" placeholder="${p.hasKey?"Key saved (leave empty to keep it)":"API key"}">
      <input data-f="dailyLimit" type="number" min="0" placeholder="Daily limit" value="${esc(p.dailyLimit||"")}"></div>
    <div class="btns">${["writer","juror","judge"].map(r=>`<label class="chk"><input type="checkbox" data-role="${r}"${roles.has(r)?" checked":""}> ${r}</label>`).join("")}
      <label class="chk"><input type="checkbox" data-f="enabled"${p.enabled===false?"":" checked"}> enabled</label></div></div>`;
}
function collectProviders(){
  return [...document.querySelectorAll(".prov")].map(el=>{const val=f=>el.querySelector(`[data-f="${f}"]`);
    return {name:val("name").value.trim(),kind:val("kind").value,baseUrl:val("baseUrl").value.trim(),model:val("model").value.trim(),
      apiKey:val("apiKey").value,dailyLimit:+val("dailyLimit").value||0,enabled:val("enabled").checked,
      roles:[...el.querySelectorAll("[data-role]")].filter(x=>x.checked).map(x=>x.dataset.role)}}).filter(p=>p.name);
}
async function loadSettings(){
  const [v,ex,pr]=await Promise.all([getJson("/api/settings",null),getJson("/api/user-exceptions",null),getJson("/api/ai/providers",null)]);
  if(v)tools.settings=v; if(ex)tools.exceptions=ex; if(pr)tools.providers=pr;
  applyLanguage(); if(v&&!v.settings?.firstRunDone)showWizard();
}
async function saveSettings(patch,msg){
  const busy=patch.phone!==undefined||patch.pc!==undefined;
  if(busy)note("Windows may ask for approval…",6000);
  tools.settings=await send("POST","/api/settings",patch); applyLanguage();
  note(tools.settings.lastError||msg||"Saved",tools.settings.lastError?7000:2600);
  await reloadSlow(); if(view==="open-settings")drawSettings();
}
/* First run: ask what to protect, and turn on only that */
function showWizard(){
  if($("#wizard"))return;
  const w=document.createElement("div"); w.id="wizard"; w.className="pop show wide";
  w.innerHTML=`<h2>Welcome to Privacy Protector</h2><div class="mut">What do you want to protect? You can change this any time in Settings.</div>
    <div class="btns gap8"><button data-t="wiz" data-v="phone">My phone</button><button data-t="wiz" data-v="pc">This PC</button>
      <button data-t="wiz" data-v="both">Both</button><button data-t="wiz" data-v="none">Nothing yet, just look</button></div>
    <div class="mut gap8">Protecting the phone or the PC changes Windows DNS or firewall settings, so Windows asks for approval once. Turning it off later restores everything.</div>`;
  document.body.appendChild(w);
}
async function settingsClick(b){
  const t=b.dataset.t;
  if(t==="set"){const k=b.dataset.k, kinds=KIND_ROWS.map(x=>x[0]);
    const patch=kinds.includes(k)?{capabilities:{[k]:!b.classList.contains("on")}}:k==="capabilities"?{capabilities:{enabled:!choice(k)}}:{[k]:!choice(k)};
    b.disabled=true; await saveSettings(patch); return true}
  if(t==="lang"){await saveSettings({language:b.dataset.v}); return true}
  if(t==="wiz"){const v=b.dataset.v; $("#wizard")?.remove();
    await saveSettings({firstRunDone:true,phone:v==="phone"||v==="both",pc:v==="pc"||v==="both"},"Done. More switches are in Settings."); return true}
  if(t==="ex-save"){const hosts={};linesOf("ex-hosts").forEach(l=>{const [h,...n]=l.split(/\s+/);hosts[h]=n.join(" ")});
    const r=await send("POST","/api/user-exceptions",{hosts,programs:linesOf("ex-programs"),apps:linesOf("ex-apps")});
    tools.exceptions=r; note((r.rejected||[]).length?"Not saved: "+r.rejected.join("; "):"Trusted lists saved",(r.rejected||[]).length?8000:2600); drawSettings(); return true}
  if(t==="prov-save"){const r=await send("POST","/api/ai/providers",{providers:collectProviders()});
    tools.providers=await getJson("/api/ai/providers",tools.providers); note(`${(r.providers||[]).length} provider(s) ready`); drawSettings(); return true}
  return false;
}

/* ------------------------------------------------------------ Activity and operations box */
async function fetchLogs(){
  const d=await getJson("/api/logs?limit=2000",null); if(!d)return;
  tools.logs=d.items||[]; tools.stats=d.domainStats||{}; tools.attributions=d.attributions||[];
}
function appsByDomain(){
  const m=new Map(), add=(d,n)=>{d=cleanDomain(d);if(!d||!n)return;(m.get(d)||m.set(d,new Set()).get(d)).add(n)};
  phoneApps.forEach(a=>(a.domains||[]).forEach(d=>add(d,a.name||a.bundleID)));
  profiles.forEach(p=>[...(p.confirmedDomains||[]),...(p.observedDomains||[])].forEach(d=>add(d,p.name)));
  tools.attributions.forEach(x=>add(x.domain,x.appName||x.bundleID));
  return m;
}
function activityRows(){
  const by=appsByDomain(), live=new Map();
  (tools.logs||[]).forEach(i=>{const d=cleanDomain(i.domain);if(!d.includes("."))return;const c=live.get(d);c?c.hits++:live.set(d,{hits:1,time:i.time,action:i.action})});
  const doms=new Set([...live.keys(),...Object.keys(tools.stats)]);
  const a=tools.act, sel=a.app?new Set((phoneApps.find(x=>x.bundleID===a.app)?.domains||[]).map(cleanDomain)):null;
  let rows=[...doms].filter(d=>!tray.has(d)).map(d=>{const s=tools.stats[d]||{},l=live.get(d)||{};
    return {domain:d,risk:riskOf(d),apps:[...(by.get(d)||[])],at:s.lastObservedAt||l.time||"",count:s.observedCount||l.hits||0,blocked:s.blockedCount||0,action:(policy[d]||{}).action||""}});
  if(sel)rows=rows.filter(r=>sel.has(r.domain)||r.apps.includes(phoneApps.find(x=>x.bundleID===a.app)?.name));
  if(["unclassified","green","orange","red"].includes(a.filter))rows=rows.filter(r=>(r.risk||"unclassified")===a.filter);
  if(a.filter==="managed")rows=rows.filter(r=>r.action);
  const ro={red:0,orange:1,green:2,"":3}, app=r=>r.apps[0]||"~";
  rows.sort(a.sort==="app"?(x,y)=>app(x).localeCompare(app(y))||x.domain.localeCompare(y.domain)
    :a.sort==="domain"?(x,y)=>x.domain.localeCompare(y.domain)
    :a.sort==="class"?(x,y)=>ro[x.risk]-ro[y.risk]||(Date.parse(y.at)||0)-(Date.parse(x.at)||0)
    :(x,y)=>(Date.parse(y.at)||0)-(Date.parse(x.at)||0)||x.domain.localeCompare(y.domain));
  return rows;
}
function trayRows(){
  return [...tray].map(d=>{const s=tools.stats[d]||{},c=classes[d]||{};
    return {domain:d,risk:riskOf(d),action:(policy[d]||{}).action||"",at:s.lastObservedAt||"",blockedAt:s.lastBlockedAt||"",count:s.observedCount||0,blocked:s.blockedCount||0,
      why:c.summary||c.reason||"",ai:c.aiVerdict}}).sort((x,y)=>(Date.parse(y.at)||0)-(Date.parse(x.at)||0));
}
function drawActivity(){
  if(!tools.logs){show(`<h2>Activity</h2><div class="empty">…</div>`);return}
  const a=tools.act, rows=activityRows(), ops=trayRows();
  const appOpts=[["","All apps"],...phoneApps.filter(x=>(x.domains||[]).length).sort((x,y)=>String(x.name).localeCompare(String(y.name))).map(x=>[x.bundleID,x.name||x.bundleID])];
  show(`<h2>Activity · phone</h2><div class="lg-key">${(tools.logs||[]).length} recent DNS requests · ${Object.keys(tools.stats).length} domains kept · items you move go to Operations below</div>
    <div class="tool-bar">
      <select id="act-app">${opts(appOpts,a.app)}</select>
      <select id="act-filter">${opts([["all","All classes"],["unclassified","Not studied"],["green","Green"],["orange","Orange"],["red","Red"],["managed","Has a saved decision"]],a.filter)}</select>
      <select id="act-sort">${opts([["time","Last seen"],["app","App"],["domain","Domain"],["class","Class"]],a.sort)}</select>
    </div>
    <div class="btns"><button data-t="act-refresh">Refresh</button><button data-t="act-all">Move all ${rows.length} to operations</button><button data-t="act-clear">Clear requests</button></div>
    <div class="lg"><table><colgroup><col><col class="w26p"><col class="w56px"><col class="w84px"><col class="w30px"></colgroup>
      <thead><tr><th>Domain</th><th>App</th><th>Class</th><th>Last seen</th><th></th></tr></thead><tbody>
      ${rows.slice(0,tools.actShown).map(r=>`<tr title="${esc(r.domain)} · ${r.count} seen · ${r.blocked} blocked${r.action?" · saved: "+r.action:""}"><td>${esc(r.domain)}</td><td>${esc(r.apps.length>1?r.apps.length+" apps: "+r.apps.join(", "):r.apps[0]||"—")}</td>
        <td class="st-risk-${r.risk||"none"}">${RISK_WORD[r.risk]}</td><td>${esc(t5(r.at))}</td><td class="m"><button class="mini" data-t="to-ops" data-dom="${esc(r.domain)}" title="Move to operations, no rule is made">→</button></td></tr>`).join("")}
      </tbody></table>${rows.length>tools.actShown?`<div class="btns"><button data-t="act-more">Show ${Math.min(200,rows.length-tools.actShown)} more of ${rows.length-tools.actShown}</button></div>`:""}
      ${rows.length?"":`<div class="empty">Nothing matches</div>`}</div>
    <div class="sec"><h3>Operations · ${ops.length}</h3><div class="lg-key">Only what you move here. Nothing is blocked until you choose.</div>
      ${ops.length?`<div class="btns"><span class="mut">All:</span><button data-t="bulk" data-a="monitor">Monitor all</button><button data-t="bulk" data-a="allow">Allow all</button><button data-t="bulk" data-a="block">Block all</button><button data-t="ops-clear">Empty the tray</button></div>`:""}
      ${ops.map(o=>`<div class="dom ${o.risk==="red"?"red":o.risk==="orange"?"orange":"green"}"><div class="t">${esc(o.domain)}</div>
        <div class="l">${RISK_WORD[o.risk]} · ${o.count} seen · ${o.blocked} blocked · last seen ${ago(o.at)}${o.blockedAt?" · last blocked "+ago(o.blockedAt):""}${o.action?"":` · <b class="st-orange">waiting for your decision</b>`}</div>
        ${o.ai?.color?`<div class="l">Review: ${esc(o.ai.color)}${o.ai.confidence?" "+o.ai.confidence+"%":""}${o.ai.color==="red"&&!o.ai.blockSafe?" · not safe to block":""}</div>`:""}
        ${o.why?`<div class="l ar" dir="rtl">${esc(o.why)}</div>`:""}
        <div class="btns">${["allow","monitor","block"].map(x=>`<button class="${o.action===x?"on":""}" data-t="op" data-a="${x}" data-dom="${esc(o.domain)}">${ACTION_WORD[x]}</button>`).join("")}
          <button data-t="op-review" data-dom="${esc(o.domain)}">Smart review</button><button data-t="op-remove" data-dom="${esc(o.domain)}">Remove</button></div></div>`).join("")}
      ${ops.length?"":`<div class="empty">The tray is empty</div>`}
      <div class="btns"><button data-t="export-rules">Export block rules</button></div></div>`);
}
async function setPolicy(domain,action){await send("POST","/api/policy",{domain,action});policy[domain]={...(policy[domain]||{}),action}}

/* ------------------------------------------------------------ Phone permissions center */
const PERM_KEYS=[["location","Location","Coordinates and CLLocation updates"],["motion","Motion and sensors","Acceleration, rotation, and orientation"],["tracking","Ad tracking","App Tracking Transparency state"]];
const IOS_PATH={location:"Settings → Privacy & Security → Location Services → {app} → Never",motion:"Settings → Privacy & Security → Motion & Fitness → turn {app} off",tracking:"Settings → Privacy & Security → Tracking → turn {app} off"};
function observed(key,res,ev){
  const s=res?.[key]?.state||"not_seen", v=ev?.[key]?.verdict||"";
  if(v==="violation")return ["red","privacy violation"]; if(v==="allowed")return ["green","allowed by your choice"]; if(v==="protected")return ["green","blocked by iOS"];
  if(s==="used"||s==="authorized")return ["orange","used, under watch"]; if(s==="denied"||s==="restricted")return ["green","refused by iOS"];
  if(s==="requested")return ["orange","requested"]; return ["","not seen"];
}
function evidence(key,res){const i=res?.[key]||{};
  if(key==="location")return i.updates?`${i.updates} location updates reached the app`:i.requests?`${i.requests} location requests with no visible update`:"No location request in the last check";
  if(key==="motion")return i.samples?`${i.samples} motion samples reached the app`:i.sessions?`${i.sessions} sensor sessions with no visible samples`:"No motion samples in the last check";
  const t={0:"not decided yet",1:"restricted by the system",2:"denied",3:"allowed"};
  return i.authorizationStatus in t?`Tracking ${t[i.authorizationStatus]} · ${i.checks||0} checks`:i.checks?`Tracking state queried ${i.checks} times`:"No tracking query in the last check";
}
function drawPerms(){
  const pv=tools.privacy; if(!pv){show(`<h2>Phone permissions</h2><div class="empty">…</div>`);return}
  const list=profiles.filter(p=>p.bundleID), p=list.find(x=>x.id===tools.perm.id)||list[0];
  if(p&&tools.perm.id!==p.id){tools.perm.id=p.id;tools.perm.desired=null}
  const ctl=p?(pv.apps||{})[p.bundleID]:null, res=ctl?.lastResult||{}, ev=ctl?.evaluation||{}, def=pv.defaults||{};
  const want=tools.perm.desired||(tools.perm.desired={location:ctl?.desired?.location||def.location||"deny",motion:ctl?.desired?.motion||def.motion||"deny",
    tracking:ctl?.desired?.tracking||def.tracking||"deny",systemState:ctl?.desired?.systemState||def.systemState||"monitor",containment:"monitor"});
  const bal=(tools.policyFull||{}).balancedProtection||{}, cap=pv.capture||{}, active=!!cap.active;
  const viol=PERM_KEYS.filter(([k])=>ev?.[k]?.verdict==="violation"), inc=(pv.incidents||[]).filter(x=>x.bundleID===p?.bundleID);
  const deny=PERM_KEYS.filter(([k])=>want[k]==="deny").map(([k])=>IOS_PATH[k].replace("{app}",p?.name||"the app"));
  const gib=res.groupIB||{}, chk=res.developerChecks||{};
  show(`<h2>Phone permissions</h2><div class="lg-key">Balanced protection ${bal.enabled?"is on for the whole phone":"is off"} · ${bal.exactRules||0} exact rules · location, motion, and tracking are denied by default</div>
    ${list.length?`<div class="tool-bar"><select id="perm-app"${active?" disabled":""}>${opts(list.map(x=>[x.id,x.name]),p.id)}</select><span class="mut">${esc(p.bundleID)} · process ${esc(p.processName||"unknown")}</span></div>`
      :`<div class="empty">Monitor an app from Settings first</div>`}
    ${p?`${PERM_KEYS.map(([k,name,sub])=>{const [tone,word]=observed(k,res,ev);
      return `<div class="dom ${tone}"><div class="t">${name} <span class="mut">· ${sub}</span></div><div class="l">${word} · ${esc(evidence(k,res))}</div>
        <div class="btns">${["allow","monitor","deny"].map(x=>`<button class="${want[k]===x?"on":""}" data-t="perm-set" data-k="${k}" data-v="${x}">${x==="deny"?"Deny":ACTION_WORD[x]}</button>`).join("")}</div></div>`}).join("")}
      <div class="dom ${want.systemState==="block"?"red":""}"><div class="t">System state protection</div><div class="l">Stops device-state checks from being sent once their receiving domain is proven. ${want.systemState==="block"?"Blocking is on":"Watching only"}.</div>
        <div class="btns"><button class="${want.systemState==="monitor"?"on":""}" data-t="perm-set" data-k="systemState" data-v="monitor">Watch only</button><button class="${want.systemState==="block"?"on":""}" data-t="perm-set" data-k="systemState" data-v="block">Block sending</button></div></div>
      <div class="sec"><div class="rows"><span>Finding</span><span class="${viol.length?"st-red":""}">${!res.capturedAt?"no check yet":viol.length?`${p.name} received data you chose to deny`:"no confirmed violation"}</span>
        <span>Incidents</span><span>${inc.length?`${inc.length} saved · last ${ago(inc[0].capturedAt)}`:"none saved"}</span>
        <span>Last check</span><span>${res.capturedAt?`${ago(res.capturedAt)} · ${gib.detected?`GIBMobileSDK seen: ${gib.requests||0} sends`:"no GIBMobileSDK"} · ${chk.detected?"environment checks: "+esc((chk.signals||[]).join(", ")):"no environment checks"}`:"never"}</span></div>
        ${deny.length?`<div class="mut gap6">The real change happens on the iPhone: ${esc(deny.join(" · "))}</div>`:""}
        <div class="mut gap6">${active?`Checking ${esc(cap.appName||p.name)} now: open the app on the iPhone and use it normally, then stop.`:"Start a check, open the app on the iPhone, then stop to analyze location, motion, and tracking."}</div>
        <div class="btns"><button data-t="perm-save">Save choices</button>${active?`<button data-t="perm-stop">Stop and analyze</button>`:`<button data-t="perm-start">Start check</button>`}<button data-t="perm-export">Export incidents</button></div></div>`:""}`);
}
async function loadPerms(){
  const [pv,pol]=await Promise.all([getJson("/api/privacy-controls",null),getJson("/api/policy",null)]);
  tools.privacy=pv||{apps:{},defaults:{},capture:{active:false},incidents:[]}; tools.policyFull=pol;
}
async function savePerms(quiet){
  const p=profiles.find(x=>x.id===tools.perm.id); if(!p?.bundleID)throw new Error("Pick an app with a bundle ID");
  const r=await send("POST","/api/privacy-controls",{bundleID:p.bundleID,appName:p.name,desired:tools.perm.desired});
  tools.privacy.apps[p.bundleID]=r.control; (r.rules||[]).forEach(x=>policy[x.domain]=x.entry);
  if(!quiet)note(`Saved for ${p.name}`);
}

/* ------------------------------------------------------------ Smart review in the Review window */
function aiHtml(){
  const s=tools.ai; if(!s)return `<div class="sec"><h3>Smart review</h3><div class="empty">…</div></div>`;
  const pr=s.progress||{}, sum=s.summary||{}, c=sum.colors||{}, running=pr.state==="running";
  const line=!(s.trusted||[]).length?"No provider passed the exam. Add a key, then re-run the exam."
    :running?(pr.requested?`Running: ${pr.reviewed||0} of ${pr.requested} · last ${pr.lastDomain||"—"}${pr.requested&&!pr.reviewed?" (waiting for provider capacity)":""}`:"Preparing the list…")
    :pr.state==="done"||pr.state==="stopped"?`${pr.state==="stopped"?"Stopped":"Finished"}: ${pr.reviewed||0} domains, ${pr.changed||0} changed colour${pr.failed?` · ${pr.failed} deferred: providers hit their limit`:""}`
    :`Ready · trusted: ${(s.trusted||[]).join(", ")}`;
  const finds=Object.entries(classes).filter(([d,e])=>e?.aiVerdict?.color==="red"&&e.aiVerdict.blockSafe&&(policy[d]||{}).action!=="block")
    .sort((a,b)=>(b[1].hits||0)-(a[1].hits||0)).slice(0,40);
  const scores=Object.entries(s.scores||{}).sort((a,b)=>(b[1].score||0)-(a[1].score||0));
  const v3=st.status?.classificationEngine||{};
  return `<div class="sec"><h3>Smart review · phone domains</h3><div class="lg-key">${esc(line)}</div>
    <div class="lg-key">${sum.reviewed||0} reviewed · <b class="st-risk-red">${c.red||0}</b> red · <b class="st-risk-orange">${c.orange||0}</b> orange · <b class="st-risk-green">${c.green||0}</b> green · ${sum.disagreements||0} disagreements</div>
    <div class="tool-bar"><select id="ai-scope">${opts([["weak","Not settled by the local engine"],["unreviewed","Everything not reviewed yet"],["all","Review everything again"]],tools.aiScope||"weak")}</select>
      <select id="ai-limit">${opts(["30","60","150","400","1000"].map(x=>[x,x]),tools.aiLimit||"60")}</select>
      ${running?`<button data-t="ai-stop">Stop</button>`:`<button data-t="ai-start">Start review</button>`}<button data-t="ai-exam">Re-run the exam</button>
      <button data-t="v3"${v3.classificationPaused?" disabled":""}>${v3.classificationPaused?"Study paused":"Study again (V3)"}</button></div>
    ${scores.length?`<div class="lg-key gap6">${scores.map(([n,x])=>`<span class="${x.passed?"":"st-risk-red"}" title="${esc(x.model||"")}">${esc(n)} ${Math.round((x.score||0)*100)}%</span>`).join(" · ")}</div>`:""}
    ${tools.risks.length?`<h3>Blocks that may break an app · ${tools.risks.length}</h3>${tools.risks.map(r=>`<div class="dom orange"><div class="t">${esc(r.domain)}</div>
      <div class="l">blocked now · ${r.hits||0} seen${(r.callers||[]).length?" · "+esc(r.callers.join(", ")):""}</div>${r.reason?`<div class="l ar" dir="rtl">${esc(r.reason)}</div>`:""}
      <div class="btns"><button data-t="risk-open" data-dom="${esc(r.domain)}">Unblock</button><button data-t="risk-keep" data-dom="${esc(r.domain)}">Keep blocked</button></div></div>`).join("")}`:""}
    <h3>Suggested blocks · ${finds.length}</h3><div class="lg-key">Red confirmed by a second provider, and the local guard allows blocking it without breaking the app. Your call.</div>
    ${finds.map(([d,e])=>{const v=e.aiVerdict;return `<div class="dom red"><div class="t">${esc(d)}</div>
      <div class="l">${v.confidence||0}% · ${e.hits||0} seen${v.blockImpact?"":""}${(v.reviewers||[]).filter(Boolean).length?" · "+esc(v.reviewers.filter(Boolean).join(" + ")):""}</div>
      ${v.reason||v.purpose?`<div class="l ar" dir="rtl">${esc(v.reason||v.purpose)}</div>`:""}${v.blockImpact?`<div class="l ar" dir="rtl">${esc(v.blockImpact)}</div>`:""}
      <div class="btns"><button data-t="sug" data-a="block" data-dom="${esc(d)}">Block</button><button data-t="sug" data-a="monitor" data-dom="${esc(d)}">Monitor only</button></div></div>`}).join("")||`<div class="empty">Nothing to suggest</div>`}
  </div>`;
}
async function loadAI(){const [s,r]=await Promise.all([getJson("/api/ai/status",null),getJson("/api/ai/block-risks",null)]);tools.ai=s;tools.risks=r?.items||tools.risks||[]}
function pollAI(){clearTimeout(tools.aiPoll);if(tools.ai?.progress?.state!=="running")return;
  tools.aiPoll=setTimeout(async()=>{await loadAI();await reloadSlow();if(view==="review")drawReview();pollAI()},2500)}

/* ------------------------------------------------------------ Panel linking */
async function reloadSlow(){slowAt=0;await load()}
const TOOL_PANELS={
  "open-settings":async()=>{drawSettings();const c=await getJson("/api/pc/capabilities",null);if(c)tools.caps=c;await loadSettings();if(view==="open-settings")drawSettings()},
  "open-activity":async()=>{drawActivity();await fetchLogs();if(view==="open-activity")drawActivity()},
  "open-perms":async()=>{drawPerms();await loadPerms();if(view==="open-perms")drawPerms()},
};
async function toolsOnLoad(){
  if(view==="open-activity"){await fetchLogs();if(view==="open-activity")drawActivity()}
}
document.addEventListener("change",async e=>{
  const id=e.target.id;
  if(id==="report-file"){const f=e.target.files[0];if(!f)return;note("Importing…");try{await importReport(f)}catch(err){note("Import failed: "+err.message,6000)}return}
  if(id==="act-app"||id==="act-filter"||id==="act-sort"){tools.act[id.slice(4)]=e.target.value;tools.actShown=200;drawActivity();return}
  if(id==="perm-app"){tools.perm.id=e.target.value;tools.perm.desired=null;drawPerms();return}
  if(id==="ai-scope")tools.aiScope=e.target.value; if(id==="ai-limit")tools.aiLimit=e.target.value;
});
document.addEventListener("input",e=>{if(e.target.id==="det-q")drawSettings()});

async function toolClick(b){
  const t=b.dataset.t; if(!t)return false;
  try{if(await settingsClick(b))return true}catch(err){note("Couldn't save: "+err.message,6000);b.disabled=false;return true}
  const dom=b.dataset.dom, act=b.dataset.a;
  try{
    switch(t){
      case "dns-test":{b.disabled=true;const r=await send("POST","/api/dns/self-test",{});const ok=(r.checks||[]).filter(x=>x.state==="passed").length;
        note(`DNS test ${r.state==="passed"?"passed":"incomplete"}: ${ok}/${(r.checks||[]).length}`,5000);await load();drawSettings();break}
      case "hist-setup":{b.disabled=true;await send("POST","/api/pc/capability-history/setup",{});note("Approve the Windows prompt. The history shows up within minutes.",6000);break}
      case "scan-iphone":{b.disabled=true;b.textContent="Reading…";const r=await send("POST","/api/device/apps/scan",{});note(`${r.count} apps read from the iPhone`);await reloadSlow();drawSettings();break}
      case "dev-check":await devCheck();break;
      case "monitor-app":b.disabled=true;await monitorApp(b.dataset.bundle);drawSettings();break;
      case "add-app":{const name=$("#add-name").value.trim();if(!name){note("Enter a name");break}
        const r=await send("POST","/api/apps",{name,bundleID:$("#add-bundle").value.trim(),processName:$("#add-proc").value.trim()});note(`Added ${r.profile.name}`);await reloadSlow();drawSettings();break}
      case "act-refresh":await fetchLogs();drawActivity();note("Activity refreshed");break;
      case "act-more":tools.actShown+=200;drawActivity();break;
      case "act-clear":{if(!armed(b,"Confirm clear"))break;const r=await send("DELETE","/api/logs");note(`${r.removed||0} requests cleared. Known domains stay.`);await fetchLogs();drawActivity();break}
      case "act-all":{const rows=activityRows();if(!rows.length)break;if(!armed(b,`Confirm moving ${rows.length}`))break;rows.forEach(r=>tray.add(r.domain));saveTray();drawActivity();note(`${rows.length} moved to operations, no rule made`);break}
      case "to-ops":tray.add(dom);saveTray();drawActivity();break;
      case "op":{if(act==="block"&&!armed(b,"Confirm block"))break;await setPolicy(dom,act);note(`${dom}: ${ACTION_WORD[act]}`);drawActivity();load();break}
      case "op-remove":tray.delete(dom);saveTray();drawActivity();break;
      case "op-review":{b.disabled=true;b.textContent="Reviewing…";const r=await send("POST","/api/ai/review",{domain:dom});const v=(r.verdicts||[])[0];
        note(v?`${dom}: ${v.color}`:`Couldn't judge ${dom}`,5000);await reloadSlow();drawActivity();break}
      case "bulk":{const ops=trayRows();if(act==="block"&&!armed(b,`Confirm blocking ${ops.length}`))break;let ok=0,bad=0;
        for(const o of ops){try{await setPolicy(o.domain,act);ok++}catch(err){bad++}}note(`${ACTION_WORD[act]}: ${ok} done${bad?`, ${bad} failed`:""}`);drawActivity();load();break}
      case "ops-clear":if(!armed(b,"Confirm empty"))break;tray=new Set();saveTray();drawActivity();note("Tray emptied. Nothing was deleted from the activity");break;
      case "export-rules":download("privacy-protector-exact-blocklist.txt",["# Privacy Protector — exact block rules","# No wildcard rules",...Object.entries(policy).filter(([,v])=>v.action==="block").map(([d])=>d),""].join("\n"),"text/plain;charset=utf-8");break;
      case "perm-set":tools.perm.desired[b.dataset.k]=b.dataset.v;drawPerms();break;
      case "perm-save":await savePerms(false);drawPerms();break;
      case "perm-start":{const p=profiles.find(x=>x.id===tools.perm.id);await savePerms(true);const r=await send("POST","/api/privacy-capture/start",{profileID:p.id});
        tools.privacy.capture=r.capture;note(`Checking ${p.name}`);drawPerms();break}
      case "perm-stop":{const r=await send("POST","/api/privacy-capture/stop",{});tools.privacy.capture={active:false};tools.privacy.apps[r.control.bundleID]=r.control;
        await loadPerms();tools.perm.desired=null;note("Analysis saved. Domain decisions stay manual");drawPerms();break}
      case "perm-export":{const p=profiles.find(x=>x.id===tools.perm.id);const inc=(tools.privacy.incidents||[]).filter(x=>!p?.bundleID||x.bundleID===p.bundleID);
        download(`privacy-incidents-${p?.bundleID||"all"}.json`,JSON.stringify({exportedAt:new Date().toISOString(),incidents:inc},null,2),"application/json;charset=utf-8");break}
      case "ai-start":{b.disabled=true;await send("POST","/api/ai/review",{limit:+(tools.aiLimit||60),scope:tools.aiScope||"weak"});note("Review started in the background");await loadAI();drawReview();pollAI();break}
      case "ai-stop":await send("POST","/api/ai/stop",{});note("It stops after the current batch");await loadAI();drawReview();break;
      case "ai-exam":{b.disabled=true;b.textContent="Examining…";const r=await send("POST","/api/ai/calibrate",{});tools.ai=r;note(`Passed: ${(r.trusted||[]).join(", ")||"none"}`,6000);drawReview();break}
      case "v3":{b.disabled=true;const r=await send("POST","/api/classifications/analyze",{});note(`Studying ${r.queued||0} domains again. Saved classes stay`,5000);break}
      case "sug":{if(act==="block"&&!armed(b,"Confirm block"))break;tray.add(dom);saveTray();await setPolicy(dom,act);note(`${dom}: ${ACTION_WORD[act]}`);drawReview();load();break}
      case "risk-open":{tray.add(dom);saveTray();await setPolicy(dom,"monitor");await loadAI();note(`${dom} unblocked, now watched`);drawReview();load();break}
      case "risk-keep":tools.risks=tools.risks.filter(r=>r.domain!==dom);drawReview();break;
      default:return false;
    }
  }catch(err){note("Couldn't do it: "+err.message,6000);b.disabled=false}
  return true;
}
loadSettings();
