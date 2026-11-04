const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const LABEL = {green:"Safe: everything that intrudes is blocked",orange:"Attention: a decision is pending or can't be enforced",red:"At risk: an intrusion is still getting through"};
const COLOR = {red:"Red",orange:"Orange",green:"Green","":"Not reviewed"};
const PC_STATE = {"protected":"protected: needed by the program","auto-blocked":"blocked automatically","red-kept":"red, kept open by the guard",
  "guard-released":"released: a program needed it","watching":"watching","user-allowed":"allowed by you","user-blocked":"blocked by you","session-blocked":"blocked by your review session"};
const RANK = {red:3,orange:2,"":1,green:0};
const CAP_VERDICT = {deny:"deny",undetermined:"undetermined",monitor:"monitor",allow:"allow"};
const CORE_KEY = "__core__";
let device = (()=>{try{return localStorage.getItem("pp-device")||"pc"}catch(e){return "pc"}})();
let st = {}, pcItems = [], pcPrograms = [], capGroups = [], phoneApps = [], classes = {}, policy = {}, view = null, sel = null, profiles = [];
/* The judge model, when configured, is responsible for the planet and nucleus colors: every new red or yellow state is shown to it once; it either approves, downgrades it to no color, or raises it to red. Until it answers, the code's color remains. Engine alerts are determined by the code alone. */
let judged = {}, judgeAt = 0;
function judgedStatus(key,status){const v=judged[key];
  if(status==="green"||!v||v.from!==status)return status;
  return v.sev==="none"?"green":v.sev==="red"?"red":status}

function note(msg,ms=2600){const t=$("#note");t.textContent=msg;t.classList.add("show");clearTimeout(note.t);note.t=setTimeout(()=>t.classList.remove("show"),ms)}
async function getJson(url,fallback){try{const r=await fetch(url,{cache:"no-store"});return await r.json()}catch(e){return fallback}}
/* Changes carry the session token the server hands only to this page (protection against other web pages) */
let SESSION=null;
async function session(){if(!SESSION){const r=await fetch("/api/session",{cache:"no-store"});SESSION=await r.json()}return SESSION}
async function authHeaders(){const s=await session();return {"Content-Type":"application/json",[s.header]:s.token}}
async function post(url,body){const r=await fetch(url,{method:"POST",headers:await authHeaders(),body:JSON.stringify(body||{})});
  const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||("HTTP "+r.status));return j}
function ago(iso){if(!iso)return "never";const s=(Date.now()-new Date(iso))/1000;if(s<90)return "just now";const m=s/60;
  return m<60?Math.round(m)+"m ago":m<2880?Math.round(m/60)+"h ago":Math.round(m/1440)+"d ago"}
const shortName = n => String(n||"").replace(/\.exe$/i,"");

/* ------------------------------------------------------------ Planets: all programs and apps
   All appear without a border, and their color reflects their state, not their decisions: white (safe) if every intrusion in them is blocked, even if domains or functions from them were blocked.
   Yellow if something in it remains undecided, or an intrusion was kept because the program needs it, or a block that cannot be enforced.
   Red if it contains an intrusion that is currently passing through and can be blocked. The state key safe/attention/risk corresponds to green/orange/red. */
/* Color is a sign of a deficiency or a need for intervention, not a description of a decision made: a red kept because the program needs it is a correct decision and gets no color; what is waiting for a decision for more than a day, an intrusion passing through, or a block that cannot be enforced while the program still uses the permission, is what gets colored. */
const DAY=864e5, since=t=>{const v=Date.parse(t||"");return isNaN(v)?Infinity:Date.now()-v};
function domState(d){
  if(d.blocked)return "green";
  if(d.state==="allow"||d.state==="user-allowed")return "green";                       // The user's own allowance
  if(d.pending)return "green";                                                          // Awaiting the judge: waiting, not a deficiency
  if(d.color==="red"){
    if(d.state==="red-kept")return d.keptFor==="pending"?"red":"green";                 // "Pending" is a deficiency; "for function" is a decision
    return ["guard-released","protected"].includes(d.state)?"green":"red";
  }
  if(d.state==="protected")return "green";                                              // A function of the program that is not reviewed, and has no red
  if(!d.color)return since(d.firstSeen)>2*3600e3?"orange":"green";                     // Two hours without study and permanent review: a deficiency in it
  return "green";                                                                       // Green and monitored orange is normal operation
}
function capState(g){
  const v=g.verdict?.verdict, perm=g.permission||{};
  // Only an effective block is white: a Deny value, or the program's service is disabled so it does not work, or its file was deleted. Long absence is not a decision: an unenforced block
  // Remains yellow, requesting your intervention even if the permission has not been used for months
  const enforced=perm.value==="Deny"||!!perm.disabledService||!!perm.removed;
  if(v==="deny")return enforced?"green":perm.writable?"red":"orange";
  if(v==="undetermined")return enforced?"green":"orange";
  return "green";
}
function statusOf(b){const all=b.doms.map(domState).concat((b.caps||[]).map(capState));
  return all.includes("red")?"red":all.includes("orange")?"orange":"green"}
function pcBodies(){
  const by={}, body=(name,info)=>by[name]=by[name]||{key:"pc:"+name,name:shortName(name),purpose:info?.purpose,company:info?.company,doms:[],caps:[]};
  pcPrograms.forEach(p=>body(p.name,p));
  pcItems.forEach(it=>{const dec=it.decision||{};
    const d={domain:it.domain,color:it.color||"",blocked:it.action==="block",state:dec.state||"",keptFor:it.keptFor||"",pending:!!it.pending,firstSeen:it.firstSeen||"",reason:it.reason||dec.reason||"",hits:it.hits||0};
    (it.programs||[]).forEach(p=>body(p.name,p).doms.push(d))});
  capGroups.forEach(g=>body(g.program).caps.push(g));
  return Object.values(by);
}
/* Apple's report lists IP addresses the app connects to directly: they do not go through DNS, so they are not blocked or classified by name, and therefore 'unstudied' domains do not color the planet */
const isHostName = dm => /^(?=.*[a-z])[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(dm) && !/^[\d.]+$|:/.test(dm);
function phoneBodies(){
  return phoneApps.map(a=>({key:"ph:"+(a.bundleID||a.name),name:a.name||a.bundleID,bundle:a.bundleID,lastSeen:a.lastSeen,caps:[],
    /* Along with what was attributed to it via the primary site or app context without Apple's report mentioning it (inferredDomains, 2026-10-30) */
    doms:[...new Set([...(a.domains||[]),...(a.inferredDomains||[])])].filter(isHostName).map(dm=>{const c=classes[dm]||{},p=policy[dm]||{};
      /* A red that the local guard cannot block (a function the app needs) is yellow, not red: it cannot be blocked without disabling it, as on the computer.
         Likewise a red whose block was manually lifted to monitoring because it disabled a function (bank monitoring when adding a card, 2026-10-29) */
      const kept=c.risk==="red"&&((c.aiVerdict&&c.aiVerdict.blockSafe===false&&c.aiVerdict.blockVeto)||(p.action==="monitor"&&p.source==="manual"))?"red-kept":"";
      return {domain:dm,color:c.risk==="unclassified"?"":(c.risk||""),blocked:p.action==="block",state:kept||p.action||"",pending:!!(c.aiVerdict&&c.aiVerdict.pendingSonnet),reason:c.summary||c.reason||"",hits:0}})}));
}
/* Sorting is by name, not by state, so a planet does not jump out of its orbit when its color changes */
function bodies(){
  return (device==="pc"?pcBodies():phoneBodies()).map(b=>{const raw=statusOf(b);return {...b,raw,status:judgedStatus("planet:"+b.key,raw)}})
    .sort((a,b)=>a.name.localeCompare(b.name));
}
/* What is presented to the judge about the planet: its domains and permissions that colored it */
function planetWhy(b){
  const doms=b.doms.filter(d=>domState(d)!=="green").slice(0,8).map(d=>`${d.domain} (${domState(d)}, ${COLOR[d.color]||d.color}${d.state?", "+d.state:""})`);
  const caps=(b.caps||[]).filter(g=>capState(g)!=="green").slice(0,4).map(g=>`${g.capability||g.name||"capability"} (${capState(g)})`);
  return doms.concat(caps).join("; ")}
async function askJudge(){
  if(Date.now()-judgeAt<60000)return; judgeAt=Date.now();
  const items=bodies().filter(b=>b.raw!=="green").map(b=>({key:"planet:"+b.key,sev:b.raw,title:b.name,text:planetWhy(b)}))
    .concat(rawCoreIssues().map(i=>({key:i.key,sev:i.sev,title:i.title,text:i.text||"",safety:!!i.safety})));
  if(!items.length)return;
  try{const r=await post("/api/color-judge",{items}), before=JSON.stringify(judged); judged=r.verdicts||{};
    if(JSON.stringify(judged)!==before){const issues=coreIssues();coreState=issues.some(i=>i.sev==="red")?"red":issues.length?"orange":"green";
      refreshPlanets(); if(sel===CORE_KEY)drawDetail()}}catch(e){}
}

/* ------------------------------------------------------------ The scene: nucleus and planets */
const cv=$("#sky"), cx2=cv.getContext("2d"), TOP=44, K=.62, BASE=.26;
const TIP={green:"232,240,255",orange:"242,193,78",red:"239,90,90"};
const CORE={green:[210,228,255],orange:[242,193,78],red:[239,106,90]};
let W,H,CX,CY,U,AX=1,coreR,Rmin,Rmax,planetR,stars=[],planets=[],orbits=1,coreState="green",coreCol=[210,228,255],T=0,last=0,mx=-1,my=-1,hover=null;
const ring=Array.from({length:1800},(_,i)=>[Math.random()*6.283,Math.random(),Math.random(),i%3]);
/* Planets rotate as a single body: one angular speed for all, the old middle orbit speed, so no planet overtakes another and none passes over or under another. Their positions are pre-distributed and checked for each rotation angle, so no two stick together. */
// 75% of the 2026-10-30 initial speed, so the user can catch up with the planet and squeeze it (their request on the same day)
const TAU=Math.PI*2, OMEGA=BASE*1.22*Math.pow(.78/.91,1.5)*.75;
let theta=0;

function layout(){
  const dp=devicePixelRatio||1; W=innerWidth; H=innerHeight; if(!W||!H) return;
  cv.width=W*dp; cv.height=H*dp; cv.style.width=W+"px"; cv.style.height=H+"px"; cx2.setTransform(dp,0,0,dp,0,0);
  CX=W/2; CY=TOP+(H-TOP)/2; U=Math.max(120,Math.min(W/2-40,((H-TOP)/2-34)/K));
  /* The nearest distant orbit is far from the nucleus's atoms (ending around 0.37U), and orbits widen horizontally into the side space by a moderate amount */
  coreR=U*.2; Rmin=U*.78; Rmax=U*1.04; AX=Math.max(1,Math.min(1.3,(W/2-50)/(Rmax+12))); planetR=Math.max(4.5,Math.min(8,U*.011));
  stars=Array.from({length:Math.round(W*H/1600)},()=>[Math.random()*W,TOP+Math.random()*(H-TOP),Math.random()*6]);
  placePlanets();
}
/* Up to ten: each planet has its orbit as in the guard. Beyond that, they are distributed across orbits of equal distance, and on each orbit with equal spacing,
   and the planet shrinks as the number of planets increases */
const RING=6;                                           // The planet's ring extends to its radius + 6 (and the alert +8)
function gapOf(list,r){
  /* The shortest distance between the rings of two planets at any rotation angle, with samples every 7.5 degrees: the rotation is a single body so checking it once is enough */
  const S=48, pts=list.map(p=>Array.from({length:S},(_,s)=>{const a=p.a+s*TAU/S;return [Math.cos(a)*p.R*AX,Math.sin(a)*p.R*K]}));
  let worst=Infinity;
  for(let i=0;i<list.length;i++)for(let j=i+1;j<list.length;j++){
    if(Math.abs(list[i].R-list[j].R)*K>=worst)continue;    // Two orbits whose planets come no closer than the closest pair found
    for(let s=0;s<S;s++){const d=Math.hypot(pts[i][s][0]-pts[j][s][0],pts[i][s][1]-pts[j][s][1]);if(d<worst)worst=d}}
  return worst-2*(r+RING);
}
let placeKey="", placeCache=null;
function placePlanets(){
  const n=planets.length, R=(o,m)=>m>1?Rmin+(Rmax-Rmin)*o/(m-1):(Rmin+Rmax)/2;
  const assign=(m,step)=>{const by=Array.from({length:m},()=>[]);planets.forEach((p,i)=>by[i%m].push(p));
    by.forEach((list,o)=>list.forEach((p,j)=>{p.R=R(o,m);p.a=(j+(o*step)%1)/list.length*TAU}))};
  /* Up to ten: each planet has its orbit as in the guard. Beyond that, orbits are tried from 2 to 16 and the offsets between them, and the one that keeps the closest two planets furthest apart at any rotation angle is taken; fifteen orbits for 125 planets were causing orbits to be 7 pixels apart and the planet 70 */
  const key=n+"|"+Math.round(U)+"|"+AX.toFixed(3);
  if(key!==placeKey){
    let best={g:-Infinity,m:Math.max(n,1),step:.381966};   // With no offset, up to ten planets would all sit on one straight line
    if(n<=10)best.m=Math.max(n,1);
    else for(let m=2;m<=16;m++)for(const step of [.5,1/3,.381966,.618034,.25]){
      assign(m,step); const g=gapOf(planets,0); if(g>best.g)best={g,m,step}}
    placeKey=key; placeCache=best;
  }
  orbits=placeCache.m; assign(placeCache.m,placeCache.step);
  planetR=Math.max(n>60?3:4.5,Math.min(8,U*.011*(n>60?.7:n>25?.85:1)));
  const room=gapOf(planets,planetR)+2*(planetR+RING);    // Shortest distance between two centers at any angle
  planetR=Math.max(2,Math.min(planetR,room/2-RING-1));   // At least two pixels of space between two rings
  planets.forEach(p=>{if(p.rr==null){p.rr=p.R;p.ac=p.a}});
}
function setPlanets(list){
  const old=Object.fromEntries(planets.map(p=>[p.key,p]));
  planets=list.map(b=>{const o=old[b.key];return {...b,rr:o?o.rr:null,ac:o?o.ac:null}});
  placePlanets();
}
/* The drawn position follows its computed position smoothly as the planet count changes, then rotates with everything else */
const ang=p=>theta+p.ac;
const pos=p=>[CX+Math.cos(ang(p))*p.rr*AX,CY+Math.sin(ang(p))*p.rr*K];
function hitPlanet(){let b=null,bd=planetR*2.6;planets.forEach(p=>{const[X,Y]=pos(p),d=Math.hypot(X-mx,Y-my);if(d<bd){bd=d;b=p}});return b}
const onCore=()=>Math.hypot(mx-CX,my-CY)<coreR*1.4;

/* Center emblem: a traffic light inside a shield. The shield is white and never changes color; only the status lamp lights up, like the notification images: green for healthy, yellow with a note, red if it doesn't protect, and the other two off. It breathes faster as the status worsens */
const LAMPS=[["red",[255,59,48]],["orange",[255,200,40]],["green",[52,210,100]]];
function shield(){
  const x=cx2,s=coreR*.62,lvl={green:0,orange:1,red:2}[coreState],white=a=>`rgba(230,240,255,${a})`;
  x.save(); x.translate(CX,CY+Math.sin(T*.6)*1.2); x.lineJoin="round";
  const path=()=>{x.beginPath();x.moveTo(0,-s);x.quadraticCurveTo(s*.9,-s*.8,s*.85,-s*.55);x.quadraticCurveTo(s*.8,s*.5,0,s);
    x.quadraticCurveTo(-s*.8,s*.5,-s*.85,-s*.55);x.quadraticCurveTo(-s*.9,-s*.8,0,-s)};
  path(); x.fillStyle="rgba(8,14,30,.85)"; x.fill(); x.strokeStyle=white(.9); x.lineWidth=Math.max(1.2,s*.05); x.stroke();
  const bw=s*.5,bh=s*1.22,by=-s*.66;
  x.beginPath(); x.roundRect(-bw/2,by,bw,bh,bw*.4); x.fillStyle="rgba(3,6,14,.9)"; x.fill(); x.strokeStyle=white(.55); x.lineWidth=Math.max(1,s*.03); x.stroke();
  LAMPS.forEach(([state,[r,g,b]],k)=>{
    const cy=by+bh*(k*2+1)/6, lr=bw*.3, on=state===coreState, pulse=.8+.2*Math.sin(T*(1.2+lvl*.9));
    if(on){const gl=x.createRadialGradient(0,cy,0,0,cy,lr*2.6); gl.addColorStop(0,`rgba(${r},${g},${b},${.4*pulse})`); gl.addColorStop(1,`rgba(${r},${g},${b},0)`);
      x.fillStyle=gl; x.beginPath(); x.arc(0,cy,lr*2.6,0,7); x.fill()}
    x.fillStyle=on?`rgba(${r},${g},${b},${pulse})`:"rgba(70,78,95,.55)"; x.beginPath(); x.arc(0,cy,lr,0,7); x.fill();
    x.strokeStyle=white(.45); x.lineWidth=Math.max(1,s*.025); x.beginPath(); x.arc(0,cy,lr*1.3,Math.PI*1.1,Math.PI*1.9); x.stroke();
  });
  x.restore();
}
function frame(ms){
  if(!coreR||W!==innerWidth||H!==innerHeight) layout();
  if(!coreR){requestAnimationFrame(frame);return}
  const dt=Math.min(.05,(ms-last)/1000||0); last=ms; T+=dt; const x=cx2;
  const g=x.createLinearGradient(0,0,0,H); g.addColorStop(0,"#050a18"); g.addColorStop(1,"#0b1730"); x.fillStyle=g; x.fillRect(0,0,W,H);
  const m=x.createRadialGradient(W*.86,TOP,0,W*.86,TOP,Math.max(W,H)*.55); m.addColorStop(0,"rgba(150,185,255,.11)"); m.addColorStop(1,"rgba(150,185,255,0)");
  x.fillStyle=m; x.fillRect(0,0,W,H);
  stars.forEach(s=>{x.fillStyle=`rgba(225,235,255,${.06+.17*Math.sin(T*.8+s[2])**2})`;x.fillRect(s[0],s[1],1,1)});
  coreCol=coreCol.map((v,i)=>v+(CORE[coreState][i]-v)*.05);
  const [cr,cg,cb]=coreCol.map(v=>v|0), lvl={green:0,orange:1,red:2}[coreState], ag=1+lvl*.7, sp=[.2,.32,.5][lvl];
  for(let k=2;k>=0;k--) ring.forEach(q=>{if(q[3]!==k)return;
    const a=q[0]+T*(sp-k*.05), r=coreR*1.05+k*coreR*.2+q[1]*coreR*.38+Math.sin(T*1.1*ag+q[0]*4)*1.8*ag, z=k?1.2:1.6;
    x.fillStyle=`rgba(${cr},${cg},${cb},${(.16+q[2]*.62)*(1-k*.2)})`; x.fillRect(CX+Math.cos(a)*r,CY+Math.sin(a)*r,z,z)});
  const cg2=x.createRadialGradient(CX,CY,0,CX,CY,coreR*1.05); cg2.addColorStop(0,"#000"); cg2.addColorStop(.88,"#000"); cg2.addColorStop(1,"rgba(0,0,0,0)");
  x.fillStyle=cg2; x.beginPath(); x.arc(CX,CY,coreR*1.05,0,7); x.fill();
  shield();
  hover=hitPlanet(); cv.style.cursor=hover||onCore()?"pointer":"default";
  if(!sel)theta=(theta+OMEGA*dt)%TAU;                    // An open planet window freezes everything together, not just its own planet
  planets.forEach(p=>{p.rr+=(p.R-p.rr)*.08; p.ac+=(((p.a-p.ac)%TAU+TAU*1.5)%TAU-TAU/2)*.08;
    const c=TIP[p.status], [X,Y]=pos(p), r=(p===hover||p.key===sel)?planetR*1.25:planetR, bad=p.status!=="green";
    x.beginPath(); x.arc(X,Y,r*3,0,7); x.fillStyle=`rgba(${c},.06)`; x.fill();
    x.beginPath(); x.arc(X,Y,r,0,7); x.fillStyle=`rgba(${c},.95)`; x.fill();
    x.beginPath(); x.arc(X,Y,r+(bad?6+Math.sin(T*2.4)*2:5),0,7); x.strokeStyle=`rgba(${c},${bad?.5:.18})`; x.lineWidth=.9; x.stroke()});
  if(hover&&hover.key!==sel){const[X,Y]=pos(hover); x.textAlign="left"; x.font="12px 'Segoe UI',sans-serif"; x.fillStyle="rgba(240,246,255,.92)";
    x.fillText(hover.name,X+planetR+10,Y+4)}
  if(sel) anchorDetail();
  requestAnimationFrame(frame);
}
cv.addEventListener("mousemove",e=>{mx=e.clientX;my=e.clientY});
cv.addEventListener("mouseleave",()=>{mx=-1;hover=null});
cv.addEventListener("click",e=>{
  mx=e.clientX; my=e.clientY; closePanel();
  const h=hitPlanet(), key=h?h.key:onCore()?CORE_KEY:null;
  if(!key||key===sel){closeDetail();return}
  sel=key; drawDetail(); $("#detail").classList.add("show"); anchorDetail();
});
addEventListener("resize",()=>{layout();if(sel)anchorDetail()});
function closeDetail(){sel=null;$("#detail").classList.remove("show")}

function anchorDetail(){
  const d=$("#detail"), p=planets.find(q=>q.key===sel);
  let X=CX+coreR*1.7, Y=CY-60; if(p){[X,Y]=pos(p); X+=planetR+14}
  const w=d.offsetWidth||420, h=d.offsetHeight||200;
  if(X+w>W-12) X=(p?pos(p)[0]-planetR-14:CX-coreR*1.7)-w;
  d.style.left=Math.max(12,X)+"px"; d.style.top=Math.max(TOP+8,Math.min(Y-40,H-h-12))+"px";
}

/* ------------------------------------------------------------ Planet window: its ranges, functions, and decisions */
const STATE_WORD={green:"safe",orange:"attention",red:"at risk"};
function domHtml(d){
  const state=device==="pc"?(PC_STATE[d.state]||d.state):(d.state?d.state:"no saved decision");
  const acts=device==="pc"
    ?[["block","Block"],["allow","Allow"],["reset","Back to auto"]]
    :[["block","Block"],["monitor","Monitor"],["allow","Allow"]];
  return `<div class="dom ${domState(d)}"><div class="t">${esc(d.domain)}</div>
    <div class="l">${COLOR[d.color]??esc(d.color)}${d.blocked?" · blocked":""}${state?" · "+esc(state):""}${d.hits?" · "+d.hits+" hits":""}</div>
    ${d.reason?`<div class="l">${esc(d.reason)}</div>`:""}
    <div class="btns">${acts.map(([a,l])=>`<button data-act="${a}" data-dom="${esc(d.domain)}">${l}</button>`).join("")}</div></div>`;
}
const CAP_NAME={microphone:"Microphone",webcam:"Camera",location:"Location",contacts:"Contacts"};
const PERM={Allow:"allowed",Deny:"denied",Prompt:"asks"};
function capHtml(g){
  const v=g.verdict||{}, perm=g.permission||{};
  const btn=perm.restorable?`<button data-cap="restore" data-key="${esc(g.key)}">Restore</button>`
    :perm.writable&&perm.value!=="Deny"?`<button data-cap="deny" data-key="${esc(g.key)}">Deny</button>`:"";
  return `<div class="dom ${capState(g)}"><div class="t">${esc(CAP_NAME[g.capability]||g.capabilityLabel||g.capability)}</div>
    <div class="l">Verdict: ${esc(v.verdict||"—")} · ${g.uses||0} uses · last ${ago(g.lastAt)}${g.inUse?" · in use now":""} · Windows: ${esc(PERM[perm.value]||"default")}${perm.writable?"":" · can't be set from Windows"}</div>
    ${v.role?.text?`<div class="l">${esc(v.role.text)}</div>`:""}${v.action?.text?`<div class="l">${esc(v.action.text)}</div>`:""}
    ${btn?`<div class="btns">${btn}</div>`:""}</div>`;
}
const DOM_LIMIT=40, expanded=new Set();
function drawDetail(){
  const d=$("#detail");
  if(sel===CORE_KEY){d.innerHTML=coreHtml();return}
  const p=planets.find(q=>q.key===sel); if(!p){closeDetail();return}
  const keep=d.dataset.key===p.key?d.scrollTop:0; d.dataset.key=p.key;
  const doms=[...p.doms].sort((a,b)=>RANK[domState(b)]-RANK[domState(a)]||(a.blocked-b.blocked)||b.hits-a.hits);
  const caps=[...(p.caps||[])].sort((a,b)=>RANK[capState(b)]-RANK[capState(a)]);
  const n=c=>p.doms.filter(x=>domState(x)===c).length, blocked=p.doms.filter(x=>x.blocked).length, all=expanded.has(p.key);
  d.innerHTML=`<h2>${esc(p.name)}</h2><div class="st-${p.status}">${LABEL[p.status]}</div>
    <div class="rows">
      <span>Device</span><span>${device==="pc"?"PC":"Phone"}</span>
      ${p.company?`<span>Publisher</span><span>${esc(p.company)}</span>`:""}
      ${p.bundle?`<span>Bundle</span><span>${esc(p.bundle)}</span>`:""}
      ${p.lastSeen?`<span>Last seen</span><span>${ago(p.lastSeen)}</span>`:""}
      <span>Domains</span><span>${p.doms.length} · ${blocked} blocked</span>
      <span>Domain state</span><span><b class="st-red">${n("red")}</b> at risk · <b class="st-orange">${n("orange")}</b> attention · <b class="st-green">${n("green")}</b> safe</span>
      ${caps.length?`<span>Device access</span><span>${caps.length} · ${caps.filter(g=>capState(g)!=="green").length} not safe</span>`:""}
    </div>
    ${p.purpose?`<div class="l mut gap6">${esc(p.purpose)}</div>`:""}
    ${caps.length?`<div class="sec"><h3>Device access</h3>${caps.map(capHtml).join("")}</div>`:""}
    ${doms.length?`<div class="sec"><h3>Domains</h3>${(all?doms:doms.slice(0,DOM_LIMIT)).map(domHtml).join("")}
      ${doms.length>DOM_LIMIT?`<div class="btns"><button data-more="${esc(p.key)}">${all?"Show fewer":`Show all ${doms.length}`}</button></div>`:""}</div>`
      :caps.length?"":`<div class="sec mut">No domains or device access seen yet.</div>`}`;
  d.scrollTop=keep;
}

/* Core window: status of the engine, the phone and the PC */
function coreHtml(){
  const s=st.status||{}, e=s.dnsEngine||{}, ip=e.iphoneClient||{}, pc=st.pc||{}, rv=pc.review||{};
  const prov=(e.providers||[]).map(p=>`${esc(p.role)} ${p.state==="healthy"?"✓":"✗"}`).join(" · ");
  const issues=coreIssues();
  return `<h2>Privacy Protector</h2><div class="st-${coreState}">${coreState==="green"?"Running":coreState==="orange"?"Needs a look":"Not protecting"}</div>
    <div class="rows">
      <span>DNS engine</span><span>${s.ok?"port "+esc(s.dnsPort)+" · up "+Math.round((s.uptimeSeconds||0)/3600)+"h":"not answering"}</span>
      <span>Upstream</span><span>${prov||"—"}</span>
      <span>Phone</span><span>${chosen("phone")?`${ip.recent?"connected":"not seen"} · ${ago(ip.lastSeenAt)}`:"off"}</span>
      <span>PC routing</span><span>${!chosen("pc")?"off":pc.routing?.routed?"through the engine":pc.routing?.routed===false?"<b class=\"st-red\">bypassing the engine</b>":"checking…"}</span>
      <span>Blocked</span><span>${s.blockedDomains??"—"} phone rules · ${pc.blocked??"—"} PC rules</span>
      <span>Records</span><span>${s.events??"—"} DNS events · ${(s.classificationEngine||{}).total??"—"} domains studied</span>
      <span>Apps</span><span>${phoneApps.length} detected</span>
      <span>PC review</span><span>${esc(rv.state||"—")} · last ${ago(rv.lastRunAt)}${rv.lastError?" · <b class=\"st-orange\">error</b>":""}</span>
    </div>
    ${issues.length?`<div class="sec">${issues.map(i=>`<div class="dom ${i.sev}"><div class="t">${esc(i.title)}</div>${i.text?`<div class="l">${esc(i.text)}</div>`:""}</div>`).join("")}</div>`
      :`<div class="sec mut">Nothing needs you.</div>`}`;
}
/* Engine alerts (safety) by code alone and immediately; the rest goes through the judge */
function coreIssues(){
  return rawCoreIssues().map(i=>({...i,sev:i.safety?i.sev:judgedStatus(i.key,i.sev)})).filter(i=>i.sev!=="green");
}
function rawCoreIssues(){
  return rawCore().map(i=>({...i,key:"core:"+(i.title+" "+(i.text||"")).replace(/\d+/g,"#").slice(0,160)}));
}
/* Only what you turned on in Settings can raise a warning */
const chosen=key=>typeof choice==="function"&&choice(key);
function rawCore(){
  const s=st.status||{}, pc=st.pc||{}, out=[];
  if(st.status&&!s.ok) out.push({sev:"red",safety:true,title:"The DNS engine isn't answering"});
  if((chosen("phone")||chosen("pc"))&&(s.dnsEngine?.providers||[]).length&&!(s.dnsEngine.providers.some(p=>p.state==="healthy"))) out.push({sev:"red",safety:true,title:"No upstream DNS provider is healthy"});
  if(chosen("pc")&&pc.routing?.routed===false) out.push({sev:"red",safety:true,title:"The PC bypasses the engine",text:"The PC's connections don't go through the engine, so nothing is watched or blocked. Turn PC protection on in Settings."});
  const rem=s.connectionReminder||{};
  if(chosen("phone")&&(rem.state==="lost"||rem.state==="disconnected")) out.push({sev:"orange",title:`The phone isn't connected${rem.silentForSeconds?" for "+Math.round(rem.silentForSeconds/60)+"m":""}: reconnect it to the modem (DNS ${rem.dnsAddress||"—"})`});
  if(s.judgeNotes) out.push({sev:"orange",safety:true,title:`The judge couldn't settle ${s.judgeNotes} decision(s): they wait for your review`});
  if(pc.review?.lastError) out.push({sev:"orange",title:"The last PC review failed",text:pc.review.lastError});
  return out;
}

/* ------------------------------------------------------------ Tray panels */
const PANEL_BTN=["review","open-activity","open-perms","open-security","open-ledger","open-paid","open-models","open-settings"];
function closePanel(){view=null;$("#panel").classList.remove("show","wide");PANEL_BTN.forEach(id=>$("#"+id).classList.remove("on"))}
function openPanel(id,wide){
  closeDetail(); PANEL_BTN.forEach(x=>$("#"+x).classList.toggle("on",x===id));
  const pn=$("#panel"), b=$("#"+id).getBoundingClientRect();
  pn.classList.toggle("wide",!!wide); pn.classList.add("show");
  const w=pn.offsetWidth; pn.style.top=(TOP+2)+"px"; pn.style.left=Math.max(12,Math.min(b.left-(id.startsWith("open")?w-b.width:0),W-w-12))+"px";
}
function show(html){const pn=$("#panel"),keep=pn.scrollTop;pn.innerHTML=html;pn.scrollTop=keep}
const MARK={done:["✓","done"],not_done:["✗","not done"],wrong:["✗","done wrong"],missed:["!","skipped silently"]};
const t5=iso=>iso?String(iso).slice(5,16).replace("T"," "):"";

function drawReview(){
  const r=(st.pc||{}).review||{}, c=(st.pc||{}).counts||{};
  show(`<h2>Review</h2><div class="mut">The local engine studies every new PC domain. With models turned on in Settings, a writer reads it, the jury decides and the judge confirms before anything runs. Red that a program doesn't need gets blocked.</div>
    <div class="rows"><span>State</span><span>${esc(r.state||"—")}</span><span>Last run</span><span>${ago(r.lastRunAt)} · ${r.reviewed??0} reviewed · ${r.blocked??0} blocked</span>
      <span>Cycles</span><span>${r.cycles??"—"}</span>
      <span>PC domains</span><span><b class="st-red">${c["color:red"]??0}</b> red · <b class="st-orange">${c["color:orange"]??0}</b> orange · <b class="st-green">${c["color:green"]??0}</b> green</span>
      <span>Decisions</span><span>${c["auto-blocked"]??0} auto-blocked · ${c.protected??0} protected · ${c["guard-released"]??0} released</span></div>
    ${r.lastError?`<div class="dom red"><div class="l">${esc(r.lastError)}</div></div>`:""}
    <div class="btns"><button id="review-now">Review PC now</button></div>${aiHtml()}`);
}
function drawLedger(d){
  if(!d){show(`<h2>Model work log</h2><div class="empty">…</div>`);return}
  const s=d.summary||{};
  const rows=(d.rows||[]).map(r=>{const[m,w]=MARK[r.column]||["?",r.column];
    return `<tr title="${esc(r.item)}"><td class="m m-${r.column}" title="${w}">${r.carried?"⟲":""}${m}</td><td>${esc(t5(r.at))}</td><td>${esc(r.task||"")}</td><td >${esc(r.item)}</td><td>${esc(r.model||r.provider||"")}</td></tr>`}).join("");
  show(`<h2>Model work log · unresolved</h2><div class="lg-key">Since ${esc(t5(d.since))}: ${s.done||0} ✓ · ${s.wrong||0} wrong · ${s.not_done||0} not done · ${s.missed||0} skipped</div>
    <div class="lg">${rows?`<table><colgroup><col class="w30px"><col class="w84px"><col class="w20p"><col><col class="w22p"></colgroup><thead><tr><th></th><th>Time</th><th>Task</th><th>Item</th><th>Model</th></tr></thead><tbody>${rows}</tbody></table>`:`<div class="empty">Nothing unresolved</div>`}</div>`);
}
function drawPaid(d){
  if(!d){show(`<h2>Model usage</h2><div class="empty">…</div>`);return}
  const s=d.summary||{};
  const rows=(d.models||d.rows||[]).map(r=>`<tr><td>${esc(r.task)}</td><td>${esc(r.model)}</td><td class="m m-done">${r.done}</td><td class="m m-wrong">${r.wrong}</td><td class="m m-not_done">${r.not_done}</td><td class="m">${Math.round((r.rate||0)*100)}%</td></tr>`).join("");
  show(`<h2>Model usage</h2><div class="lg-key">${s.calls||0} calls · ${s.models||0} models · ${s.perfect||0} perfect · the writer reads, the jury decides, the judge confirms</div>
    <div class="lg">${rows?`<table><colgroup><col class="w24p"><col><col class="w40px"><col class="w40px"><col class="w52px"><col class="w52px"></colgroup><thead><tr><th>Task</th><th>Model</th><th>✓</th><th>✗</th><th>Undone</th><th>Rate</th></tr></thead><tbody>${rows}</tbody></table>`:`<div class="empty">No model under 100%</div>`}</div>`);
}
function drawModels(d){
  if(!d){show(`<h2>Model reviewers</h2><div class="empty">…</div>`);return}
  const rows=(d.slots||[]).map(s=>`<div class="pv" title="${esc(s.slot)}"><span class="pn">${esc(s.model)}</span><span class="${s.passed?"st-green":"st-red"}">${s.passed?"passed":"failed"}</span><span class="pc">${Math.round((s.score||0)*100)}%</span></div>`).join("");
  show(`<h2>Model reviewers</h2><div class="lg-key">${d.available?"Available":"Unavailable"} · exam on domains with a known verdict</div>${rows||`<div class="empty">No exam results yet</div>`}`);
}
/* Defender and Outlook: Defender protects and the app reads its status and asks for a scan, without changing its setting */
const SAC={0:"off",1:"on — blocks unsigned apps",2:"evaluating"};
const SCAN={clean:["st-green","clean"],threat:["st-red","threat"],error:["st-orange","not scanned"]};
const MAILV={danger:["st-red","removed"],promo:["st-orange","ad"],trackers:["st-orange","ad"],clean:["st-green","clean"]};
function drawSecurity(d){
  if(!d){show(`<h2>Defender and Outlook</h2><div class="empty">…</div>`);return}
  const df=d.defender||{}, s=df.status||{}, m=d.mail||{}, td=m.today||{}, au=(df.audit||{}).counts||{}, ap=(df.audit||{}).processes||{};
  const yes=v=>v?`<b class="st-green">on</b>`:`<b class="st-red">off</b>`;
  const top=o=>Object.entries(o||{}).sort((a,b)=>b[1]-a[1]).slice(0,4).map(([n,c])=>`${esc(n)} ${c}`).join(" · ")||"—";
  const issues=(df.issues||[]).map(i=>`<div class="dom ${i.level==="red"?"red":"orange"}"><div class="t">${esc(i.title)}</div><div class="l">${esc(i.text||"")}</div>${i.command?`<div class="l mut">${esc(i.command)}</div>`:""}</div>`).join("");
  const threats=(df.threats||[]).slice(0,8).map(t=>`<div class="dom ${t.actionOk?"":"red"}"><div class="t">${esc(t.name||t.threatId)}</div><div class="l mut">${esc(t5(t.at))} · ${t.actionOk?"handled":"not handled"} · ${esc((t.resources||[])[0]||"")}</div></div>`).join("");
  const scans=(df.scans||[]).slice(0,8).map(x=>{const[c,w]=SCAN[x.verdict]||["",x.verdict];return `<div class="dom"><div class="t"><b class="${c}">${w}</b> ${esc(String(x.path).split("\\").pop())}</div><div class="l mut">${esc(t5(x.at))}${x.signature?" · signature "+esc(x.signature)+(x.signer?" ("+esc(x.signer)+")":""):""}</div></div>`}).join("");
  const mails=(m.recent||[]).slice(0,12).map(x=>{const[c,w]=MAILV[x.verdict]||["",x.verdict];return `<div class="dom"><div class="t"><b class="${c}">${w}${x.verdict==="danger"&&x.removed===false?" — failed":""}</b> ${esc(x.subject||"(no subject)")}</div><div class="l mut">${esc(x.sender)} · ${esc(t5(x.at))}</div>${(x.reasons||[]).length?`<div class="l">${esc(x.reasons.join(", "))}</div>`:""}</div>`}).join("");
  show(`<h2>Defender and Outlook</h2><div class="mut">Windows Defender protects; this app reads its state, asks it to scan new downloads, and checks new Outlook mail. It never changes Defender's settings.</div>
    <div class="rows">
      <span>Defender</span><span>${esc(s.mode||"—")} · real-time ${yes(s.realtime)} · tamper ${yes(s.tamper)}</span>
      <span>Signatures</span><span>${esc(s.signatureVersion||"—")} · ${ago(s.signatures)}</span>
      <span>Smart App Control</span><span>${esc(SAC[df.smartAppControl]??"unknown")}</span>
      <span>Antivirus</span><span>${esc((df.antivirus||[]).join(", ")||"—")}</span>
      <span>Audit week (24h)</span><span>ransomware ${au.folders??0}: ${top(ap.folders)} · Office/email ${au.asr??0}: ${top(ap.asr)}</span>
      <span>Outlook</span><span>${esc(m.outlook||"—")} · checked on arrival, last ${ago(m.lastRunAt)} · today <b class="st-red">${td.danger??0}</b> removed · <b class="st-orange">${td.promo??0}</b> ads · <b class="st-green">${td.clean??0}</b> clean · unread ${m.unread??0}</span>
      <span>Last read</span><span>${ago(df.readAt)}${df.readError?` · <b class="st-orange">${esc(df.readError)}</b>`:""}</span>
    </div>
    ${issues?`<div class="sec">${issues}</div>`:`<div class="sec mut">Nothing needs you.</div>`}
    ${threats?`<div class="sec"><h3>Detections</h3>${threats}</div>`:""}
    ${scans?`<div class="sec"><h3>Downloads scanned</h3>${scans}</div>`:""}
    ${mails?`<div class="sec"><h3>Recent mail</h3>${mails}</div>`:""}
    ${cleanupHtml(d.tempCleanup)}`);
}
/* Temporary file cleanup: shown to the user first; nothing is deleted until they approve */
const MB=b=>b>=1073741824?(b/1073741824).toFixed(2)+" GB":Math.round((b||0)/1048576)+" MB";
function cleanupHtml(t){
  if(!t)return "";
  const p=t.preview||{}, r=t.lastRun;
  const top=(p.top||[]).slice(0,8).map(e=>`<div class="l mut">${MB(e.bytes)} · ${esc(String(e.path).split("\\").pop())}</div>`).join("");
  const head=`<h3>Temp cleanup</h3><div class="rows">
      <span>Rule</span><span>daily at ${t.hour}:00 · files untouched for ${t.ageDays} days · never ${esc((t.keep||[]).join(", "))}</span>
      ${r?`<span>Last run</span><span>${ago(r.at)} · ${MB(r.bytes)} freed · ${r.deleted} files${r.locked?" · "+r.locked+" in use, skipped":""}</span>`:""}
      <span>Total freed</span><span>${MB(t.totalBytes)}</span>
      ${t.postponedUntil?`<span>Postponed</span><span>an installer is running (${esc((t.postponedFor||[]).join(", "))})</span>`:""}
      ${(p.skipped||[]).length?`<span>Needs admin</span><span>${esc(p.skipped.join(", "))}: skipped</span>`:""}</div>`;
  if(t.approved)return `<div class="sec">${head}</div>`;
  return `<div class="sec">${head}<div class="dom orange"><div class="t">First cleanup waits for you: ${MB(p.bytes)} in ${p.files??0} files</div>
    <div class="l">This is what the first cleanup deletes; nothing has been deleted yet. After you approve, it runs by itself every day at 9 pm.</div>${top}
    <div class="btns"><button id="tc-preview">Recount</button><button id="tc-approve">Approve and clean now</button></div></div></div>`;
}
const PANELS={"open-security":["/api/pc/security",drawSecurity,true],"open-ledger":["/api/model-ledger",drawLedger,true],"open-paid":["/api/model-ledger/paid",drawPaid,true],
  "open-models":["/api/ai/status",drawModels,false]};

document.addEventListener("click", async e=>{
  const b=e.target.closest("button"); if(!b) return;
  const id=b.id;
  if(id==="dev-pc"||id==="dev-phone"){device=id==="dev-pc"?"pc":"phone";try{localStorage.setItem("pp-device",device)}catch(err){}
    closeDetail();closePanel();drawBar();refreshPlanets();return}
  if(b.dataset.t){await toolClick(b);return}
  if(PANEL_BTN.includes(id)){
    if(b.classList.contains("on")){closePanel();return}
    if(id==="review"){openPanel(id,true);view="review";drawReview();await loadAI();if(view==="review")drawReview();pollAI();return}
    if(TOOL_PANELS[id]){openPanel(id,true);view=id;return TOOL_PANELS[id]()}
    const [url,draw,wide]=PANELS[id]; openPanel(id,wide); view=id; draw(null);
    const d=await getJson(url,null); if(view===id){d?draw(d):show(`<div class="empty">Couldn't load it</div>`)}
    return;
  }
  if(id==="tc-approve"||id==="tc-preview"){
    if(id==="tc-approve"&&!armed(b,"Confirm: delete now"))return;
    b.disabled=true;try{await post("/api/pc/temp-cleanup/"+(id==="tc-approve"?"approve":"preview"),{});
      note(id==="tc-approve"?"Cleanup started. It runs by itself every day at 9 pm.":"Recounted");
      const d=await getJson("/api/pc/security",null);if(view==="open-security"&&d)drawSecurity(d)}catch(err){note(err.message)}return}
  if(id==="review-now"){b.disabled=true;try{await post("/api/pc/review",{});note("PC review started")}catch(err){note(err.message)}return}
  if(b.dataset.more){const k=b.dataset.more;expanded.has(k)?expanded.delete(k):expanded.add(k);drawDetail();return}
  if(b.dataset.cap){
    if(!b.classList.contains("arm")){const t=b.textContent;b.classList.add("arm");b.textContent=b.dataset.cap==="deny"?"Confirm deny":"Confirm restore";
      setTimeout(()=>{b.classList.remove("arm");b.textContent=t},4000);return}
    b.disabled=true;
    try{await post("/api/pc/capability-permission",{key:b.dataset.key,action:b.dataset.cap});note(b.dataset.cap==="deny"?"Denied in Windows":"Restored");await load()}
    catch(err){note("Not saved: "+err.message,5000);b.disabled=false}
    return}
  if(b.dataset.act){
    const act=b.dataset.act, dom=b.dataset.dom;
    if(act==="block"&&!b.classList.contains("arm")){b.classList.add("arm");b.textContent="Confirm block";setTimeout(()=>{b.classList.remove("arm");b.textContent="Block"},4000);return}
    b.disabled=true;
    try{await post(device==="pc"?"/api/pc/decision":"/api/policy",{domain:dom,action:act});note(`${dom}: ${act==="reset"?"back to automatic review":act==="block"?"blocked":act==="allow"?"allowed":"monitored"}`);await load()}
    catch(err){note("Not saved: "+err.message,5000);b.disabled=false}
  }
});
document.addEventListener("keydown",e=>{if(e.key==="Escape"){closePanel();closeDetail()}});

/* ------------------------------------------------------------ Loading */
function drawBar(){$("#dev-pc").classList.toggle("on",device==="pc");$("#dev-phone").classList.toggle("on",device==="phone")}
function refreshPlanets(){setPlanets(bodies());if(sel&&sel!==CORE_KEY)drawDetail()}
let slowAt=0;
async function load(){
  const slow=Date.now()-slowAt>120000;   // Categories and the application list are large and change slowly: every two minutes
  const [s,pc,dm,caps,apps,cl,pol]=await Promise.all([getJson("/api/status",null),getJson("/api/pc/status",null),
    getJson("/api/pc/domains?limit=100000",{items:[]}),getJson("/api/pc/capabilities",null),slow?getJson("/api/apps",null):null,slow?getJson("/api/classifications",null):null,getJson("/api/policy",null)]);
  st={status:s,pc}; pcItems=dm?.items||[]; pcPrograms=dm?.programs||[]; if(caps)capGroups=caps.groups||[];
  if(apps){phoneApps=apps.detectedApps||[];profiles=apps.apps||[]} if(cl){classes=cl.domains||{};slowAt=Date.now()} if(pol)policy=pol.domains||{};
  const issues=coreIssues(); coreState=issues.some(i=>i.sev==="red")?"red":issues.length?"orange":"green";
  refreshPlanets(); if(sel===CORE_KEY)drawDetail(); if(view==="review")drawReview(); toolsOnLoad(); askJudge();
}
drawBar(); layout(); requestAnimationFrame(frame); load(); setInterval(load,30000);
