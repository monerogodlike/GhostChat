// GhostCHAT PFS build
/* global QRCode */

import { initializeApp } from "https://www.gstatic.com/firebasejs/9.22.0/firebase-app.js";
import { getDatabase, ref, push, onChildAdded, onValue, runTransaction, serverTimestamp, set } from "https://www.gstatic.com/firebasejs/9.22.0/firebase-database.js";
import { getAuth, signInAnonymously } from "https://www.gstatic.com/firebasejs/9.22.0/firebase-auth.js";

const firebaseConfig = {
  apiKey: "AIzaSyBmBE4Mjb6q7yjp32Rs0OEOaTmEokAG2Xo",
  authDomain: "anon-chat-5801b.firebaseapp.com",
  databaseURL: "https://anon-chat-5801b-default-rtdb.firebaseio.com",
  projectId: "anon-chat-5801b",
  storageBucket: "anon-chat-5801b.firebasestorage.app",
  messagingSenderId: "375816738737",
  appId: "1:375816738737:web:3876f1d50fa9e45be10f90"
};

// XSS hardening: sanitize user-provided room names to alphanum + basic symbols
function __sanitizeRoomName__(v){
  try{
    v = (v||"").toString();
    // Trim and collapse spaces
    v = v.replace(/[\u0000-\u001F\u007F]/g, "").trim();
    // Limit length
    return v.slice(0, 120);
  }catch{return "";}
}


const appFB = initializeApp(firebaseConfig);
const db = getDatabase(appFB);
const auth = getAuth(appFB);
signInAnonymously(auth).catch(e=>console.warn("Anon auth error", e));

const $ = id=>document.getElementById(id);
let room = null;
let uid = localStorage.uid||("u_"+Math.random().toString(36).slice(2,8)); localStorage.uid=uid;

// ===== AES helpers =====
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const ub64 = b => Uint8Array.from(atob(b),c=>c.charCodeAt(0));
const keyToCrypto = raw => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt","decrypt"]);
async function enc(text,raw){
  const key=await keyToCrypto(raw);
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,new TextEncoder().encode(text));
  return {iv:b64(iv),ct:b64(ct)};
}
async function dec(msg,raw){
  try{
    const key=await keyToCrypto(raw);
    const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:ub64(msg.iv)},key,ub64(msg.ct));
    return new TextDecoder().decode(pt);
  }catch{return null;}
}

// ===== PFS (ECDH) helpers =====
async function genECDHPair(){ return crypto.subtle.generateKey({name:"ECDH", namedCurve:"P-256"}, true, ["deriveKey","deriveBits"]); }
async function exportPubRawB64(pubKey){ const raw = await crypto.subtle.exportKey("raw", pubKey); return btoa(String.fromCharCode(...new Uint8Array(raw))); }
async function importPubRawB64(b64s){ const raw = Uint8Array.from(atob(b64s), c=>c.charCodeAt(0)); return crypto.subtle.importKey("raw", raw, {name:"ECDH", namedCurve:"P-256"}, true, []); }
async function deriveAESFromECDH(privKey, peerPubB64){
  const peerKey = await importPubRawB64(peerPubB64);
  const bits = await crypto.subtle.deriveBits({name:"ECDH", public: peerKey}, privKey, 256);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hkdfKey = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey({name:"HKDF", hash:"SHA-256", salt, info:new Uint8Array([])}, hkdfKey, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
  const raw = await crypto.subtle.exportKey("raw", aesKey);
  return { keyB64: btoa(String.fromCharCode(...new Uint8Array(raw))) };
}

// ===== Local key store =====
function saveKey(r,k){ let o=JSON.parse(localStorage.keys||"{}"); o[r]=k; localStorage.keys=JSON.stringify(o); }
function getKey(r){ let o=JSON.parse(localStorage.keys||"{}"); return o[r]; }
function delKey(r){ let o=JSON.parse(localStorage.keys||"{}"); delete o[r]; localStorage.keys=JSON.stringify(o); }

// Rooms UX
const roomsKey="roomsListGC";
function renderRooms(){ const arr=JSON.parse(localStorage.getItem(roomsKey)||"[]"); const box=$("roomsList"); box.innerHTML=""; arr.forEach(r=>{let b=document.createElement("button"); b.textContent=r; b.onclick=()=>join(r); box.appendChild(b);}); }
function saveRoom(r){ r=__sanitizeRoomName__(r); const arr=JSON.parse(localStorage.getItem(roomsKey)||"[]"); if(!arr.includes(r)) arr.push(r); localStorage.setItem(roomsKey, JSON.stringify(arr)); renderRooms(); }
function clearRooms(){ localStorage.removeItem(roomsKey); renderRooms(); }
renderRooms();

// QR/link
function showQR(r,k){
  const link=location.origin+location.pathname+`?room=${r}&k=${encodeURIComponent(k)}`;
  $("inviteLink").textContent=link;
  const qr=$("qrcode"); qr.innerHTML=""; new QRCode(qr,{text:link,width:160,height:160,colorDark:"#00ff90",colorLight:"#001a0f"});
  $("btnCopy").onclick=()=>navigator.clipboard.writeText(link);
}
function showKeyOnlyQR(r){
  const k=getKey(r); if(!k) return alert("Ключ отсутствует");
  const qr=$("qrcode"); qr.innerHTML=""; new QRCode(qr,{text:k,width:160,height:160,colorDark:"#00ff90",colorLight:"#001a0f"});
}

// State
let ecdhPair=null;

// PFS handshake
async function startHandshake(r){
  try{
    ecdhPair = await genECDHPair();
    const pubB64 = await exportPubRawB64(ecdhPair.publicKey);
    set(ref(db, `rooms/${r}/handshake/${uid}`), {pub: pubB64, ts: serverTimestamp()});
    onChildAdded(ref(db, `rooms/${r}/handshake`), async s=>{
      const v=s.val(); if(!v||!v.pub) return; if(s.key===uid) return;
      const derived = await deriveAESFromECDH(ecdhPair.privateKey, v.pub);
      saveKey(r, derived.keyB64); // override session key
      console.log("PFS session ready");
    });
  }catch(e){ console.warn("handshake error", e); }
}

// Join/create
async function createRoom(){
  const r=Math.random().toString(36).slice(2,12);
  const raw=crypto.getRandomValues(new Uint8Array(32));
  const k=b64(raw);
  saveKey(r,k); saveRoom(r);
  showQR(r,k);
  if(!$("qrBox").classList.contains("open")) toggleQR();
  join(r);
}
function joinFromInput(){
  let v=__sanitizeRoomName__($("joinInput").value); if(!v) return;
  try{ const u=new URL(v); const r=u.searchParams.get("room"); const k=u.searchParams.get("k"); if(r){ if(k) saveKey(r,k); join(r); return; } }catch{}
  join(v);
}
function join(r){
  room=r; saveRoom(r);
  $("chatArea").innerHTML="";
  const k=getKey(r); if(k) showQR(r,k);
  startHandshake(r);
  const refMsg=ref(db,`rooms/${r}/messages`);
  onChildAdded(refMsg,async s=>{
    const m=s.val();
    if(m.system==="panic"){ $("chatArea").innerHTML="<div style='color:#ff8282;padding:8px'>⚠ Палево — чат стёрт</div>"; return; }
    let text="🔒";
    const sk=getKey(r);
    if(sk && m.ct && m.iv){ const t=await dec(m,ub64(sk)); if(t) text=t; }
    renderMsg(m.uid===uid, text, s.key);
  });
}

// Render (kept DOM to preserve reactions)
function renderMsg(isMine, text, key){
  if(document.querySelector(`[data-id="${key}"]`)) return;
  const row=document.createElement("div"); row.className="msgRow"+(isMine?" self":""); row.dataset.id=key;
  const b=document.createElement("div"); b.className="bubble"+(isMine?" mine":""); b.textContent=text; row.appendChild(b);
  const reacts=document.createElement("div"); reacts.className="reacts";
  ["❤️","😂","🔥"].forEach(e=>{ let btn=document.createElement("button"); btn.className="reactBtn"; btn.innerHTML=`${e} <span>0</span>`; btn.onclick=(()=>toggleReact(key,e)); reacts.appendChild(btn); });
  row.appendChild(reacts);
  $("chatArea").appendChild(row);
  $("chatArea").scrollTop=$("chatArea").scrollHeight;
  onValue(ref(db,`rooms/${room}/messages/${key}/reactions`),snap=>updateReactUI(key,snap.val()));
}

function toggleReact(key,emoji){
  const r=ref(db,`rooms/${room}/messages/${key}/reactions/${emoji}`);
  runTransaction(r,current=>{ current=current||{}; if(current[uid]) delete current[uid]; else current[uid]=true; return current; });
}
function updateReactUI(key,data){
  const row=document.querySelector(`[data-id="${key}"]`); if(!row) return;
  const btns=row.querySelectorAll(".reactBtn");
  ["❤️","😂","🔥"].forEach((e,i)=>{ const users=data&&data[e]?Object.keys(data[e]):[]; btns[i].querySelector("span").textContent=users.length; btns[i].classList.toggle("active",users.includes(uid)); });
}

// Send (PFS key required)
async function sendMsg(){
  if(!room) return alert("Создайте или войдите в комнату");
  const text=$("msgInput").value.trim(); if(!text) return;
  const k=getKey(room); if(!k) return alert("Нет ключа (ожидаем PFS handshake)");
  const e=await enc(text,ub64(k));
  await push(ref(db,`rooms/${room}/messages`),{uid,...e,ts:serverTimestamp()});
  $("msgInput").value=""; autoGrow();
}
$("btnSend").onclick=sendMsg;
$("msgInput").addEventListener("keydown",e=>{ if(e.key==="Enter"&&!e.shiftKey){ e.preventDefault(); sendMsg(); } });
function autoGrow(){ const el=$("msgInput"); el.style.height="auto"; el.style.height=Math.min(160, el.scrollHeight)+"px"; }
$("msgInput").addEventListener("input", autoGrow);

// Panic
function panic(){
  if(!room) return;
  const base=ref(db,`rooms/${room}/messages`);
  push(base,{system:"panic"}); set(base,null);
  document.querySelector("#appBox").style.display="none";
  const n=document.createElement("div"); n.style="color:#ff4d4d;font-size:20px;text-align:center;margin-top:40vh"; n.textContent="❌ Чат уничтожен"; document.body.appendChild(n);
}

// TTL prune (client)
function pruneOldMessages(r){
  const cutoff=Date.now()-30*60*1000;
  (async()=>{
    const mod = await import("https://www.gstatic.com/firebasejs/9.22.0/firebase-database.js");
    const snap = await mod.get(ref(db, `rooms/${r}/messages`)).catch(()=>null);
    if(!snap||!snap.exists()) return;
    const val = snap.val();
    for(const k in val){ const m=val[k]; const ts=(typeof m.ts==='number')?m.ts:0; if(ts && ts<cutoff){ set(ref(db,`rooms/${r}/messages/${k}`), null);} }
  })();
}
setInterval(()=>{ if(room) pruneOldMessages(room); }, 5*60*1000);

// UI wiring
$("btnCreate").onclick=createRoom;
$("btnJoin").onclick=joinFromInput;
$("btnClear").onclick=()=>{ localStorage.keys="{}"; clearRooms(); alert("Локальные данные очищены"); };
$("btnQR").onclick=()=>{ const el=$("qrBox"); const isOpen=el.classList.toggle("open"); el.setAttribute("aria-hidden", String(!isOpen)); };
$("btnPanic").onclick=panic;
$("btnCopy").onclick=()=>{ const t=$("inviteLink").textContent.trim(); if(t) navigator.clipboard.writeText(t); };
$("btnShowKey").onclick=()=>{ if(!room) return; const k=getKey(room); if(k) alert("AES ключ (base64):\n"+k); else alert("Ключ не найден"); };
$("btnKeyQR").onclick=()=>{ if(!room) return; showKeyOnlyQR(room); };
$("btnResetKey").onclick=()=>{ if(!room) return; delKey(room); alert("Ключ удалён из браузера"); };
$("attachBtn").onclick=()=>window.open("https://ru.files.fm/","_blank");

// URL auto join
(()=>{ const p=new URLSearchParams(location.search); const r=p.get("room"),k=p.get("k"); if(r){ if(k) saveKey(r,k); join(r);} })();

// Matrix
const c=document.getElementById("matrixBG"), ctx=c.getContext("2d");
function resize(){ c.width=innerWidth; c.height=innerHeight; }
resize(); addEventListener("resize", resize);
const cols=()=>Math.floor(c.width/12); let ys=new Array(cols()).fill(0);
(function matrix(){ ctx.fillStyle="rgba(0,0,0,.06)"; ctx.fillRect(0,0,c.width,c.height); ctx.fillStyle="#00ff90"; ctx.font="14px monospace"; for(let i=0;i<cols();i++){ let ch=Math.random()<.5?"0":"1"; ctx.fillText(ch,i*12,ys[i]*14); if(ys[i]*14>c.height && Math.random()>.97) ys[i]=0; ys[i]++; } requestAnimationFrame(matrix); })();

// window.*
window.createRoom=createRoom; window.joinFromInput=joinFromInput; window.panic=panic;
