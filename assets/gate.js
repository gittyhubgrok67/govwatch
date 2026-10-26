/* Loader: fetches data.json (and, on demand, data-archive-YYYY.json chunks with the same key via window.GW_FETCH). Encrypted envelope -> PBKDF2-SHA256 -> AES-256-GCM decrypt in the browser.
   Preview builds carry {"plain": bundle} instead and skip the password screen. */
(function(){
"use strict";
var KEY="gw-key", $=function(id){return document.getElementById(id)};
var b64=function(s){var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u};
var tob64=function(buf){var u=new Uint8Array(buf),s="";for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s)};
function toggleTheme(){var t=document.documentElement.getAttribute("data-theme")==="light"?"dark":"light";document.documentElement.setAttribute("data-theme",t);try{localStorage.setItem("gw-theme",t)}catch(e){}}
$("gateTheme").onclick=toggleTheme;
function err(m){$("gateErr").textContent=m||""}
function busy(b){$("unlock").disabled=b;$("unlock").textContent=b?"Unlocking…":"Unlock"}
function boot(bundle){
  var app=$("app");app.innerHTML=bundle.html;window.GW=bundle.data;
  window.GW_LOCK=ENV&&ENV.ct?function(){try{localStorage.removeItem(KEY)}catch(e){}location.reload()}:null;
  $("gate").classList.add("hidden");app.classList.remove("hidden");
  (new Function(bundle.js))();
  if(location.hash){var t=document.getElementById(location.hash.slice(1));if(t)t.scrollIntoView()}
}
var ENV=null,AKEY=null;
window.GW_FETCH=function(name){return fetch(name,{cache:"no-cache"}).then(function(r){if(!r.ok)throw new Error(r.status);return r.json()}).then(function(e){if(e.plain)return e.plain;if(!AKEY)throw new Error("locked");return crypto.subtle.decrypt({name:"AES-GCM",iv:b64(e.iv)},AKEY,b64(e.ct)).then(function(pt){return JSON.parse(new TextDecoder().decode(pt))})})};
async function decryptWith(key){
  AKEY=key;
  var pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:b64(ENV.iv)},key,b64(ENV.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}
async function derive(pw){
  var base=await crypto.subtle.importKey("raw",new TextEncoder().encode(pw),"PBKDF2",false,["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2",salt:b64(ENV.salt),iterations:ENV.iter,hash:"SHA-256"},base,{name:"AES-GCM",length:256},true,["decrypt"]);
}
async function tryRemembered(){
  try{var s=JSON.parse(localStorage.getItem(KEY)||"null");if(!s||s.salt!==ENV.salt||s.iter!==ENV.iter)return false;
    var k=await crypto.subtle.importKey("raw",b64(s.k),{name:"AES-GCM"},false,["decrypt"]);
    boot(await decryptWith(k));return true;}catch(e){try{localStorage.removeItem(KEY)}catch(_){}return false}
}
$("gateForm").addEventListener("submit",async function(e){
  e.preventDefault();if(!ENV)return;err("");busy(true);
  try{var k=await derive($("pw").value),bundle=await decryptWith(k);
    if($("remember").checked){try{localStorage.setItem(KEY,JSON.stringify({salt:ENV.salt,iter:ENV.iter,k:tob64(await crypto.subtle.exportKey("raw",k))}))}catch(_){}}
    $("pw").value="";boot(bundle);
  }catch(x){busy(false);err("Wrong password. Try again.");$("pw").select();}
});
fetch("data.json",{cache:"no-cache"}).then(function(r){if(!r.ok)throw new Error(r.status);return r.json()}).then(async function(env){
  ENV=env;
  if(env.plain){boot(env.plain);return}
  if(!window.crypto||!crypto.subtle){err("This browser can't decrypt the page (needs HTTPS and Web Crypto).");return}
  await tryRemembered();
}).catch(function(){err("Couldn't load data.json. Serve this folder over HTTP(S), not file://.")});
})();
