// Theme
document.getElementById('themeToggle').addEventListener('click', () => {
  document.body.classList.toggle('dark-mode');
  localStorage.setItem('theme', document.body.classList.contains('dark-mode') ? 'dark' : 'light');
});

// Load saved theme
if (localStorage.getItem('theme') === 'dark') {
  document.body.classList.add('dark-mode');
}

// Routing
const views = {};
document.querySelectorAll('.view').forEach(v => views[v.id] = v);
function showView(id) {
  Object.values(views).forEach(v => v.classList.add('hidden'));
  (views[id] || views['view-dashboard']).classList.remove('hidden');
}
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    const tool = btn.dataset.tool;
    if (tool === 'runbook') {
      renderRunbook(btn.dataset.runbook);
      showView('view-runbook');
    } else {
      showView('view-' + tool);
    }
  });
});

// Subnetting
function ipToInt(ip) {
  const a = ip.split('.').map(Number);
  return ((a[0] << 24) >>> 0) + (a[1] << 16) + (a[2] << 8) + a[3];
}
function intToIp(n) {
  return [(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255].join('.');
}
function maskFromPrefix(p) {
  return p===0 ? 0 : (0xFFFFFFFF << (32-p)) >>> 0;
}
document.getElementById('subnet-calc').addEventListener('click', () => {
  const ip = ipToInt(document.getElementById('subnet-ip').value);
  const prefix = Number(document.getElementById('subnet-mask').value);
  const mask = maskFromPrefix(prefix);
  const network = (ip & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  document.getElementById('subnet-out').value =
    `Network: ${intToIp(network)}\nBroadcast: ${intToIp(broadcast)}`;
});

// CIDR
document.getElementById('cidr-calc').addEventListener('click', () => {
  const ip = ipToInt(document.getElementById('cidr-ip').value);
  const prefix = Number(document.getElementById('cidr-prefix').value);
  const mask = maskFromPrefix(prefix);
  const network = (ip & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  document.getElementById('cidr-out').value =
    `Network: ${intToIp(network)}/${prefix}\nBroadcast: ${intToIp(broadcast)}`;
});

// Wildcard
function parseDotted(str){return str.split('.').map(Number);}
function wildcardFromMask(oct){return oct.map(o=>255-o);}
document.getElementById('wm-fromMask').addEventListener('click', () => {
  const val = parseDotted(document.getElementById('wm-subnet').value);
  document.getElementById('wm-out-fromMask').value = wildcardFromMask(val).join('.');
});
document.getElementById('wm-fromCidr').addEventListener('click', () => {
  const prefix = Number(document.getElementById('wm-cidr').value);
  const mask = maskFromPrefix(prefix);
  const arr = [(mask>>>24)&255,(mask>>>16)&255,(mask>>>8)&255,mask&255];
  document.getElementById('wm-out-mask').value = arr.join('.');
  document.getElementById('wm-out-wild').value = arr.map(o=>255-o).join('.');
});

// Base64
function b64enc(s){return btoa(unescape(encodeURIComponent(s)));}
function b64dec(s){return decodeURIComponent(escape(atob(s)));}
document.getElementById('b64-encode').addEventListener('click',()=>{document.getElementById('b64-out').value=b64enc(document.getElementById('b64-in').value);});
document.getElementById('b64-decode').addEventListener('click',()=>{document.getElementById('b64-out').value=b64dec(document.getElementById('b64-in').value);});

// ALE
document.getElementById('calc-ale').addEventListener('click', () => {
  const av = Number(document.getElementById('av').value);
  const ef = Number(document.getElementById('ef').value);
  const aro = Number(document.getElementById('aro').value);
  const sle = av * ef;
  const ale = sle * aro;
  document.getElementById('ale-out').value = `SLE=${sle}\nALE=${ale}`;
});

// CVSS
document.getElementById('cvss-build').addEventListener('click', () => {
  const av = document.getElementById('cvss-av').value;
  document.getElementById('cvss-vector').value = "CVSS:3.1/" + av;
});

// Regex
document.getElementById('re-run').addEventListener('click', () => {
  const pat = document.getElementById('re-pattern').value;
  const flags = document.getElementById('re-flags').value;
  const txt = document.getElementById('re-text').value;
  try {
    const re = new RegExp(pat, flags);
    const matches = [...txt.matchAll(re)];
    document.getElementById('re-out').value = matches.map(m=>`Match: ${m[0]}`).join("\n");
  } catch(e) {
    document.getElementById('re-out').value = "Error: "+e.message;
  }
});

// Runbooks
const RUNBOOKS = {
  ransomware:{title:"Ransomware",quick:["Isolate","Disable","Block"],full:["Scope","Collect","Contain"]},
  phishing:{title:"Phishing",quick:["Block domains","Notify users"],full:["Collect headers","Contain"]},
  unauth:{title:"Unauthorized",quick:["Reset password"],full:["Review sign-ins"]}
};
function renderRunbook(key){
  const rb = RUNBOOKS[key];
  document.getElementById('rb-title').innerText = rb.title;
  document.getElementById('rb-quick').innerText = "Quick:\n" + rb.quick.join("\n");
  document.getElementById('rb-full').innerText = "Full:\n" + rb.full.join("\n");
}
