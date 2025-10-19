// ======= State & Defaults =======
const state = {
  email: null,
  totpSecret: "JBSWY3DPEHPK3PXP", // Base32 demo secret
  jwtSecret: "andrew-iam-portfolio-demo-key", // HS256 demo key (client-only demo)
  interval: null,
  audit: [],
  latestPayload: null,
  latestToken: null,
  _totpKey: null, // CryptoKey for HMAC-SHA1
  _jwtKey: null   // CryptoKey for HMAC-SHA256
};
const policy = {
  expectedAud: "https://app.example.com",
  requireMFA: true,
  minRoles: 1,
  expLeewaySec: 0
};

// ======= Utilities =======
function go(n){
  document.querySelectorAll('.panel').forEach(p=>p.classList.add('hidden'));
  const el = document.getElementById(`step-${n}`);
  if(el) el.classList.remove('hidden');
  document.querySelectorAll('.step').forEach(s=>{
    s.classList.toggle('active', Number(s.dataset.step)===Number(n));
  });
  logAudit('navigate', { step: n });
}

function downloadFile(name, text){
  const blob = new Blob([text], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  setTimeout(()=>URL.revokeObjectURL(url), 1000);
}

const b64u = {
  encode(bytes){
    let bin = '';
    bytes.forEach(b=>bin += String.fromCharCode(b));
    return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  },
  decodeToBytes(str){
    str = str.replace(/-/g,'+').replace(/_/g,'/');
    const pad = str.length % 4 === 2 ? '==' : str.length % 4 === 3 ? '=' : '';
    const bin = atob(str + pad);
    const arr = new Uint8Array(bin.length);
    for(let i=0;i<bin.length;i++) arr[i] = bin.charCodeAt(i);
    return arr;
  },
  decodeJSON(str){
    const bytes = b64u.decodeToBytes(str);
    const text = new TextDecoder().decode(bytes);
    return JSON.parse(text);
  },
  encodeJSON(obj){
    const text = JSON.stringify(obj);
    const bytes = new TextEncoder().encode(text);
    return b64u.encode(bytes);
  }
};

function logAudit(event, details={}){
  const ts = new Date().toISOString();
  const entry = { ts, event, ...details };
  state.audit.push(entry);
  const pre = document.getElementById('audit-pre');
  pre.textContent = JSON.stringify(state.audit, null, 2);
}

// ======= Base32 (RFC 4648) =======
function base32DecodeToBytes(b32){
  const alph = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let cleaned = b32.toUpperCase().replace(/[^A-Z2-7]/g,'');
  let bits = '';
  for(const c of cleaned){
    const val = alph.indexOf(c);
    if(val < 0) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for(let i=0;i+8<=bits.length;i+=8){
    bytes.push(parseInt(bits.slice(i,i+8),2));
  }
  return new Uint8Array(bytes);
}

// ======= Crypto helpers (Web Crypto) =======
async function importHmacKey(raw, algo){
  const keyBytes = typeof raw === 'string' ? new TextEncoder().encode(raw) : raw;
  return crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: algo }, false, ['sign','verify']);
}

async function hmacSign(key, data){
  const buf = await crypto.subtle.sign('HMAC', key, data);
  return new Uint8Array(buf);
}

async function hmacVerify(key, data, sig){
  return crypto.subtle.verify('HMAC', key, sig, data);
}

// ======= TOTP (RFC 6238, SHA-1, 30s, 6 digits) =======
function counterFor(timeMs){
  return Math.floor(timeMs/1000/30);
}

function intToBytes8(n){
  const b = new ArrayBuffer(8);
  const v = new DataView(b);
  // big-endian
  v.setUint32(0, Math.floor(n / 0x100000000));
  v.setUint32(4, n >>> 0);
  return new Uint8Array(b);
}

async function totpAt(timeMs){
  if(!state._totpKey){
    const secretBytes = base32DecodeToBytes(state.totpSecret);
    state._totpKey = await importHmacKey(secretBytes, 'SHA-1');
  }
  const ctr = counterFor(timeMs);
  const msg = intToBytes8(ctr);
  const mac = await hmacSign(state._totpKey, msg);
  const offset = mac[mac.length-1] & 0x0f;
  const bin = ((mac[offset]&0x7f)<<24) | (mac[offset+1]<<16) | (mac[offset+2]<<8) | (mac[offset+3]);
  const otp = (bin % 1_000_000).toString().padStart(6,'0');
  return { code: otp, ctr };
}

function drawMockQR(){
  const canvas = document.getElementById('qr-canvas');
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  // background
  ctx.fillStyle = '#fff'; ctx.fillRect(0,0,w,h);
  ctx.strokeStyle = '#222'; ctx.lineWidth = 4; ctx.strokeRect(2,2,w-4,h-4);
  // fake finder patterns
  function finder(x,y){
    ctx.fillStyle = '#000'; ctx.fillRect(x,y,42,42);
    ctx.fillStyle = '#fff'; ctx.fillRect(x+6,y+6,30,30);
    ctx.fillStyle = '#000'; ctx.fillRect(x+12,y+12,18,18);
  }
  finder(12,12); finder(w-54-12,12); finder(12,h-54-12);
  // some random modules
  ctx.fillStyle = '#000';
  for(let i=0;i<120;i++){
    const x = 70 + Math.floor(Math.random()*90);
    const y = 20 + Math.floor(Math.random()*140);
    if((x%6===0)&&(y%6===0)) ctx.fillRect(x,y,6,6);
  }
}

// The otpauth URL (not displayed; included for completeness per requirements):
const otpauthURL = () => `otpauth://totp/Access%20Control%20%E2%80%A2%20Secure:${encodeURIComponent(state.email||'user@example.com')}?secret=${state.totpSecret}&issuer=Access%20Control%20%E2%80%A2%20Secure&algorithm=SHA1&digits=6&period=30`;

function startTotpLoop(){
  const codeEl = document.getElementById('totp-code');
  const ttlEl = document.getElementById('totp-ttl');
  if(state.interval) clearInterval(state.interval);
  state.interval = setInterval(async ()=>{
    const now = Date.now();
    const stepEnd = (counterFor(now)+1)*30*1000;
    const ttl = Math.max(0, Math.floor((stepEnd - now)/1000));
    ttlEl.textContent = String(ttl);
    const { code } = await totpAt(now);
    codeEl.textContent = code;
  }, 1000);
}

// ======= JWT (HS256) =======
async function ensureJwtKey(){
  if(!state._jwtKey){
    state._jwtKey = await importHmacKey(state.jwtSecret, 'SHA-256');
  }
}

function uuidv4(){
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40; // version
  b[8] = (b[8] & 0x3f) | 0x80; // variant
  const hex = [...b].map(x=>x.toString(16).padStart(2,'0'));
  return `${hex[0]}${hex[1]}${hex[2]}${hex[3]}-${hex[4]}${hex[5]}-${hex[6]}${hex[7]}-${hex[8]}${hex[9]}-${hex.slice(10).join('')}`;
}

async function issueJwt(){
  await ensureJwtKey();
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now()/1000);
  const payload = {
    iss: "https://idp.example.com",
    aud: "https://app.example.com",
    sub: state.email,
    name: "Andrew Symister (Demo)",
    roles: ["User","PAM-Viewer","Access-Reviewer"],
    groups: ["iam-lab","security","audit-readers"],
    amr: ["pwd","mfa"],
    scope: "openid profile email",
    iat: now,
    exp: now + 600,
    jti: uuidv4()
  };
  state.latestPayload = payload;
  const encHeader = b64u.encodeJSON(header);
  const encPayload = b64u.encodeJSON(payload);
  const signingInput = new TextEncoder().encode(`${encHeader}.${encPayload}`);
  const sigBytes = await hmacSign(state._jwtKey, signingInput);
  const signature = b64u.encode(sigBytes);
  const token = `${encHeader}.${encPayload}.${signature}`;
  state.latestToken = token;
  logAudit('jwt.issued', { sub: state.email, jti: payload.jti, exp: payload.exp });
  renderToken(token);
  renderClaims(payload);
  evaluatePolicy();
}

function renderToken(token){
  const pre = document.getElementById('token-pre');
  pre.textContent = token;
}

function renderClaims(payload){
  const table = document.getElementById('claims-table');
  table.innerHTML = '';
  const addRow = (k,v)=>{
    const tr = document.createElement('tr');
    const tdK = document.createElement('td'); tdK.className='key'; tdK.textContent = k;
    const tdV = document.createElement('td');
    if(Array.isArray(v)){
      const div = document.createElement('div'); div.className='badges';
      v.forEach(item=>{ const b = document.createElement('span'); b.className='badge'; b.textContent=item; div.appendChild(b); });
      tdV.appendChild(div);
    } else tdV.textContent = String(v);
    tr.appendChild(tdK); tr.appendChild(tdV);
    table.appendChild(tr);
  };
  Object.entries(payload).forEach(([k,v])=>addRow(k,v));
}

async function verifyJwtSignature(){
  if(!state.latestToken){ return false; }
  await ensureJwtKey();
  const [h,p,s] = state.latestToken.split('.');
  const signingInput = new TextEncoder().encode(`${h}.${p}`);
  const sigBytes = b64u.decodeToBytes(s);
  const ok = await hmacVerify(state._jwtKey, signingInput, sigBytes);
  document.getElementById('verify-status').textContent = ok ? 'Signature valid ✅' : 'Signature invalid ❌';
  logAudit('jwt.verify', { ok });
  return ok;
}

// ======= Policy Checks =======
function policyResult(label, pass){
  const li = document.createElement('li');
  const span = document.createElement('span'); span.textContent = label;
  const chip = document.createElement('span'); chip.className = 'chip ' + (pass?'pass':'fail'); chip.textContent = pass? 'PASS' : 'CHECK';
  li.appendChild(span); li.appendChild(chip);
  return li;
}

function evaluatePolicy(){
  const ul = document.getElementById('policy-checks');
  ul.innerHTML = '';
  const p = state.latestPayload; if(!p) return;
  const now = Math.floor(Date.now()/1000);
  const notExpired = (p.exp + (policy.expLeewaySec||0)) >= now;
  const audOk = p.aud === policy.expectedAud;
  const mfaOk = !policy.requireMFA || (Array.isArray(p.amr) && p.amr.includes('mfa'));
  const rolesOk = Array.isArray(p.roles) && p.roles.length >= Number(policy.minRoles||0);
  const groupsOk = Array.isArray(p.groups) && p.groups.length >= 1;
  ul.appendChild(policyResult(`Not expired (now=${now}, exp=${p.exp}, leeway=${policy.expLeewaySec}s)`, notExpired));
  ul.appendChild(policyResult(`Audience equals expected aud (${policy.expectedAud})`, audOk));
  ul.appendChild(policyResult(`Require MFA ⇒ amr includes "mfa"`, mfaOk));
  ul.appendChild(policyResult(`Roles count ≥ ${policy.minRoles}`, rolesOk));
  ul.appendChild(policyResult(`Has ≥ 1 group`, groupsOk));
  logAudit('policy.evaluate', { notExpired, audOk, mfaOk, rolesOk, groupsOk });
}

// ======= Event Wiring =======
function initThemeControls(){
  const select = document.getElementById('vendor-theme');
  select.addEventListener('change', () => {
    document.body.classList.remove('theme-entra','theme-okta','theme-ping','theme-cyberark','theme-beyondtrust','theme-duo','theme-aws','theme-gcp');
    const v = select.value;
    const map = { base:'', entra:'theme-entra', okta:'theme-okta', ping:'theme-ping', cyberark:'theme-cyberark', beyondtrust:'theme-beyondtrust', duo:'theme-duo', aws:'theme-aws', gcp:'theme-gcp' };
    const cls = map[v] || '';
    if(cls) document.body.classList.add(cls);
    logAudit('theme.change', { vendor: v });
  });

  const darkToggle = document.getElementById('dark-toggle');
  darkToggle.addEventListener('change', () => {
    document.body.classList.toggle('dark', darkToggle.checked);
    logAudit('theme.dark', { enabled: darkToggle.checked });
  });
}

function initForms(){
  // Step 1
  document.getElementById('form-credentials').addEventListener('submit', (e)=>{
    e.preventDefault();
    const email = document.getElementById('email').value.trim();
    const pwd = document.getElementById('password').value;
    if(!email || pwd.length < 8){
      alert('Please enter a valid email and an 8+ character password.');
      return;
    }
    state.email = email;
    logAudit('auth.password', { email: state.email, ok: true });
    go(2);
    document.getElementById('totp-secret').textContent = state.totpSecret;
    drawMockQR();
    startTotpLoop();
  });

  document.getElementById('back-to-1').addEventListener('click', ()=>{
    if(state.interval) clearInterval(state.interval);
    go(1);
  });

  // Step 2
  document.getElementById('form-totp').addEventListener('submit', async (e)=>{
    e.preventDefault();
    const val = document.getElementById('totp-input').value.trim();
    const { code } = await totpAt(Date.now());
    if(val !== code){
      logAudit('auth.totp', { ok:false, entered: val });
      alert('MFA failed — incorrect code.');
      return;
    }
    logAudit('auth.totp', { ok:true });
    go(3);
    await issueJwt();
  });

  // Step 3
  document.getElementById('btn-copy').addEventListener('click', async ()=>{
    if(!state.latestToken) return;
    await navigator.clipboard.writeText(state.latestToken);
    logAudit('jwt.copy', {});
  });

  document.getElementById('btn-verify').addEventListener('click', ()=>{ verifyJwtSignature(); });
  document.getElementById('btn-download-token').addEventListener('click', ()=>{
    if(!state.latestToken) return;
    const [h,p,s] = state.latestToken.split('.');
    const payload = state.latestPayload || b64u.decodeJSON(p);
    const header = b64u.decodeJSON(h);
    const out = { token: state.latestToken, header, payload, signature: s };
    downloadFile('token.json', JSON.stringify(out, null, 2));
    logAudit('download.token', { jti: payload.jti });
  });

  document.getElementById('form-policy').addEventListener('submit', (e)=>{
    e.preventDefault();
    policy.expectedAud = document.getElementById('policy-aud').value || policy.expectedAud;
    policy.requireMFA = document.getElementById('policy-mfa').checked;
    policy.minRoles = Number(document.getElementById('policy-roles').value || policy.minRoles);
    policy.expLeewaySec = Number(document.getElementById('policy-leeway').value || policy.expLeewaySec);
    evaluatePolicy();
    logAudit('policy.update', { ...policy });
  });

  document.getElementById('proceed-redirect').addEventListener('click', ()=>{
    logAudit('redirect', { to: 'https://app.example.com' });
    go(4);
  });

  document.getElementById('restart').addEventListener('click', ()=>{
    if(state.interval) clearInterval(state.interval);
    state.email = null; state.latestPayload = null; state.latestToken = null; state._totpKey = null;
    document.getElementById('email').value = '';
    document.getElementById('password').value = '';
    document.getElementById('token-pre').textContent='';
    document.getElementById('claims-table').innerHTML='';
    go(1);
    logAudit('restart', {});
  });

  document.getElementById('btn-download-audit').addEventListener('click', ()=>{
    downloadFile('audit.json', JSON.stringify(state.audit, null, 2));
  });
}

function seedPolicyUI(){
  document.getElementById('policy-aud').value = policy.expectedAud;
  document.getElementById('policy-mfa').checked = policy.requireMFA;
  document.getElementById('policy-roles').value = String(policy.minRoles);
  document.getElementById('policy-leeway').value = String(policy.expLeewaySec);
}

// ======= Bootstrap =======
window.addEventListener('DOMContentLoaded', ()=>{
  initThemeControls();
  initForms();
  seedPolicyUI();
  go(1);
});
