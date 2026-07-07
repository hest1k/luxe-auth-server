const express   = require('express');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');
const { createClient } = require('@libsql/client');
const crypto    = require('crypto');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET  = process.env.JWT_SECRET  || 'luxe-secret-change-me';
const ADMIN_KEY   = process.env.ADMIN_KEY   || 'luxe-admin-key';
const PORT        = process.env.PORT        || 3000;
const TURSO_URL   = process.env.TURSO_URL;
const TURSO_TOKEN = process.env.TURSO_TOKEN;

if (!TURSO_URL || !TURSO_TOKEN) {
  console.error('❌ Нет TURSO_URL или TURSO_TOKEN');
  process.exit(1);
}

const db = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });

async function initDB() {
  await db.batch([
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      hwid TEXT DEFAULT NULL,
      hwid_raw TEXT DEFAULT NULL,
      hwid_locked INTEGER DEFAULT 0,
      banned INTEGER DEFAULT 0,
      sub_expires TEXT DEFAULT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      last_login TEXT DEFAULT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS license_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key_value TEXT UNIQUE NOT NULL,
      duration_minutes INTEGER NOT NULL,
      used INTEGER DEFAULT 0,
      used_by TEXT DEFAULT NULL,
      used_at TEXT DEFAULT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    )`,
  ], 'write');
  try { await db.execute('ALTER TABLE users ADD COLUMN hwid_raw TEXT DEFAULT NULL'); } catch(_){}
  try { await db.execute('ALTER TABLE users ADD COLUMN sub_expires TEXT DEFAULT NULL'); } catch(_){}
  console.log('✅ БД готова');
}

const hashHwid = (h) => crypto.createHash('sha256').update(h).digest('hex');

function authMiddleware(req, res, next) {
  const h = req.headers['authorization'];
  if (!h) return res.status(401).json({ error: 'Нет токена' });
  try { req.user = jwt.verify(h.replace('Bearer ', ''), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Токен недействителен' }); }
}

function adminMiddleware(req, res, next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY)
    return res.status(403).json({ error: 'Нет доступа' });
  next();
}

// Проверка активной подписки
function hasActiveSub(user) {
  if (!user.sub_expires) return false;
  if (user.sub_expires === 'unlimited') return true;
  return new Date(user.sub_expires) > new Date();
}

// Генерация ключа
function generateKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const seg = () => Array.from({length:5}, () => chars[Math.floor(Math.random()*chars.length)]).join('');
  return `LUXE-${seg()}-${seg()}-${seg()}`;
}

// ── Регистрация ───────────────────────────────────────────────────────────────
app.post('/auth/register', async (req, res) => {
  const { username, password, hwid } = req.body;
  if (!username || !password || !hwid)
    return res.status(400).json({ error: 'Заполни все поля' });
  if (username.length < 3 || username.length > 16)
    return res.status(400).json({ error: 'Никнейм: 3–16 символов' });
  if (!/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: 'Никнейм: только буквы, цифры и _' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Пароль: минимум 6 символов' });
  try {
    const ex = await db.execute({ sql: 'SELECT id FROM users WHERE username=?', args: [username] });
    if (ex.rows.length) return res.status(409).json({ error: 'Никнейм уже занят' });
    const hashed = await bcrypt.hash(password, 10);
    await db.execute({ sql: 'INSERT INTO users (username,password,hwid,hwid_raw,hwid_locked) VALUES (?,?,?,?,1)', args: [username, hashed, hashHwid(hwid), hwid] });
    const userRow = await db.execute({ sql: 'SELECT id,username,sub_expires FROM users WHERE username=?', args: [username] });
    const user  = userRow.rows[0];
    const token = jwt.sign({ id: Number(user.id), username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    await db.execute({ sql: 'INSERT INTO sessions (user_id,token) VALUES (?,?)', args: [Number(user.id), token] });
    res.json({ success: true, token, username: user.username, sub_expires: user.sub_expires, has_sub: hasActiveSub(user) });
  } catch(e) { res.status(500).json({ error: 'Ошибка сервера: ' + e.message }); }
});

// ── Вход ──────────────────────────────────────────────────────────────────────
app.post('/auth/login', async (req, res) => {
  const { username, password, hwid } = req.body;
  if (!username || !password || !hwid)
    return res.status(400).json({ error: 'Заполни все поля' });
  try {
    const r = await db.execute({ sql: 'SELECT * FROM users WHERE username=?', args: [username] });
    if (!r.rows.length) return res.status(404).json({ error: 'Аккаунт не найден' });
    const user = r.rows[0];
    if (user.banned) return res.status(403).json({ error: 'Аккаунт заблокирован' });
    if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Неверный пароль' });
    const hh = hashHwid(hwid);
    if (user.hwid_locked && user.hwid && user.hwid !== hh)
      return res.status(403).json({ error: 'Аккаунт привязан к другому ПК. Обратись к администратору.' });
    if (!user.hwid_locked || !user.hwid)
      await db.execute({ sql: 'UPDATE users SET hwid=?,hwid_raw=?,hwid_locked=1 WHERE id=?', args: [hh, hwid, Number(user.id)] });
    await db.execute({ sql: "UPDATE users SET last_login=datetime('now') WHERE id=?", args: [Number(user.id)] });
    const token = jwt.sign({ id: Number(user.id), username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    await db.execute({ sql: 'INSERT INTO sessions (user_id,token) VALUES (?,?)', args: [Number(user.id), token] });
    res.json({ success: true, token, username: user.username, sub_expires: user.sub_expires, has_sub: hasActiveSub(user) });
  } catch(e) { res.status(500).json({ error: 'Ошибка сервера: ' + e.message }); }
});

// ── Проверка токена ───────────────────────────────────────────────────────────
app.post('/auth/verify', authMiddleware, async (req, res) => {
  const { hwid } = req.body;
  if (!hwid) return res.status(400).json({ error: 'Нет HWID' });
  try {
    const r = await db.execute({ sql: 'SELECT * FROM users WHERE id=?', args: [req.user.id] });
    if (!r.rows.length) return res.status(404).json({ error: 'Не найден' });
    const user = r.rows[0];
    if (user.banned) return res.status(403).json({ error: 'Заблокирован' });
    if (user.hwid && user.hwid !== hashHwid(hwid)) return res.status(403).json({ error: 'HWID не совпадает' });
    res.json({ success: true, username: user.username, sub_expires: user.sub_expires, has_sub: hasActiveSub(user) });
  } catch(e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ── Активация ключа ───────────────────────────────────────────────────────────
app.post('/auth/activate', authMiddleware, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'Введи ключ' });
  try {
    const kr = await db.execute({ sql: 'SELECT * FROM license_keys WHERE key_value=?', args: [key.trim().toUpperCase()] });
    if (!kr.rows.length) return res.status(404).json({ error: 'Ключ не найден' });
    const k = kr.rows[0];
    if (k.used) return res.status(409).json({ error: 'Ключ уже использован' });

    const ur = await db.execute({ sql: 'SELECT * FROM users WHERE id=?', args: [req.user.id] });
    const user = ur.rows[0];

    let newExpiry;
    if (k.duration_minutes === -1) {
      newExpiry = 'unlimited';
    } else {
      const base = (user.sub_expires && user.sub_expires !== 'unlimited' && new Date(user.sub_expires) > new Date())
        ? new Date(user.sub_expires) : new Date();
      base.setMinutes(base.getMinutes() + Number(k.duration_minutes));
      newExpiry = base.toISOString();
    }

    await db.execute({ sql: 'UPDATE users SET sub_expires=? WHERE id=?', args: [newExpiry, req.user.id] });
    await db.execute({ sql: "UPDATE license_keys SET used=1,used_by=?,used_at=datetime('now') WHERE key_value=?", args: [user.username, key.trim().toUpperCase()] });

    res.json({ success: true, sub_expires: newExpiry, has_sub: true,
      message: k.duration_minutes === -1 ? 'Навсегда активировано!' : `Подписка продлена на ${k.duration_minutes} минут` });
  } catch(e) { res.status(500).json({ error: 'Ошибка сервера: ' + e.message }); }
});

// ══ ADMIN ═════════════════════════════════════════════════════════════════════

// Создать ключ
app.post('/admin/keys/create', adminMiddleware, async (req, res) => {
  const { duration_minutes, count = 1 } = req.body;
  if (duration_minutes === undefined) return res.status(400).json({ error: 'Укажи duration_minutes (-1 = навсегда)' });
  const keys = [];
  for (let i = 0; i < Math.min(count, 100); i++) {
    const k = generateKey();
    await db.execute({ sql: 'INSERT INTO license_keys (key_value,duration_minutes) VALUES (?,?)', args: [k, duration_minutes] });
    keys.push(k);
  }
  res.json({ success: true, keys });
});

// Список ключей
app.get('/admin/keys', adminMiddleware, async (_req, res) => {
  const r = await db.execute('SELECT * FROM license_keys ORDER BY created_at DESC');
  res.json(r.rows);
});

// Удалить ключ
app.delete('/admin/keys/:key', adminMiddleware, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM license_keys WHERE key_value=?', args: [req.params.key] });
  res.json({ success: true });
});

// Список пользователей
app.get('/admin/users', adminMiddleware, async (_req, res) => {
  const r = await db.execute('SELECT id,username,hwid_raw,hwid_locked,banned,sub_expires,created_at,last_login FROM users ORDER BY created_at DESC');
  res.json(r.rows);
});

// Сброс HWID
app.post('/admin/reset-hwid', adminMiddleware, async (req, res) => {
  const { username } = req.body;
  await db.execute({ sql: 'UPDATE users SET hwid=NULL,hwid_raw=NULL,hwid_locked=0 WHERE username=?', args: [username] });
  res.json({ success: true });
});

// Бан/разбан
app.post('/admin/ban', adminMiddleware, async (req, res) => {
  const { username, banned } = req.body;
  await db.execute({ sql: 'UPDATE users SET banned=? WHERE username=?', args: [banned?1:0, username] });
  res.json({ success: true });
});

// Удалить пользователя
app.delete('/admin/user/:username', adminMiddleware, async (req, res) => {
  const r = await db.execute({ sql: 'SELECT id FROM users WHERE username=?', args: [req.params.username] });
  if (!r.rows.length) return res.status(404).json({ error: 'Не найден' });
  const uid = Number(r.rows[0].id);
  await db.execute({ sql: 'DELETE FROM sessions WHERE user_id=?', args: [uid] });
  await db.execute({ sql: 'DELETE FROM users WHERE id=?', args: [uid] });
  res.json({ success: true });
});

// Установить подписку вручную
app.post('/admin/set-sub', adminMiddleware, async (req, res) => {
  const { username, duration_minutes } = req.body;
  let expiry = duration_minutes === -1 ? 'unlimited' : new Date(Date.now() + duration_minutes * 60000).toISOString();
  await db.execute({ sql: 'UPDATE users SET sub_expires=? WHERE username=?', args: [expiry, username] });
  res.json({ success: true, sub_expires: expiry });
});

// ══ ADMIN PANEL (веб) ════════════════════════════════════════════════════════
app.get('/', (_req, res) => res.json({ status: 'ok', name: 'Luxe Auth Server', version: '1.0.0' }));

app.get('/admin/panel', (req, res) => {
  const key = req.query.key;
  if (key !== ADMIN_KEY) return res.send(`<html><head><meta charset="utf-8"><title>Luxe Admin</title>
    <style>body{background:#0f1117;color:#e8e9f0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
    .box{background:#1a1d27;padding:32px;border-radius:16px;width:320px}h2{margin:0 0 20px;color:#7c6ff7}
    input{width:100%;padding:10px;background:#0f1117;border:1px solid #23263a;border-radius:8px;color:#fff;font-size:14px;box-sizing:border-box}
    button{width:100%;margin-top:12px;padding:12px;background:linear-gradient(135deg,#7c6ff7,#a78bfa);border:none;border-radius:8px;color:#fff;font-size:15px;font-weight:700;cursor:pointer}</style></head>
    <body><div class="box"><h2>Luxe Admin</h2><input type="password" id="k" placeholder="Admin Key..."/>
    <button onclick="location.href='/admin/panel?key='+document.getElementById('k').value">Войти</button></div></body></html>`);

  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Luxe Admin</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}body{background:#0f1117;color:#e8e9f0;font-family:'Segoe UI',sans-serif;padding:20px}
    h1{color:#7c6ff7;margin-bottom:16px;font-size:20px}.tabs{display:flex;gap:8px;margin-bottom:20px}
    .tab{padding:8px 20px;border:1px solid #23263a;border-radius:8px;background:#1a1d27;color:#9295a8;cursor:pointer;font-size:13px;font-weight:600}
    .tab.active{background:rgba(124,111,247,.18);border-color:#7c6ff7;color:#7c6ff7}
    .section{display:none}.section.active{display:block}
    table{width:100%;border-collapse:collapse;background:#1a1d27;border-radius:12px;overflow:hidden;margin-top:12px}
    th{background:#13151c;padding:10px 14px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#6b6f85}
    td{padding:10px 14px;border-top:1px solid #23263a;font-size:12px}
    .badge{padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700}
    .ok{background:rgba(34,197,94,.15);color:#22c55e}.ban{background:rgba(232,64,87,.15);color:#e84057}
    .sub{background:rgba(124,111,247,.15);color:#7c6ff7}.nosub{background:rgba(255,255,255,.06);color:#6b6f85}
    .btn{padding:3px 10px;border:none;border-radius:6px;cursor:pointer;font-size:11px;font-weight:600;margin:0 2px}
    .br{background:rgba(124,111,247,.2);color:#7c6ff7}.bb{background:rgba(232,64,87,.2);color:#e84057}
    .bd{background:rgba(255,255,255,.08);color:#9295a8}
    .card{background:#1a1d27;border:1px solid #23263a;border-radius:12px;padding:16px;margin-bottom:12px}
    label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:#6b6f85;display:block;margin-bottom:6px}
    input,select{background:#0f1117;border:1px solid #23263a;border-radius:8px;padding:8px 12px;color:#fff;font-size:13px}
    .row{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap}
    .gbtn{padding:9px 20px;background:linear-gradient(135deg,#7c6ff7,#a78bfa);border:none;border-radius:8px;color:#fff;font-size:13px;font-weight:700;cursor:pointer}
    .keys-list{margin-top:12px;display:flex;flex-direction:column;gap:6px}
    .key-row{background:#0f1117;border:1px solid #23263a;border-radius:8px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center;font-family:monospace;font-size:13px}
    .key-used{opacity:.4}.search{padding:8px 12px;background:#1a1d27;border:1px solid #23263a;border-radius:8px;color:#fff;font-size:13px;width:250px;margin-bottom:12px}
    .stats{display:flex;gap:10px;margin-bottom:16px}.stat{background:#1a1d27;border:1px solid #23263a;border-radius:10px;padding:12px 20px;text-align:center}
    .sv{font-size:24px;font-weight:800;color:#7c6ff7}.sl{font-size:11px;color:#6b6f85;margin-top:2px}
    .copy-btn{padding:2px 8px;background:rgba(124,111,247,.15);border:1px solid rgba(124,111,247,.3);border-radius:4px;color:#7c6ff7;cursor:pointer;font-size:11px}
  </style></head><body>
  <h1>⚡ Luxe Admin Panel</h1>
  <div class="tabs">
    <button class="tab active" onclick="showTab('users',this)">👥 Пользователи</button>
    <button class="tab" onclick="showTab('keys',this)">🔑 Ключи</button>
  </div>

  <div id="tab-users" class="section active">
    <div class="stats" id="ustats"></div>
    <input class="search" placeholder="Поиск по нику..." oninput="filterUsers(this.value)" />
    <table><thead><tr><th>#</th><th>Никнейм</th><th>HWID</th><th>Подписка</th><th>Статус</th><th>Регистрация</th><th>Действия</th></tr></thead>
    <tbody id="utbody"></tbody></table>
  </div>

  <div id="tab-keys" class="section">
    <div class="card">
      <label>Создать ключи</label>
      <div class="row">
        <div><label>Длительность</label>
          <select id="dur">
            <option value="1">1 минута</option><option value="60">1 час</option>
            <option value="1440">1 день</option><option value="10080">1 неделя</option>
            <option value="43200">1 месяц</option><option value="-1">♾ Навсегда</option>
            <option value="custom">Своя...</option>
          </select>
        </div>
        <div id="customDiv" style="display:none"><label>Минут</label><input type="number" id="customMin" min="1" value="60" style="width:100px"/></div>
        <div><label>Количество</label><input type="number" id="cnt" min="1" max="100" value="1" style="width:80px"/></div>
        <button class="gbtn" onclick="createKeys()">Создать</button>
      </div>
      <div class="keys-list" id="newKeys"></div>
    </div>
    <input class="search" placeholder="Поиск по ключу..." oninput="filterKeys(this.value)" />
    <table><thead><tr><th>Ключ</th><th>Длительность</th><th>Статус</th><th>Использован</th><th></th></tr></thead>
    <tbody id="ktbody"></tbody></table>
  </div>

  <script>
  const K='${key}';
  let allUsers=[],allKeys=[];

  function showTab(name,el){
    document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
    document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));
    el.classList.add('active');
    document.getElementById('tab-'+name).classList.add('active');
    if(name==='users') loadUsers(); else loadKeys();
  }

  document.getElementById('dur').onchange=function(){
    document.getElementById('customDiv').style.display=this.value==='custom'?'block':'none';
  };

  async function loadUsers(){
    const r=await fetch('/admin/users',{headers:{'x-admin-key':K}});
    allUsers=await r.json();
    renderUsers(allUsers);
    document.getElementById('ustats').innerHTML=
      '<div class="stat"><div class="sv">'+allUsers.length+'</div><div class="sl">Всего</div></div>'+
      '<div class="stat"><div class="sv">'+allUsers.filter(u=>u.sub_expires&&(u.sub_expires==='unlimited'||new Date(u.sub_expires)>new Date())).length+'</div><div class="sl">С подпиской</div></div>'+
      '<div class="stat"><div class="sv">'+allUsers.filter(u=>u.banned).length+'</div><div class="sl">Забанено</div></div>';
  }

  function subLabel(u){
    if(!u.sub_expires) return '<span class="badge nosub">Нет</span>';
    if(u.sub_expires==='unlimited') return '<span class="badge sub">♾ Навсегда</span>';
    const d=new Date(u.sub_expires);
    if(d<new Date()) return '<span class="badge nosub">Истекла</span>';
    return '<span class="badge sub">До '+d.toLocaleString('ru')+'</span>';
  }

  function renderUsers(users){
    document.getElementById('utbody').innerHTML=users.map((u,i)=>\`
      <tr>
        <td style="color:#6b6f85">\${i+1}</td>
        <td><b>\${u.username}</b></td>
        <td style="font-family:monospace;font-size:11px;color:#9295a8;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="\${u.hwid_raw||'—'}">\${u.hwid_raw||'—'}</td>
        <td>\${subLabel(u)}</td>
        <td>\${u.banned?'<span class="badge ban">Бан</span>':'<span class="badge ok">Актив</span>'}</td>
        <td style="color:#6b6f85;font-size:11px">\${u.created_at?.slice(0,16)||'—'}</td>
        <td>
          <button class="btn br" onclick="resetHwid('\${u.username}')">HWID</button>
          <button class="btn bb" onclick="toggleBan('\${u.username}',\${u.banned})">\${u.banned?'Разбан':'Бан'}</button>
          <button class="btn bd" onclick="delUser('\${u.username}')">✕</button>
        </td>
      </tr>\`).join('');
  }

  function filterUsers(q){renderUsers(allUsers.filter(u=>u.username.toLowerCase().includes(q.toLowerCase())));}

  async function loadKeys(){
    const r=await fetch('/admin/keys',{headers:{'x-admin-key':K}});
    allKeys=await r.json();
    renderKeys(allKeys);
  }

  function durLabel(m){
    if(m===-1||m===-'1') return '♾ Навсегда';
    if(m<60) return m+' мин';
    if(m<1440) return (m/60|0)+' ч';
    if(m<10080) return (m/1440|0)+' дн';
    return (m/10080|0)+' нед';
  }

  function renderKeys(keys){
    document.getElementById('ktbody').innerHTML=keys.map(k=>\`
      <tr class="\${k.used?'key-used':''}">
        <td style="font-family:monospace">\${k.key_value} <button class="copy-btn" onclick="navigator.clipboard.writeText('\${k.key_value}')">copy</button></td>
        <td>\${durLabel(Number(k.duration_minutes))}</td>
        <td>\${k.used?'<span class="badge ban">Использован</span>':'<span class="badge ok">Активен</span>'}</td>
        <td style="font-size:11px;color:#6b6f85">\${k.used_by||'—'} \${k.used_at?.slice(0,16)||''}</td>
        <td><button class="btn bd" onclick="delKey('\${k.key_value}')">✕</button></td>
      </tr>\`).join('');
  }

  function filterKeys(q){renderKeys(allKeys.filter(k=>k.key_value.includes(q.toUpperCase())));}

  async function createKeys(){
    const sel=document.getElementById('dur').value;
    const dur=sel==='custom'?parseInt(document.getElementById('customMin').value):parseInt(sel);
    const cnt=parseInt(document.getElementById('cnt').value)||1;
    const r=await fetch('/admin/keys/create',{method:'POST',headers:{'Content-Type':'application/json','x-admin-key':K},body:JSON.stringify({duration_minutes:dur,count:cnt})});
    const d=await r.json();
    document.getElementById('newKeys').innerHTML=d.keys.map(k=>\`<div class="key-row">\${k}<button class="copy-btn" onclick="navigator.clipboard.writeText('\${k}')">copy</button></div>\`).join('');
    loadKeys();
  }

  async function delKey(k){
    if(!confirm('Удалить ключ '+k+'?')) return;
    await fetch('/admin/keys/'+k,{method:'DELETE',headers:{'x-admin-key':K}});
    loadKeys();
  }

  async function resetHwid(u){
    if(!confirm('Сбросить HWID для '+u+'?')) return;
    await fetch('/admin/reset-hwid',{method:'POST',headers:{'Content-Type':'application/json','x-admin-key':K},body:JSON.stringify({username:u})});
    loadUsers();
  }

  async function toggleBan(u,b){
    await fetch('/admin/ban',{method:'POST',headers:{'Content-Type':'application/json','x-admin-key':K},body:JSON.stringify({username:u,banned:!b})});
    loadUsers();
  }

  async function delUser(u){
    if(!confirm('Удалить '+u+'?')) return;
    await fetch('/admin/user/'+u,{method:'DELETE',headers:{'x-admin-key':K}});
    loadUsers();
  }

  loadUsers();
  </script></body></html>`);
});

initDB().then(()=>{
  app.listen(PORT,()=>{
    console.log(\`✅ Luxe Auth Server on port \${PORT}\`);
  });
}).catch(e=>{ console.error('❌ БД ошибка:', e); process.exit(1); });
