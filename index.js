const express   = require('express');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');
const { createClient } = require('@libsql/client');
const crypto    = require('crypto');

const app = express();
app.use(express.json());
app.use(cors());

// ─── Конфиг ───────────────────────────────────────────────────────────────────
const JWT_SECRET  = process.env.JWT_SECRET  || 'luxe-secret-change-me';
const ADMIN_KEY   = process.env.ADMIN_KEY   || 'luxe-admin-key';
const PORT        = process.env.PORT        || 3000;
const TURSO_URL   = process.env.TURSO_URL;   // libsql://ИМЯ-БАЗЫ.turso.io
const TURSO_TOKEN = process.env.TURSO_TOKEN; // eyJ...

if (!TURSO_URL || !TURSO_TOKEN) {
  console.error('❌ Нет TURSO_URL или TURSO_TOKEN в переменных окружения!');
  process.exit(1);
}

// ─── Turso клиент ─────────────────────────────────────────────────────────────
const db = createClient({
  url:       TURSO_URL,
  authToken: TURSO_TOKEN,
});

// ─── Инициализация таблиц ─────────────────────────────────────────────────────
async function initDB() {
  await db.batch([
    `CREATE TABLE IF NOT EXISTS users (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      username    TEXT    UNIQUE NOT NULL,
      password    TEXT    NOT NULL,
      hwid        TEXT    DEFAULT NULL,
      hwid_raw    TEXT    DEFAULT NULL,
      hwid_locked INTEGER DEFAULT 0,
      banned      INTEGER DEFAULT 0,
      created_at  TEXT    DEFAULT (datetime('now')),
      last_login  TEXT    DEFAULT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL,
      token      TEXT    NOT NULL,
      created_at TEXT    DEFAULT (datetime('now'))
    )`,
  ], 'write');
  // Добавляем hwid_raw если таблица уже существовала без неё
  try {
    await db.execute('ALTER TABLE users ADD COLUMN hwid_raw TEXT DEFAULT NULL');
  } catch (_) { /* уже есть */ }
  console.log('✅ БД готова');
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
// HWID храним открыто — только хэшируем для сравнения при входе
const hashHwid = (hwid) =>
  crypto.createHash('sha256').update(hwid).digest('hex');

function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Нет токена' });
  try {
    req.user = jwt.verify(header.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Токен недействителен' });
  }
}

function adminMiddleware(req, res, next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY)
    return res.status(403).json({ error: 'Нет доступа' });
  next();
}

// ══════════════════════════════════════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.get('/', (_req, res) => {
  res.json({ status: 'ok', name: 'Luxe Auth Server', version: '1.0.0' });
});

// ─── Веб-панель администратора ────────────────────────────────────────────────
app.get('/admin/panel', (req, res) => {
  const key = req.query.key;
  if (key !== ADMIN_KEY) {
    return res.send(`
      <html><head><meta charset="utf-8">
      <title>Luxe Admin</title>
      <style>
        body{background:#0f1117;color:#e8e9f0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
        .box{background:#1a1d27;padding:32px;border-radius:16px;width:320px}
        h2{margin:0 0 20px;color:#7c6ff7}
        input{width:100%;padding:10px;background:#0f1117;border:1px solid #23263a;border-radius:8px;color:#fff;font-size:14px;box-sizing:border-box}
        button{width:100%;margin-top:12px;padding:12px;background:linear-gradient(135deg,#7c6ff7,#a78bfa);border:none;border-radius:8px;color:#fff;font-size:15px;font-weight:700;cursor:pointer}
      </style></head>
      <body><div class="box">
        <h2>Luxe Admin Panel</h2>
        <input type="password" id="k" placeholder="Admin Key..." />
        <button onclick="location.href='/admin/panel?key='+document.getElementById('k').value">Войти</button>
      </div></body></html>
    `);
  }
  res.send(`
    <!DOCTYPE html><html><head><meta charset="utf-8">
    <title>Luxe Admin Panel</title>
    <style>
      *{box-sizing:border-box;margin:0;padding:0}
      body{background:#0f1117;color:#e8e9f0;font-family:'Segoe UI',sans-serif;padding:24px}
      h1{color:#7c6ff7;margin-bottom:20px;font-size:22px}
      .stats{display:flex;gap:12px;margin-bottom:24px}
      .stat{background:#1a1d27;border:1px solid #23263a;border-radius:12px;padding:16px 24px;text-align:center}
      .stat-val{font-size:28px;font-weight:800;color:#7c6ff7}
      .stat-lbl{font-size:12px;color:#6b6f85;margin-top:4px}
      table{width:100%;border-collapse:collapse;background:#1a1d27;border-radius:12px;overflow:hidden}
      th{background:#13151c;padding:12px 16px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#6b6f85}
      td{padding:12px 16px;border-top:1px solid #23263a;font-size:13px}
      .badge{padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700}
      .badge-ok{background:rgba(34,197,94,.15);color:#22c55e}
      .badge-ban{background:rgba(232,64,87,.15);color:#e84057}
      .badge-lock{background:rgba(124,111,247,.15);color:#7c6ff7}
      .hwid{font-family:monospace;font-size:11px;color:#9295a8;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
      .actions{display:flex;gap:6px}
      .btn{padding:4px 10px;border:none;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600}
      .btn-reset{background:rgba(124,111,247,.2);color:#7c6ff7}
      .btn-ban{background:rgba(232,64,87,.2);color:#e84057}
      .btn-del{background:rgba(255,255,255,.08);color:#9295a8}
      input[type=text]{background:#0f1117;border:1px solid #23263a;border-radius:8px;padding:8px 12px;color:#fff;font-size:13px;width:220px}
      .search-bar{display:flex;gap:10px;margin-bottom:16px;align-items:center}
      .refresh{padding:8px 16px;background:rgba(124,111,247,.15);border:1px solid rgba(124,111,247,.3);border-radius:8px;color:#7c6ff7;cursor:pointer;font-size:13px}
    </style></head>
    <body>
    <h1>⚡ Luxe Admin Panel</h1>
    <div class="stats" id="stats"></div>
    <div class="search-bar">
      <input type="text" id="search" placeholder="Поиск по нику..." oninput="filterTable()" />
      <button class="refresh" onclick="loadUsers()">↻ Обновить</button>
    </div>
    <table><thead><tr>
      <th>#</th><th>Никнейм</th><th>HWID</th><th>Статус</th><th>Регистрация</th><th>Последний вход</th><th>Действия</th>
    </tr></thead><tbody id="tbody"></tbody></table>

    <script>
    const KEY = '${key}';
    let allUsers = [];

    async function loadUsers() {
      const r = await fetch('/admin/users', { headers: { 'x-admin-key': KEY } });
      allUsers = await r.json();
      renderUsers(allUsers);
      document.getElementById('stats').innerHTML =
        '<div class="stat"><div class="stat-val">'+allUsers.length+'</div><div class="stat-lbl">Всего</div></div>' +
        '<div class="stat"><div class="stat-val">'+allUsers.filter(u=>!u.banned).length+'</div><div class="stat-lbl">Активных</div></div>' +
        '<div class="stat"><div class="stat-val">'+allUsers.filter(u=>u.banned).length+'</div><div class="stat-lbl">Забанено</div></div>' +
        '<div class="stat"><div class="stat-val">'+allUsers.filter(u=>u.hwid_locked).length+'</div><div class="stat-lbl">С HWID</div></div>';
    }

    function renderUsers(users) {
      const tbody = document.getElementById('tbody');
      tbody.innerHTML = users.map((u,i) => \`
        <tr>
          <td style="color:#6b6f85">\${i+1}</td>
          <td><b>\${u.username}</b></td>
          <td><div class="hwid" title="\${u.hwid_raw||'—'}">\${u.hwid_raw||'—'}</div></td>
          <td>
            \${u.banned ? '<span class="badge badge-ban">Забанен</span>' : '<span class="badge badge-ok">Активен</span>'}
            \${u.hwid_locked ? ' <span class="badge badge-lock">HWID</span>' : ''}
          </td>
          <td style="color:#6b6f85">\${u.created_at?.slice(0,16)||'—'}</td>
          <td style="color:#6b6f85">\${u.last_login?.slice(0,16)||'—'}</td>
          <td><div class="actions">
            <button class="btn btn-reset" onclick="resetHwid('\${u.username}')">Сброс HWID</button>
            <button class="btn btn-ban" onclick="toggleBan('\${u.username}',\${u.banned})">\${u.banned?'Разбан':'Бан'}</button>
            <button class="btn btn-del" onclick="delUser('\${u.username}')">✕</button>
          </div></td>
        </tr>
      \`).join('');
    }

    function filterTable() {
      const q = document.getElementById('search').value.toLowerCase();
      renderUsers(allUsers.filter(u => u.username.toLowerCase().includes(q)));
    }

    async function resetHwid(username) {
      if(!confirm('Сбросить HWID для '+username+'?')) return;
      await fetch('/admin/reset-hwid', { method:'POST', headers:{'Content-Type':'application/json','x-admin-key':KEY}, body:JSON.stringify({username}) });
      loadUsers();
    }

    async function toggleBan(username, banned) {
      await fetch('/admin/ban', { method:'POST', headers:{'Content-Type':'application/json','x-admin-key':KEY}, body:JSON.stringify({username, banned:!banned}) });
      loadUsers();
    }

    async function delUser(username) {
      if(!confirm('Удалить '+username+'? Это нельзя отменить.')) return;
      await fetch('/admin/user/'+username, { method:'DELETE', headers:{'x-admin-key':KEY} });
      loadUsers();
    }

    loadUsers();
    setInterval(loadUsers, 30000);
    </script>
    </body></html>
  `);
});

// ─── Регистрация ──────────────────────────────────────────────────────────────
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
    const existing = await db.execute({
      sql: 'SELECT id FROM users WHERE username = ?',
      args: [username],
    });
    if (existing.rows.length > 0)
      return res.status(409).json({ error: 'Никнейм уже занят' });

    const hashed     = await bcrypt.hash(password, 10);
    const hashedHwid = hashHwid(hwid);

    await db.execute({
      sql:  'INSERT INTO users (username, password, hwid, hwid_raw, hwid_locked) VALUES (?, ?, ?, ?, 1)',
      args: [username, hashed, hashedHwid, hwid],
    });

    const userRow = await db.execute({
      sql: 'SELECT id, username FROM users WHERE username = ?',
      args: [username],
    });
    const user  = userRow.rows[0];
    const token = jwt.sign({ id: Number(user.id), username: user.username }, JWT_SECRET, { expiresIn: '30d' });

    await db.execute({
      sql:  'INSERT INTO sessions (user_id, token) VALUES (?, ?)',
      args: [Number(user.id), token],
    });

    res.json({ success: true, token, username: user.username });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Ошибка сервера: ' + e.message });
  }
});

// ─── Вход ─────────────────────────────────────────────────────────────────────
app.post('/auth/login', async (req, res) => {
  const { username, password, hwid } = req.body;

  if (!username || !password || !hwid)
    return res.status(400).json({ error: 'Заполни все поля' });

  try {
    const result = await db.execute({
      sql: 'SELECT * FROM users WHERE username = ?',
      args: [username],
    });

    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Аккаунт не найден' });

    const user = result.rows[0];

    if (user.banned)
      return res.status(403).json({ error: 'Аккаунт заблокирован' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Неверный пароль' });

    const hashedHwid = hashHwid(hwid);

    if (user.hwid_locked && user.hwid) {
      if (user.hwid !== hashedHwid)
        return res.status(403).json({
          error: 'Аккаунт привязан к другому ПК. Обратись к администратору.',
        });
    } else {
      await db.execute({
        sql:  'UPDATE users SET hwid = ?, hwid_raw = ?, hwid_locked = 1 WHERE id = ?',
        args: [hashedHwid, hwid, Number(user.id)],
      });
    }

    await db.execute({
      sql:  "UPDATE users SET last_login = datetime('now') WHERE id = ?",
      args: [Number(user.id)],
    });

    const token = jwt.sign({ id: Number(user.id), username: user.username }, JWT_SECRET, { expiresIn: '30d' });

    await db.execute({
      sql:  'INSERT INTO sessions (user_id, token) VALUES (?, ?)',
      args: [Number(user.id), token],
    });

    res.json({ success: true, token, username: user.username });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Ошибка сервера: ' + e.message });
  }
});

// ─── Проверка токена ──────────────────────────────────────────────────────────
app.post('/auth/verify', authMiddleware, async (req, res) => {
  const { hwid } = req.body;
  if (!hwid) return res.status(400).json({ error: 'Нет HWID' });

  try {
    const result = await db.execute({
      sql: 'SELECT * FROM users WHERE id = ?',
      args: [req.user.id],
    });

    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Пользователь не найден' });

    const user = result.rows[0];
    if (user.banned) return res.status(403).json({ error: 'Аккаунт заблокирован' });

    const hashedHwid = hashHwid(hwid);
    if (user.hwid && user.hwid !== hashedHwid)
      return res.status(403).json({ error: 'HWID не совпадает' });

    res.json({ success: true, username: user.username });
  } catch (e) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN
// ══════════════════════════════════════════════════════════════════════════════

app.get('/admin/users', adminMiddleware, async (_req, res) => {
  const result = await db.execute(
    'SELECT id, username, hwid_raw, hwid_locked, banned, created_at, last_login FROM users ORDER BY created_at DESC'
  );
  res.json(result.rows);
});

app.post('/admin/reset-hwid', adminMiddleware, async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Укажи username' });
  await db.execute({
    sql:  'UPDATE users SET hwid = NULL, hwid_locked = 0 WHERE username = ?',
    args: [username],
  });
  res.json({ success: true, message: `HWID сброшен для ${username}` });
});

app.post('/admin/ban', adminMiddleware, async (req, res) => {
  const { username, banned } = req.body;
  if (!username) return res.status(400).json({ error: 'Укажи username' });
  await db.execute({
    sql:  'UPDATE users SET banned = ? WHERE username = ?',
    args: [banned ? 1 : 0, username],
  });
  res.json({ success: true, message: `${username} ${banned ? 'заблокирован' : 'разблокирован'}` });
});

app.delete('/admin/user/:username', adminMiddleware, async (req, res) => {
  const { username } = req.params;
  const userRow = await db.execute({
    sql: 'SELECT id FROM users WHERE username = ?', args: [username],
  });
  if (userRow.rows.length === 0)
    return res.status(404).json({ error: 'Пользователь не найден' });

  const uid = Number(userRow.rows[0].id);
  await db.execute({ sql: 'DELETE FROM sessions WHERE user_id = ?', args: [uid] });
  await db.execute({ sql: 'DELETE FROM users WHERE id = ?', args: [uid] });
  res.json({ success: true });
});

// ─── Запуск ───────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ Luxe Auth Server on port ${PORT}`);
  });
}).catch((e) => {
  console.error('❌ Ошибка инициализации БД:', e);
  process.exit(1);
});
