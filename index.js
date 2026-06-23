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
  await db.executeMultiple(`
    CREATE TABLE IF NOT EXISTS users (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      username    TEXT    UNIQUE NOT NULL,
      password    TEXT    NOT NULL,
      hwid        TEXT    DEFAULT NULL,
      hwid_locked INTEGER DEFAULT 0,
      banned      INTEGER DEFAULT 0,
      created_at  TEXT    DEFAULT (datetime('now')),
      last_login  TEXT    DEFAULT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL,
      token      TEXT    NOT NULL,
      created_at TEXT    DEFAULT (datetime('now'))
    );
  `);
  console.log('✅ БД готова');
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
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
      sql:  'INSERT INTO users (username, password, hwid, hwid_locked) VALUES (?, ?, ?, 1)',
      args: [username, hashed, hashedHwid],
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
        sql:  'UPDATE users SET hwid = ?, hwid_locked = 1 WHERE id = ?',
        args: [hashedHwid, Number(user.id)],
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
    'SELECT id, username, hwid_locked, banned, created_at, last_login FROM users ORDER BY created_at DESC'
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
