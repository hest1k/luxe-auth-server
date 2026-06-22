const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');

const app = express();
app.use(express.json());
app.use(cors());

// ─── БД ──────────────────────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'users.db');
const db = new Database(DB_PATH);

// Создаём таблицы при первом запуске
db.exec(`
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
    hwid       TEXT    NOT NULL,
    created_at TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// ─── Конфиг ───────────────────────────────────────────────────────────────────
const JWT_SECRET   = process.env.JWT_SECRET   || 'luxe-secret-change-this-in-production';
const ADMIN_KEY    = process.env.ADMIN_KEY    || 'luxe-admin-key-change-this';
const PORT         = process.env.PORT         || 3000;

// ─── Middleware: проверка JWT ─────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Нет токена' });

  const token = header.replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Токен недействителен' });
  }
}

// ─── Middleware: проверка Admin ───────────────────────────────────────────────
function adminMiddleware(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (key !== ADMIN_KEY) return res.status(403).json({ error: 'Нет доступа' });
  next();
}

// ─── Хэш HWID ────────────────────────────────────────────────────────────────
function hashHwid(hwid) {
  return crypto.createHash('sha256').update(hwid).digest('hex');
}

// ══════════════════════════════════════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// Проверка работы сервера
app.get('/', (req, res) => {
  res.json({ status: 'ok', name: 'Luxe Auth Server', version: '1.0.0' });
});

// ─── Регистрация ──────────────────────────────────────────────────────────────
app.post('/auth/register', async (req, res) => {
  const { username, password, hwid } = req.body;

  if (!username || !password || !hwid) {
    return res.status(400).json({ error: 'Заполни все поля' });
  }

  if (username.length < 3 || username.length > 16) {
    return res.status(400).json({ error: 'Никнейм должен быть от 3 до 16 символов' });
  }

  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return res.status(400).json({ error: 'Никнейм может содержать только буквы, цифры и _' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  }

  // Проверяем не занят ли ник
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    return res.status(409).json({ error: 'Этот никнейм уже занят' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const hashedHwid     = hashHwid(hwid);

  try {
    db.prepare(`
      INSERT INTO users (username, password, hwid, hwid_locked)
      VALUES (?, ?, ?, 1)
    `).run(username, hashedPassword, hashedHwid);

    const user = db.prepare('SELECT id, username FROM users WHERE username = ?').get(username);
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });

    // Сохраняем сессию
    db.prepare('INSERT INTO sessions (user_id, token, hwid) VALUES (?, ?, ?)').run(user.id, token, hashedHwid);

    res.json({ success: true, token, username: user.username });
  } catch (e) {
    res.status(500).json({ error: 'Ошибка сервера: ' + e.message });
  }
});

// ─── Вход ─────────────────────────────────────────────────────────────────────
app.post('/auth/login', async (req, res) => {
  const { username, password, hwid } = req.body;

  if (!username || !password || !hwid) {
    return res.status(400).json({ error: 'Заполни все поля' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user) {
    return res.status(404).json({ error: 'Аккаунт не найден' });
  }

  if (user.banned) {
    return res.status(403).json({ error: 'Аккаунт заблокирован' });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ error: 'Неверный пароль' });
  }

  const hashedHwid = hashHwid(hwid);

  // Проверяем HWID
  if (user.hwid_locked && user.hwid) {
    if (user.hwid !== hashedHwid) {
      return res.status(403).json({
        error: 'Аккаунт привязан к другому компьютеру. Обратись к администратору для сброса.',
      });
    }
  } else {
    // Привязываем HWID при первом входе
    db.prepare('UPDATE users SET hwid = ?, hwid_locked = 1 WHERE id = ?').run(hashedHwid, user.id);
  }

  // Обновляем last_login
  db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(user.id);

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });

  // Сохраняем сессию
  db.prepare('INSERT INTO sessions (user_id, token, hwid) VALUES (?, ?, ?)').run(user.id, token, hashedHwid);

  res.json({ success: true, token, username: user.username });
});

// ─── Проверка токена (при повторном запуске) ──────────────────────────────────
app.post('/auth/verify', authMiddleware, (req, res) => {
  const { hwid } = req.body;
  if (!hwid) return res.status(400).json({ error: 'Нет HWID' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  if (user.banned) return res.status(403).json({ error: 'Аккаунт заблокирован' });

  const hashedHwid = hashHwid(hwid);
  if (user.hwid && user.hwid !== hashedHwid) {
    return res.status(403).json({ error: 'HWID не совпадает' });
  }

  res.json({ success: true, username: user.username });
});

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN ROUTES (защищены ключом)
// ══════════════════════════════════════════════════════════════════════════════

// Список всех пользователей
app.get('/admin/users', adminMiddleware, (req, res) => {
  const users = db.prepare(`
    SELECT id, username, hwid_locked, banned, created_at, last_login
    FROM users ORDER BY created_at DESC
  `).all();
  res.json(users);
});

// Сброс HWID
app.post('/admin/reset-hwid', adminMiddleware, (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Укажи username' });

  const result = db.prepare('UPDATE users SET hwid = NULL, hwid_locked = 0 WHERE username = ?').run(username);
  if (result.changes === 0) return res.status(404).json({ error: 'Пользователь не найден' });

  res.json({ success: true, message: `HWID сброшен для ${username}` });
});

// Бан / разбан
app.post('/admin/ban', adminMiddleware, (req, res) => {
  const { username, banned } = req.body;
  if (!username) return res.status(400).json({ error: 'Укажи username' });

  const result = db.prepare('UPDATE users SET banned = ? WHERE username = ?').run(banned ? 1 : 0, username);
  if (result.changes === 0) return res.status(404).json({ error: 'Пользователь не найден' });

  res.json({ success: true, message: `${username} ${banned ? 'заблокирован' : 'разблокирован'}` });
});

// Удаление пользователя
app.delete('/admin/user/:username', adminMiddleware, (req, res) => {
  const { username } = req.params;
  db.prepare('DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)').run(username);
  const result = db.prepare('DELETE FROM users WHERE username = ?').run(username);
  if (result.changes === 0) return res.status(404).json({ error: 'Пользователь не найден' });

  res.json({ success: true, message: `${username} удалён` });
});

// ─── Запуск ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Luxe Auth Server запущен на порту ${PORT}`);
  console.log(`Admin key: ${ADMIN_KEY}`);
});
