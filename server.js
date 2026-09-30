require('dotenv').config();

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const db = require('./db');

// ============ КОНФИГ ============
const PORT = process.env.PORT || 3000;
const SECRET = process.env.CIPHER_SECRET || 'cipher-dev-secret-change-me';
const IS_PROD = process.env.NODE_ENV === 'production';
const MAX_FILE_MB = parseInt(process.env.MAX_FILE_MB || '30', 10);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');

const CORS_ORIGINS = (process.env.CORS_ORIGINS || 'http://localhost:3000')
  .split(',').map(s => s.trim()).filter(Boolean);

if (IS_PROD && SECRET === 'cipher-dev-secret-change-me') {
  console.error('❌ В production задай CIPHER_SECRET!');
  process.exit(1);
}

// ============ ИНИЦИАЛИЗАЦИЯ ============
const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: CORS_ORIGINS, credentials: true },
  maxHttpBufferSize: 1e6
});

// Папка загрузок внутри DATA_DIR
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
console.log('📁 Загрузки:', UPLOAD_DIR);

// ============ MIDDLEWARE ============
app.set('trust proxy', 1); // важно для Render (он за прокси)
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use(cors({ origin: CORS_ORIGINS, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// Rate limit
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Слишком много попыток, попробуй позже' },
  standardHeaders: true,
  legacyHeaders: false
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', apiLimiter);

// Health check для Render
app.get('/health', (req, res) => res.json({ ok: true, uptime: process.uptime() }));

// Статика
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR, {
  setHeaders: (res) => res.setHeader('Cache-Control', 'public, max-age=31536000')
}));

// ============ ФАЙЛЫ ============
const ALLOWED_MIME = [
  'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml',
  'audio/webm', 'audio/ogg', 'audio/mpeg', 'audio/mp4', 'audio/wav',
  'application/pdf', 'text/plain',
  'application/zip', 'application/x-zip-compressed'
];

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).slice(0, 8).toLowerCase();
      const safe = Date.now() + '-' + Math.random().toString(36).slice(2, 10) + ext;
      cb(null, safe);
    }
  }),
  limits: { fileSize: MAX_FILE_MB * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') ||
        file.mimetype.startsWith('audio/') ||
        ALLOWED_MIME.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Тип файла не разрешён'));
    }
  }
});

// ============ AUTH ============
function auth(req, res, next) {
  const token = req.cookies?.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Токен недействителен' });
  }
}

function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '30d' });
}

function cookieOpts() {
  return {
    httpOnly: true,
    sameSite: IS_PROD ? 'none' : 'lax',
    secure: IS_PROD,
    maxAge: 30 * 24 * 60 * 60 * 1000
  };
}

// ============ AUTH ROUTES ============
app.post('/api/register', authLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Заполни все поля' });
  if (username.length < 3 || username.length > 24)
    return res.status(400).json({ error: 'Логин от 3 до 24 символов' });
  if (!/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: 'Только латиница, цифры, _' });
  if (password.length < 4)
    return res.status(400).json({ error: 'Пароль минимум 4 символа' });

  const hash = bcrypt.hashSync(password, 10);
  try {
    const info = db.prepare('INSERT INTO users (username,password) VALUES (?,?)').run(username, hash);
    const user = { id: info.lastInsertRowid, username };
    const token = signToken(user);
    res.cookie('token', token, cookieOpts()).json({ ...user, token });
  } catch {
    res.status(400).json({ error: 'Логин уже занят' });
  }
});

app.post('/api/login', authLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Заполни все поля' });

  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(400).json({ error: 'Неверный логин или пароль' });

  const token = signToken(user);
  res.cookie('token', token, cookieOpts()).json({
    id: user.id, username: user.username, token
  });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token').json({ ok: true });
});

// ============ PROFILE ============
app.get('/api/me', auth, (req, res) => {
  const u = db.prepare('SELECT id, username, avatar FROM users WHERE id=?').get(req.user.id);
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json(u);
});

app.get('/api/users', auth, (req, res) => {
  res.json(db.prepare('SELECT id, username, avatar FROM users WHERE id != ?').all(req.user.id));
});

// ============ CHATS ============
app.post('/api/chats/personal', auth, (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'userId обязателен' });
  if (userId === req.user.id) return res.status(400).json({ error: 'Нельзя с самим собой' });

  const exists = db.prepare('SELECT id FROM users WHERE id=?').get(userId);
  if (!exists) return res.status(404).json({ error: 'Пользователь не найден' });

  const existing = db.prepare(`
    SELECT c.id FROM chats c
    JOIN chat_members m1 ON m1.chat_id=c.id AND m1.user_id=?
    JOIN chat_members m2 ON m2.chat_id=c.id AND m2.user_id=?
    WHERE c.is_group=0 LIMIT 1
  `).get(req.user.id, userId);
  if (existing) return res.json({ id: existing.id });

  const info = db.prepare('INSERT INTO chats (is_group) VALUES (0)').run();
  const chatId = info.lastInsertRowid;
  const ins = db.prepare('INSERT INTO chat_members (chat_id,user_id) VALUES (?,?)');
  ins.run(chatId, req.user.id);
  ins.run(chatId, userId);

  io.to('user:' + userId).emit('new-chat');
  res.json({ id: chatId });
});

app.post('/api/chats/group', auth, (req, res) => {
  const { name, userIds } = req.body || {};
  if (!name || name.trim().length < 1 || name.length > 50)
    return res.status(400).json({ error: 'Название 1–50 символов' });

  const info = db.prepare('INSERT INTO chats (name,is_group) VALUES (?,1)').run(name.trim());
  const chatId = info.lastInsertRowid;
  const ins = db.prepare('INSERT INTO chat_members (chat_id,user_id) VALUES (?,?)');
  ins.run(chatId, req.user.id);

  const uniqueIds = [...new Set((userIds || []).map(Number).filter(id => id !== req.user.id))];
  uniqueIds.forEach(uid => {
    if (db.prepare('SELECT id FROM users WHERE id=?').get(uid)) ins.run(chatId, uid);
  });
  uniqueIds.forEach(uid => io.to('user:' + uid).emit('new-chat'));

  res.json({ id: chatId });
});

app.get('/api/chats', auth, (req, res) => {
  const chats = db.prepare(`
    SELECT c.id, c.name, c.is_group FROM chats c
    JOIN chat_members m ON m.chat_id=c.id
    WHERE m.user_id=?
  `).all(req.user.id);

  const result = chats.map(c => {
    const members = db.prepare(`
      SELECT u.id, u.username, u.avatar FROM users u
      JOIN chat_members m ON m.user_id=u.id
      WHERE m.chat_id=?
    `).all(c.id);
    const other = members.find(m => m.id !== req.user.id);
    const last = db.prepare(`
      SELECT text, file_name, voice_url, deleted, created_at FROM messages
      WHERE chat_id=? ORDER BY id DESC LIMIT 1
    `).get(c.id);
    return {
      id: c.id,
      is_group: !!c.is_group,
      name: c.is_group ? c.name : (other?.username || 'Чат'),
      members,
      last: last || null
    };
  });

  result.sort((a, b) => (b.last?.created_at || 0) - (a.last?.created_at || 0));
  res.json(result);
});

// ============ MESSAGES ============
app.get('/api/messages/:chatId', auth, (req, res) => {
  const chatId = +req.params.chatId;
  const member = db.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?')
    .get(chatId, req.user.id);
  if (!member) return res.status(403).json({ error: 'Нет доступа' });

  const limit = Math.min(parseInt(req.query.limit || '200', 10), 500);
  const before = parseInt(req.query.before || '0', 10);

  let rows;
  if (before > 0) {
    rows = db.prepare(`
      SELECT m.id, m.text, m.file_url, m.file_name, m.voice_url, m.voice_duration,
             m.reply_to, m.deleted, m.created_at,
             u.id as user_id, u.username, u.avatar
      FROM messages m JOIN users u ON u.id=m.user_id
      WHERE m.chat_id=? AND m.id < ?
      ORDER BY m.id DESC LIMIT ?
    `).all(chatId, before, limit);
    rows.reverse();
  } else {
    rows = db.prepare(`
      SELECT m.id, m.text, m.file_url, m.file_name, m.voice_url, m.voice_duration,
             m.reply_to, m.deleted, m.created_at,
             u.id as user_id, u.username, u.avatar
      FROM messages m JOIN users u ON u.id=m.user_id
      WHERE m.chat_id=?
      ORDER BY m.id DESC LIMIT ?
    `).all(chatId, limit);
    rows.reverse();
  }

  rows.forEach(msg => {
    msg.reactions = db.prepare(`
      SELECT emoji, COUNT(*) as count, GROUP_CONCAT(user_id) as users
      FROM reactions WHERE message_id=? GROUP BY emoji
    `).all(msg.id);
    if (msg.reply_to) {
      msg.reply = db.prepare(`
        SELECT m.text, m.deleted, u.username FROM messages m
        JOIN users u ON u.id=m.user_id WHERE m.id=?
      `).get(msg.reply_to);
    }
  });

  res.json(rows);
});

app.delete('/api/messages/:id', auth, (req, res) => {
  const id = +req.params.id;
  const msg = db.prepare('SELECT * FROM messages WHERE id=?').get(id);
  if (!msg) return res.status(404).json({ error: 'Не найдено' });
  if (msg.user_id !== req.user.id) return res.status(403).json({ error: 'Не твоё' });
  if (msg.deleted) return res.json({ ok: true });

  db.prepare(`
    UPDATE messages SET deleted=1, text=NULL, file_url=NULL, file_name=NULL,
      voice_url=NULL, voice_duration=NULL WHERE id=?
  `).run(id);

  if (msg.file_url) deleteUploadedFile(msg.file_url);
  if (msg.voice_url) deleteUploadedFile(msg.voice_url);

  io.to('chat:' + msg.chat_id).emit('message-deleted', { messageId: id, chatId: msg.chat_id });
  res.json({ ok: true });
});

function deleteUploadedFile(url) {
  if (!url || !url.startsWith('/uploads/')) return;
  const filename = path.basename(url);
  const filepath = path.join(UPLOAD_DIR, filename);
  fs.unlink(filepath, (err) => {
    if (err) console.warn('⚠️  не удалось удалить:', filepath, err.message);
  });
}

// ============ UPLOADS ============
app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не получен' });
  res.json({
    url: '/uploads/' + req.file.filename,
    name: req.file.originalname,
    size: req.file.size,
    mime: req.file.mimetype
  });
});

app.post('/api/avatar', auth, upload.single('avatar'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не получен' });
  if (!req.file.mimetype.startsWith('image/'))
    return res.status(400).json({ error: 'Аватар должен быть картинкой' });

  const url = '/uploads/' + req.file.filename;
  const old = db.prepare('SELECT avatar FROM users WHERE id=?').get(req.user.id);
  if (old?.avatar) deleteUploadedFile(old.avatar);

  db.prepare('UPDATE users SET avatar=? WHERE id=?').run(url, req.user.id);

  const chats = db.prepare('SELECT chat_id FROM chat_members WHERE user_id=?').all(req.user.id);
  chats.forEach(c => io.to('chat:' + c.chat_id).emit('avatar', { userId: req.user.id, avatar: url }));
  io.to('user:' + req.user.id).emit('avatar', { userId: req.user.id, avatar: url });

  res.json({ url });
});

app.delete('/api/avatar', auth, (req, res) => {
  const old = db.prepare('SELECT avatar FROM users WHERE id=?').get(req.user.id);
  if (old?.avatar) deleteUploadedFile(old.avatar);
  db.prepare('UPDATE users SET avatar=NULL WHERE id=?').run(req.user.id);

  const chats = db.prepare('SELECT chat_id FROM chat_members WHERE user_id=?').all(req.user.id);
  chats.forEach(c => io.to('chat:' + c.chat_id).emit('avatar', { userId: req.user.id, avatar: null }));
  io.to('user:' + req.user.id).emit('avatar', { userId: req.user.id, avatar: null });
  res.json({ ok: true });
});

// ============ ERROR HANDLER ============
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE')
      return res.status(413).json({ error: `Файл больше ${MAX_FILE_MB} МБ` });
    return res.status(400).json({ error: err.message });
  }
  console.error('❌', err);
  res.status(500).json({ error: IS_PROD ? 'Ошибка сервера' : err.message });
});

// SPA fallback
app.get('*', (req, res) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/uploads') || req.path.startsWith('/socket.io')) {
    return res.status(404).json({ error: 'not found' });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============ SOCKET.IO ============
const online = new Map();

io.use((socket, next) => {
  const token = socket.handshake.auth?.token ||
                socket.handshake.headers?.authorization?.split(' ')[1];
  try {
    socket.user = jwt.verify(token, SECRET);
    next();
  } catch {
    next(new Error('auth'));
  }
});

io.on('connection', (socket) => {
  const uid = socket.user.id;

  if (!online.has(uid)) online.set(uid, new Set());
  online.get(uid).add(socket.id);
  socket.join('user:' + uid);

  const chats = db.prepare('SELECT chat_id FROM chat_members WHERE user_id=?').all(uid);
  chats.forEach(c => socket.join('chat:' + c.chat_id));

  io.emit('online', Array.from(online.keys()));

  socket.on('message', (payload) => {
    const { chatId, text, file, voice, replyTo } = payload || {};
    if (!chatId) return;

    const member = db.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?')
      .get(chatId, uid);
    if (!member) return;

    const safeText = typeof text === 'string' ? text.slice(0, 4000) : null;
    if (!safeText && !file && !voice) return;

    const info = db.prepare(`
      INSERT INTO messages (chat_id, user_id, text, file_url, file_name, voice_url, voice_duration, reply_to)
      VALUES (?,?,?,?,?,?,?,?)
    `).run(
      chatId, uid,
      safeText || null,
      file?.url || null, file?.name || null,
      voice?.url || null, voice?.duration || null,
      replyTo || null
    );

    const u = db.prepare('SELECT avatar FROM users WHERE id=?').get(uid);

    const msg = {
      id: info.lastInsertRowid,
      chat_id: chatId,
      user_id: uid,
      username: socket.user.username,
      avatar: u?.avatar || null,
      text: safeText || null,
      file_url: file?.url || null,
      file_name: file?.name || null,
      voice_url: voice?.url || null,
      voice_duration: voice?.duration || null,
      reply_to: replyTo || null,
      deleted: 0,
      created_at: Math.floor(Date.now() / 1000),
      reactions: []
    };

    if (replyTo) {
      msg.reply = db.prepare(`
        SELECT m.text, m.deleted, u.username FROM messages m
        JOIN users u ON u.id=m.user_id WHERE m.id=?
      `).get(replyTo);
    }

    io.to('chat:' + chatId).emit('message', msg);
  });

  socket.on('reaction', ({ messageId, emoji } = {}) => {
    if (!messageId || !emoji || emoji.length > 8) return;
    const msg = db.prepare('SELECT chat_id, deleted FROM messages WHERE id=?').get(messageId);
    if (!msg || msg.deleted) return;

    const member = db.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?')
      .get(msg.chat_id, uid);
    if (!member) return;

    const exists = db.prepare('SELECT 1 FROM reactions WHERE message_id=? AND user_id=? AND emoji=?')
      .get(messageId, uid, emoji);

    if (exists) {
      db.prepare('DELETE FROM reactions WHERE message_id=? AND user_id=? AND emoji=?').run(messageId, uid, emoji);
    } else {
      db.prepare('INSERT INTO reactions (message_id,user_id,emoji) VALUES (?,?,?)').run(messageId, uid, emoji);
    }

    const reactions = db.prepare(`
      SELECT emoji, COUNT(*) as count, GROUP_CONCAT(user_id) as users
      FROM reactions WHERE message_id=? GROUP BY emoji
    `).all(messageId);

    io.to('chat:' + msg.chat_id).emit('reaction', { messageId, reactions });
  });

  socket.on('typing', ({ chatId, isTyping } = {}) => {
    if (!chatId) return;
    const member = db.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?').get(chatId, uid);
    if (!member) return;

    socket.to('chat:' + chatId).emit('typing', {
      chatId, userId: uid, username: socket.user.username, isTyping: !!isTyping
    });
  });

  socket.on('join-chat', (chatId) => {
    const member = db.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?').get(chatId, uid);
    if (member) socket.join('chat:' + chatId);
  });

  socket.on('disconnect', () => {
    const set = online.get(uid);
    if (set) {
      set.delete(socket.id);
      if (set.size === 0) online.delete(uid);
    }
    io.emit('online', Array.from(online.keys()));
  });
});

// ============ START ============
server.listen(PORT, () => {
  console.log(`\n  🔐 Cipher v2 запущен`);
  console.log(`  → Порт:      ${PORT}`);
  console.log(`  → Режим:     ${IS_PROD ? 'production' : 'development'}`);
  console.log(`  → Данные:    ${DATA_DIR}`);
  console.log(`  → Загрузки:  ${UPLOAD_DIR}`);
  console.log(`  → CORS:      ${CORS_ORIGINS.join(', ')}\n`);
});

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
function shutdown() {
  console.log('\n⏻  Останавливаю сервер...');
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000);
}