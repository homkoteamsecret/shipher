const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// Папка данных: на Render — /var/data, локально — ./data
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_PATH = path.join(DATA_DIR, 'cipher.db');
console.log('📦 База данных:', DB_PATH);

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ============ ТАБЛИЦЫ ============
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  avatar TEXT,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS chats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  is_group INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS chat_members (
  chat_id INTEGER,
  user_id INTEGER,
  PRIMARY KEY (chat_id, user_id)
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  text TEXT,
  file_url TEXT,
  file_name TEXT,
  voice_url TEXT,
  voice_duration INTEGER,
  reply_to INTEGER,
  deleted INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS reactions (
  message_id INTEGER,
  user_id INTEGER,
  emoji TEXT,
  PRIMARY KEY (message_id, user_id, emoji)
);
`);

// ============ ИНДЕКСЫ ============
db.exec(`
CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages (chat_id, id);
CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_members (user_id);
CREATE INDEX IF NOT EXISTS idx_chat_members_chat ON chat_members (chat_id);
CREATE INDEX IF NOT EXISTS idx_reactions_message ON reactions (message_id);
`);

// ============ МИГРАЦИИ ============
function ensureColumn(table, name, def) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.find(c => c.name === name)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${def}`);
    console.log(`  ⚙️  migration: ${table}.${name} добавлена`);
  }
}

ensureColumn('users', 'avatar', 'TEXT');
ensureColumn('messages', 'voice_url', 'TEXT');
ensureColumn('messages', 'voice_duration', 'INTEGER');
ensureColumn('messages', 'deleted', 'INTEGER DEFAULT 0');

module.exports = db;
module.exports.DATA_DIR = DATA_DIR;