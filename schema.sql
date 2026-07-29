-- D1 Schema for 今天吃什么🤔
-- 在 Cloudflare Dashboard → D1 → 你的数据库 → Console 中执行

CREATE TABLE IF NOT EXISTS profiles (
  user_id    TEXT PRIMARY KEY,
  email      TEXT NOT NULL UNIQUE,
  nickname   TEXT NOT NULL,
  avatar_data TEXT,
  password_hash TEXT NOT NULL DEFAULT '',
  password_salt TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS recipes (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  name        TEXT NOT NULL,
  category    TEXT NOT NULL DEFAULT '',
  cover_image TEXT,
  cook_time   TEXT NOT NULL DEFAULT '30',
  difficulty  TEXT NOT NULL DEFAULT '简单',
  servings    TEXT NOT NULL DEFAULT '2人份',
  ingredients TEXT NOT NULL DEFAULT '[]',
  steps       TEXT NOT NULL DEFAULT '[]',
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES profiles(user_id)
);

CREATE INDEX IF NOT EXISTS idx_recipes_user ON recipes(user_id);

CREATE TABLE IF NOT EXISTS friends (
  user_id     TEXT NOT NULL,
  friend_id   TEXT NOT NULL,
  friend_name TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (user_id, friend_id),
  FOREIGN KEY (user_id) REFERENCES profiles(user_id)
);

CREATE TABLE IF NOT EXISTS friend_requests (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  from_user_id  TEXT NOT NULL,
  to_user_id    TEXT NOT NULL,
  from_nickname TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL DEFAULT 'pending',
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_fr_to ON friend_requests(to_user_id);
CREATE INDEX IF NOT EXISTS idx_fr_from ON friend_requests(from_user_id);

CREATE TABLE IF NOT EXISTS messages (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL,
  type         TEXT NOT NULL DEFAULT 'order',
  dir          TEXT NOT NULL DEFAULT 'sent',
  from_user    TEXT NOT NULL DEFAULT '',
  from_id      TEXT NOT NULL DEFAULT '',
  to_user      TEXT NOT NULL DEFAULT '',
  to_id        TEXT NOT NULL DEFAULT '',
  recipe_name  TEXT NOT NULL DEFAULT '',
  message_text TEXT NOT NULL DEFAULT '',
  status       TEXT NOT NULL DEFAULT 'unread',
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_msg_user ON messages(user_id);
