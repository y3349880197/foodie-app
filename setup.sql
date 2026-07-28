-- ============================================================
-- 「今天吃什么🤔」Supabase 数据库初始化脚本
-- 可重复执行，不会报错
-- ============================================================

-- 1. 用户资料表
CREATE TABLE IF NOT EXISTS profiles (
  id BIGSERIAL PRIMARY KEY,
  user_id TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  nickname TEXT NOT NULL,
  avatar_data TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. 菜谱表
CREATE TABLE IF NOT EXISTS recipes (
  id BIGINT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  cover_image TEXT,
  cook_time TEXT,
  difficulty TEXT DEFAULT '简单',
  servings TEXT DEFAULT '2人份',
  ingredients JSONB DEFAULT '[]'::jsonb,
  steps JSONB DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_recipes_user ON recipes(user_id);

-- 3. 好友关系表
CREATE TABLE IF NOT EXISTS friends (
  id BIGSERIAL PRIMARY KEY,
  user_id TEXT NOT NULL,
  friend_id TEXT NOT NULL,
  friend_name TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, friend_id)
);
CREATE INDEX IF NOT EXISTS idx_friends_user ON friends(user_id);

-- 4. 好友请求表
CREATE TABLE IF NOT EXISTS friend_requests (
  id BIGSERIAL PRIMARY KEY,
  from_user_id TEXT NOT NULL,
  from_nickname TEXT NOT NULL,
  to_user_id TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_requests_to ON friend_requests(to_user_id);
CREATE INDEX IF NOT EXISTS idx_requests_from ON friend_requests(from_user_id);

-- 5. 消息表
CREATE TABLE IF NOT EXISTS messages (
  id BIGINT PRIMARY KEY,
  user_id TEXT NOT NULL,
  type TEXT NOT NULL,
  dir TEXT,
  from_user TEXT,
  from_id TEXT,
  to_user TEXT,
  to_id TEXT,
  recipe_name TEXT,
  message_text TEXT,
  read BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_messages_user ON messages(user_id);

-- ============================================================
-- 行级安全策略 (RLS) — 先删再加，可重复执行
-- ============================================================

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE recipes ENABLE ROW LEVEL SECURITY;
ALTER TABLE friends ENABLE ROW LEVEL SECURITY;
ALTER TABLE friend_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;

-- 先删除所有旧策略
DROP POLICY IF EXISTS "anon can read all profiles" ON profiles;
DROP POLICY IF EXISTS "anon can insert own profile" ON profiles;
DROP POLICY IF EXISTS "anon can update own profile" ON profiles;
DROP POLICY IF EXISTS "anon can read own recipes" ON recipes;
DROP POLICY IF EXISTS "anon can insert own recipes" ON recipes;
DROP POLICY IF EXISTS "anon can update own recipes" ON recipes;
DROP POLICY IF EXISTS "anon can delete own recipes" ON recipes;
DROP POLICY IF EXISTS "anon can read own friends" ON friends;
DROP POLICY IF EXISTS "anon can insert own friends" ON friends;
DROP POLICY IF EXISTS "anon can delete own friends" ON friends;
DROP POLICY IF EXISTS "anon can read own requests" ON friend_requests;
DROP POLICY IF EXISTS "anon can insert requests" ON friend_requests;
DROP POLICY IF EXISTS "anon can update requests" ON friend_requests;
DROP POLICY IF EXISTS "anon can read own messages" ON messages;
DROP POLICY IF EXISTS "anon can insert messages" ON messages;
DROP POLICY IF EXISTS "anon can update messages" ON messages;

-- 重建策略：profiles
CREATE POLICY "anon can read all profiles" ON profiles
  FOR SELECT TO anon USING (true);

CREATE POLICY "anon can insert own profile" ON profiles
  FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "anon can update own profile" ON profiles
  FOR UPDATE TO anon USING (true);

-- 重建策略：recipes
CREATE POLICY "anon can read own recipes" ON recipes
  FOR SELECT TO anon USING (true);

CREATE POLICY "anon can insert own recipes" ON recipes
  FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "anon can update own recipes" ON recipes
  FOR UPDATE TO anon USING (true);

CREATE POLICY "anon can delete own recipes" ON recipes
  FOR DELETE TO anon USING (true);

-- 重建策略：friends
CREATE POLICY "anon can read own friends" ON friends
  FOR SELECT TO anon USING (true);

CREATE POLICY "anon can insert own friends" ON friends
  FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "anon can delete own friends" ON friends
  FOR DELETE TO anon USING (true);

-- 重建策略：friend_requests
CREATE POLICY "anon can read own requests" ON friend_requests
  FOR SELECT TO anon USING (true);

CREATE POLICY "anon can insert requests" ON friend_requests
  FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "anon can update requests" ON friend_requests
  FOR UPDATE TO anon USING (true);

-- 重建策略：messages
CREATE POLICY "anon can read own messages" ON messages
  FOR SELECT TO anon USING (true);

CREATE POLICY "anon can insert messages" ON messages
  FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "anon can update messages" ON messages
  FOR UPDATE TO anon USING (true);
