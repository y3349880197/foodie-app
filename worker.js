/**
 * 今天吃什么🤔 — Cloudflare Worker API
 * 部署：绑定 D1 数据库（binding 名: DB）
 */
const JWT_SECRET_KEY = 'foodie-jwt-secret-change-in-production';
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Max-Age': '86400'
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json;charset=utf-8', ...CORS_HEADERS } });
}

function err(msg, status = 400) { return json({ error: msg }, status); }

// ==================== BASE64 HELPERS (Cloudflare Workers safe) ====================
// btoa() in Workers only accepts Latin1. Must encode UTF-8 -> binary string first.
function utf8ToBase64Url(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function base64UrlToUtf8(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}
function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

// ==================== JWT ====================
async function signJWT(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = { ...payload, iat: now, exp: now + 7 * 24 * 3600 }; // 7 days
  const headerStr = utf8ToBase64Url(JSON.stringify(header));
  const payloadStr = utf8ToBase64Url(JSON.stringify(fullPayload));
  const signingInput = headerStr + '.' + payloadStr;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(JWT_SECRET_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signingInput));
  const sigStr = bufferToBase64(sig).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return signingInput + '.' + sigStr;
}

async function verifyJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const signingInput = parts[0] + '.' + parts[1];
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(JWT_SECRET_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBytes = Uint8Array.from(atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(signingInput));
    if (!valid) return null;
    const payload = JSON.parse(base64UrlToUtf8(parts[1]));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (e) { return null; }
}

// ==================== PASSWORD HASHING (PBKDF2) ====================
async function hashPassword(password, salt) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: encoder.encode(salt), iterations: 100000, hash: 'SHA-256' },
    key, 256
  );
  return bufferToBase64(derived);
}

async function verifyPassword(password, salt, hash) {
  const attempt = await hashPassword(password, salt);
  return attempt === hash;
}

function generateUserId() {
  return 'U_' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).substring(2, 6).toUpperCase();
}

// ==================== AUTH MIDDLEWARE ====================
async function authRequired(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.substring(7);
  return await verifyJWT(token);
}

// ==================== ROUTER ====================
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // CORS preflight
  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS_HEADERS });

  // Parse body for POST/PUT
  let body = {};
  if (method === 'POST' || method === 'PUT') {
    try { body = await request.json(); } catch (e) {}
  }

  // ==================== AUTH ROUTES ====================
  if (path === '/api/auth/register' && method === 'POST') {
    return handleRegister(body, env);
  }
  if (path === '/api/auth/login' && method === 'POST') {
    return handleLogin(body, env);
  }
  if (path === '/api/auth/me' && method === 'GET') {
    const user = await authRequired(request, env);
    if (!user) return err('未登录', 401);
    try {
      const profile = await env.DB.prepare('SELECT * FROM profiles WHERE user_id = ?').bind(user.userId).first();
      if (!profile) return err('用户不存在', 404);
      return json({ user: { userId: profile.user_id, email: profile.email, nickname: profile.nickname } });
    } catch (e) { return err('查询失败: ' + e.message, 500); }
  }

  // ==================== RECIPES ====================
  if (path === '/api/recipes') {
    const user = await authRequired(request, env);
    if (!user) return err('未登录', 401);
    if (method === 'GET') {
      try {
        const result = await env.DB.prepare('SELECT * FROM recipes WHERE user_id = ? ORDER BY created_at DESC').bind(user.userId).all();
        const recipes = (result.results || []).map(mapRecipe);
        return json({ recipes });
      } catch (e) { return err('查询失败: ' + e.message, 500); }
    }
    if (method === 'POST') {
      try {
        const id = body.id || String(Date.now());
        const stmt = env.DB.prepare(
          'INSERT INTO recipes (id, user_id, name, category, cover_image, cook_time, difficulty, servings, ingredients, steps) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        ).bind(id, user.userId, body.name, body.category || '', body.cover_image || null,
               body.cook_time || '', body.difficulty || '简单', body.servings || '2人份',
               JSON.stringify(body.ingredients || []), JSON.stringify(body.steps || []));
        await stmt.run();
        return json({ id }, 201);
      } catch (e) { return err('创建失败: ' + e.message, 500); }
    }
  }

  // Recipe by ID
  const recipeMatch = path.match(/^\/api\/recipes\/([^\/]+)$/);
  if (recipeMatch) {
    const user = await authRequired(request, env);
    if (!user) return err('未登录', 401);
    const rid = recipeMatch[1];

    if (method === 'PUT') {
      try {
        await env.DB.prepare(
          'UPDATE recipes SET name=?, category=?, cover_image=?, cook_time=?, difficulty=?, servings=?, ingredients=?, steps=? WHERE id=? AND user_id=?'
        ).bind(body.name, body.category || '', body.cover_image || null,
               body.cook_time || '', body.difficulty || '简单', body.servings || '2人份',
               JSON.stringify(body.ingredients || []), JSON.stringify(body.steps || []),
               rid, user.userId).run();
        return json({ ok: true });
      } catch (e) { return err('更新失败: ' + e.message, 500); }
    }
    if (method === 'DELETE') {
      try {
        await env.DB.prepare('DELETE FROM recipes WHERE id=? AND user_id=?').bind(rid, user.userId).run();
        return json({ ok: true });
      } catch (e) { return err('删除失败: ' + e.message, 500); }
    }
  }

  // Friend's recipes
  const friendRecipesMatch = path.match(/^\/api\/recipes\/user\/(.+)$/);
  if (friendRecipesMatch && method === 'GET') {
    const user = await authRequired(request, env);
    if (!user) return err('未登录', 401);
    try {
      const result = await env.DB.prepare('SELECT * FROM recipes WHERE user_id = ? ORDER BY created_at DESC').bind(friendRecipesMatch[1]).all();
      return json({ recipes: (result.results || []).map(mapRecipe) });
    } catch (e) { return err('查询失败: ' + e.message, 500); }
  }

  // ==================== FRIENDS ====================
  if (path === '/api/friends') {
    const user = await authRequired(request, env);
    if (!user) return err('未登录', 401);
    if (method === 'GET') {
      try {
        const result = await env.DB.prepare('SELECT * FROM friends WHERE user_id = ?').bind(user.userId).all();
        return json({ friends: (result.results || []).map(r => ({ id: r.friend_id, name: r.friend_name })) });
      } catch (e) { return err('查询失败: ' + e.message, 500); }
    }
    if (method === 'POST') {
      try {
        await env.DB.prepare('INSERT OR IGNORE INTO friends (user_id, friend_id, friend_name) VALUES (?, ?, ?)').bind(user.userId, body.friend_id, body.friend_name).run();
        return json({ ok: true }, 201);
      } catch (e) { return err('添加失败: ' + e.message, 500); }
    }
  }

  if (path.startsWith('/api/friends/') && method === 'DELETE') {
    const user = await authRequired(request, env);
    if (!user) return err('未登录', 401);
    const fid = path.split('/')[3];
    try {
      await env.DB.prepare('DELETE FROM friends WHERE user_id=? AND friend_id=?').bind(user.userId, fid).run();
      return json({ ok: true });
    } catch (e) { return err('删除失败: ' + e.message, 500); }
  }

  // ==================== FRIEND REQUESTS ====================
  if (path === '/api/friend-requests') {
    const user = await authRequired(request, env);
    if (!user) return err('未登录', 401);
    if (method === 'GET') {
      try {
        const result = await env.DB.prepare("SELECT * FROM friend_requests WHERE to_user_id = ? OR from_user_id = ? ORDER BY created_at DESC").bind(user.userId, user.userId).all();
        const requests = (result.results || []).map(r => ({
          id: r.id, type: r.to_user_id === user.userId ? 'received' : 'sent',
          fromId: r.from_user_id, fromName: r.from_nickname,
          toId: r.to_user_id, time: r.created_at, status: r.status
        }));
        return json({ requests });
      } catch (e) { return err('查询失败: ' + e.message, 500); }
    }
    if (method === 'POST') {
      try {
        await env.DB.prepare('INSERT INTO friend_requests (from_user_id, to_user_id, from_nickname, status) VALUES (?, ?, ?, ?)').bind(user.userId, body.to_user_id, body.from_nickname || user.nickname, 'pending').run();
        return json({ ok: true }, 201);
      } catch (e) { return err('发送失败: ' + e.message, 500); }
    }
  }

  const reqMatch = path.match(/^\/api\/friend-requests\/(.+)$/);
  if (reqMatch && method === 'PUT') {
    const user = await authRequired(request, env);
    if (!user) return err('未登录', 401);
    try {
      await env.DB.prepare('UPDATE friend_requests SET status = ? WHERE id = ? AND to_user_id = ?').bind(body.status, reqMatch[1], user.userId).run();
      // If accepted, add mutual friends
      if (body.status === 'accepted') {
        const req = await env.DB.prepare('SELECT * FROM friend_requests WHERE id = ?').bind(reqMatch[1]).first();
        if (req) {
          // Add as friend for both users
          const fromName = req.from_nickname;
          const toProf = await env.DB.prepare('SELECT * FROM profiles WHERE user_id = ?').bind(user.userId).first();
          const toName = toProf ? toProf.nickname : user.nickname;
          await env.DB.prepare('INSERT OR IGNORE INTO friends (user_id, friend_id, friend_name) VALUES (?, ?, ?)').bind(user.userId, req.from_user_id, fromName).run();
          await env.DB.prepare('INSERT OR IGNORE INTO friends (user_id, friend_id, friend_name) VALUES (?, ?, ?)').bind(req.from_user_id, user.userId, toName).run();
        }
      }
      return json({ ok: true });
    } catch (e) { return err('更新失败: ' + e.message, 500); }
  }

  // ==================== MESSAGES ====================
  if (path === '/api/messages') {
    const user = await authRequired(request, env);
    if (!user) return err('未登录', 401);
    if (method === 'GET') {
      try {
        const result = await env.DB.prepare('SELECT * FROM messages WHERE user_id = ? ORDER BY created_at DESC LIMIT 100').bind(user.userId).all();
        const messages = (result.results || []).map(m => ({
          id: m.id, type: m.type, dir: m.dir, from: m.from_user, fromId: m.from_id,
          to: m.to_user, toId: m.to_id, recipe: m.recipe_name, msg: m.message_text,
          time: m.created_at, status: m.status
        }));
        return json({ messages });
      } catch (e) { return err('查询失败: ' + e.message, 500); }
    }
    if (method === 'POST') {
      try {
        const id = String(Date.now());
        await env.DB.prepare(
          'INSERT INTO messages (id, user_id, type, dir, from_user, from_id, to_user, to_id, recipe_name, message_text, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        ).bind(id, body.user_id || user.userId, body.type, body.dir, body.from, body.fromId,
               body.to, body.toId, body.recipe || '', body.msg || '', body.status || 'unread').run();
        // Also insert for recipient
        if (body.toId) {
          await env.DB.prepare(
            'INSERT INTO messages (id, user_id, type, dir, from_user, from_id, to_user, to_id, recipe_name, message_text, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
          ).bind(id + '_r', body.toId, body.type, 'received', body.from, body.fromId,
                 body.to, body.toId, body.recipe || '', body.msg || '', 'unread').run();
        }
        return json({ id }, 201);
      } catch (e) { return err('发送失败: ' + e.message, 500); }
    }
  }

  // ==================== PROFILE ====================
  if (path === '/api/profile' && method === 'PUT') {
    const user = await authRequired(request, env);
    if (!user) return err('未登录', 401);
    try {
      await env.DB.prepare('UPDATE profiles SET nickname = ?, avatar_data = ? WHERE user_id = ?').bind(body.nickname || user.nickname, body.avatar_data || null, user.userId).run();
      return json({ ok: true });
    } catch (e) { return err('更新失败: ' + e.message, 500); }
  }

  const profileMatch = path.match(/^\/api\/profile\/(.+)$/);
  if (profileMatch && method === 'GET') {
    const user = await authRequired(request, env);
    if (!user) return err('未登录', 401);
    try {
      const profile = await env.DB.prepare('SELECT user_id, email, nickname, avatar_data FROM profiles WHERE user_id = ?').bind(profileMatch[1]).first();
      if (!profile) return err('用户不存在', 404);
      return json({ profile: { userId: profile.user_id, email: profile.email, nickname: profile.nickname, avatar_data: profile.avatar_data } });
    } catch (e) { return err('查询失败: ' + e.message, 500); }
  }

  // ==================== USER SEARCH ====================
  if (path === '/api/users/search' && method === 'GET') {
    const user = await authRequired(request, env);
    if (!user) return err('未登录', 401);
    const q = url.searchParams.get('q') || '';
    try {
      const result = await env.DB.prepare("SELECT user_id, email, nickname, avatar_data FROM profiles WHERE (email LIKE ? OR nickname LIKE ?) AND user_id != ? LIMIT 10").bind(`%${q}%`, `%${q}%`, user.userId).all();
      return json({ users: (result.results || []).map(p => ({ userId: p.user_id, email: p.email, nickname: p.nickname })) });
    } catch (e) { return err('搜索失败: ' + e.message, 500); }
  }

  // ==================== MIGRATION (one-time use) ====================
  if (path === '/api/admin/migrate' && method === 'POST') {
    if (body.key !== 'foodie-migrate-2026') return err('Unauthorized', 403);
    return handleMigrate(body, env);
  }

  return err('Not found', 404);
}

// ==================== HANDLERS ====================
async function handleRegister(body, env) {
  const { email, password, nickname } = body;
  if (!email || !email.includes('@')) return err('请输入有效的邮箱');
  if (!password || password.length < 6) return err('密码至少6位');
  if (!nickname) return err('请输入昵称');

  try {
    const existing = await env.DB.prepare('SELECT user_id FROM profiles WHERE email = ?').bind(email).first();
    if (existing) return err('该邮箱已被注册');

    const userId = generateUserId();
    const salt = crypto.randomUUID();
    const hash = await hashPassword(password, salt);

    await env.DB.prepare('INSERT INTO profiles (user_id, email, nickname, password_hash, password_salt) VALUES (?, ?, ?, ?, ?)').bind(userId, email, nickname, hash, salt).run();

    const token = await signJWT({ userId, email, nickname });
    return json({ token, user: { userId, email, nickname } }, 201);
  } catch (e) { return err('注册失败: ' + e.message, 500); }
}

async function handleLogin(body, env) {
  const { email, password } = body;
  if (!email || !password) return err('请输入邮箱和密码');

  try {
    const profile = await env.DB.prepare('SELECT * FROM profiles WHERE email = ?').bind(email).first();
    if (!profile) return err('邮箱或密码错误');

    const valid = await verifyPassword(password, profile.password_salt, profile.password_hash);
    if (!valid) return err('邮箱或密码错误');

    const token = await signJWT({ userId: profile.user_id, email: profile.email, nickname: profile.nickname });
    return json({ token, user: { userId: profile.user_id, email: profile.email, nickname: profile.nickname } });
  } catch (e) { return err('登录失败: ' + e.message, 500); }
}

// ==================== HELPERS ====================
function mapRecipe(r) {
  return {
    id: r.id, name: r.name, coverEmoji: '🍳', category: r.category,
    time: r.cook_time || '', difficulty: r.difficulty || '简单', servings: r.servings || '2人份',
    ingredients: typeof r.ingredients === 'string' ? JSON.parse(r.ingredients) : (r.ingredients || []),
    steps: typeof r.steps === 'string' ? JSON.parse(r.steps) : (r.steps || []),
    coverImage: r.cover_image || null
  };
}

async function handleMigrate(body, env) {
  const { users, recipes, friends, friend_requests, messages } = body;
  const results = { users: 0, recipes: 0, friends: 0, friend_requests: 0, messages: 0, errors: [] };

  try {
    // Migrate users
    if (users && Array.isArray(users)) {
      for (const u of users) {
        try {
          const salt = crypto.randomUUID();
          const hash = await hashPassword('migrate123456', salt);
          await env.DB.prepare(
            'INSERT OR IGNORE INTO profiles (user_id, email, nickname, avatar_data, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
          ).bind(u.user_id, u.email, u.nickname, u.avatar_data || null, hash, salt, u.created_at || new Date().toISOString()).run();
          results.users++;
        } catch (e) { results.errors.push('user:' + u.user_id + ' - ' + e.message); }
      }
    }

    // Migrate recipes
    if (recipes && Array.isArray(recipes)) {
      for (const r of recipes) {
        try {
          await env.DB.prepare(
            'INSERT OR IGNORE INTO recipes (id, user_id, name, category, cover_image, cook_time, difficulty, servings, ingredients, steps, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
          ).bind(
            r.id, r.user_id, r.name, r.category || '', r.cover_image || null,
            r.cook_time || '', r.difficulty || '简单', r.servings || '2人份',
            JSON.stringify(r.ingredients || []), JSON.stringify(r.steps || []),
            r.created_at || new Date().toISOString()
          ).run();
          results.recipes++;
        } catch (e) { results.errors.push('recipe:' + r.id + ' - ' + e.message); }
      }
    }

    // Migrate friends
    if (friends && Array.isArray(friends)) {
      for (const f of friends) {
        try {
          await env.DB.prepare('INSERT OR IGNORE INTO friends (user_id, friend_id, friend_name) VALUES (?, ?, ?)')
            .bind(f.user_id, f.friend_id, f.friend_name || '').run();
          results.friends++;
        } catch (e) { results.errors.push('friend:' + f.user_id + '-' + f.friend_id + ' - ' + e.message); }
      }
    }

    // Migrate friend_requests
    if (friend_requests && Array.isArray(friend_requests)) {
      for (const fr of friend_requests) {
        try {
          await env.DB.prepare('INSERT OR IGNORE INTO friend_requests (id, from_user_id, to_user_id, from_nickname, status, created_at) VALUES (?, ?, ?, ?, ?, ?)')
            .bind(fr.id, fr.from_user_id, fr.to_user_id, fr.from_nickname || '', fr.status || 'pending', fr.created_at || new Date().toISOString()).run();
          results.friend_requests++;
        } catch (e) { results.errors.push('req:' + fr.id + ' - ' + e.message); }
      }
    }

    // Migrate messages
    if (messages && Array.isArray(messages)) {
      for (const m of messages) {
        try {
          await env.DB.prepare(
            'INSERT OR IGNORE INTO messages (id, user_id, type, dir, from_user, from_id, to_user, to_id, recipe_name, message_text, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
          ).bind(m.id, m.user_id, m.type || 'order', m.dir || 'sent', m.from_user || '', m.from_id || '',
                 m.to_user || '', m.to_id || '', m.recipe_name || '', m.message_text || '',
                 m.status || 'unread', m.created_at || new Date().toISOString()).run();
          results.messages++;
        } catch (e) { results.errors.push('msg:' + m.id + ' - ' + e.message); }
      }
    }

    return json({ ok: true, results });
  } catch (e) {
    return err('Migration failed: ' + e.message, 500);
  }
}

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  }
};
