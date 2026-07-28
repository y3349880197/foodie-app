-- ============================================================
-- 清理重复的 profiles（同一邮箱多个 user_id）
-- 保留最早创建的那条记录
-- ============================================================

-- 1. 先查看有多少重复的邮箱
SELECT email, COUNT(*) as cnt, array_agg(user_id) as user_ids
FROM profiles
GROUP BY email
HAVING COUNT(*) > 1;

-- 2. 删除重复的 profile，保留 id 最小（最早创建）的那条
DELETE FROM profiles
WHERE id NOT IN (
  SELECT MIN(id) FROM profiles GROUP BY email
)
AND email IN (
  SELECT email FROM profiles GROUP BY email HAVING COUNT(*) > 1
);

-- 3. 确认清理后没有重复
SELECT email, COUNT(*) as cnt
FROM profiles
GROUP BY email
HAVING COUNT(*) > 1;
