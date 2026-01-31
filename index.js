// index.js
import { hash, variant } from "https://deno.land/x/argon2ian@2.0.1/dist/argon2ian.sync.min.js";
import { encode, decode } from "https://deno.land/std@0.192.0/encoding/base64.ts";

const kv = await Deno.openKv();
const QUEUE_KEY = ["comments"];
const MAX_QUEUE_SIZE = 50;

// 超长站长密码
const ADMIN_PASSWORD =
  Deno.env.get("ADMIN_PASSWORD") ||
  ".i6}HDhQIdu2.wOmqPLaA8Qp<JXTze*XJL>{<c@r4!^a|A|k,O#x}{04PCy*wl&nfhPTVUpm>i7ATOQiZ<A#irY?Q>NU-QVEAiua)X2_#</.q)[r9:JHM]Qb46Ju-$U?a/w8+C9lODT6h@|:^!54:&21_j3WqcO=8g<M9I]Kn|D#(*Dkb_[XOdn*_eZybHT|f#WSW5|?w_](/@d.jog3%+&NNlp]tw}mN!v7_Z&yE[3yN98Q_DD#{KTpmqOV^__Q";

// 工具函数
async function checkTempPassword(password) {
  const temp = await kv.get(["tempPassword", password]);
  if (!temp.value) return false;
  if (Date.now() > temp.value) {
    await kv.delete(["tempPassword", password]);
    return false;
  }
  return true;
}

async function checkLogin(token) {
  const res = await kv.get(["token", token]);
  if (!res.value || res.value.validityTime < Date.now()) {
    if (res.value) await kv.delete(["token", token]);
    return null;
  }
  return res.value.name;
}

function validateUsername(name) {
  if (!name || name.length < 3 || name.length > 20) return "用户名需要3-20位";
  if (!/^[0-9a-zA-Z_]+$/.test(name)) return "用户名只能包含字母、数字、下划线";
  return null;
}

function validatePassword(password, minLength = 8) {
  if (!password || password.length < minLength) return `密码长度至少${minLength}位`;
  if (!/[0-9]/.test(password)) return "密码需要包含数字";
  if (!/[a-zA-Z]/.test(password)) return "密码需要包含字母";
  return null;
}

// 清理过期 invite key / temp password / token
async function cleanExpiredKeys() {
  for await (const entry of kv.list({ prefix: ["invitekey"] })) {
    if (entry.value < Date.now()) await kv.delete(entry.key);
  }
  for await (const entry of kv.list({ prefix: ["tempPassword"] })) {
    if (entry.value < Date.now()) await kv.delete(entry.key);
  }
  for await (const entry of kv.list({ prefix: ["token"] })) {
    if (entry.value.validityTime < Date.now()) await kv.delete(entry.key);
  }
}

// Argon2 哈希函数，返回 Base64
function argon2(password, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const hashedBytes = hash(new TextEncoder().encode(password), salt, {
    t: 3,
    m: 65536,
    p: 1,
    variant: variant.Argon2id,
  });
  return {
    salt: encode(salt),
    hashed: encode(hashedBytes),
  };
}

const header = {
  "Content-Type": "application/json;charset=UTF-8",
  "Access-Control-Allow-Origin": "https://songlll.pages.dev",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};


export default {
  async fetch(req) {
    try {
      const url = new URL(req.url);
      const data = await req.json().catch(() => ({}));

      if (req.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: header });
      }

      if (url.pathname === "/ping") {
        return new Response("pong", { status: 200, headers: header });
      }

      // --- 清理过期 ---
      if (url.pathname === "/clean") {
        const { password } = data;
        if (password !== ADMIN_PASSWORD && !(await checkTempPassword(password))) {
          return new Response(JSON.stringify({ error: "无权限" }), { status: 403, headers: header });
        }
        await cleanExpiredKeys();
        return new Response(JSON.stringify({ message: "清理任务已触发" }), { status: 200, headers: header });
      }

      // --- 获取 token 用户名 ---
      if (url.pathname === "/me") {
        const { token } = data;
        const name = await checkLogin(token);
        if (!name) return new Response(JSON.stringify({ error: "未登录" }), { status: 403, headers: header });
        return new Response(JSON.stringify({ name }), { status: 200, headers: header });
      }

      // --- 注册 ---
      if (url.pathname === "/register") {
        const { name, password, key } = data;

        const usernameErr = validateUsername(name);
        if (usernameErr) return new Response(JSON.stringify({ error: usernameErr }), { status: 400, headers: header });

        const passwordErr = validatePassword(password);
        if (passwordErr) return new Response(JSON.stringify({ error: passwordErr }), { status: 400, headers: header });

        const keyRes = await kv.get(["invitekey", key]);
        if (!keyRes.value) return new Response(JSON.stringify({ error: "邀请码无效" }), { status: 400, headers: header });
        if (keyRes.value < Date.now()) {
          await kv.delete(["invitekey", key]);
          return new Response(JSON.stringify({ error: "邀请码已过期" }), { status: 400, headers: header });
        }

        const user = await kv.get(["user", name]);
        if (user.value) return new Response(JSON.stringify({ error: "用户名已存在" }), { status: 400, headers: header });
        await kv.set(["user", name], argon2(password));
        await kv.delete(["invitekey", key]);

        return new Response(JSON.stringify({ message: "注册成功" }), { status: 200, headers: header });
      }

      // --- 生成邀请码 ---
      if (url.pathname === "/newInviteKey") {
        const { password } = data;
        if (password !== ADMIN_PASSWORD && !(await checkTempPassword(password))) {
          return new Response(JSON.stringify({ error: "密码无效" }), { status: 403, headers: header });
        }
        const key = Math.random().toString(36).slice(-8);
        const validityTime = Date.now() + 7 * 24 * 60 * 60 * 1000;
        await kv.set(["invitekey", key], validityTime);
        return new Response(JSON.stringify({ key, validUntil: validityTime }), { status: 200, headers: header });
      }

      // --- 添加临时密码 ---
      if (url.pathname === "/addTempPassword") {
        const { password, newPassword } = data;
        if (password !== ADMIN_PASSWORD) {
          return new Response(JSON.stringify({ error: "只有站长可添加临时密码" }), { status: 403, headers: header });
        }
        const pwErr = validatePassword(newPassword, 10);
        if (pwErr) return new Response(JSON.stringify({ error: pwErr }), { status: 400, headers: header });

        const temp = await kv.get(["tempPassword", newPassword]);
        if (temp.value) return new Response(JSON.stringify({ error: "临时密码已存在" }), { status: 400, headers: header });

        const validityTime = Date.now() + 7 * 24 * 60 * 60 * 1000;
        await kv.set(["tempPassword", newPassword], validityTime);

        return new Response(JSON.stringify({ message: "临时密码添加成功", validUntil: validityTime }), { status: 200, headers: header });
      }

      // --- 登录 ---
      if (url.pathname === "/login") {
        const { name, password } = data;
        const user = await kv.get(["user", name]);
        if (!user.value) return new Response(JSON.stringify({ error: "用户名或密码错误" }), { status: 400, headers: header });

        // 迁移旧明文密码
        if (user.value.password) {
          const hashedUser = argon2(user.value.password);
          await kv.set(["user", name], hashedUser);
          return new Response(JSON.stringify({ error: "数据刚刚迁移完成，请重试。" }), { status: 400, headers: header });
        }

        const hashedAttempt = encode(hash(new TextEncoder().encode(password), decode(user.value.salt), {
          t: 3, m: 65536, p: 1, variant: variant.Argon2id
        }));

        if (user.value.hashed !== hashedAttempt) {
          return new Response(JSON.stringify({ error: "用户名或密码错误" }), { status: 400, headers: header });
        }

        const token = crypto.randomUUID();
        const validityTime = Date.now() + 24 * 60 * 60 * 1000;
        await kv.set(["token", token], { name, validityTime });
        return new Response(JSON.stringify({ token, validUntil: validityTime }), { status: 200, headers: header });
      }

      // --- 发表评论 ---
      if (url.pathname === "/postComment") {
        const { token, content } = data;
        const name = await checkLogin(token);
        if (!name) return new Response(JSON.stringify({ error: "未登录" }), { status: 403, headers: header });

        if (!content || content.length === 0) return new Response(JSON.stringify({ error: "评论不能为空" }), { status: 400, headers: header });
        if (content.length > 500) return new Response(JSON.stringify({ error: "评论过长，限制500字" }), { status: 400, headers: header });

        const comment = { name, content, date: Date.now() };
        const q = await kv.get(QUEUE_KEY);
        const queue = q.value || [];
        queue.push(comment);
        while (queue.length > MAX_QUEUE_SIZE) queue.shift();
        await kv.set(QUEUE_KEY, queue);

        return new Response(JSON.stringify({ message: "评论成功" }), { status: 200, headers: header });
      }

      // --- 获取评论 ---
      if (url.pathname === "/getComments") {
        const q = await kv.get(QUEUE_KEY);
        return new Response(
          JSON.stringify(q.value || [{ name: "提示", content: "还没有人评论，发一条友好的信息吧。", date: Date.now() }]),
          { status: 200, headers: header }
        );
      }

      return new Response(JSON.stringify({ error: "404 Not Found" }), { status: 404, headers: header });
    } catch (e) {
      console.error(e);
      return new Response(JSON.stringify({ error: "出错了" }), { status: 500, headers: header });
    }
  },
};
