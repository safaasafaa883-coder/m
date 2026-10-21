import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const SECRET = process.env.TOKEN_SECRET || "غيّر-هذا-السر-من-إعدادات-نتلفاي";
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } });
const mac = p => crypto.createHmac("sha256", SECRET).update(p).digest("base64url");
const sign = u => { const p = Buffer.from(JSON.stringify({ u, e: Date.now() + 30 * 864e5 })).toString("base64url"); return p + "." + mac(p); };
const verify = t => {
  try {
    const [p, s] = t.split(".");
    const x = mac(p);
    if (s.length !== x.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(x))) return null;
    const d = JSON.parse(Buffer.from(p, "base64url"));
    return d.e > Date.now() ? d.u : null;
  } catch { return null; }
};
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString("hex");

export default async (req) => {
  const store = getStore("masarifi");
  const path = new URL(req.url).pathname.replace(/^\/api\//, "");
  const body = req.method === "POST" ? await req.json().catch(() => ({})) : {};

  if (path === "signup" || path === "login") {
    const name = String(body.username || "").toLowerCase().trim();
    const pw = String(body.password || "");
    if (!/^[a-z0-9_]{3,20}$/.test(name)) return json({ error: "اسم المستخدم: 3-20 حرف انجليزي أو رقم أو _" }, 400);
    if (pw.length < 6) return json({ error: "كلمة السر لازم 6 أحرف على الأقل" }, 400);
    const u = await store.get("u:" + name, { type: "json" });
    if (path === "signup") {
      if (u) return json({ error: "اسم المستخدم مأخوذ" }, 409);
      const salt = crypto.randomBytes(16).toString("hex");
      await store.setJSON("u:" + name, { salt, hash: hash(pw, salt) });
      return json({ token: sign(name), username: name });
    }
    if (!u || hash(pw, u.salt) !== u.hash) return json({ error: "اسم المستخدم أو كلمة السر غلط" }, 401);
    return json({ token: sign(name), username: name });
  }

  const user = verify((req.headers.get("authorization") || "").replace("Bearer ", ""));
  if (!user) return json({ error: "سجّل دخول" }, 401);
  const key = "d:" + user;
  const list = (await store.get(key, { type: "json" })) || [];

  if (path === "tx" && req.method === "GET") return json(list);
  if (path === "tx" && req.method === "POST") {
    const amount = Number(body.amount);
    if (!(amount > 0) || !["income", "expense"].includes(body.type)) return json({ error: "بيانات غير صحيحة" }, 400);
    const t = { id: crypto.randomUUID(), type: body.type, amount, category: String(body.category || "أخرى").slice(0, 30), note: String(body.note || "").slice(0, 100), date: body.date || new Date().toISOString().slice(0, 10) };
    list.unshift(t);
    await store.setJSON(key, list);
    return json(t, 201);
  }
  if (path.startsWith("tx/") && req.method === "DELETE") {
    await store.setJSON(key, list.filter(x => x.id !== path.slice(3)));
    return json({ ok: true });
  }
  return json({ error: "غير موجود" }, 404);
};

export const config = { path: "/api/*" };
