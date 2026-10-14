// سێرڤەری سۆراغ - بێ پاکێجی دەرەکی (تەنها Node.js 18+)
const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");

// ---------- ڕێکخستن ----------
const cfg = { adminUser: "admin", adminPass: "ChangeMe-12345", port: 3000 };
try { Object.assign(cfg, JSON.parse(fs.readFileSync(path.join(__dirname, "config.json"), "utf8"))); } catch (e) {}
if (process.env.ADMIN_PASS) cfg.adminPass = process.env.ADMIN_PASS;
if (process.env.PORT) cfg.port = +process.env.PORT;
if (process.env.NODE_ENV === "production" && cfg.adminPass === "ChangeMe-12345") {
  console.error("❌ تکایە وشەی نهێنی بەڕێوەبەر لە config.json بگۆڕە"); process.exit(1);
}

// ---------- داتابەیس (فایلی JSON) ----------
const DB_FILE = path.join(__dirname, "data.json");
let db = { users: [], posts: [] };
try {
  const d = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  if (Array.isArray(d)) db.posts = d.map((p) => Object.assign({}, p, { uid: null, owner: undefined }));
  else db = Object.assign(db, d);
} catch (e) {}
function save() { fs.writeFileSync(DB_FILE + ".tmp", JSON.stringify(db)); fs.renameSync(DB_FILE + ".tmp", DB_FILE); }

const rid = (p) => p + Date.now().toString(36) + crypto.randomBytes(3).toString("hex");
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString("hex");
function checkPw(u, pw) {
  const a = Buffer.from(hashPw(pw, u.salt), "hex"), b = Buffer.from(u.hash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function setPw(u, pw) { u.salt = crypto.randomBytes(16).toString("hex"); u.hash = hashPw(pw, u.salt); }

// بەڕێوەبەر: هەر جارێک سێرڤەر دەست پێدەکات لە config.json نوێ دەکرێتەوە
let admin = db.users.find((u) => u.role === "admin");
if (!admin) { admin = { id: rid("u"), name: "بەڕێوەبەر", role: "admin", banned: false, ts: Date.now() }; db.users.push(admin); }
admin.login = cfg.adminUser; setPw(admin, cfg.adminPass); save();
if (cfg.adminPass === "ChangeMe-12345") console.warn("⚠️  وشەی نهێنی بەڕێوەبەر هێشتا ئاساییە؛ لە config.json بیگۆڕە!");

// ---------- ناسنامە و سنووردارکردن ----------
const sessions = new Map(); // token -> {uid, exp}
const DAY7 = 7 * 24 * 3600 * 1000;
const hits = new Map();
function limited(key, max) {
  const now = Date.now(), arr = (hits.get(key) || []).filter((t) => now - t < 60000);
  if (arr.length >= max) { hits.set(key, arr); return true; }
  arr.push(now); hits.set(key, arr); return false;
}
function clientIp(req) {
  const x = req.headers["x-forwarded-for"];
  return process.env.TRUST_PROXY && x ? x.split(",")[0].trim() : req.socket.remoteAddress;
}
function cookie(req, n) {
  const m = (req.headers.cookie || "").split(";").map((s) => s.trim()).find((s) => s.startsWith(n + "="));
  return m ? m.slice(n.length + 1) : null;
}
function getUser(req) {
  const t = cookie(req, "sid"), s = t && sessions.get(t);
  if (!s || s.exp < Date.now()) return null;
  const u = db.users.find((x) => x.id === s.uid);
  return u && !u.banned ? u : null;
}
function startSession(req, res, u) {
  const t = crypto.randomBytes(24).toString("hex");
  sessions.set(t, { uid: u.id, exp: Date.now() + DAY7 });
  const secure = req.headers["x-forwarded-proto"] === "https" ? "; Secure" : "";
  return "sid=" + t + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800" + secure;
}

// ---------- یاریدەدەر ----------
const SEC = {
  "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
};
function send(res, code, body, type, extra) {
  res.writeHead(code, Object.assign({ "Content-Type": type || "application/json; charset=utf-8" }, SEC, extra || {}));
  res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
function readBody(req, max) {
  return new Promise((ok, no) => {
    let d = "";
    req.on("data", (c) => { d += c; if (d.length > (max || 10000)) { no(); req.destroy(); } });
    req.on("end", () => { try { ok(JSON.parse(d || "{}")); } catch (e) { no(); } });
  });
}
const clean = (s, n) => String(s == null ? "" : s).replace(/[<>]/g, "").trim().slice(0, n);
const pubPost = (p, me) => ({ id: p.id, type: p.type, title: p.title, place: p.place, city: p.city, phone: p.phone,
  desc: p.desc, cat: p.cat, img: p.img || "", date: p.date, ts: p.ts, done: p.done, can: !!me && (me.role === "admin" || p.uid === me.id) });
const pubUser = (u) => (u ? { id: u.id, name: u.name, role: u.role, login: u.login } : null);
const UP = path.join(__dirname, "uploads");
fs.mkdirSync(UP, { recursive: true });
function saveImg(id, data) {
  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+\/=]+)$/.exec(String(data || ""));
  if (!m) return "";
  const buf = Buffer.from(m[1], "base64");
  if (buf.length > 400000 || buf[0] !== 0xff || buf[1] !== 0xd8 || buf[2] !== 0xff) return "";
  fs.writeFileSync(path.join(UP, id + ".jpg"), buf);
  return "/uploads/" + id + ".jpg";
}
function rmImg(p) { if (p.img) fs.unlink(path.join(UP, path.basename(p.img)), () => {}); }
const PHONE = /^[0-9+]{7,20}$/;

const STATIC = {
  "/": ["index.html", "text/html; charset=utf-8"], "/index.html": ["index.html", "text/html; charset=utf-8"],
  "/style.css": ["style.css", "text/css; charset=utf-8"], "/app.js": ["app.js", "application/javascript; charset=utf-8"],
};

http.createServer(async (req, res) => {
  try {
    const url = req.url.split("?")[0], ip = clientIp(req);
    if (req.method === "GET" && STATIC[url])
      return send(res, 200, fs.readFileSync(path.join(__dirname, "public", STATIC[url][0])), STATIC[url][1]);
    const um = req.method === "GET" && /^\/uploads\/(p[a-z0-9]+\.jpg)$/.exec(url);
    if (um) {
      const f = path.join(UP, um[1]);
      return fs.existsSync(f) ? send(res, 200, fs.readFileSync(f), "image/jpeg", { "Cache-Control": "public, max-age=86400" }) : send(res, 404, { error: "نەدۆزرایەوە" });
    }
    if (!url.startsWith("/api/")) return send(res, 404, { error: "نەدۆزرایەوە" });
    if (req.method !== "GET" && req.headers.origin) {
      let h; try { h = new URL(req.headers.origin).host; } catch (e) {}
      if (h !== req.headers.host) return send(res, 403, { error: "ڕێگەپێدان نییە" });
    }
    const me = getUser(req);

    if (url === "/api/me") return send(res, 200, { user: pubUser(me) });
    if (url === "/api/stats") return send(res, 200, {
      lost: db.posts.filter((p) => p.type === "lost" && !p.done).length,
      found: db.posts.filter((p) => p.type === "found" && !p.done).length,
      done: db.posts.filter((p) => p.done).length, users: db.users.length });
    if (req.method === "GET" && url === "/api/posts") return send(res, 200, db.posts.map((p) => pubPost(p, me)));

    if (req.method === "POST" && url === "/api/register") {
      if (limited("reg" + ip, 5)) return send(res, 429, { error: "زۆر داواکاری، کەمێک چاوەڕێ بکە" });
      const b = await readBody(req), name = clean(b.name, 40), phone = String(b.phone || "").replace(/[\s-]/g, ""), pw = String(b.password || "");
      if (name.length < 2 || !PHONE.test(phone) || pw.length < 8 || pw.length > 100)
        return send(res, 400, { error: "ناو، ژمارەی مۆبایلی دروست و وشەی نهێنی (٨ پیت لانیکەم) پێویستن" });
      if (db.users.some((u) => u.login === phone)) return send(res, 409, { error: "ئەم ژمارەیە پێشتر تۆمارکراوە" });
      const u = { id: rid("u"), name, login: phone, role: "user", banned: false, ts: Date.now() };
      setPw(u, pw); db.users.push(u); save();
      return send(res, 201, { user: pubUser(u) }, null, { "Set-Cookie": startSession(req, res, u) });
    }
    if (req.method === "POST" && url === "/api/login") {
      if (limited("log" + ip, 10)) return send(res, 429, { error: "زۆر هەوڵدان، دواتر دووبارە بکەوە" });
      const b = await readBody(req), login = String(b.login || "").replace(/[\s-]/g, ""), u = db.users.find((x) => x.login === login);
      if (!u || !checkPw(u, String(b.password || ""))) return send(res, 401, { error: "زانیارییەکان هەڵەن" });
      if (u.banned) return send(res, 403, { error: "ئەم هەژمارە ڕاگیراوە" });
      return send(res, 200, { user: pubUser(u) }, null, { "Set-Cookie": startSession(req, res, u) });
    }
    if (req.method === "POST" && url === "/api/logout") {
      sessions.delete(cookie(req, "sid"));
      return send(res, 200, { ok: true }, null, { "Set-Cookie": "sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" });
    }

    if (req.method === "POST" && url === "/api/posts") {
      if (!me) return send(res, 401, { error: "سەرەتا بچۆ ژوورەوە" });
      if (limited("post" + me.id, 5)) return send(res, 429, { error: "تکایە کەمێک چاوەڕێ بکە" });
      const b = await readBody(req, 600000);
      const p = { id: rid("p"), uid: me.id, type: b.type === "found" ? "found" : "lost",
        title: clean(b.title, 60), place: clean(b.place, 60), city: clean(b.city, 30), phone: String(b.phone || "").replace(/[\s-]/g, ""),
        desc: clean(b.desc, 300), cat: clean(b.cat, 30),
        date: /^\d{4}-\d{2}-\d{2}$/.test(b.date) ? b.date : new Date().toISOString().slice(0, 10), ts: Date.now(), done: false };
      if (!p.title || !p.place || !PHONE.test(p.phone)) return send(res, 400, { error: "زانیاری دروست نییە" });
      p.img = saveImg(p.id, b.img);
      db.posts.push(p); save();
      return send(res, 201, pubPost(p, me));
    }
    const m = url.match(/^\/api\/posts\/(p[a-z0-9]+)$/);
    if (m && (req.method === "PATCH" || req.method === "DELETE")) {
      if (!me) return send(res, 401, { error: "سەرەتا بچۆ ژوورەوە" });
      const p = db.posts.find((x) => x.id === m[1]);
      if (!p) return send(res, 404, { error: "نەدۆزرایەوە" });
      if (p.uid !== me.id && me.role !== "admin") return send(res, 403, { error: "ڕێگەپێدان نییە" });
      if (req.method === "DELETE") { rmImg(p); db.posts = db.posts.filter((x) => x !== p); } else p.done = true;
      save(); return send(res, 200, { ok: true });
    }

    // ---------- بەشی بەڕێوەبەر ----------
    if (url.startsWith("/api/admin/")) {
      if (!me || me.role !== "admin") return send(res, 403, { error: "تەنها بەڕێوەبەر" });
      if (req.method === "GET" && url === "/api/admin/users")
        return send(res, 200, db.users.map((u) => ({ id: u.id, name: u.name, login: u.login, role: u.role, banned: u.banned,
          posts: db.posts.filter((p) => p.uid === u.id).length })));
      const a = url.match(/^\/api\/admin\/users\/(u[a-z0-9]+)\/ban$/);
      if (req.method === "POST" && a) {
        const u = db.users.find((x) => x.id === a[1]), b = await readBody(req);
        if (!u || u.role === "admin") return send(res, 400, { error: "نەگونجاوە" });
        u.banned = !!b.banned;
        if (u.banned) sessions.forEach((s, t) => { if (s.uid === u.id) sessions.delete(t); });
        save(); return send(res, 200, { ok: true });
      }
    }
    send(res, 404, { error: "نەدۆزرایەوە" });
  } catch (e) { send(res, 400, { error: "داواکاری هەڵەیە" }); }
}).listen(cfg.port, () => console.log("✅ سۆراغ کاردەکات: http://localhost:" + cfg.port));
