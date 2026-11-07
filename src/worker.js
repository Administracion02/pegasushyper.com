// Pegasus Hyper — servidor de la tienda (Cloudflare Worker + D1).
// Rutas públicas:   GET /api/catalog, POST /api/orders, GET /api/foto/:id
// Rutas privadas:   /api/admin/*  (requieren la sesión creada con POST /api/login)
// La contraseña vive solo en el secreto ADMIN_PASSWORD de Cloudflare.

const COLS = ["productos", "ventas", "campanas", "gastos", "pedidos", "fotos"];
const DEFAULT_CFG = {
  nombre: "Pegasus Hyper", iva: false, ivaTasa: 0.13, comision: 0.04, publicidad: 0.10, margen: 0.30,
  margenMin: 0.15, empaque: 300, envio: 0, redondeo: 500, roas: 3, whatsapp: "50661611731", prefijo: "PH",
  envios: [{ n: "Correos de Costa Rica", c: 2500 }, { n: "Mensajero (GAM)", c: 2000 }, { n: "Retiro en persona", c: 0 }],
  pagos: ["SINPE Móvil", "Transferencia", "Efectivo contra entrega"],
};
const SESSION_DAYS = 30;

let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS docs (col TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY (col, id))"
  ).run();
  schemaReady = true;
}

const json = (body, status = 200, extra = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra } });
const num = (v) => { const x = parseFloat(String(v ?? "").replace(/[^\d.\-]/g, "")); return isFinite(x) ? x : 0; };
const newId = () => crypto.randomUUID().replace(/-/g, "").slice(0, 20);

async function getCfg(db) {
  const r = await db.prepare("SELECT data FROM docs WHERE col='tienda' AND id='config'").first();
  return { ...DEFAULT_CFG, ...(r ? JSON.parse(r.data) : {}) };
}
async function listCol(db, col) {
  const { results } = await db.prepare("SELECT id, data, updated FROM docs WHERE col=?").bind(col).all();
  return results.map((r) => ({ id: r.id, ...JSON.parse(r.data), _u: r.updated }));
}
async function putDoc(db, col, id, data) {
  await db.prepare("INSERT INTO docs (col,id,data,updated) VALUES (?,?,?,?) ON CONFLICT(col,id) DO UPDATE SET data=excluded.data, updated=excluded.updated")
    .bind(col, id, JSON.stringify(data), Date.now()).run();
}

// Same pricing rule as the admin panel: cost ÷ (1 − margin − ads − fee), rounded up.
function precioDe(p, c) {
  const blank = (v) => v === "" || v == null;
  if (num(p.precio) > 0) return num(p.precio);
  const costo = num(p.costo) + (blank(p.empaque) ? c.empaque : num(p.empaque)) + (blank(p.envio) ? c.envio : num(p.envio)) + num(p.otros);
  const den = 1 - c.margen - c.publicidad - c.comision;
  const red = c.redondeo > 0 ? c.redondeo : 1;
  return den > 0 ? Math.ceil((costo / den) * (c.iva ? 1 + c.ivaTasa : 1) / red) * red : 0;
}
function fotoUrl(p) {
  if (p.fotoSubida) return "/api/foto/" + encodeURIComponent(p.id) + "?v=" + (p.fotoV || 1);
  return p.foto || "";
}

// ---------- sessions ----------
const enc = new TextEncoder();
async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey("raw", enc.encode("pegasus:" + secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/[+/=]/g, (c) => ({ "+": "-", "/": "_", "=": "" }[c]));
}
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}
async function makeSession(env) {
  const exp = Date.now() + SESSION_DAYS * 864e5;
  return exp + "." + (await hmac(env.ADMIN_PASSWORD, "s:" + exp));
}
async function isAdmin(req, env) {
  if (!env.ADMIN_PASSWORD) return false;
  const m = (req.headers.get("cookie") || "").match(/(?:^|;\s*)ph_s=([^;]+)/);
  if (!m) return false;
  const [exp, sig] = decodeURIComponent(m[1]).split(".");
  if (!exp || !sig || +exp < Date.now()) return false;
  return safeEqual(sig, await hmac(env.ADMIN_PASSWORD, "s:" + exp));
}
const cookie = (v, maxAge) => `ph_s=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

// ---------- handlers ----------
async function catalog(env) {
  const c = await getCfg(env.DB);
  const prods = (await listCol(env.DB, "productos"))
    .filter((p) => p.nombre && p.visible !== false)
    .map((p) => ({ id: p.id, nombre: p.nombre, categoria: p.categoria || "", descripcion: p.descripcion || "", foto: fotoUrl(p), precio: precioDe(p, c), agotado: !!p.agotado }))
    .sort((a, b) => (a.categoria + a.nombre).localeCompare(b.categoria + b.nombre, "es"));
  const store = { nombre: c.nombre, whatsapp: c.whatsapp, prefijo: c.prefijo || "PH", envios: c.envios, pagos: c.pagos };
  return json({ store, productos: prods }, 200, { "cache-control": "public, max-age=30" });
}

async function createOrder(req, env) {
  let b;
  try { b = await req.json(); } catch { return json({ error: "Pedido inválido" }, 400); }
  const s = (v, n) => String(v ?? "").trim().slice(0, n);
  const items = Array.isArray(b.items) ? b.items.slice(0, 30) : [];
  if (!items.length) return json({ error: "El pedido está vacío" }, 400);
  if (!s(b.cliente, 120) || !s(b.telefono, 40)) return json({ error: "Faltan nombre o teléfono" }, 400);
  const c = await getCfg(env.DB);
  const prods = await listCol(env.DB, "productos");
  const lines = [];
  for (const it of items) {
    const p = prods.find((x) => x.id === String(it.id));
    const q = Math.max(1, Math.min(50, Math.floor(num(it.cantidad))));
    if (!p || p.visible === false) return json({ error: "Un producto del pedido ya no está disponible. Recargue la página." }, 409);
    lines.push({ productoId: p.id, nombre: p.nombre, cantidad: q, precio: precioDe(p, c) });
  }
  const env0 = (c.envios || []).find((e) => e.n === b.envio) || (c.envios || [])[0] || { n: "", c: 0 };
  const pago = (c.pagos || []).includes(b.pago) ? b.pago : (c.pagos || [""])[0];
  const codigo = /^[A-Z]{1,5}-\d{4}-\d{3}$/.test(String(b.codigo || "")) ? b.codigo : (c.prefijo || "PH") + "-" + Date.now().toString().slice(-7);
  const now = new Date(Date.now() - 6 * 3600e3); // Costa Rica (UTC-6)
  const pedido = {
    codigo, fecha: now.toISOString().slice(0, 10), estado: "nuevo", canal: "Catálogo",
    cliente: s(b.cliente, 120), telefono: s(b.telefono, 40), direccion: s(b.direccion, 400), notas: s(b.notas, 400),
    envio: env0.n, envioCosto: num(env0.c), pago, items: lines, origen: "web",
  };
  await putDoc(env.DB, "pedidos", newId(), pedido);
  const total = lines.reduce((a, l) => a + l.cantidad * l.precio, 0) + pedido.envioCosto;
  return json({ ok: true, codigo, total });
}

async function foto(env, id) {
  const r = await env.DB.prepare("SELECT data FROM docs WHERE col='fotos' AND id=?").bind(id).first();
  if (!r) return new Response("No encontrada", { status: 404 });
  const { img } = JSON.parse(r.data);
  const m = /^data:(image\/(?:jpeg|png|webp));base64,(.+)$/.exec(img || "");
  if (!m) return new Response("No encontrada", { status: 404 });
  const bin = Uint8Array.from(atob(m[2]), (ch) => ch.charCodeAt(0));
  return new Response(bin, { headers: { "content-type": m[1], "cache-control": "public, max-age=31536000, immutable" } });
}

async function admin(req, env, path) {
  const db = env.DB;
  if (path === "/api/admin/all" && req.method === "GET") {
    const out = { cfg: await getCfg(db) };
    for (const c of ["productos", "ventas", "campanas", "gastos", "pedidos"]) out[c] = await listCol(db, c);
    return json(out);
  }
  if (path === "/api/admin/config" && req.method === "PUT") {
    const data = await req.json();
    await putDoc(db, "tienda", "config", { ...DEFAULT_CFG, ...data });
    return json({ ok: true });
  }
  if (path === "/api/admin/import" && req.method === "POST") {
    const data = await req.json();
    let n = 0;
    if (data.cfg) { await putDoc(db, "tienda", "config", { ...DEFAULT_CFG, ...data.cfg }); n++; }
    for (const c of COLS) for (const d of Array.isArray(data[c]) ? data[c] : []) {
      const { id, _u, ...rest } = d;
      await putDoc(db, c, String(id || newId()), rest); n++;
    }
    return json({ ok: true, importados: n });
  }
  const m = path.match(/^\/api\/admin\/doc\/([a-z]+)(?:\/([\w\-.:@+~]+))?$/);
  if (m && COLS.includes(m[1])) {
    const [, col, id] = m;
    if (req.method === "POST" && !id) { const nid = newId(); await putDoc(db, col, nid, await req.json()); return json({ ok: true, id: nid }); }
    if (req.method === "PUT" && id) { const { id: _x, _u, ...data } = await req.json(); await putDoc(db, col, id, data); return json({ ok: true, id }); }
    if (req.method === "DELETE" && id) { await db.prepare("DELETE FROM docs WHERE col=? AND id=?").bind(col, id).run(); return json({ ok: true }); }
  }
  return json({ error: "Ruta no encontrada" }, 404);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    if (!path.startsWith("/api/")) return env.ASSETS.fetch(req);
    try {
      await ensureSchema(env.DB);
      if (path === "/api/catalog" && req.method === "GET") return await catalog(env);
      if (path === "/api/orders" && req.method === "POST") return await createOrder(req, env);
      if (path.startsWith("/api/foto/") && req.method === "GET") return await foto(env, decodeURIComponent(path.slice(10)));
      if (path === "/api/login" && req.method === "POST") {
        if (!env.ADMIN_PASSWORD) return json({ error: "Falta configurar ADMIN_PASSWORD en Cloudflare" }, 503);
        let b = {}; try { b = await req.json(); } catch {}
        if (!safeEqual(String(b.password || ""), env.ADMIN_PASSWORD)) {
          await new Promise((r) => setTimeout(r, 1200));
          return json({ error: "Contraseña incorrecta" }, 401);
        }
        return json({ ok: true }, 200, { "set-cookie": cookie(await makeSession(env), SESSION_DAYS * 86400) });
      }
      if (path === "/api/logout") return json({ ok: true }, 200, { "set-cookie": cookie("", 0) });
      if (path.startsWith("/api/admin/")) {
        if (!(await isAdmin(req, env))) return json({ error: "Sesión vencida" }, 401);
        return await admin(req, env, path);
      }
      return json({ error: "Ruta no encontrada" }, 404);
    } catch (e) {
      return json({ error: "Error del servidor", detalle: String(e && e.message || e) }, 500);
    }
  },
};
