// Pegasus Hyper — servidor de la tienda (Cloudflare Worker + D1).
// Rutas públicas:   GET /api/catalog, POST /api/orders, GET /api/foto/:id
// Rutas privadas:   /api/admin/*  (requieren la sesión creada con POST /api/login)
// La contraseña vive solo en el secreto ADMIN_PASSWORD de Cloudflare.

const COLS = ["productos", "ventas", "campanas", "gastos", "pedidos", "fotos", "clientes"];
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

// ---------- customer accounts ----------
const PBKDF2_ITER = 10000;
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
async function hashPassword(pw, saltB64) {
  const salt = saltB64 ? Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0)) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITER }, key, 256);
  return { hash: b64(bits), salt: b64(salt) };
}
async function clienteId(usuario) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode("u:" + usuario));
  return "c_" + [...new Uint8Array(d)].slice(0, 12).map((b) => b.toString(16).padStart(2, "0")).join("");
}
const normUser = (u) => String(u || "").trim().toLowerCase().slice(0, 120);
async function getDoc(db, col, id) {
  const r = await db.prepare("SELECT data FROM docs WHERE col=? AND id=?").bind(col, id).first();
  return r ? JSON.parse(r.data) : null;
}
async function custSession(env, id) {
  const exp = Date.now() + 60 * 864e5;
  return id + "." + exp + "." + (await hmac(env.ADMIN_PASSWORD, "c:" + id + ":" + exp));
}
async function currentCustomer(req, env) {
  if (!env.ADMIN_PASSWORD) return null;
  const m = (req.headers.get("cookie") || "").match(/(?:^|;\s*)ph_c=([^;]+)/);
  if (!m) return null;
  const [id, exp, sig] = decodeURIComponent(m[1]).split(".");
  if (!id || !exp || !sig || +exp < Date.now()) return null;
  if (!safeEqual(sig, await hmac(env.ADMIN_PASSWORD, "c:" + id + ":" + exp))) return null;
  const c = await getDoc(env.DB, "clientes", id);
  return c ? { id, ...c } : null;
}
const custCookie = (v, maxAge) => `ph_c=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const publicCustomer = (c) => ({ usuario: c.usuario, nombre: c.nombre || "", telefono: c.telefono || "", direccion: c.direccion || "" });

async function cuenta(req, env, path) {
  const db = env.DB;
  if (!env.ADMIN_PASSWORD) return json({ error: "La tienda todavía no está configurada" }, 503);
  let b = {};
  if (req.method !== "GET") { try { b = await req.json(); } catch {} }
  const s = (v, n) => String(v ?? "").trim().slice(0, n);
  if (path === "/api/cuenta/registro" && req.method === "POST") {
    const usuario = normUser(b.usuario);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(usuario)) return json({ error: "Escriba un correo válido como usuario." }, 400);
    if (String(b.password || "").length < 8) return json({ error: "La contraseña debe tener al menos 8 caracteres." }, 400);
    if (!s(b.nombre, 120)) return json({ error: "Escriba su nombre." }, 400);
    if (!b.acepta) return json({ error: "Debe aceptar el uso de sus datos para crear la cuenta." }, 400);
    const id = await clienteId(usuario);
    if (await getDoc(db, "clientes", id)) return json({ error: "Ya existe una cuenta con ese correo. Inicie sesión." }, 409);
    const { hash, salt } = await hashPassword(String(b.password));
    const now = new Date(Date.now() - 6 * 3600e3).toISOString().slice(0, 10);
    const c = { usuario, nombre: s(b.nombre, 120), telefono: s(b.telefono, 40), direccion: s(b.direccion, 400), hash, salt, creado: now, acepta: now };
    await putDoc(db, "clientes", id, c);
    return json({ ok: true, cliente: publicCustomer(c) }, 200, { "set-cookie": custCookie(await custSession(env, id), 60 * 86400) });
  }
  if (path === "/api/cuenta/login" && req.method === "POST") {
    const usuario = normUser(b.usuario);
    // the store owner signs in from the same window with the admin user and the ADMIN_PASSWORD secret
    const adminUser = normUser(env.ADMIN_USER || "admin");
    if (usuario === adminUser) {
      if (!safeEqual(String(b.password || ""), env.ADMIN_PASSWORD)) { await new Promise((r) => setTimeout(r, 1200)); return json({ error: "Correo o contraseña incorrectos." }, 401); }
      return json({ ok: true, admin: true }, 200, { "set-cookie": cookie(await makeSession(env), SESSION_DAYS * 86400) });
    }
    const id = await clienteId(usuario);
    const c = await getDoc(db, "clientes", id);
    const ok = c && safeEqual((await hashPassword(String(b.password || ""), c.salt)).hash, c.hash);
    if (!ok) { await new Promise((r) => setTimeout(r, 1000)); return json({ error: "Correo o contraseña incorrectos." }, 401); }
    return json({ ok: true, cliente: publicCustomer(c) }, 200, { "set-cookie": custCookie(await custSession(env, id), 60 * 86400) });
  }
  if (path === "/api/cuenta/logout") return json({ ok: true }, 200, { "set-cookie": custCookie("", 0) });
  const c = await currentCustomer(req, env);
  if (!c) return json({ error: "Inicie sesión" }, 401);
  if (path === "/api/cuenta" && req.method === "GET") {
    const pedidos = (await listCol(db, "pedidos")).filter((p) => p.clienteId === c.id)
      .map((p) => ({ codigo: p.codigo, fecha: p.fecha, estado: p.estado, items: (p.items || []).map((i) => ({ nombre: i.nombre, cantidad: i.cantidad, precio: i.precio })), envio: p.envio, envioCosto: p.envioCosto }))
      .sort((a, b) => String(b.fecha + b.codigo).localeCompare(String(a.fecha + a.codigo)));
    return json({ cliente: publicCustomer(c), pedidos });
  }
  if (path === "/api/cuenta" && req.method === "PUT") {
    const { id, ...rest } = c;
    const upd = { ...rest, nombre: s(b.nombre, 120) || rest.nombre, telefono: s(b.telefono, 40), direccion: s(b.direccion, 400) };
    if (b.password) {
      if (String(b.password).length < 8) return json({ error: "La contraseña debe tener al menos 8 caracteres." }, 400);
      Object.assign(upd, await hashPassword(String(b.password)));
    }
    await putDoc(db, "clientes", id, upd);
    return json({ ok: true, cliente: publicCustomer(upd) });
  }
  if (path === "/api/cuenta" && req.method === "DELETE") {
    await db.prepare("DELETE FROM docs WHERE col='clientes' AND id=?").bind(c.id).run();
    return json({ ok: true }, 200, { "set-cookie": custCookie("", 0) });
  }
  return json({ error: "Ruta no encontrada" }, 404);
}

// ---------- handlers ----------
async function catalog(env) {
  const c = await getCfg(env.DB);
  const prods = (await listCol(env.DB, "productos"))
    .filter((p) => p.nombre && p.visible !== false)
    .map((p) => ({ id: p.id, nombre: p.nombre, modelo: p.modelo || "", marca: p.marca || "", ...(Array.isArray(p.conexiones) ? { conexiones: p.conexiones.slice(0, 8).map(String) } : {}), categoria: p.categoria || "", descripcion: p.descripcion || "", foto: fotoUrl(p), precio: precioDe(p, c), agotado: !!p.agotado }))
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
  const cli = await currentCustomer(req, env);
  const now = new Date(Date.now() - 6 * 3600e3); // Costa Rica (UTC-6)
  const pedido = {
    codigo, fecha: now.toISOString().slice(0, 10), estado: "nuevo", canal: "Catálogo",
    cliente: s(b.cliente, 120), telefono: s(b.telefono, 40), direccion: s(b.direccion, 400), notas: s(b.notas, 400),
    envio: env0.n, envioCosto: num(env0.c), pago, items: lines, origen: "web",
    ...(cli ? { clienteId: cli.id, clienteUsuario: cli.usuario } : {}),
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
    out.clientes = (await listCol(db, "clientes")).map(({ hash, salt, ...c }) => c);
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
    const now = Date.now();
    for (const c of COLS.filter((x) => x !== "clientes")) {
      const list = Array.isArray(data[c]) ? data[c] : [];
      for (let i = 0; i < list.length; i += 40) {
        const chunk = list.slice(i, i + 40).map((d) => { const { id, _u, ...rest } = d; return [String(id || newId()), rest]; });
        // merge mode only adds or updates the fields sent, keeping prices, photos and stock already saved
        let prevMap = {};
        if (data.merge && chunk.length) {
          const rs = await db.prepare(`SELECT id,data FROM docs WHERE col=? AND id IN (${chunk.map(() => "?").join(",")})`).bind(c, ...chunk.map((x) => x[0])).all();
          for (const r of rs.results || []) prevMap[r.id] = JSON.parse(r.data);
        }
        const stmts = [];
        for (const [key, rest] of chunk) {
          const prev = prevMap[key];
          if (data.merge && !prev) continue;
          stmts.push(db.prepare("INSERT INTO docs (col,id,data,updated) VALUES (?,?,?,?) ON CONFLICT(col,id) DO UPDATE SET data=excluded.data, updated=excluded.updated").bind(c, key, JSON.stringify(prev ? { ...prev, ...rest } : rest), now));
        }
        if (stmts.length) { await db.batch(stmts); n += stmts.length; }
      }
    }
    // remove products that left the catalog, and hide ones kept only for the record
    const borrar = (Array.isArray(data.borrar) ? data.borrar : []).map(String).slice(0, 400);
    for (let i = 0; i < borrar.length; i += 40) {
      const ids = borrar.slice(i, i + 40);
      await db.batch(ids.flatMap((id) => [db.prepare("DELETE FROM docs WHERE col='productos' AND id=?").bind(id), db.prepare("DELETE FROM docs WHERE col='fotos' AND id=?").bind(id)]));
      n += ids.length;
    }
    const ocultar = (Array.isArray(data.ocultar) ? data.ocultar : []).map(String).slice(0, 400);
    for (let i = 0; i < ocultar.length; i += 40) {
      const ids = ocultar.slice(i, i + 40);
      const rs = await db.prepare(`SELECT id,data FROM docs WHERE col='productos' AND id IN (${ids.map(() => "?").join(",")})`).bind(...ids).all();
      const st = (rs.results || []).map((r) => db.prepare("UPDATE docs SET data=?, updated=? WHERE col='productos' AND id=?").bind(JSON.stringify({ ...JSON.parse(r.data), visible: false }), now, r.id));
      if (st.length) { await db.batch(st); n += st.length; }
    }
    return json({ ok: true, importados: n });
  }
  const rs = path.match(/^\/api\/admin\/clientes\/([\w]+)\/reset$/);
  if (rs && req.method === "POST") {
    const c = await getDoc(db, "clientes", rs[1]);
    if (!c) return json({ error: "Cliente no encontrado" }, 404);
    const temp = "PH-" + [...crypto.getRandomValues(new Uint8Array(4))].map((b) => b.toString(36).padStart(2, "0")).join("").toUpperCase().slice(0, 6);
    await putDoc(db, "clientes", rs[1], { ...c, ...(await hashPassword(temp)) });
    return json({ ok: true, temporal: temp });
  }
  const m = path.match(/^\/api\/admin\/doc\/([a-z]+)(?:\/([\w\-.:@+~]+))?$/);
  if (m && COLS.includes(m[1])) {
    const [, col, id] = m;
    if (col === "clientes" && req.method !== "DELETE") return json({ error: "Use las acciones de clientes" }, 400);
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
    // www.pegasushyper.com → pegasushyper.com (one address, one login)
    if (url.hostname.startsWith("www.")) { url.hostname = url.hostname.slice(4); return Response.redirect(url.toString(), 301); }
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
      if (path.startsWith("/api/cuenta")) return await cuenta(req, env, path);
      if (path.startsWith("/api/admin/")) {
        if (!(await isAdmin(req, env))) return json({ error: "Sesión vencida" }, 401);
        if (path === "/api/admin/ping") return json({ ok: true });
        return await admin(req, env, path);
      }
      return json({ error: "Ruta no encontrada" }, 404);
    } catch (e) {
      return json({ error: "Error del servidor", detalle: String(e && e.message || e) }, 500);
    }
  },
};
