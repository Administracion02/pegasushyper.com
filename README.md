# Pegasus Hyper — pegasushyper.com

- `public/` — catálogo para clientes (`index.html`) y panel de administración (`admin/`).
- `src/worker.js` — servidor: catálogo en vivo, pedidos, acceso con contraseña.
- `wrangler.jsonc` — configuración de Cloudflare (base de datos D1 `pegasus-db`).

La contraseña del panel se guarda solo como secreto `ADMIN_PASSWORD` en Cloudflare.
Los costos, proveedores y pedidos viven en la base de datos, nunca en este repositorio.
