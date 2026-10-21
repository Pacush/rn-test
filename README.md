# test1 — Hola Mundo con registro de visitas

## Estructura

```
test1/
├── server.js          # Servidor Express + lógica de BD
├── package.json
├── visitas.db         # Se crea automáticamente al iniciar
└── public/
    ├── index.html     # Página "Hola Mundo"
    └── admin.html     # Panel de visitas
```

## Instalación y uso

```bash
# 1. Instalar dependencias
npm install

# 2. Iniciar servidor
npm start

# Modo desarrollo (auto-reinicio)
npm run dev
```

Abre http://localhost:3000 en el navegador.

## Endpoints

| Ruta | Descripción |
|------|-------------|
| `GET /` | Página principal |
| `GET /admin` | Panel de visitas |
| `GET /api/visitas` | JSON con las últimas visitas (`?limite=N`) |
| `GET /api/stats` | Estadísticas agrupadas |

## Datos que se guardan por visita

- Fecha y hora
- IP del visitante
- Navegador y versión
- Sistema operativo y versión
- Tipo de dispositivo (desktop, mobile, tablet)
- Modelo del dispositivo (si aplica)
- Idioma del navegador
- Referrer (página de origen)
- Ruta visitada
