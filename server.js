const express = require('express');
const Anthropic = require('@anthropic-ai/sdk');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// ── Validar que la API key exista antes de arrancar ──────────────────────────
if (!process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY === 'sk-ant-xxxxxxxxxxxxx') {
  console.error('\n  ❌  ERROR: ANTHROPIC_API_KEY no está configurada.');
  console.error('  Crea un archivo .env con tu key real y reinicia el servidor.\n');
  process.exit(1);
}

const app = express();

// Confiar en el proxy de Railway/Nginx para obtener la IP real del cliente
app.set('trust proxy', 1);

// ── Redirect www → non-www (el cert SSL solo cubre el apex domain) ───────────
app.use((req, res, next) => {
  const host = req.headers.host || '';
  if (host.startsWith('www.')) {
    const apex = host.slice(4);
    return res.redirect(301, `https://${apex}${req.url}`);
  }
  next();
});

// ── Headers de seguridad (helmet) ────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:     ["'self'", "'unsafe-inline'"],   // necesario: scripts inline en index.html
      scriptSrcAttr: ["'unsafe-inline'"],             // necesario: onclick/onXXX en botones (ej. openPolicy)
      styleSrc:      ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:       ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:        ["'self'", 'data:', 'https:'],
      connectSrc:    ["'self'"],
      frameSrc:      ["'self'"],                      // iframes de políticas internas
      objectSrc:     ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  // HSTS: fuerza HTTPS en producción (Railway lo maneja automáticamente)
  hsts: process.env.NODE_ENV === 'production'
    ? { maxAge: 31536000, includeSubDomains: true, preload: true }
    : false,
  // Ocultar que usamos Express
  hidePoweredBy: true,
  // No permitir que el sitio sea embebido en iframes de terceros
  frameguard: { action: 'sameorigin' },
  // Evitar que el browser detecte el tipo de contenido automáticamente
  noSniff: true,
  // Activar el filtro XSS del browser (legacy, pero sin costo)
  xssFilter: true,
}));

// ── Límite global: 120 peticiones por IP cada 15 minutos ─────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes. Espera unos minutos e intenta de nuevo.' },
});
app.use(globalLimiter);

// ── Límite de tamaño del body (evita ataques de payload gigante) ─────────────
app.use(express.json({ limit: '10kb' }));

// ── Proteger lp.js: no-cache + no-index ─────────────────────────────────────
app.get('/js/lp.js', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('X-Robots-Tag', 'noindex, noarchive, nosnippet');
  next();
});

// ── Archivos estáticos ───────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname)));

// ── Cargar system prompt una sola vez al arrancar ────────────────────────────
const SYSTEM_PROMPT = fs.readFileSync(
  path.join(__dirname, 'system-prompt.txt'),
  'utf-8'
);

const anthropic = new Anthropic();

// ── Límite de chat por IP: 20 mensajes por día ───────────────────────────────
const DAILY_MSG_LIMIT = 20;
const ipUsage = new Map();

function checkChatLimit(ip) {
  const today = new Date().toISOString().slice(0, 10); // "YYYY-MM-DD"
  const entry = ipUsage.get(ip);
  if (!entry || entry.date !== today) {
    ipUsage.set(ip, { count: 1, date: today });
    return true;
  }
  if (entry.count >= DAILY_MSG_LIMIT) return false;
  entry.count += 1;
  return true;
}

// ── Endpoint de chat ─────────────────────────────────────────────────────────
app.post('/api/chat', async (req, res) => {
  const { messages, lang } = req.body;

  // Validar que lleguen mensajes
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'messages array is required' });
  }

  // Validar estructura y longitud de cada mensaje (evita payloads maliciosos)
  const MAX_MSG_LENGTH = 2000;
  const valid = messages.every(m =>
    m &&
    (m.role === 'user' || m.role === 'assistant') &&
    typeof m.content === 'string' &&
    m.content.length <= MAX_MSG_LENGTH
  );
  if (!valid) {
    return res.status(400).json({ error: 'Formato de mensaje inválido o demasiado largo.' });
  }

  // Límite diario por IP
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
  if (!checkChatLimit(ip)) {
    const msg = lang === 'en'
      ? "You've reached the daily limit of messages. Come back tomorrow or contact us on WhatsApp! 💬"
      : '¡Has alcanzado el límite diario de mensajes! Vuelve mañana o contáctanos por WhatsApp. 💬';
    return res.status(429).json({ error: msg });
  }

  const langInstruction = lang === 'en'
    ? '\n\n[The user is browsing in English. Respond in English unless they write in Spanish.]'
    : '\n\n[The user is browsing in Spanish. Respond in Spanish unless they write in English.]';

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  try {
    const stream = anthropic.messages.stream({
      model: 'claude-haiku-4-5',
      max_tokens: 1000,
      system: SYSTEM_PROMPT + langInstruction,
      messages: messages.map(m => ({ role: m.role, content: m.content }))
    });

    for await (const event of stream) {
      if (event.type === 'content_block_delta' && event.delta?.text) {
        res.write(`data: ${JSON.stringify({ text: event.delta.text })}\n\n`);
      }
    }

    res.write('data: [DONE]\n\n');
    res.end();
  } catch (err) {
    console.error('Claude API error:', err.message);
    const fallback = lang === 'en'
      ? "Sorry, I'm having a little trouble right now. Please try again or contact us on WhatsApp! 💬"
      : 'Disculpa, estoy teniendo un pequeño problema. ¡Intenta de nuevo o contáctanos por WhatsApp! 💬';
    res.write(`data: ${JSON.stringify({ text: fallback })}\n\n`);
    res.write('data: [DONE]\n\n');
    res.end();
  }
});

// ── 404 para cualquier ruta no existente ─────────────────────────────────────
app.use((req, res) => {
  res.status(404).send('Not found');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  🟢 Tiangix Sellers — http://localhost:${PORT}`);
  console.log(`  🔒 Seguridad activa: helmet + rate limiting + validación\n`);
});
