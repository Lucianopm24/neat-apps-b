const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { MongoClient, ObjectId } = require("mongodb");
// ── Agregar al inicio del archivo junto a las otras constantes ─────────────────
const webpush = require("web-push");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const SECRET = process.env.JWT_SECRET || "changeme";
const ADMIN_USER = process.env.ADMIN_USER || "luciano";
const ADMIN_PASS = process.env.ADMIN_PASS || "changeme";
const MONGO_URI = process.env.MONGODB_URI;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const EMAIL_DOMAIN = "neat.qzz.io";
const GMAIL_USER = process.env.GMAIL_USER || null;   // ej. neatappsmail@gmail.com
const GMAIL_PASS = process.env.GMAIL_PASS || null;   // contraseña de aplicación de Google
const NEAT_ID_BASE = process.env.NEAT_ID_BASE || "https://id.neat.qzz.io"; // base pública del servidor

// ── Envío de correo (Gmail SMTP vía nodemailer) ───────────────────────────────
// Solo disponible si GMAIL_USER y GMAIL_PASS están configurados.
// Para activarlo: npm install nodemailer y configurar las variables de entorno.
let _nodemailer = null;
async function getMailer() {
  if (!GMAIL_USER || !GMAIL_PASS) return null;
  if (!_nodemailer) {
    try { _nodemailer = require("nodemailer"); } catch { return null; }
  }
  return _nodemailer.createTransport({
    service: "gmail",
    auth: { user: GMAIL_USER, pass: GMAIL_PASS }
  });
}

async function sendEmail({ to, subject, html }) {
  const transporter = await getMailer();
  if (!transporter) {
    console.warn("[email] GMAIL_USER/GMAIL_PASS no configurados — correo no enviado:", subject, "→", to);
    return false;
  }
  try {
    await transporter.sendMail({ from: `"Neat ID" <${GMAIL_USER}>`, to, subject, html });
    return true;
  } catch (err) {
    console.error("[email] Error enviando correo:", err.message);
    return false;
  }
}

let db;
async function getDb() {
  if (!db) {
    const client = await MongoClient.connect(MONGO_URI);
    db = client.db("neat");
  }
  return db;
}

// ── Middlewares de auth ───────────────────────────────────────────────────────

// Verifica cualquier token JWT válido (admin o usuario normal)
// Compatible con el sistema anterior — Neat Astore y otras apps no se rompen
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Unauthorized" });
  try {
    const payload = jwt.verify(header.replace("Bearer ", ""), SECRET);
    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

function requireScope(scope) {
  return (req, res, next) => {
    if (req.user.type !== "oauth") return next();
    if (req.user.scopes?.includes(scope)) return next();
    res.status(403).json({ error: `Se requiere scope '${scope}'` });
  };
}

// Bloquea CUALQUIER token OAuth, sin importar el scope. Para acciones que
// nunca deberían poder hacer apps de terceros (cambiar contraseña, gestionar
// apps OAuth propias, etc.) — solo pasa con tu sesión real (login directo).
function requireAuth(req, res, next) {
  if (req.user.type === "oauth") {
    return res.status(403).json({ error: "Esta acción no está disponible para apps externas" });
  }
  next();
}

// Solo permite admins (role: 'admin')
function adminAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Unauthorized" });
  try {
    const payload = jwt.verify(header.replace("Bearer ", ""), SECRET);
    if (payload.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }
    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// ── Auth admin (sin cambios — compatible con Neat Astore) ─────────────────────
app.post("/auth/login", (req, res) => {
  const { username, password } = req.body;
  if (username !== ADMIN_USER || password !== ADMIN_PASS)
    return res.status(401).json({ error: "Invalid credentials" });
  const token = jwt.sign({ username, role: "admin" }, SECRET, { expiresIn: "30d" });
  res.json({ token, role: "admin", username, email: `${username}@${EMAIL_DOMAIN}` });
});

// ── Auth usuarios normales ─────────────────────────────────────────────────────
// Registro de usuarios de la plataforma (role "user").
// R2: endpoint público ÚNICO montado en /auth/register (nombre semántico para la Play)
// y mantenido en /chat/register por compatibilidad con la app Chatter actual.
// Defensas: honeypot "website" (bots) + rate limit 5 registros/IP/hora (register_attempts).
async function registerHandler(req, res) {
  try {
    // Honeypot: los humanos nunca ven este campo en la UI; si viene lleno = bot.
    // Respondemos éxito falso para no enseñarles nada. Silencio y a otra cosa.
    if (req.body?.website) return res.status(201).json({ ok: true });

    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: "username y password requeridos" });

    // username solo letras, números, guiones bajos, 3-20 chars
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
      return res.status(400).json({ error: "Username inválido (3-20 chars, solo letras/números/_)" });

    if (password.length < 6)
      return res.status(400).json({ error: "Password debe tener al menos 6 caracteres" });

    // Bloquear username del admin
    if (username.toLowerCase() === ADMIN_USER.toLowerCase())
      return res.status(400).json({ error: "Username no disponible" });

    // Rate limit por IP: máx 5 registros por hora (registro público sin captcha aún)
    const ip = String(
      req.headers["cf-connecting-ip"] ||
      (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
      req.ip || "unknown"
    ).slice(0, 64);
    const database = await getDb();
    const sinceHour = new Date(Date.now() - 60 * 60 * 1000);
    const recent = await database.collection("register_attempts").countDocuments({ ip, at: { $gt: sinceHour } });
    if (recent >= 5)
      return res.status(429).json({ error: "Demasiados registros desde esta red. Intenta en una hora." });
    await database.collection("register_attempts").insertOne({ ip, at: new Date() });

    const exists = await database.collection("users").findOne({
      username: { $regex: new RegExp(`^${username}$`, "i") }
    });
    if (exists) return res.status(409).json({ error: "Username ya existe" });

    const passwordHash = await bcrypt.hash(password, 10);
    const email = `${username.toLowerCase()}@${EMAIL_DOMAIN}`;
    const result = await database.collection("users").insertOne({
      username,
      email,
      passwordHash,
      role: "user",
      avatar: null,
      createdAt: new Date(),
    });

    const token = jwt.sign(
      { userId: result.insertedId.toString(), username, role: "user" },
      SECRET,
      { expiresIn: "30d" }
    );

    res.status(201).json({ token, role: "user", username, email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
}
app.post("/auth/register", registerHandler);
app.post("/chat/register", registerHandler); // compat: la app Chatter lo llama hoy


webpush.setVapidDetails(
  process.env.VAPID_EMAIL,
  process.env.VAPID_PUBLIC_KEY,
  process.env.VAPID_PRIVATE_KEY
);

// ── Función interna — llamar desde POST /chat/messages/:chatId ─────────────────
// Reemplaza el res.status(201).json(...) final del endpoint de mensajes con esto:
async function notifyParticipants(database, chatId, message, senderIdentifier) {
  const chat = await database.collection("chats").findOne({ _id: new ObjectId(chatId) });
  if (!chat) return;

  const recipients = chat.participants.filter(p => p !== senderIdentifier);
  if (!recipients.length) return;

  const subscriptions = await database.collection("push_subscriptions")
    .find({ userId: { $in: recipients } })
    .toArray();

  const payload = JSON.stringify({
    title: `${message.senderUsername} en ${chat.name || "chat"}`,
    body: message.type === "text" ? message.content : `[${message.type}]`,
    chatId: chatId,
    url: `/chat/${chatId}`,
  });

  await Promise.allSettled(
    subscriptions.map(sub =>
      webpush.sendNotification(sub.subscription, payload).catch(async err => {
        if (err.statusCode === 410) {
          await database.collection("push_subscriptions").deleteOne({ _id: sub._id });
        }
      })
    )
  );

  // ntfy para usuarios Plus
  for (const username of recipients) {
    const recipientUser = await database.collection("users").findOne(
      { username },
      { projection: { ntfyTopic: 1, neatPlus: 1 } }
    );
    if (!recipientUser?.ntfyTopic || !recipientUser?.neatPlus) continue;
    const chatUrl = `https://neat.qzz.io/byneat/chatter?chat=${chatId}`;
    fetch(`https://push.tchncs.de/${recipientUser.ntfyTopic}`, {
      method: "POST",
      headers: {
        "Title": `Nuevo mensaje de ${message.senderUsername}`,
        "Priority": "default",
        "Actions": `view, Responder, ${chatUrl}`,
        "Content-Type": "text/plain"
      },
      body: message.content || `[${message.type}]`
    }).catch(() => {});
  }
}

// ── Guardar suscripción push del browser ───────────────────────────────────────
app.post("/chat/push/subscribe", auth, requireScope("chatter"), async (req, res) => {
  try {
    const { subscription } = req.body;
    if (!subscription?.endpoint) return res.status(400).json({ error: "Suscripción inválida" });

    const identifier = req.user.userId || req.user.username;
    const database = await getDb();

    await database.collection("push_subscriptions").updateOne(
      { "subscription.endpoint": subscription.endpoint },
      {
        $set: {
          userId: identifier,
          username: req.user.username,
          subscription,
          updatedAt: new Date(),
        },
        $setOnInsert: { createdAt: new Date() },
      },
      { upsert: true }
    );

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// ── Eliminar suscripción push ──────────────────────────────────────────────────
app.delete("/chat/push/subscribe", auth, requireScope("chatter"), async (req, res) => {
  try {
    const { endpoint } = req.body;
    if (!endpoint) return res.status(400).json({ error: "endpoint requerido" });

    const database = await getDb();
    await database.collection("push_subscriptions").deleteOne({
      "subscription.endpoint": endpoint,
    });

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── Devolver la VAPID public key al frontend ───────────────────────────────────
app.get("/chat/push/vapid-public-key", (req, res) => {
  res.json({ key: process.env.VAPID_PUBLIC_KEY });
});

// ── Así queda el POST /chat/messages/:chatId modificado ───────────────────────
// Agrega esto ANTES del res.status(201).json(...) final del endpoint de mensajes:
//
//   const savedMessage = { _id: result.insertedId, ...message };
//   notifyParticipants(database, req.params.chatId, savedMessage, identifier);
//   res.status(201).json(savedMessage);

// ── Telegram upload ────────────────────────────────────────────────────────────
const multer = require("multer");
const FormData = require("form-data");
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

app.post("/chat/telegram/upload", auth, requireScope("chatter"), upload.single("file"), async (req, res) => {
  try {
    if (!TELEGRAM_BOT_TOKEN)
      return res.status(503).json({ error: "TELEGRAM_BOT_TOKEN no configurado" });
    if (!req.file)
      return res.status(400).json({ error: "Archivo requerido" });

    const STORAGE_CHAT_ID = process.env.TELEGRAM_STORAGE_CHAT_ID;
    if (!STORAGE_CHAT_ID)
      return res.status(503).json({ error: "TELEGRAM_STORAGE_CHAT_ID no configurado" });

    // Elegir método según mimetype
    const mime = req.file.mimetype;
    let method = "sendDocument";
    if (mime.startsWith("image/")) method = "sendPhoto";
    else if (mime.startsWith("video/")) method = "sendVideo";
    else if (mime.startsWith("audio/")) method = "sendAudio";
    else if (mime === "audio/ogg" || mime.includes("opus")) method = "sendVoice";

    const form = new FormData();
    form.append("chat_id", STORAGE_CHAT_ID);
    const fieldName = method.replace("send", "").toLowerCase();
    form.append(fieldName, req.file.buffer, {
      filename: req.file.originalname,
      contentType: req.file.mimetype,
    });

    const https = require("https");
    const formBuffer = form.getBuffer();
    const formHeaders = form.getHeaders();

    const tgResponse = await new Promise((resolve, reject) => {
      const options = {
        hostname: "api.telegram.org",
        path: `/bot${TELEGRAM_BOT_TOKEN}/${method}`,
        method: "POST",
        headers: { ...formHeaders, "Content-Length": formBuffer.length },
      };
      const reqTg = https.request(options, (resTg) => {
        let data = "";
        resTg.on("data", chunk => data += chunk);
        resTg.on("end", () => resolve(data));
      });
      reqTg.on("error", reject);
      reqTg.write(formBuffer);
      reqTg.end();
    });

    let tgData;
    try {
      tgData = JSON.parse(tgResponse);
    } catch {
      return res.status(500).json({ error: "Telegram respuesta inválida", raw: tgResponse });
    }

    if (!tgData.ok)
      return res.status(500).json({ error: "Error subiendo a Telegram", detail: tgData.description });

    // Extraer file_id del mensaje devuelto
    const msg = tgData.result;
    const fileObj = msg.photo
      ? msg.photo[msg.photo.length - 1]  // foto: array, tomar la de mayor resolución
      : msg[fieldName];

    res.json({
      telegramFileId: fileObj.file_id,
      type: fieldName,
      mimeType: req.file.mimetype,
      originalName: req.file.originalname,
      fileSize: fileObj.file_size || req.file.size,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

app.get("/chat/users/list", auth, requireScope("chatter"), async (req, res) => {
  try {
    const database = await getDb();
    const users = await database.collection("users")
      .find({}, { projection: { passwordHash: 0 } })
      .toArray();
    const adminUser = { _id: "admin", username: ADMIN_USER, email: `${ADMIN_USER}@${EMAIL_DOMAIN}`, role: "admin" };
    res.json([adminUser, ...users]);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Actualizar perfil (bio + foto de perfil vía Telegram file_id)
app.put("/chat/me", auth, requireScope("chatter"), async (req, res) => {
  try {
    const { bio, avatarFileId } = req.body;
    if (req.user.role === "admin") return res.status(400).json({ error: "Admin no tiene perfil editable" });
    const database = await getDb();
    await database.collection("users").updateOne(
      { _id: new ObjectId(req.user.userId) },
      { $set: { bio: bio ?? undefined, avatarFileId: avatarFileId ?? undefined } }
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Error interno" });
  }
});

// Cambiar contraseña — nunca accesible vía OAuth, ni siquiera con scope
// "account". Solo la sesión real del usuario (login directo) puede tocarla.
app.put("/chat/me/password", auth, requireAuth, async (req, res) => {
  try {
    if (req.user.role === "admin") return res.status(400).json({ error: "Admin no tiene contraseña gestionable aquí" });
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
      return res.status(400).json({ error: "currentPassword y newPassword requeridos" });
    if (newPassword.length < 6)
      return res.status(400).json({ error: "La nueva contraseña debe tener al menos 6 caracteres" });

    const database = await getDb();
    const user = await database.collection("users").findOne({ _id: new ObjectId(req.user.userId) });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    const valid = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!valid) return res.status(401).json({ error: "Contraseña actual incorrecta" });

    const passwordHash = await bcrypt.hash(newPassword, 10);
    await database.collection("users").updateOne(
      { _id: new ObjectId(req.user.userId) },
      { $set: { passwordHash } }
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

app.post("/chat/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: "username y password requeridos" });

    // Si es admin, usar flujo admin
    if (username === ADMIN_USER && password === ADMIN_PASS) {
      const token = jwt.sign({ username, role: "admin" }, SECRET, { expiresIn: "30d" });
      return res.json({ token, role: "admin", username, email: `${username}@${EMAIL_DOMAIN}` });
    }

    const database = await getDb();
    const user = await database.collection("users").findOne({
      username: { $regex: new RegExp(`^${username}$`, "i") }
    });
    if (!user) return res.status(401).json({ error: "Credenciales inválidas" });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: "Credenciales inválidas" });
    if (user.suspended) return res.status(403).json({ 
  error: "Cuenta suspendida", 
  note: "Your account is suspended",
  reason: user.suspendedReason || "Sin razón especificada"
});

    const token = jwt.sign(
      { userId: user._id.toString(), username: user.username, role: user.role },
      SECRET,
      { expiresIn: "30d" }
    );

    res.json({ token, role: user.role, username: user.username, email: user.email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// ── Usuarios (gestión) ─────────────────────────────────────────────────────────

// Perfil propio
app.get("/chat/me", auth, requireScope("chatter"), async (req, res) => {
  if (req.user.role === "admin") {
    return res.json({
      username: req.user.username,
      email: `${req.user.username}@${EMAIL_DOMAIN}`,
      role: "admin",
    });
  }
  const database = await getDb();
  const user = await database.collection("users").findOne({ _id: new ObjectId(req.user.userId) });
  if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
  const { passwordHash, ...safe } = user;
  res.json(safe);
});

// Listar usuarios (solo admin)
app.get("/chat/users", adminAuth, async (req, res) => {
  const database = await getDb();
  const users = await database.collection("users")
    .find({}, { projection: { passwordHash: 0 } })
    .sort({ createdAt: -1 })
    .toArray();

  // Incluir admin virtual al inicio
  const adminUser = {
    _id: "admin",
    username: ADMIN_USER,
    email: `${ADMIN_USER}@${EMAIL_DOMAIN}`,
    role: "admin",
    createdAt: null,
  };
  res.json([adminUser, ...users]);
});

// Promover/degradar usuario (solo admin)
app.put("/chat/users/:id/role", adminAuth, async (req, res) => {
  try {
    const { role } = req.body;
    if (!["user", "admin"].includes(role))
      return res.status(400).json({ error: "Role inválido" });
    const database = await getDb();
    await database.collection("users").updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { role } }
    );
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "ID inválido" });
  }
});

// ── Chats ──────────────────────────────────────────────────────────────────────

// Listar chats del usuario autenticado
app.get("/chat/chats", auth, requireScope("chatter"), async (req, res) => {
  const database = await getDb();
  const identifier = req.user.username;
const userId = req.user.userId;
const chats = await database.collection("chats")
  .find({ participants: { $in: [identifier, userId].filter(Boolean) } })
    .sort({ updatedAt: -1 })
    .toArray();
  res.json(chats);
});

// Crear chat
app.post("/chat/chats", auth, requireScope("chatter"), async (req, res) => {
  try {
    const { name, type = "direct", participants = [] } = req.body;
const identifier = req.user.username; // siempre username, nunca ID

// Resolver usernames de los participantes
const database = await getDb();
const resolvedParticipants = await Promise.all(participants.map(async (p) => {
  if (!p.match(/^[0-9a-f]{24}$/i)) return p; // ya es username
  const user = await database.collection("users").findOne({ _id: new ObjectId(p) });
  return user ? user.username : p;
}));

const allParticipants = [...new Set([identifier, ...resolvedParticipants])];
    
    const result = await database.collection("chats").insertOne({
      name: name || null,
      type,
      participants: allParticipants,
      createdBy: identifier,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    res.status(201).json({ _id: result.insertedId, name, type, participants: allParticipants });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// Obtener chat por ID
app.get("/chat/chats/:id", auth, requireScope("chatter"), async (req, res) => {
  try {
    const database = await getDb();
    const chat = await database.collection("chats").findOne({ _id: new ObjectId(req.params.id) });
    if (!chat) return res.status(404).json({ error: "Chat no encontrado" });

    const identifier = req.user.userId || req.user.username;
    if (!chat.participants.includes(identifier) && req.user.role !== "admin")
      return res.status(403).json({ error: "No eres participante de este chat" });

    res.json(chat);
  } catch {
    res.status(400).json({ error: "ID inválido" });
  }
});

// ── Mensajes ───────────────────────────────────────────────────────────────────

// Obtener mensajes de un chat (con paginación)
app.get("/chat/messages/:chatId", auth, requireScope("chatter"), async (req, res) => {
  try {
    const database = await getDb();
    const chat = await database.collection("chats").findOne({ _id: new ObjectId(req.params.chatId) });
    if (!chat) return res.status(404).json({ error: "Chat no encontrado" });

    const identifier = req.user.username;
if (!chat.participants.includes(identifier) && req.user.role !== "admin")
  return res.status(403).json({ error: "No eres participante" });

    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const before = req.query.before ? new Date(req.query.before) : new Date();

    const messages = await database.collection("messages")
      .find({ chatId: req.params.chatId, createdAt: { $lt: before } })
      .sort({ createdAt: -1 })
      .limit(limit)
      .toArray();

    res.json(messages.reverse());
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: "Error al obtener mensajes" });
  }
});

// Enviar mensaje
app.post("/chat/messages/:chatId", auth, requireScope("chatter"), async (req, res) => {
  try {
    const { content, type = "text", telegramFileId = null, mimeType = null } = req.body;
    if (!content && !telegramFileId)
      return res.status(400).json({ error: "content o telegramFileId requerido" });

    const database = await getDb();
    const chat = await database.collection("chats").findOne({ _id: new ObjectId(req.params.chatId) });
    if (!chat) return res.status(404).json({ error: "Chat no encontrado" });

   const identifier = req.user.username;
if (!chat.participants.includes(identifier) && req.user.role !== "admin")
  return res.status(403).json({ error: "No eres participante" });

    const message = {
      chatId: req.params.chatId,
      senderId: identifier,
      senderUsername: req.user.username,
      content: content || null,
      type,            // text | photo | video | audio | document | voice
      telegramFileId,  // file_id de Telegram — persistente, nunca expira
      mimeType,
      createdAt: new Date(),
    };

    const result = await database.collection("messages").insertOne(message);
    await database.collection("chats").updateOne(
      { _id: new ObjectId(req.params.chatId) },
      { $set: { updatedAt: new Date(), lastMessage: content || `[${type}]` } }
    );

    const savedMessage = { _id: result.insertedId, ...message };
notifyParticipants(database, req.params.chatId, savedMessage, identifier);
res.status(201).json(savedMessage);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// Mensajes nuevos desde timestamp (para polling)
app.get("/chat/messages/:chatId/since", auth, requireScope("chatter"), async (req, res) => {
  try {
    const { since } = req.query;
    if (!since) return res.status(400).json({ error: "since requerido" });

    const database = await getDb();
    const chat = await database.collection("chats").findOne({ _id: new ObjectId(req.params.chatId) });
    if (!chat) return res.status(404).json({ error: "Chat no encontrado" });

    const identifier = req.user.username;
if (!chat.participants.includes(identifier) && req.user.role !== "admin")
      return res.status(403).json({ error: "No eres participante" });

    const messages = await database.collection("messages")
      .find({ chatId: req.params.chatId, createdAt: { $gt: new Date(since) } })
      .sort({ createdAt: 1 })
      .toArray();

    res.json(messages);
  } catch (err) {
    res.status(400).json({ error: "Error" });
  }
});

// ── Telegram file proxy ────────────────────────────────────────────────────────
// Recibe un file_id de Telegram y devuelve la URL temporal de descarga.
// El file_id queda guardado en MongoDB — es permanente.
// La URL que devuelve Telegram expira, por eso la resolvemos on-demand.
app.get("/chat/telegram/file/:fileId", auth, requireScope("chatter"), async (req, res) => {
  try {
    if (!TELEGRAM_BOT_TOKEN)
      return res.status(503).json({ error: "TELEGRAM_BOT_TOKEN no configurado" });

    const response = await fetch(
      `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getFile?file_id=${req.params.fileId}`
    );
    const data = await response.json();

    if (!data.ok) return res.status(404).json({ error: "File no encontrado en Telegram" });

    const fileUrl = `https://api.telegram.org/file/bot${TELEGRAM_BOT_TOKEN}/${data.result.file_path}`;
    res.json({ url: fileUrl, filePath: data.result.file_path, fileSize: data.result.file_size });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error resolviendo file de Telegram" });
  }
});

// ── Watch — Videos ────────────────────────────────────────────────────────────

// El Worker de Cloudflare llama esto ANTES de aceptar una subida — confirma que el
// JWT es válido (gracias al middleware `auth`) y le dice al Worker si el usuario
// es Plus o no, para que decida Telegram vs Filebrowser. neatPlus nunca viaja en
// el JWT (se consulta siempre en Mongo), así que no se puede confiar en el token solo.
app.get("/watch/upload-auth", auth, requireScope("watch"), async (req, res) => {
  try {
    if (req.user.role === "admin") {
      return res.json({ ok: true, username: req.user.username, neatPlus: true });
    }
    const database = await getDb();
    const user = await database.collection("users").findOne(
      { username: req.user.username },
      { projection: { neatPlus: 1, neatPlusExpiresAt: 1 } }
    );
    const expired = user?.neatPlusExpiresAt && new Date() > new Date(user.neatPlusExpiresAt);
    if (expired) {
      await database.collection("users").updateOne(
        { username: req.user.username }, { $set: { neatPlus: false } }
      );
    }
    res.json({
      ok: true,
      username: req.user.username,
      neatPlus: expired ? false : !!user?.neatPlus,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

app.post("/watch/videos", auth, requireScope("watch"), async (req, res) => {
  try {
    const { title, description, fileId, rawUrl, fbPath, thumbnailFileId, duration, category } = req.body;
    if (!title || (!fileId && !rawUrl && !fbPath))
      return res.status(400).json({ error: "title y (fileId, rawUrl o fbPath) requeridos" });

    const identifier = req.user.userId || req.user.username;
    const database = await getDb();
    const result = await database.collection("watch_videos").insertOne({
      title, description,
      fileId: fileId || null,
      rawUrl: rawUrl || null,
      fbPath: fbPath || null,
      thumbnailFileId: thumbnailFileId || null,
      duration: duration || null, category: category || null,
      uploadedBy: identifier, uploaderUsername: req.user.username,
      uploaderVerified: false,
      likes: [], views: 0, createdAt: new Date()
    });
    res.status(201).json({ _id: result.insertedId, title, fileId: fileId || null, rawUrl: rawUrl || null, fbPath: fbPath || null });
  } catch (err) {
    res.status(500).json({ error: "Error interno" });
  }
});

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

app.get("/watch/videos", async (req, res) => {
  try {
    const database = await getDb();
    const { category, uploader, quick, limit = 20, before, q } = req.query;
    const filter = {};
    if (category) filter.category = category;
    if (uploader) filter.uploaderUsername = uploader;
    if (quick === "true") filter.duration = { $lte: 120 };
    if (quick === "false") filter.duration = { $gt: 120 };
    if (before) filter.createdAt = { $lt: new Date(before) };
    if (q && q.trim()) {
      const re = new RegExp(escapeRegex(q.trim()), "i");
      filter.$or = [{ title: re }, { description: re }, { uploaderUsername: re }];
    }

    const videos = await database.collection("watch_videos")
  .find(filter).sort({ createdAt: -1 }).limit(parseInt(limit)).toArray();

const usernames = [...new Set(videos.map(v => v.uploaderUsername))];
const users = await database.collection("users")
  .find({ username: { $in: usernames } }, { projection: { username: 1, verified: 1 } })
  .toArray();
const verifiedMap = {};
users.forEach(u => verifiedMap[u.username] = !!u.verified);
verifiedMap[process.env.ADMIN_USER] = true; // admin siempre verificado

const withVerified = videos.map(v => ({ ...v, uploaderVerified: verifiedMap[v.uploaderUsername] || false }));
res.json(withVerified);
  } catch (err) {
    res.status(500).json({ error: "Error interno" });
  }
});

app.get("/watch/videos/:id", async (req, res) => {
  try {
    const database = await getDb();
    const video = await database.collection("watch_videos")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!video) return res.status(404).json({ error: "Video no encontrado" });

    // Sumar vista
    await database.collection("watch_videos").updateOne(
      { _id: new ObjectId(req.params.id) },
      { $inc: { views: 1 } }
    );
    res.json(video);
  } catch {
    res.status(400).json({ error: "ID inválido" });
  }
});

app.put("/watch/videos/:id", auth, requireScope("watch"), async (req, res) => {
  try {
    const database = await getDb();
    const video = await database.collection("watch_videos")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!video) return res.status(404).json({ error: "No encontrado" });

    const identifier = req.user.userId || req.user.username;
    if (video.uploadedBy !== identifier && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const { title, description, thumbnailFileId, category } = req.body;
    await database.collection("watch_videos").updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { title, description, thumbnailFileId, category } }
    );
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "ID inválido" });
  }
});

app.delete("/watch/videos/:id", auth, requireScope("watch"), async (req, res) => {
  try {
    const database = await getDb();
    const video = await database.collection("watch_videos")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!video) return res.status(404).json({ error: "No encontrado" });

    const identifier = req.user.userId || req.user.username;
    if (video.uploadedBy !== identifier && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    await database.collection("watch_videos").deleteOne({ _id: new ObjectId(req.params.id) });
    await database.collection("watch_comments").deleteMany({ videoId: req.params.id });
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "ID inválido" });
  }
});

// ── Watch — Likes ─────────────────────────────────────────────────────────────

app.post("/watch/videos/:id/like", auth, requireScope("watch"), async (req, res) => {
  try {
    const identifier = req.user.userId || req.user.username;
    const database = await getDb();
    const video = await database.collection("watch_videos")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!video) return res.status(404).json({ error: "No encontrado" });

    const liked = video.likes.includes(identifier);
    await database.collection("watch_videos").updateOne(
      { _id: new ObjectId(req.params.id) },
      liked ? { $pull: { likes: identifier } } : { $push: { likes: identifier } }
    );
    res.json({ liked: !liked, total: video.likes.length + (liked ? -1 : 1) });
  } catch {
    res.status(400).json({ error: "ID inválido" });
  }
});

// ── Watch — Comentarios ───────────────────────────────────────────────────────

app.post("/watch/videos/:id/comments", auth, requireScope("watch"), async (req, res) => {
  try {
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: "content requerido" });

    const identifier = req.user.userId || req.user.username;
    const database = await getDb();
    const result = await database.collection("watch_comments").insertOne({
      videoId: req.params.id,
      authorId: identifier,
      authorUsername: req.user.username,
      content,
      createdAt: new Date()
    });
    res.status(201).json({ _id: result.insertedId, content, authorUsername: req.user.username });
  } catch (err) {
    res.status(500).json({ error: "Error interno" });
  }
});

app.get("/watch/videos/:id/comments", async (req, res) => {
  try {
    const database = await getDb();
    const comments = await database.collection("watch_comments")
  .find({ videoId: req.params.id }).sort({ createdAt: 1 }).toArray();

const usernames = [...new Set(comments.map(c => c.authorUsername))];
const users = await database.collection("users")
  .find({ username: { $in: usernames } }, { projection: { username: 1, verified: 1 } })
  .toArray();
const verifiedMap = {};
users.forEach(u => verifiedMap[u.username] = !!u.verified);
verifiedMap[process.env.ADMIN_USER] = true; // admin siempre verificado

res.json(comments.map(c => ({ ...c, authorVerified: verifiedMap[c.authorUsername] || false })));
  } catch {
    res.status(400).json({ error: "Error" });
  }
});

app.delete("/watch/comments/:id", auth, requireScope("watch"), async (req, res) => {
  try {
    const database = await getDb();
    const comment = await database.collection("watch_comments")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!comment) return res.status(404).json({ error: "No encontrado" });

    const identifier = req.user.userId || req.user.username;
    if (comment.authorId !== identifier && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    await database.collection("watch_comments").deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "ID inválido" });
  }
});

// ── Watch — Canales / Suscripciones ──────────────────────────────────────────

app.post("/watch/channels/:userId/subscribe", auth, requireScope("watch"), async (req, res) => {
  try {
    const identifier = req.user.userId || req.user.username;
    if (identifier === req.params.userId)
      return res.status(400).json({ error: "No puedes suscribirte a ti mismo" });

    const database = await getDb();
    const existing = await database.collection("watch_subscriptions")
      .findOne({ subscriberId: identifier, channelId: req.params.userId });

    if (existing) {
      await database.collection("watch_subscriptions").deleteOne({ _id: existing._id });
      return res.json({ subscribed: false });
    }

    await database.collection("watch_subscriptions").insertOne({
      subscriberId: identifier, channelId: req.params.userId, createdAt: new Date()
    });
    res.json({ subscribed: true });
  } catch (err) {
    res.status(500).json({ error: "Error interno" });
  }
});

app.get("/watch/channels/:userId", async (req, res) => {
  try {
    const database = await getDb();
    const videos = await database.collection("watch_videos")
  .find({ uploadedBy: req.params.userId }).sort({ createdAt: -1 }).toArray();
const subscriberCount = await database.collection("watch_subscriptions")
  .countDocuments({ channelId: req.params.userId });

const usernames = [...new Set(videos.map(v => v.uploaderUsername))];
const users = await database.collection("users")
  .find({ username: { $in: usernames } }, { projection: { username: 1, verified: 1 } })
  .toArray();
const verifiedMap = {};
users.forEach(u => verifiedMap[u.username] = !!u.verified);
verifiedMap[process.env.ADMIN_USER] = true;

res.json({ userId: req.params.userId, videos: videos.map(v => ({ ...v, uploaderVerified: verifiedMap[v.uploaderUsername] || false })), subscriberCount });
  } catch (err) {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── Verificación ──────────────────────────────────────────────────────────────
app.put("/chat/users/:id/verify", adminAuth, async (req, res) => {
  try {
    const { verified } = req.body;
    const database = await getDb();
    await database.collection("users").updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { verified: !!verified } }
    );
    res.json({ ok: true, verified: !!verified });
  } catch {
    res.status(400).json({ error: "ID inválido" });
  }
});

app.get("/chat/users/:username/verified", async (req, res) => {
  if (req.params.username === process.env.ADMIN_USER) return res.json({ verified: true });
  try {
    const database = await getDb();
    const user = await database.collection("users")
      .findOne({ username: req.params.username }, { projection: { verified: 1 } });
    res.json({ verified: !!user?.verified });
  } catch {
    res.json({ verified: false });
  }
});

app.put("/chat/chats/:id", auth, requireScope("chatter"), async (req, res) => {
  try {
    const database = await getDb();
    const { participants } = req.body;
    if (!participants || !Array.isArray(participants))
      return res.status(400).json({ error: "participants requerido" });
    await database.collection("chats").updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { participants } }
    );
    res.json({ ok: true });
  } catch { res.status(400).json({ error: "ID inválido" }); }
});

// ── Neat Points ───────────────────────────────────────────────────────────────

const INNERNET_API = "https://own-net.vercel.app";
const INNERNET_EXCHANGE_KEY = process.env.INNERNET_EXCHANGE_KEY;
const NEAT_PLUS_PRICE = 500; // NP

// Ver balance de NP
app.get("/neat/points/balance", auth, requireScope("points"), async (req, res) => {
  try {
    if (req.user.role === "admin") return res.json({ points: 999999999, neatPlus: true, forever: true });
    const database = await getDb();
    let user = await database.collection("users")
      .findOne({ username: req.user.username }, { projection: { neatPoints: 1, neatPlus: 1, neatPlusExpiresAt: 1 } });
    if (user && user.neatPoints === undefined) {
      await database.collection("users").updateOne(
        { username: req.user.username },
        { $set: { neatPoints: 0 } }
      );
      user.neatPoints = 0; // actualizar en memoria también
    }
    const expired = user?.neatPlusExpiresAt && new Date() > new Date(user.neatPlusExpiresAt);
    if (expired) await database.collection("users").updateOne(
      { username: req.user.username }, { $set: { neatPlus: false } }
    );
    res.json({
      points: user?.neatPoints ?? 0,
      neatPlus: expired ? false : !!user?.neatPlus,
      expiresAt: expired ? null : user?.neatPlusExpiresAt || null
    });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Admin añade NP a un usuario
app.post("/neat/points/add", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ error: "Solo admin" });
    const { username, amount } = req.body;
    if (!username || !amount || amount <= 0)
      return res.status(400).json({ error: "Faltan campos" });
    const database = await getDb();
    const user = await database.collection("users").findOne({ username });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
    await database.collection("users").updateOne(
      { username }, { $inc: { neatPoints: Number(amount) } }
    );
    await database.collection("np_history").insertOne({
      from: "admin", to: username, amount, type: "admin_grant", createdAt: new Date()
    });
    res.json({ ok: true, newBalance: (user.neatPoints || 0) + Number(amount) });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Transferir NP entre usuarios
app.post("/neat/points/transfer", auth, requireScope("points"), async (req, res) => {
  try {
    const { to, amount } = req.body;
    if (!to || !amount || amount <= 0) return res.status(400).json({ error: "Faltan campos" });
    if (to === req.user.username) return res.status(400).json({ error: "No puedes transferirte a ti mismo" });
    const database = await getDb();
    const sender = await database.collection("users").findOne({ username: req.user.username });
    const receiver = await database.collection("users").findOne({ username: to });
    if (!receiver) return res.status(404).json({ error: "Usuario no encontrado" });
    if ((sender.neatPoints || 0) < amount) return res.status(400).json({ error: "NP insuficientes" });
    await database.collection("users").updateOne(
      { username: req.user.username }, { $inc: { neatPoints: -Number(amount) } }
    );
    await database.collection("users").updateOne(
      { username: to }, { $inc: { neatPoints: Number(amount) } }
    );
    await database.collection("np_history").insertOne({
      from: req.user.username, to, amount, type: "transfer", createdAt: new Date()
    });
    res.json({ ok: true, balance: (sender.neatPoints || 0) - Number(amount) });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Historial de NP
app.get("/neat/points/history", auth, requireScope("points"), async (req, res) => {
  try {
    const database = await getDb();
    const history = await database.collection("np_history")
      .find({ $or: [{ from: req.user.username }, { to: req.user.username }] })
      .sort({ createdAt: -1 }).limit(50).toArray();
    res.json(history);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.post("/neat/points/exchange", auth, requireScope("points"), async (req, res) => {
  try {
    const { lucks, innernetUsername, innernetPassword } = req.body;
    if (!lucks || lucks <= 0 || lucks % 12 !== 0)
      return res.status(400).json({ error: "Debe ser múltiplo de 12 LUCKS" });
    if (!innernetUsername || !innernetPassword)
      return res.status(400).json({ error: "Credenciales de InnerNet requeridas" });

    // Paso 1 — Login en InnerNet para obtener token
    const loginRes = await fetch(`${INNERNET_API}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: innernetUsername, password: innernetPassword })
    });
    const loginData = await loginRes.json();
    if (!loginRes.ok) return res.status(401).json({ error: "Credenciales de InnerNet inválidas" });
    if (loginData.requiresTwoFactor)
      return res.status(400).json({ error: "Tu cuenta de InnerNet tiene 2FA activado, desactívalo para hacer exchange" });

    // Paso 2 — Descontar LUCKS en InnerNet
    const exchangeRes = await fetch(`${INNERNET_API}/exchange/lucks-to-neat`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${loginData.token}`
      },
      body: JSON.stringify({
        lucks,
        neatUsername: req.user.username,
        neatKey: process.env.INNERNET_EXCHANGE_KEY
      })
    });
    const exchangeData = await exchangeRes.json();
    if (!exchangeRes.ok) return res.status(exchangeRes.status).json(exchangeData);

    // Paso 3 — Acreditar NP en Neat
    const np = exchangeData.npToCredit;
    const database = await getDb();
    await database.collection("users").updateOne(
      { username: req.user.username }, { $inc: { neatPoints: np } }
    );
    await database.collection("np_history").insertOne({
      from: `InnerNet:${innernetUsername}`, to: req.user.username,
      amount: np, type: "exchange", lucksSpent: lucks, createdAt: new Date()
    });
    res.json({ ok: true, npReceived: np, lucksSpent: lucks });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Neat Plus — activar con NP
app.post("/neat/plus/activate", auth, requireScope("points"), async (req, res) => {
  try {
    if (req.user.role === "admin") return res.json({ ok: true, neatPlus: true, forever: true });
    const database = await getDb();
    const user = await database.collection("users")
      .findOne({ username: req.user.username }, { projection: { neatPoints: 1 } });
    if ((user?.neatPoints || 0) < NEAT_PLUS_PRICE)
      return res.status(400).json({ error: `NP insuficientes. Necesitas ${NEAT_PLUS_PRICE}, tienes ${user?.neatPoints || 0}` });
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await database.collection("users").updateOne(
      { username: req.user.username },
      { $inc: { neatPoints: -NEAT_PLUS_PRICE }, $set: { neatPlus: true, neatPlusExpiresAt: expiresAt } }
    );
    await database.collection("np_history").insertOne({
      from: req.user.username, to: "Neat", amount: NEAT_PLUS_PRICE,
      type: "neat_plus", createdAt: new Date()
    });
    res.json({ ok: true, neatPlus: true, expiresAt, npSpent: NEAT_PLUS_PRICE });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Estado de Neat Plus
app.get("/neat/plus/status", auth, requireScope("points"), async (req, res) => {
  try {
    if (req.user.role === "admin") return res.json({ neatPlus: true, forever: true });
    const database = await getDb();
    const user = await database.collection("users")
      .findOne({ username: req.user.username }, { projection: { neatPlus: 1, neatPlusExpiresAt: 1 } });
    const expired = user?.neatPlusExpiresAt && new Date() > new Date(user.neatPlusExpiresAt);
    if (expired) await database.collection("users").updateOne(
      { username: req.user.username }, { $set: { neatPlus: false } }
    );
    res.json({ neatPlus: expired ? false : !!user?.neatPlus, expiresAt: expired ? null : user?.neatPlusExpiresAt || null });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// ── Neat Forums ───────────────────────────────────────────────────────────────

app.get("/forums/communities", async (req, res) => {
  try {
    const database = await getDb();
    const communities = await database.collection("forum_communities")
      .find().sort({ members: -1 }).toArray();
    res.json(communities);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.post("/forums/communities", auth, async (req, res) => {
  try {
    const database = await getDb();
    const user = await database.collection("users").findOne({ username: req.user.username });
    const isAdmin = req.user.role === "admin";
    if (!isAdmin && !user?.neatPlus) return res.status(403).json({ error: "Necesitas Neat Plus para crear comunidades" });

    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: "Nombre requerido" });
    if (!/^[a-zA-Z0-9_]{3,30}$/.test(name)) return res.status(400).json({ error: "Nombre inválido (solo letras, números y _)" });

    const exists = await database.collection("forum_communities").findOne({ name });
    if (exists) return res.status(400).json({ error: "Comunidad ya existe" });

    const community = {
      name, description: description || "",
      createdBy: req.user.username,
      members: 1, createdAt: new Date()
    };
    const result = await database.collection("forum_communities").insertOne(community);
    await database.collection("forum_members").insertOne({
      communityName: name, username: req.user.username, joinedAt: new Date()
    });
    res.json({ ...community, _id: result.insertedId });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.get("/forums/communities/:name", async (req, res) => {
  try {
    const database = await getDb();
    const community = await database.collection("forum_communities").findOne({ name: req.params.name });
    if (!community) return res.status(404).json({ error: "Comunidad no encontrada" });
    res.json(community);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.post("/forums/communities/:name/join", auth, async (req, res) => {
  try {
    const database = await getDb();
    const community = await database.collection("forum_communities").findOne({ name: req.params.name });
    if (!community) return res.status(404).json({ error: "Comunidad no encontrada" });
    const already = await database.collection("forum_members").findOne({ communityName: req.params.name, username: req.user.username });
    if (already) return res.json({ ok: true });
    await database.collection("forum_members").insertOne({ communityName: req.params.name, username: req.user.username, joinedAt: new Date() });
    await database.collection("forum_communities").updateOne({ name: req.params.name }, { $inc: { members: 1 } });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Posts
app.get("/forums/posts", async (req, res) => {
  try {
    const database = await getDb();
    const filter = {};
    if (req.query.community) filter.community = req.query.community;
    const posts = await database.collection("forum_posts")
      .find(filter).sort({ score: -1, createdAt: -1 }).limit(50).toArray();
    res.json(posts);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.post("/forums/posts", auth, async (req, res) => {
  try {
    const { title, body, community, anonymous } = req.body;
    if (!title || !community) return res.status(400).json({ error: "Título y comunidad requeridos" });

    const database = await getDb();
    const isMember = await database.collection("forum_members").findOne({ communityName: community, username: req.user.username });
    if (!isMember) return res.status(403).json({ error: "Únete a la comunidad primero" });

    let authorUsername = req.user.username;
    if (anonymous) {
      const user = await database.collection("users").findOne({ username: req.user.username });
      const isAdmin = req.user.role === "admin";
      if (!isAdmin && !user?.neatPlus) return res.status(403).json({ error: "Necesitas Neat Plus para postear anónimo" });
      authorUsername = "anónimo";
    }

    const post = {
      title, body: body || "", community,
      authorUsername, realAuthor: req.user.username,
      anonymous: !!anonymous, score: 0,
      upvotes: 0, downvotes: 0, commentCount: 0,
      createdAt: new Date(), editedAt: null
    };
    const result = await database.collection("forum_posts").insertOne(post);
    res.json({ ...post, _id: result.insertedId });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.put("/forums/posts/:id", auth, async (req, res) => {
  try {
    const database = await getDb();
    const post = await database.collection("forum_posts").findOne({ _id: new ObjectId(req.params.id) });
    if (!post) return res.status(404).json({ error: "Post no encontrado" });
    if (post.realAuthor !== req.user.username && req.user.role !== "admin") return res.status(403).json({ error: "No autorizado" });

    const user = await database.collection("users").findOne({ username: req.user.username });
    const isAdmin = req.user.role === "admin";
    if (!isAdmin && !user?.neatPlus) return res.status(403).json({ error: "Necesitas Neat Plus para editar posts" });

    const { title, body } = req.body;
    await database.collection("forum_posts").updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { title: title || post.title, body: body || post.body, editedAt: new Date() } }
    );
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.delete("/forums/posts/:id", auth, async (req, res) => {
  try {
    const database = await getDb();
    const post = await database.collection("forum_posts").findOne({ _id: new ObjectId(req.params.id) });
    if (!post) return res.status(404).json({ error: "Post no encontrado" });
    if (post.realAuthor !== req.user.username && req.user.role !== "admin") return res.status(403).json({ error: "No autorizado" });
    await database.collection("forum_posts").deleteOne({ _id: new ObjectId(req.params.id) });
    await database.collection("forum_comments").deleteMany({ postId: req.params.id });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.post("/forums/posts/:id/vote", auth, async (req, res) => {
  try {
    const { vote } = req.body; // 1 o -1
    if (vote !== 1 && vote !== -1) return res.status(400).json({ error: "Voto inválido" });

    const database = await getDb();
    const postId = req.params.id;
    const existing = await database.collection("forum_votes").findOne({ postId, username: req.user.username });

    if (existing) {
      if (existing.vote === vote) {
        // quitar voto
        await database.collection("forum_votes").deleteOne({ postId, username: req.user.username });
        await database.collection("forum_posts").updateOne(
          { _id: new ObjectId(postId) },
          { $inc: { score: -vote, upvotes: vote === 1 ? -1 : 0, downvotes: vote === -1 ? -1 : 0 } }
        );
        return res.json({ ok: true, removed: true });
      } else {
        // cambiar voto
        await database.collection("forum_votes").updateOne({ postId, username: req.user.username }, { $set: { vote } });
        await database.collection("forum_posts").updateOne(
          { _id: new ObjectId(postId) },
          { $inc: { score: vote * 2, upvotes: vote === 1 ? 1 : -1, downvotes: vote === -1 ? 1 : -1 } }
        );
        return res.json({ ok: true, changed: true });
      }
    }

    await database.collection("forum_votes").insertOne({ postId, username: req.user.username, vote, createdAt: new Date() });
    await database.collection("forum_posts").updateOne(
      { _id: new ObjectId(postId) },
      { $inc: { score: vote, upvotes: vote === 1 ? 1 : 0, downvotes: vote === -1 ? 1 : 0 } }
    );
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Comentarios
app.get("/forums/posts/:id/comments", async (req, res) => {
  try {
    const database = await getDb();
    const comments = await database.collection("forum_comments")
      .find({ postId: req.params.id }).sort({ createdAt: 1 }).toArray();
    res.json(comments);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.post("/forums/posts/:id/comments", auth, async (req, res) => {
  try {
    const { body } = req.body;
    if (!body) return res.status(400).json({ error: "Comentario vacío" });
    const database = await getDb();
    const comment = {
      postId: req.params.id, body,
      authorUsername: req.user.username,
      createdAt: new Date()
    };
    await database.collection("forum_comments").insertOne(comment);
    await database.collection("forum_posts").updateOne(
      { _id: new ObjectId(req.params.id) }, { $inc: { commentCount: 1 } }
    );
    res.json(comment);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Guardados
app.post("/forums/posts/:id/save", auth, async (req, res) => {
  try {
    const database = await getDb();
    const user = await database.collection("users").findOne({ username: req.user.username });
    const isAdmin = req.user.role === "admin";
    if (!isAdmin && !user?.neatPlus) return res.status(403).json({ error: "Necesitas Neat Plus para guardar posts" });

    const existing = await database.collection("forum_saved").findOne({ postId: req.params.id, username: req.user.username });
    if (existing) {
      await database.collection("forum_saved").deleteOne({ postId: req.params.id, username: req.user.username });
      return res.json({ ok: true, saved: false });
    }
    await database.collection("forum_saved").insertOne({ postId: req.params.id, username: req.user.username, savedAt: new Date() });
    res.json({ ok: true, saved: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.get("/forums/saved", auth, async (req, res) => {
  try {
    const database = await getDb();
    const user = await database.collection("users").findOne({ username: req.user.username });
    const isAdmin = req.user.role === "admin";
    if (!isAdmin && !user?.neatPlus) return res.status(403).json({ error: "Necesitas Neat Plus" });

    const saved = await database.collection("forum_saved")
      .find({ username: req.user.username }).sort({ savedAt: -1 }).toArray();
    const postIds = saved.map(s => new ObjectId(s.postId));
    const posts = await database.collection("forum_posts")
      .find({ _id: { $in: postIds } }).toArray();
    res.json(posts);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Ver upvoters (solo Plus)
app.get("/forums/posts/:id/upvoters", auth, async (req, res) => {
  try {
    const database = await getDb();
    const user = await database.collection("users").findOne({ username: req.user.username });
    const isAdmin = req.user.role === "admin";
    if (!isAdmin && !user?.neatPlus) return res.status(403).json({ error: "Necesitas Neat Plus" });

    const votes = await database.collection("forum_votes")
      .find({ postId: req.params.id, vote: 1 }).toArray();
    res.json(votes.map(v => v.username));
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// ── Neat ID ───────────────────────────────────────────────────────────────────

app.get("/u/:username", async (req, res) => {
  try {
    const database = await getDb();
    const isAdmin = req.params.username.toLowerCase() === ADMIN_USER.toLowerCase();
    
    let profile;
    if (isAdmin) {
      profile = {
        username: ADMIN_USER,
        email: `${ADMIN_USER}@${EMAIL_DOMAIN}`,
        role: "admin",
        verified: true,
        bio: "¡Hola! Soy el Creador de las apps de Neat. Si deseas contactarme, hazlo por Chatter.",
        avatarFileId: null,
        customLinks: [],
        neatPlus: true
      };
    } else {
      const user = await database.collection("users")
        .findOne({ username: { $regex: new RegExp(`^${req.params.username}$`, "i") } },
          { projection: { passwordHash: 0 } });
      if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
      profile = user;
    }

    // Links automáticos — siempre presentes
    const autoLinks = [
      { label: "Neat Chatter", url: `https://neat.qzz.io/byneat/chatter`, icon: "💬", auto: true },
      { label: "Neat Watch", url: `https://neat.qzz.io/byneat/watch`, icon: "▶️", auto: true },
      { label: "Neat Forums", url: `https://neat.qzz.io/byneat/forums`, icon: "🗣️", auto: true },
      { label: "Neat Points", url: `https://neat.qzz.io/byneat/points`, icon: "💰", auto: true },
    ];

  let profileViews = undefined;
    if (!isAdmin && profile.neatPlus) {
      const updated = await database.collection("users").findOneAndUpdate(
        { username: { $regex: new RegExp(`^${req.params.username}$`, "i") } },
        { $inc: { profileViews: 1 } },
        { returnDocument: 'after', projection: { profileViews: 1 } }
      );
      profileViews = updated?.profileViews || 1;
    }

    res.json({
      username: profile.username,
      email: profile.email,
      role: profile.role,
      verified: !!profile.verified,
      bio: profile.bio || null,
      avatarFileId: profile.avatarFileId || null,
      neatPlus: !!profile.neatPlus,
      customLinks: profile.customLinks || [],
      customCategories: profile.customCategories || [],
      autoLinks,
      hasCustomWeb: !!profile.customWeb,
      profileViews
    });
  } catch (err) {
    res.status(500).json({ error: "Error interno" });
  }
});

// Actualizar perfil de Neat ID
app.put("/u/:username", auth, requireScope("profile"), async (req, res) => {
  try {
    if (req.user.username.toLowerCase() !== req.params.username.toLowerCase() && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });
    if (req.user.role === "admin")
      return res.status(400).json({ error: "Admin no tiene perfil editable aquí" });

    const { bio, customLinks, customCategories } = req.body;
    const database = await getDb();
    const user = await database.collection("users").findOne({ username: req.user.username });

    const update = {};
    if (bio !== undefined) update.bio = bio;
    
    if (customLinks !== undefined) {
      // Sin Plus: máximo 10 links sin categorías
      const hasPlus = !!user?.neatPlus;
      const links = customLinks.slice(0, hasPlus ? 1000 : 10).map(l => ({
        label: String(l.label || "").slice(0, 50),
        url: String(l.url || ""),
        icon: String(l.icon || "🔗").slice(0, 10),
        category: hasPlus ? (l.category || null) : null
      }));
      update.customLinks = links;
    }

    if (customCategories !== undefined) {
      const hasPlus = !!user?.neatPlus;
      if (!hasPlus) return res.status(403).json({ error: "Necesitas Neat Plus para categorías" });
      update.customCategories = customCategories.slice(0, 20).map(c => String(c).slice(0, 30));
    }

    await database.collection("users").updateOne(
      { username: req.user.username },
      { $set: update }
    );
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Custom web (solo Plus)
app.get("/u/:username/web", async (req, res) => {
  try {
    const database = await getDb();
    const user = await database.collection("users")
      .findOne({ username: { $regex: new RegExp(`^${req.params.username}$`, "i") } },
        { projection: { customWeb: 1, neatPlus: 1 } });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
    if (!user.neatPlus) return res.status(403).json({ error: "Necesitas Neat Plus" });
    if (!user.customWeb) return res.status(404).json({ error: "Sin página personalizada" });
    // Devolver el HTML directamente
    res.setHeader("Content-Type", "text/html");
    res.send(user.customWeb);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.put("/u/:username/web", auth, requireScope("web"), async (req, res) => {
  try {
    if (req.user.username.toLowerCase() !== req.params.username.toLowerCase() && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const database = await getDb();
    const user = await database.collection("users").findOne({ username: req.user.username });
    if (!user?.neatPlus && req.user.role !== "admin")
      return res.status(403).json({ error: "Necesitas Neat Plus" });

    const { html } = req.body;
    if (!html) return res.status(400).json({ error: "html requerido" });
    if (html.length > 500000) return res.status(400).json({ error: "HTML demasiado grande (max 500KB)" });

    await database.collection("users").updateOne(
      { username: req.user.username },
      { $set: { customWeb: html } }
    );
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// ── OAuth2 ────────────────────────────────────────────────────────────────────

const crypto = require("crypto");

// Registrar cliente OAuth (solo admin)
app.post("/oauth/clients", auth, async (req, res) => {
  try {
    const { name, redirectUris, scopes, isPublic } = req.body;
    if (!name || !redirectUris?.length) return res.status(400).json({ error: "name y redirectUris requeridos" });

    const database = await getDb();
    const isAdmin = req.user.role === "admin";

    if (!isAdmin) {
      const user = await database.collection("users").findOne({ username: req.user.username });
      const hasPlus = !!user?.neatPlus;
      const myClients = await database.collection("oauth_clients")
        .countDocuments({ ownerUsername: req.user.username });

      if (!hasPlus && myClients >= 3) {
        // Cobrar 75 NP por app extra
        if ((user?.neatPoints || 0) < 75)
          return res.status(403).json({ error: "Límite de 3 apps alcanzado. Necesitas 75 NP para una app extra o Neat Plus para ilimitadas." });
        await database.collection("users").updateOne(
          { username: req.user.username }, { $inc: { neatPoints: -75 } }
        );
        await database.collection("np_history").insertOne({
          from: req.user.username, to: "Neat", amount: 75,
          type: "oauth_app_slot", createdAt: new Date()
        });
      }
    }

    const client = {
      name,
      clientId: crypto.randomBytes(16).toString("hex"),
      clientSecret: crypto.randomBytes(32).toString("hex"),
      redirectUris,
      scopes: scopes || ["profile"],
      isPublic: !!isPublic,
      ownerUsername: isAdmin ? null : req.user.username,
      createdAt: new Date()
    };
    await database.collection("oauth_clients").insertOne(client);
    res.json(client);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Listar clientes OAuth (solo admin)
app.get("/oauth/clients", adminAuth, async (req, res) => {
  try {
    const database = await getDb();
    const clients = await database.collection("oauth_clients")
      .find({}, { projection: { clientSecret: 0 } }).toArray();
    res.json(clients);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.get("/oauth/clients/:clientId/secret", auth, async (req, res) => {
  try {
    const database = await getDb();
    const client = await database.collection("oauth_clients")
      .findOne({ clientId: req.params.clientId });
    if (!client) return res.status(404).json({ error: "Cliente no encontrado" });
    const isAdmin = req.user.role === "admin";
    if (!isAdmin && client.ownerUsername !== req.user.username)
      return res.status(403).json({ error: "Sin permisos" });
    res.json({ clientSecret: client.clientSecret });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.get("/oauth/clients/me/list", auth, async (req, res) => {
  try {
    const database = await getDb();
    const filter = req.user.role === "admin"
      ? {}
      : { ownerUsername: req.user.username };
    const clients = await database.collection("oauth_clients")
      .find(filter, { projection: { clientSecret: 0 } })
      .sort({ createdAt: -1 }).toArray();
    res.json(clients);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Info del cliente OAuth (público — para mostrar en la pantalla de autorización)
app.get("/oauth/clients/:clientId", async (req, res) => {
  try {
    const database = await getDb();
    const client = await database.collection("oauth_clients")
      .findOne({ clientId: req.params.clientId }, { projection: { clientSecret: 0 } });
    if (!client) return res.status(404).json({ error: "Cliente no encontrado" });
    res.json(client);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Autorizar — el usuario aprueba, se genera el code
app.post("/oauth/authorize", auth, async (req, res) => {
  try {
    const { clientId, redirectUri, scopes, codeChallenge, codeChallengeMethod } = req.body;
    const database = await getDb();

    const client = await database.collection("oauth_clients").findOne({ clientId });
    const userCheck = await database.collection("users").findOne({ username: req.user.username });
if (userCheck?.suspended) return res.status(403).json({
  error: "Cuenta suspendida",
  note: "Your account is suspended", 
  reason: userCheck.suspendedReason || "Sin razón especificada"
});
    if (!client) return res.status(404).json({ error: "Cliente no encontrado" });
    if (!client.redirectUris.includes(redirectUri))
      return res.status(400).json({ error: "redirect_uri no autorizada" });

    // Validar scopes pedidos
    const validScopes = ["openid", "profile", "email", "points", "chatter", "watch", "forums", "forms", "notes", "ruletas", "web", "ntfy", "kv", "account"];
    const requestedScopes = (scopes || ["profile"]).filter(s => validScopes.includes(s));

    const code = crypto.randomBytes(32).toString("hex");
    await database.collection("oauth_codes").insertOne({
      code,
      clientId,
      username: req.user.username,
      redirectUri,
      scopes: requestedScopes,
      codeChallenge: codeChallenge || null,
      codeChallengeMethod: codeChallengeMethod || "S256",
      expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutos
      used: false
    });

    res.json({ code, redirectUri });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.post("/oauth/token", async (req, res) => {
  try {
    // Soporta JSON (clientId/clientSecret) y form-urlencoded estándar OAuth2 (client_id/client_secret)
    const code = req.body.code;
    const clientId = req.body.clientId || req.body.client_id;
    const clientSecret = req.body.clientSecret || req.body.client_secret;
    const redirectUri = req.body.redirectUri || req.body.redirect_uri;
    const codeVerifier = req.body.codeVerifier || req.body.code_verifier;
    if (!code || !clientId)
      return res.status(400).json({ error: "Faltan campos" });

    const database = await getDb();

    const oauthCode = await database.collection("oauth_codes").findOne({ code, clientId });
    if (!oauthCode) return res.status(400).json({ error: "Código inválido" });
    if (oauthCode.used) return res.status(400).json({ error: "Código ya usado" });
    if (new Date() > oauthCode.expiresAt) return res.status(400).json({ error: "Código expirado" });
    if (oauthCode.redirectUri !== redirectUri) return res.status(400).json({ error: "redirect_uri no coincide" });

    const client = await database.collection("oauth_clients").findOne({ clientId });
    if (!client) return res.status(401).json({ error: "Cliente no encontrado" });

    if (oauthCode.codeChallenge) {
      // Flujo PKCE — no requiere client_secret, se valida el code_verifier
      if (!codeVerifier) return res.status(400).json({ error: "code_verifier requerido" });
      const hash = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
      if (hash !== oauthCode.codeChallenge)
        return res.status(401).json({ error: "code_verifier inválido" });
    } else {
      // Flujo clásico — requiere client_secret
      if (!clientSecret || client.clientSecret !== clientSecret)
        return res.status(401).json({ error: "Credenciales de cliente inválidas" });
    }

    // Marcar código como usado
    await database.collection("oauth_codes").updateOne({ code }, { $set: { used: true } });

    const scopes = oauthCode.scopes;

    // Si pide scope "account" — dar token real completo (30 días)
    if (scopes.includes("account")) {
      const user = await database.collection("users").findOne({ username: oauthCode.username });
      const isAdmin = oauthCode.username === ADMIN_USER;
      
      const fullToken = jwt.sign(
        isAdmin
          ? { username: oauthCode.username, role: "admin" }
          : { userId: user._id.toString(), username: user.username, role: user.role },
        SECRET,
        { expiresIn: "30d" }
      );

      await database.collection("oauth_tokens").insertOne({
        token: fullToken,
        clientId,
        username: oauthCode.username,
        scopes,
        type: "account",
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
      });

      return res.json({
        access_token: fullToken,
        token_type: "Bearer",
        expires_in: 2592000,
        scopes
      });
    }

    // Token limitado por scopes (24 horas)
    const scopedToken = jwt.sign(
      { username: oauthCode.username, scopes, type: "oauth" },
      SECRET,
      { expiresIn: "24h" }
    );

    await database.collection("oauth_tokens").insertOne({
      token: scopedToken,
      clientId,
      username: oauthCode.username,
      scopes,
      type: "scoped",
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
    });

// Dentro de POST /oauth/token, antes del res.json final, agrega:
let idToken = null;
if (oauthCode.scopes.includes("openid")) {
  const database2 = await getDb();
  const oidcUser = await database2.collection("users").findOne({ username: oauthCode.username });
  idToken = jwt.sign({
    iss: "https://neat-apps-b.vercel.app",
    sub: oauthCode.username,
    aud: clientId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 86400,
    username: oauthCode.username,
    email: scopes.includes("email") ? oidcUser?.email : undefined,
    verified: !!oidcUser?.verified,
  }, SECRET, { algorithm: "HS256" });
}

// Y en el res.json:
res.json({
  access_token: scopedToken,
  token_type: "Bearer",
  expires_in: 86400,
  scopes,
  id_token: idToken || undefined
});
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Revocar token OAuth
app.post("/oauth/revoke", auth, async (req, res) => {
  try {
    const { token: tokenToRevoke } = req.body;
    if (!tokenToRevoke) return res.status(400).json({ error: "token requerido" });
    const database = await getDb();
    await database.collection("oauth_tokens").deleteOne({
      token: tokenToRevoke,
      username: req.user.username
    });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Tokens activos del usuario
app.get("/oauth/tokens", auth, async (req, res) => {
  try {
    const database = await getDb();
    const tokens = await database.collection("oauth_tokens")
      .find({ username: req.user.username }, { projection: { token: 0 } })
      .sort({ createdAt: -1 }).toArray();
    res.json(tokens);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Userinfo — para apps con scope "profile"
app.get("/oauth/userinfo", auth, requireScope("profile"), async (req, res) => {
  try {
    const database = await getDb();

    const isAdmin = req.user.role === "admin" || req.user.username === ADMIN_USER;
    if (isAdmin) {
      return res.json({
        sub: req.user.username,
        username: req.user.username,
        email: `${req.user.username}@${EMAIL_DOMAIN}`,
        verified: true,
        role: "admin",
        neatPlus: true
      });
    }

    const user = await database.collection("users")
      .findOne({ username: req.user.username }, { projection: { passwordHash: 0 } });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    // Respetar scopes si es token OAuth
    const scopes = req.user.scopes || ["account"];
    // sub siempre se incluye (es el identificador estándar de OIDC)
    const response = { sub: user.username, username: user.username };
    if (scopes.includes("profile") || scopes.includes("openid") || scopes.includes("account")) {
      response.bio = user.bio || null;
      response.avatarFileId = user.avatarFileId || null;
      response.verified = !!user.verified;
      response.neatPlus = !!user.neatPlus;
      response.role = user.role;
    }
    if (scopes.includes("email") || scopes.includes("account")) {
      response.email = user.email;
    }

    res.json(response);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// ── OAuth — KV: JSON consolidado del usuario, filtrado por scope ──────────────
// Cada bloque solo se incluye si el token tiene el scope del dominio
// correspondiente. "kv" es la llave que habilita el endpoint en sí; el
// contenido de cada bloque sigue respetando su propio scope.
app.get("/oauth/kv", auth, requireScope("kv"), async (req, res) => {
  try {
    const database = await getDb();
    const username = req.user.username;
    const isAdmin = req.user.role === "admin" || username === ADMIN_USER;

    // Token de cuenta completa (no-oauth, o scope "account") ve todo.
    // Token scoped solo ve los bloques cuyo scope también esté presente.
    const scopes = req.user.scopes || ["account"];
    const hasScope = (s) => scopes.includes("account") || scopes.includes(s);

    const result = { sub: username, username };

    // ── profile / email (mismo criterio que /oauth/userinfo) ────────────────
    if (hasScope("profile") || hasScope("openid")) {
      if (isAdmin) {
        result.profile = { verified: true, role: "admin", neatPlus: true };
      } else {
        const user = await database.collection("users")
          .findOne({ username }, { projection: { passwordHash: 0 } });
        if (user) {
          result.profile = {
            bio: user.bio || null,
            avatarFileId: user.avatarFileId || null,
            verified: !!user.verified,
            neatPlus: !!user.neatPlus,
            role: user.role
          };
        }
      }
    }
    if (hasScope("email")) {
      result.email = isAdmin ? `${username}@${EMAIL_DOMAIN}` :
        (await database.collection("users").findOne({ username }))?.email || null;
    }

    // ── points ───────────────────────────────────────────────────────────────
    if (hasScope("points") && !isAdmin) {
      const user = await database.collection("users").findOne({ username });
      const history = await database.collection("np_history")
        .find({ $or: [{ from: username }, { to: username }] })
        .sort({ createdAt: -1 }).limit(50).toArray();
      result.points = {
        balance: user?.neatPoints || 0,
        neatPlus: !!user?.neatPlus,
        history
      };
    }

    // ── notes ────────────────────────────────────────────────────────────────
    if (hasScope("notes")) {
      const notes = await database.collection("notes")
        .find({ authorUsername: username })
        .project({ passwordHash: 0 })
        .sort({ createdAt: -1 }).toArray();
      result.notes = notes;
    }

    // ── ruletas ──────────────────────────────────────────────────────────────
    if (hasScope("ruletas")) {
      const ruletas = await database.collection("ruletas")
        .find({ autorUsername: username })
        .sort({ createdAt: -1 }).toArray();
      result.ruletas = ruletas;
    }

    // ── watch (historial, listas, suscripciones) ────────────────────────────
    if (hasScope("watch")) {
      const identifier = req.user.userId || req.user.username;
      const historyDoc = await database.collection("watch_history").findOne({ username });
      const lists = await database.collection("watch_lists")
        .find({ creatorUsername: username }).sort({ createdAt: -1 }).toArray();
      const subscriptions = await database.collection("watch_subscriptions")
        .find({ subscriberId: identifier }).toArray();
      result.watch = {
        history: historyDoc?.history || [],
        lists,
        subscriptions
      };
    }

    // ── chatter (chats donde participa) ─────────────────────────────────────
    if (hasScope("chatter")) {
      const chats = await database.collection("chats")
        .find({ participants: username }).sort({ updatedAt: -1 }).toArray();
      result.chatter = { chats };
    }

    // ── forums (posts, comentarios y guardados propios) ─────────────────────
    if (hasScope("forums")) {
      const posts = await database.collection("forum_posts")
        .find({ realAuthor: username }).sort({ createdAt: -1 }).toArray();
      const comments = await database.collection("forum_comments")
        .find({ authorUsername: username }).sort({ createdAt: -1 }).toArray();
      const saved = await database.collection("forum_saved")
        .find({ username }).sort({ savedAt: -1 }).toArray();
      result.forums = { posts, comments, saved };
    }

    // ── forms (encuestas creadas) ────────────────────────────────────────────
    if (hasScope("forms")) {
      const polls = await database.collection("forms_polls")
        .find({ creatorUsername: username }).sort({ createdAt: -1 }).toArray();
      result.forms = { polls };
    }

    // ── web (sitio personalizado) ────────────────────────────────────────────
    if (hasScope("web")) {
      const user = await database.collection("users").findOne({ username });
      result.web = user?.customWeb || null;
    }

    // ── ntfy (config de notificaciones) ──────────────────────────────────────
    if (hasScope("ntfy")) {
      const user = await database.collection("users").findOne({ username });
      result.ntfy = { topic: user?.ntfyTopic || null };
    }

    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

app.put("/chat/users/:id/suspend", adminAuth, async (req, res) => {
  try {
    const { suspended, reason } = req.body;
    const database = await getDb();
    await database.collection("users").updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { 
        suspended: !!suspended,
        suspendedReason: suspended ? (reason || "Sin razón especificada") : null,
        suspendedAt: suspended ? new Date() : null
      }}
    );
    res.json({ ok: true, suspended: !!suspended });
  } catch { res.status(400).json({ error: "ID inválido" }); }
});

// ── OpenID Connect ─────────────────────────────────────────────────────────────

app.get("/.well-known/openid-configuration", (req, res) => {
  const base = "https://neat-apps-b.vercel.app";
  res.json({
    issuer: base,
    authorization_endpoint: "https://neat.qzz.io/oauth.html",
    token_endpoint: `${base}/oauth/token`,
    userinfo_endpoint: `${base}/oauth/userinfo`,
    jwks_uri: `${base}/.well-known/jwks.json`,
    registration_endpoint: `${base}/oauth/clients`,
    scopes_supported: ["openid", "profile", "email", "points", "chatter", "watch", "forums", "forms", "notes", "ruletas", "web", "ntfy", "kv", "account"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["HS256"],
    claims_supported: ["sub", "username", "email", "verified", "neatPlus", "role"]
  });
});

app.get("/.well-known/jwks.json", (req, res) => {
  // HS256 no usa JWKS real pero Gitea lo requiere
  res.json({ keys: [] });
});

// Dar/quitar Neat Plus (admin)
app.put("/neat/plus/admin", adminAuth, async (req, res) => {
  try {
    const { username, active, days } = req.body;
    const database = await getDb();
    const user = await database.collection("users").findOne({ username });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
    const expiresAt = active ? new Date(Date.now() + (days || 30) * 24 * 60 * 60 * 1000) : null;
    await database.collection("users").updateOne(
      { username },
      { $set: { neatPlus: !!active, neatPlusExpiresAt: expiresAt } }
    );
    res.json({ ok: true, neatPlus: !!active, expiresAt });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Historial global de NP (admin)
app.get("/neat/points/history/all", adminAuth, async (req, res) => {
  try {
    const database = await getDb();
    const history = await database.collection("np_history")
      .find().sort({ createdAt: -1 }).limit(100).toArray();
    res.json(history);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// ── Neat Notes ────────────────────────────────────────────────────────────────

const NOTE_ID_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789';
function randomNoteId(len = 8) {
  return Array.from(crypto.randomBytes(len))
    .map(b => NOTE_ID_CHARS[b % NOTE_ID_CHARS.length]).join('');
}

// Crear nota
app.post("/notes", auth, requireScope("notes"), async (req, res) => {
  try {
    const { title, content, visibility: visibilityInput, password, customId } = req.body;
    if (!content) return res.status(400).json({ error: "content requerido" });

    const database = await getDb();
    const user = req.user.role === "admin" ? null : 
      await database.collection("users").findOne({ username: req.user.username });
    const hasPlus = req.user.role === "admin" || !!user?.neatPlus;

    // URL personalizada solo Plus
    let noteId;
    if (customId) {
      if (!hasPlus) return res.status(403).json({ error: "Necesitas Neat Plus para URLs personalizadas" });
      if (!/^[a-zA-Z0-9_-]{3,30}$/.test(customId))
        return res.status(400).json({ error: "ID inválido (3-30 chars, letras/números/_/-)" });
      const exists = await database.collection("notes").findOne({ noteId: customId });
      if (exists) return res.status(409).json({ error: "Esa URL ya está en uso" });
      noteId = customId;
    } else {
      noteId = randomNoteId();
      // Garantizar unicidad
      while (await database.collection("notes").findOne({ noteId })) {
        noteId = randomNoteId();
      }
    }

    // Contraseña solo Plus
    let passwordHash = null;
    if (password) {
      if (!hasPlus) return res.status(403).json({ error: "Necesitas Neat Plus para notas con contraseña" });
      passwordHash = await bcrypt.hash(password, 10);
    }

    const visibility = ['public', 'unlisted', 'private'].includes(visibilityInput) ? visibilityInput : 'public';

    const note = {
      noteId,
      title: title || null,
      content,
      authorUsername: req.user.username,
      visibility,
      passwordHash,
      hasPassword: !!password,
      history: [],
      createdAt: new Date(),
      updatedAt: new Date()
    };

    await database.collection("notes").insertOne(note);
    res.status(201).json({ noteId, title: note.title, visibility: note.visibility, hasPassword: note.hasPassword, createdAt: note.createdAt });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// Ver nota por ID
app.get("/notes/:id", async (req, res) => {
  try {
    const database = await getDb();
    const note = await database.collection("notes").findOne({ noteId: req.params.id });
    if (!note) return res.status(404).json({ error: "Nota no encontrada" });

    // Si tiene contraseña, verificar
    if (note.passwordHash) {
      const { password } = req.query;
      if (!password) return res.status(403).json({ error: "Nota protegida", protected: true });
      const valid = await bcrypt.compare(password, note.passwordHash);
      if (!valid) return res.status(403).json({ error: "Contraseña incorrecta", protected: true });
    }

    // Verificación del autor
    const isAdmin = note.authorUsername === process.env.ADMIN_USER;
    let verified = false;
    if (isAdmin) {
      verified = true;
    } else {
      const author = await database.collection("users")
        .findOne({ username: note.authorUsername }, { projection: { verified: 1 } });
      verified = !!author?.verified;
    }

    const { passwordHash, ...safe } = note;
    res.json({ ...safe, authorVerified: verified });
  } catch (err) {
    res.status(500).json({ error: "Error interno" });
  }
});

// Mis notas
app.get("/notes/me/list", auth, requireScope("notes"), async (req, res) => {
  try {
    const database = await getDb();
    const notes = await database.collection("notes")
      .find({ authorUsername: req.user.username }, { projection: { passwordHash: 0, content: 0, history: 0 } })
      .sort({ updatedAt: -1 }).toArray();
    res.json(notes);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Editar nota
app.put("/notes/:id", auth, requireScope("notes"), async (req, res) => {
  try {
    const database = await getDb();
    const note = await database.collection("notes").findOne({ noteId: req.params.id });
    if (!note) return res.status(404).json({ error: "Nota no encontrada" });
    if (note.authorUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const { title, content, visibility: visibilityInput, password } = req.body;

    // Guardar historial (máx 2 versiones)
    const historyEntry = {
      title: note.title,
      content: note.content,
      savedAt: note.updatedAt
    };
    const newHistory = [historyEntry, ...(note.history || [])].slice(0, 2);

    const update = {
      updatedAt: new Date(),
      history: newHistory
    };
    if (title !== undefined) update.title = title;
    if (content !== undefined) update.content = content;
    if (visibilityInput !== undefined) {
      if (!['public', 'unlisted', 'private'].includes(visibilityInput))
        return res.status(400).json({ error: "visibility inválido (public, unlisted o private)" });
      update.visibility = visibilityInput;
    }

    // Cambiar contraseña (solo Plus)
    if (password !== undefined) {
      const user = req.user.role === "admin" ? null :
        await database.collection("users").findOne({ username: req.user.username });
      const hasPlus = req.user.role === "admin" || !!user?.neatPlus;
      if (!hasPlus) return res.status(403).json({ error: "Necesitas Neat Plus para notas con contraseña" });
      update.passwordHash = password ? await bcrypt.hash(password, 10) : null;
      update.hasPassword = !!password;
    }

    await database.collection("notes").updateOne({ noteId: req.params.id }, { $set: update });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Ver historial (solo Plus)
app.get("/notes/:id/history", auth, requireScope("notes"), async (req, res) => {
  try {
    const database = await getDb();
    const note = await database.collection("notes").findOne({ noteId: req.params.id });
    if (!note) return res.status(404).json({ error: "Nota no encontrada" });
    if (note.authorUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const user = req.user.role === "admin" ? null :
      await database.collection("users").findOne({ username: req.user.username });
    const hasPlus = req.user.role === "admin" || !!user?.neatPlus;
    if (!hasPlus) return res.status(403).json({ error: "Necesitas Neat Plus para ver el historial" });

    res.json(note.history || []);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Eliminar nota
app.delete("/notes/:id", auth, requireScope("notes"), async (req, res) => {
  try {
    const database = await getDb();
    const note = await database.collection("notes").findOne({ noteId: req.params.id });
    if (!note) return res.status(404).json({ error: "Nota no encontrada" });
    if (note.authorUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });
    await database.collection("notes").deleteOne({ noteId: req.params.id });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.get("/notes", async (req, res) => {
  try {
    const database = await getDb();
    const notes = await database.collection("notes")
      .find({ visibility: 'public' }, { projection: { passwordHash: 0, content: 0, history: 0 } })
      .sort({ createdAt: -1 }).limit(30).toArray();
    const usernames = [...new Set(notes.map(n => n.authorUsername))];
    const users = await database.collection("users")
      .find({ username: { $in: usernames } }, { projection: { username: 1, verified: 1 } })
      .toArray();
    const verifiedMap = {};
    users.forEach(u => verifiedMap[u.username] = !!u.verified);
    verifiedMap[process.env.ADMIN_USER] = true;
    res.json(notes.map(n => ({ ...n, authorVerified: verifiedMap[n.authorUsername] || false })));
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// ── Neat Ruletas ────────────────────────────────────────────────────────────────

function randomRuletaId(len = 8) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from(crypto.randomBytes(len))
    .map(b => chars[b % chars.length]).join('');
}

// Crear ruleta
app.post("/ruletas", auth, requireScope("ruletas"), async (req, res) => {
  try {
    const { nombre, opciones, colores } = req.body;
    if (!opciones || opciones.length < 2) return res.status(400).json({ error: "Mínimo 2 opciones" });

    const database = await getDb();
    const user = req.user.role === "admin" ? null :
      await database.collection("users").findOne({ username: req.user.username });
    const hasPlus = req.user.role === "admin" || !!user?.neatPlus;

    // Colores personalizados solo Plus
    if (colores && !hasPlus)
      return res.status(403).json({ error: "Necesitas Neat Plus para colores personalizados" });

    const ruletaId = randomRuletaId();
    const ruleta = {
      ruletaId,
      nombre: nombre || "Mi ruleta",
      opciones,
      colores: hasPlus && colores ? colores : null,
      autorUsername: req.user.username,
      historial: [],
      createdAt: new Date(),
      updatedAt: new Date()
    };

    await database.collection("ruletas").insertOne(ruleta);
    res.status(201).json({ ruletaId, nombre: ruleta.nombre });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// Ver ruleta por ID
app.get("/ruletas/:id", async (req, res) => {
  try {
    const database = await getDb();
    const ruleta = await database.collection("ruletas").findOne({ ruletaId: req.params.id });
    if (!ruleta) return res.status(404).json({ error: "Ruleta no encontrada" });

    const isAdmin = ruleta.autorUsername === process.env.ADMIN_USER;
    let verified = false;
    if (isAdmin) {
      verified = true;
    } else {
      const autor = await database.collection("users")
        .findOne({ username: ruleta.autorUsername }, { projection: { verified: 1 } });
      verified = !!autor?.verified;
    }

    res.json({ ...ruleta, autorVerified: verified });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Mis ruletas
app.get("/ruletas/me/list", auth, requireScope("ruletas"), async (req, res) => {
  try {
    const database = await getDb();
    const ruletas = await database.collection("ruletas")
      .find({ autorUsername: req.user.username }, { projection: { historial: 0 } })
      .sort({ updatedAt: -1 }).toArray();
    res.json(ruletas);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Girar ruleta (registra resultado)
app.post("/ruletas/:id/girar", auth, requireScope("ruletas"), async (req, res) => {
  try {
    const { resultado } = req.body;
    if (!resultado) return res.status(400).json({ error: "resultado requerido" });

    const database = await getDb();
    const ruleta = await database.collection("ruletas").findOne({ ruletaId: req.params.id });
    if (!ruleta) return res.status(404).json({ error: "Ruleta no encontrada" });
    if (ruleta.autorUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const entrada = { resultado, fecha: new Date() };
    const nuevoHistorial = [entrada, ...(ruleta.historial || [])].slice(0, 50);

    await database.collection("ruletas").updateOne(
      { ruletaId: req.params.id },
      { $set: { historial: nuevoHistorial, updatedAt: new Date() } }
    );
    res.json({ ok: true, resultado });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Ver historial (solo Plus)
app.get("/ruletas/:id/historial", auth, requireScope("ruletas"), async (req, res) => {
  try {
    const database = await getDb();
    const ruleta = await database.collection("ruletas").findOne({ ruletaId: req.params.id });
    if (!ruleta) return res.status(404).json({ error: "Ruleta no encontrada" });
    if (ruleta.autorUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const user = req.user.role === "admin" ? null :
      await database.collection("users").findOne({ username: req.user.username });
    const hasPlus = req.user.role === "admin" || !!user?.neatPlus;
    if (!hasPlus) return res.status(403).json({ error: "Necesitas Neat Plus para ver el historial" });

    res.json(ruleta.historial || []);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Editar ruleta
app.put("/ruletas/:id", auth, requireScope("ruletas"), async (req, res) => {
  try {
    const database = await getDb();
    const ruleta = await database.collection("ruletas").findOne({ ruletaId: req.params.id });
    if (!ruleta) return res.status(404).json({ error: "Ruleta no encontrada" });
    if (ruleta.autorUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const { nombre, opciones, colores } = req.body;
    const user = req.user.role === "admin" ? null :
      await database.collection("users").findOne({ username: req.user.username });
    const hasPlus = req.user.role === "admin" || !!user?.neatPlus;

    if (colores && !hasPlus)
      return res.status(403).json({ error: "Necesitas Neat Plus para colores personalizados" });

    const update = { updatedAt: new Date() };
    if (nombre) update.nombre = nombre;
    if (opciones && opciones.length >= 2) update.opciones = opciones;
    if (colores !== undefined) update.colores = hasPlus && colores ? colores : null;

    await database.collection("ruletas").updateOne({ ruletaId: req.params.id }, { $set: update });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Eliminar ruleta
app.delete("/ruletas/:id", auth, requireScope("ruletas"), async (req, res) => {
  try {
    const database = await getDb();
    const ruleta = await database.collection("ruletas").findOne({ ruletaId: req.params.id });
    if (!ruleta) return res.status(404).json({ error: "Ruleta no encontrada" });
    if (ruleta.autorUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });
    await database.collection("ruletas").deleteOne({ ruletaId: req.params.id });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Watch — Historial de vistos (Plus)
app.post("/watch/history", auth, requireScope("watch"), async (req, res) => {
  try {
    const { videoId } = req.body;
    if (!videoId) return res.status(400).json({ error: "videoId requerido" });
    const database = await getDb();
    const user = req.user.role === "admin" ? null :
      await database.collection("users").findOne({ username: req.user.username });
    const hasPlus = req.user.role === "admin" || !!user?.neatPlus;
    if (!hasPlus) return res.json({ ok: true }); // silencioso para no-Plus
    const entry = { videoId, viewedAt: new Date() };
    await database.collection("watch_history").updateOne(
      { username: req.user.username },
      { $pull: { history: { videoId } } }
    );
    await database.collection("watch_history").updateOne(
      { username: req.user.username },
      { $push: { history: { $each: [entry], $position: 0, $slice: 25 } }, $setOnInsert: { username: req.user.username } },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.get("/watch/history", auth, requireScope("watch"), async (req, res) => {
  try {
    const database = await getDb();
    const user = req.user.role === "admin" ? null :
      await database.collection("users").findOne({ username: req.user.username });
    const hasPlus = req.user.role === "admin" || !!user?.neatPlus;
    if (!hasPlus) return res.status(403).json({ error: "Necesitas Neat Plus" });
    const doc = await database.collection("watch_history").findOne({ username: req.user.username });
    if (!doc?.history?.length) return res.json([]);
    const videoIds = doc.history.map(h => new ObjectId(h.videoId));
    const videos = await database.collection("watch_videos")
      .find({ _id: { $in: videoIds } }).toArray();
    const videoMap = {};
    videos.forEach(v => videoMap[v._id.toString()] = v);
    res.json(doc.history.map(h => ({ ...videoMap[h.videoId], viewedAt: h.viewedAt })).filter(v => v._id));
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// ── Watch — Listas de reproducción ───────────────────────────────────────────

function randomListId(len = 8) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from(crypto.randomBytes(len))
    .map(b => chars[b % chars.length]).join('');
}

// Crear lista
app.post("/watch/lists", auth, requireScope("watch"), async (req, res) => {
  try {
    const { nombre } = req.body;
    if (!nombre) return res.status(400).json({ error: "nombre requerido" });
    const database = await getDb();
    let listId = randomListId();
    while (await database.collection("watch_lists").findOne({ listId })) listId = randomListId();
    const lista = {
      listId, nombre,
      creatorUsername: req.user.username,
      videos: [],
      createdAt: new Date(), updatedAt: new Date()
    };
    await database.collection("watch_lists").insertOne(lista);
    res.status(201).json({ listId, nombre });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Ver lista por ID (público)
app.get("/watch/lists/:id", async (req, res) => {
  try {
    const database = await getDb();
    const lista = await database.collection("watch_lists").findOne({ listId: req.params.id });
    if (!lista) return res.status(404).json({ error: "Lista no encontrada" });
    const videoIds = lista.videos.map(id => { try { return new ObjectId(id); } catch { return null; } }).filter(Boolean);
    const videos = videoIds.length
      ? await database.collection("watch_videos").find({ _id: { $in: videoIds } }).toArray()
      : [];
    const videoMap = {};
    videos.forEach(v => videoMap[v._id.toString()] = v);
    const ordered = lista.videos.map(id => videoMap[id]).filter(Boolean);
    res.json({ ...lista, videos: ordered });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Mis listas
app.get("/watch/lists/me/list", auth, requireScope("watch"), async (req, res) => {
  try {
    const database = await getDb();
    const listas = await database.collection("watch_lists")
      .find({ creatorUsername: req.user.username })
      .sort({ updatedAt: -1 }).toArray();
    res.json(listas);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Añadir video a lista
app.post("/watch/lists/:id/videos", auth, requireScope("watch"), async (req, res) => {
  try {
    const { videoId } = req.body;
    if (!videoId) return res.status(400).json({ error: "videoId requerido" });
    const database = await getDb();
    const lista = await database.collection("watch_lists").findOne({ listId: req.params.id });
    if (!lista) return res.status(404).json({ error: "Lista no encontrada" });
    if (lista.creatorUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });
    if (lista.videos.includes(videoId))
      return res.status(409).json({ error: "Video ya está en la lista" });
    await database.collection("watch_lists").updateOne(
      { listId: req.params.id },
      { $push: { videos: videoId }, $set: { updatedAt: new Date() } }
    );
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Quitar video de lista
app.delete("/watch/lists/:id/videos/:videoId", auth, requireScope("watch"), async (req, res) => {
  try {
    const database = await getDb();
    const lista = await database.collection("watch_lists").findOne({ listId: req.params.id });
    if (!lista) return res.status(404).json({ error: "Lista no encontrada" });
    if (lista.creatorUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });
    await database.collection("watch_lists").updateOne(
      { listId: req.params.id },
      { $pull: { videos: req.params.videoId }, $set: { updatedAt: new Date() } }
    );
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Eliminar lista
app.delete("/watch/lists/:id", auth, requireScope("watch"), async (req, res) => {
  try {
    const database = await getDb();
    const lista = await database.collection("watch_lists").findOne({ listId: req.params.id });
    if (!lista) return res.status(404).json({ error: "Lista no encontrada" });
    if (lista.creatorUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });
    await database.collection("watch_lists").deleteOne({ listId: req.params.id });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Renombrar lista
app.put("/watch/lists/:id", auth, requireScope("watch"), async (req, res) => {
  try {
    const { nombre } = req.body;
    if (!nombre) return res.status(400).json({ error: "nombre requerido" });
    const database = await getDb();
    const lista = await database.collection("watch_lists").findOne({ listId: req.params.id });
    if (!lista) return res.status(404).json({ error: "Lista no encontrada" });
    if (lista.creatorUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });
    await database.collection("watch_lists").updateOne(
      { listId: req.params.id },
      { $set: { nombre, updatedAt: new Date() } }
    );
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// ── Neat ntfy ─────────────────────────────────────────────────────────────────

// Generar/obtener topic ntfy
app.post("/ntfy/setup", auth, requireScope("ntfy"), async (req, res) => {
  try {
    if (req.user.role === "admin") return res.json({ ok: true, topic: "admin_no_necesita" });
    const database = await getDb();
    const user = await database.collection("users").findOne({ username: req.user.username });
    if (!user?.neatPlus) return res.status(403).json({ error: "Necesitas Neat Plus" });
    if (user.ntfyTopic) return res.json({ ok: true, topic: user.ntfyTopic });
    const topic = "neat_" + crypto.randomBytes(8).toString("hex");
    await database.collection("users").updateOne(
      { username: req.user.username },
      { $set: { ntfyTopic: topic } }
    );
    res.json({ ok: true, topic });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Ver topic actual
app.get("/ntfy/topic", auth, requireScope("ntfy"), async (req, res) => {
  try {
    const database = await getDb();
    const user = await database.collection("users").findOne({ username: req.user.username });
    res.json({ topic: user?.ntfyTopic || null });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.delete("/oauth/clients/:clientId", auth, async (req, res) => {
  try {
    const database = await getDb();
    const client = await database.collection("oauth_clients").findOne({ clientId: req.params.clientId });
    if (!client) return res.status(404).json({ error: "No encontrada" });
    const isAdmin = req.user.role === "admin";
    if (!isAdmin && client.ownerUsername !== req.user.username)
      return res.status(403).json({ error: "Sin permisos" });
    await database.collection("oauth_clients").deleteOne({ clientId: req.params.clientId });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.put("/oauth/clients/:clientId", auth, async (req, res) => {
  try {
    const database = await getDb();
    const client = await database.collection("oauth_clients").findOne({ clientId: req.params.clientId });
    if (!client) return res.status(404).json({ error: "No encontrada" });
    const isAdmin = req.user.role === "admin";
    if (!isAdmin && client.ownerUsername !== req.user.username)
      return res.status(403).json({ error: "Sin permisos" });

    const { name, redirectUris, scopes, isPublic } = req.body;
    if (!name || !redirectUris?.length) return res.status(400).json({ error: "name y redirectUris requeridos" });

    await database.collection("oauth_clients").updateOne(
      { clientId: req.params.clientId },
      { $set: { name, redirectUris, scopes: scopes || ["profile"], isPublic: !!isPublic } }
    );
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

app.put("/oauth/clients/:clientId/verify", adminAuth, async (req, res) => {
  try {
    const { verified } = req.body;
    const database = await getDb();
    const client = await database.collection("oauth_clients").findOne({ clientId: req.params.clientId });
    if (!client) return res.status(404).json({ error: "Cliente no encontrado" });

    await database.collection("oauth_clients").updateOne(
      { clientId: req.params.clientId },
      { $set: {
        verified: !!verified,
        verifiedAt: verified ? new Date() : null
      }}
    );
    res.json({ ok: true, verified: !!verified });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// ── Neat Forms ──────────────────────────────────────────────────────────────

function randomPollId(len = 8) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from(crypto.randomBytes(len))
    .map(b => chars[b % chars.length]).join('');
}

const FORMS_QUESTION_TYPES = [
  "multiple_choice", "checkboxes", "datetime", "text",
  "paragraph", "linear_scale", "grid", "file_upload"
];

// Crear poll — requiere scope 'forms'
// Helpers compartidos entre crear y editar polls de Forms.
// existingSections/existingQuestions permiten preservar el id original cuando
// el cliente manda de vuelta una sección/pregunta que ya existía, para que las
// respuestas ya guardadas (forms_votes) sigan vinculadas correctamente.
function buildFormsSections(sections, hasPlus, existingSections = []) {
  const builtSections = [];
  if (sections === undefined) return { builtSections };
  if (!hasPlus) return { error: "Necesitas Neat Plus para usar Secciones" };
  if (!Array.isArray(sections)) return { error: "sections debe ser un array" };
  if (sections.length > 20) return { error: "Máximo 20 secciones" };
  for (let i = 0; i < sections.length; i++) {
    const s = sections[i] || {};
    if (!s.title) return { error: `Sección ${i + 1}: title requerido` };
    const existing = s.id && existingSections.find(es => es.id === s.id);
    builtSections.push({
      id: existing ? existing.id : `s${i + 1}_${crypto.randomBytes(3).toString("hex")}`,
      title: s.title
    });
  }
  return { builtSections };
}

function buildFormsQuestions(questions, builtSections, existingQuestions = []) {
  if (!Array.isArray(questions) || questions.length === 0)
    return { error: "questions requerido (al menos 1 pregunta)" };
  if (questions.length > 50)
    return { error: "Máximo 50 preguntas" };

  const builtQuestions = [];
  for (let i = 0; i < questions.length; i++) {
    const q = questions[i] || {};
    const {
      questionType, title: qTitle, required = false, options,
      scaleMin, scaleMax, scaleMinLabel, scaleMaxLabel, gridRows, gridColumns,
      sectionIndex, id: qId
    } = q;

    if (!qTitle) return { error: `Pregunta ${i + 1}: title requerido` };
    if (!FORMS_QUESTION_TYPES.includes(questionType))
      return { error: `Pregunta ${i + 1}: questionType inválido` };

    if (["multiple_choice", "checkboxes", "datetime"].includes(questionType) && (!options || options.length < 2))
      return { error: `Pregunta ${i + 1}: mínimo 2 opciones` };

    if (questionType === "linear_scale") {
      if (typeof scaleMin !== "number" || typeof scaleMax !== "number" || scaleMin >= scaleMax)
        return { error: `Pregunta ${i + 1}: scaleMin y scaleMax inválidos` };
      if (scaleMax - scaleMin > 10) return { error: `Pregunta ${i + 1}: rango máximo de 10` };
    }

    if (questionType === "grid") {
      if (!gridRows?.length || !gridColumns?.length)
        return { error: `Pregunta ${i + 1}: gridRows y gridColumns requeridos` };
    }

    let sectionId = null;
    if (sectionIndex !== undefined && sectionIndex !== null) {
      if (!builtSections[sectionIndex])
        return { error: `Pregunta ${i + 1}: sectionIndex inválido` };
      sectionId = builtSections[sectionIndex].id;
    }

    // Solo se preserva el id si además el tipo de pregunta no cambió — si cambió
    // de tipo, las respuestas viejas ya no tendrían sentido con la nueva forma,
    // así que se trata como una pregunta nueva (las respuestas previas quedan huérfanas, sin romper nada).
    const existing = qId && existingQuestions.find(eq => eq.id === qId && eq.questionType === questionType);

    builtQuestions.push({
      id: existing ? existing.id : `q${i + 1}_${crypto.randomBytes(3).toString("hex")}`,
      questionType,
      title: qTitle,
      required: !!required,
      sectionId,
      options: ["multiple_choice", "checkboxes", "datetime"].includes(questionType) ? options : [],
      scaleMin: questionType === "linear_scale" ? scaleMin : null,
      scaleMax: questionType === "linear_scale" ? scaleMax : null,
      scaleMinLabel: questionType === "linear_scale" ? (scaleMinLabel || null) : null,
      scaleMaxLabel: questionType === "linear_scale" ? (scaleMaxLabel || null) : null,
      gridRows: questionType === "grid" ? gridRows : null,
      gridColumns: questionType === "grid" ? gridColumns : null
    });
  }
  return { builtQuestions };
}

// Valida y resuelve answers[] contra las preguntas reales de un poll.
// Compartido entre votar (crear) y editar una respuesta ya existente.
function resolveFormsAnswers(poll, answers) {
  if (!Array.isArray(answers)) return { error: "answers requerido" };
  const answersByQId = {};
  answers.forEach(a => { if (a && a.questionId) answersByQId[a.questionId] = a; });

  const resolvedAnswers = [];
  for (const q of poll.questions) {
    const a = answersByQId[q.id];

    if (!a) {
      if (q.required) return { error: `Falta responder: ${q.title}` };
      continue;
    }

    let selections;

    if (["text", "paragraph"].includes(q.questionType)) {
      if (!a.text) {
        if (q.required) return { error: `Falta responder: ${q.title}` };
        continue;
      }
      selections = [String(a.text).slice(0, q.questionType === "paragraph" ? 5000 : 500)];

    } else if (q.questionType === "file_upload") {
      if (!a.fileId) {
        if (q.required) return { error: `Falta responder: ${q.title}` };
        continue;
      }
      selections = [a.fileId];

    } else if (q.questionType === "linear_scale") {
      if (typeof a.scaleValue !== "number" || a.scaleValue < q.scaleMin || a.scaleValue > q.scaleMax)
        return { error: `${q.title}: scaleValue fuera de rango` };
      selections = [a.scaleValue];

    } else if (q.questionType === "grid") {
      if (!Array.isArray(a.gridSelections) || !a.gridSelections.length) {
        if (q.required) return { error: `Falta responder: ${q.title}` };
        continue;
      }
      const valid = a.gridSelections.every(s => q.gridRows.includes(s.row) && q.gridColumns.includes(s.column));
      if (!valid) return { error: `${q.title}: selección de grid inválida` };
      selections = a.gridSelections;

    } else {
      // multiple_choice, checkboxes, datetime
      if (!Array.isArray(a.selections) || !a.selections.length) {
        if (q.required) return { error: `Falta responder: ${q.title}` };
        continue;
      }
      if (q.questionType === "multiple_choice" && a.selections.length > 1)
        return { error: `${q.title}: solo permite una opción` };
      selections = a.selections.filter(i => i >= 0 && i < q.options.length);
    }

    resolvedAnswers.push({ questionId: q.id, selections });
  }
  return { resolvedAnswers };
}

app.post("/forms/polls", auth, requireScope("forms"), async (req, res) => {
  try {
    const {
      title, description, questions, sections,
      accessMode = "public", anonymous = false,
      allowMultipleVotes = false, expiresAt,
      publicResults = false, allowEditingResponses = false
    } = req.body;

    if (!title) return res.status(400).json({ error: "title requerido" });

    const database = await getDb();
    const user = req.user.role === "admin" ? null :
      await database.collection("users").findOne({ username: req.user.username });
    const hasPlus = req.user.role === "admin" || !!user?.neatPlus;

    // Secciones — solo Plus. Cada pregunta opcionalmente referencia una
    // sección por su índice en el array que mandó el cliente.
    const sectionsResult = buildFormsSections(sections, hasPlus);
    if (sectionsResult.error) return res.status(sectionsResult.error.includes("Plus") ? 403 : 400).json({ error: sectionsResult.error });
    const { builtSections } = sectionsResult;

    const questionsResult = buildFormsQuestions(questions, builtSections);
    if (questionsResult.error) return res.status(400).json({ error: questionsResult.error });
    const { builtQuestions } = questionsResult;

    let pollId = randomPollId();
    while (await database.collection("forms_polls").findOne({ pollId })) pollId = randomPollId();

    const poll = {
      pollId,
      title,
      description: description || "",
      questions: builtQuestions,
      sections: builtSections,
      accessMode: ["public", "neat_only"].includes(accessMode) ? accessMode : "public",
      anonymous: !!anonymous,
      allowMultipleVotes: !!allowMultipleVotes,
      publicResults: !!publicResults,
      allowEditingResponses: !!allowEditingResponses,
      expiresAt: expiresAt ? new Date(expiresAt) : null,
      creatorUsername: req.user.username,
      closed: false,
      createdAt: new Date()
    };

    await database.collection("forms_polls").insertOne(poll);
    res.status(201).json(poll);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// Ver poll por ID — público, sin auth (necesario para votantes sin cuenta)
app.get("/forms/polls/:id", async (req, res) => {
  try {
    const database = await getDb();
    const poll = await database.collection("forms_polls").findOne({ pollId: req.params.id });
    if (!poll) return res.status(404).json({ error: "Poll no encontrada" });

    const expired = poll.expiresAt && new Date() > new Date(poll.expiresAt);

    const isAdmin = poll.creatorUsername === process.env.ADMIN_USER;
    let verified = isAdmin;
    if (!isAdmin) {
      const author = await database.collection("users")
        .findOne({ username: poll.creatorUsername }, { projection: { verified: 1 } });
      verified = !!author?.verified;
    }

    res.json({ ...poll, expired, creatorVerified: verified });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Resultados — ahora requiere estar logueado en Neat (cualquier cuenta, no solo el creador)
// Resultados — el dueño siempre puede verlos; cualquier otra persona solo si
// el creador activó publicResults. No exige login salvo para identificarte como dueño.
app.get("/forms/polls/:id/results", async (req, res) => {
  try {
    const database = await getDb();
    const poll = await database.collection("forms_polls").findOne({ pollId: req.params.id });
    if (!poll) return res.status(404).json({ error: "Poll no encontrada" });

    let requesterUsername = null;
    const header = req.headers.authorization;
    if (header) {
      try { requesterUsername = jwt.verify(header.replace("Bearer ", ""), SECRET).username; } catch {}
    }
    const isCreator = requesterUsername === poll.creatorUsername;

    if (!isCreator && !poll.publicResults) {
      return res.status(403).json({ error: "Los resultados de esta poll son privados", private: true });
    }

    const votes = await database.collection("forms_votes")
      .find({ pollId: req.params.id }).toArray();

    const questions = poll.questions.map(q => {
      // Empareja cada voto con su respuesta a ESTA pregunta (si la respondió)
      const pairs = votes
        .map(v => ({ vote: v, answer: (v.answers || []).find(a => a.questionId === q.id) }))
        .filter(p => p.answer);

      if (["text", "paragraph", "file_upload"].includes(q.questionType)) {
        return {
          questionId: q.id, title: q.title, questionType: q.questionType,
          totalResponses: pairs.length,
          responses: isCreator
            ? pairs.map(p => ({
                value: p.answer.selections[0],
                voter: poll.anonymous ? null : (p.vote.voterUsername || p.vote.voterName)
              }))
            : null
        };
      }

      if (q.questionType === "linear_scale") {
        const counts = {};
        for (let i = q.scaleMin; i <= q.scaleMax; i++) counts[i] = 0;
        pairs.forEach(p => { if (counts[p.answer.selections[0]] !== undefined) counts[p.answer.selections[0]]++; });
        const avg = pairs.length
          ? pairs.reduce((s, p) => s + Number(p.answer.selections[0]), 0) / pairs.length
          : 0;
        return { questionId: q.id, title: q.title, questionType: q.questionType, totalVotes: pairs.length, counts, average: avg };
      }

      if (q.questionType === "grid") {
        const grid = {};
        q.gridRows.forEach(row => {
          grid[row] = {};
          q.gridColumns.forEach(col => grid[row][col] = 0);
        });
        pairs.forEach(p => {
          (p.answer.selections || []).forEach(sel => {
            if (grid[sel.row] && grid[sel.row][sel.column] !== undefined) grid[sel.row][sel.column]++;
          });
        });
        return { questionId: q.id, title: q.title, questionType: q.questionType, totalVotes: pairs.length, grid };
      }

      // multiple_choice, checkboxes, datetime
      const counts = q.options.map((opt, i) => ({
        option: opt,
        count: pairs.filter(p => p.answer.selections.includes(i)).length,
        voters: poll.anonymous ? null : pairs
          .filter(p => p.answer.selections.includes(i))
          .map(p => p.vote.voterUsername || p.vote.voterName)
      }));
      return { questionId: q.id, title: q.title, questionType: q.questionType, totalVotes: pairs.length, counts };
    });

    res.json({ totalResponses: votes.length, questions });
  } catch (err) { console.error(err); res.status(500).json({ error: "Error interno" }); }
});

// Votar — público, sin auth obligatorio salvo accessMode === "neat_only"
app.post("/forms/polls/:id/vote", async (req, res) => {
  try {
    const database = await getDb();
    const poll = await database.collection("forms_polls").findOne({ pollId: req.params.id });
    if (!poll) return res.status(404).json({ error: "Poll no encontrada" });
    if (poll.closed) return res.status(403).json({ error: "Poll cerrada" });
    if (poll.expiresAt && new Date() > new Date(poll.expiresAt))
      return res.status(403).json({ error: "Poll expirada" });

    const { answers, voterName, voterToken } = req.body;

    let voterUsername = null;
    let resolvedVoterName = null;
    let resolvedToken = voterToken;

    if (poll.accessMode === "neat_only") {
      const header = req.headers.authorization;
      if (!header) return res.status(401).json({ error: "Esta poll requiere cuenta de Neat" });
      let payload;
      try {
        payload = jwt.verify(header.replace("Bearer ", ""), SECRET);
      } catch { return res.status(401).json({ error: "Token inválido" }); }

      // Si es token OAuth, exigir scope 'forms'
      if (payload.type === "oauth" && !payload.scopes?.includes("forms"))
        return res.status(403).json({ error: "Se requiere scope 'forms'" });

      voterUsername = payload.username;

      const already = await database.collection("forms_votes")
        .findOne({ pollId: req.params.id, voterUsername });
      if (already) return res.status(409).json({ error: "Ya votaste en esta poll" });
    } else {
      if (!voterName) return res.status(400).json({ error: "voterName requerido" });
      resolvedVoterName = String(voterName).slice(0, 40);
      resolvedToken = voterToken || crypto.randomBytes(12).toString("hex");

      if (voterToken) {
        const already = await database.collection("forms_votes")
          .findOne({ pollId: req.params.id, voterToken });
        if (already) return res.status(409).json({ error: "Ya votaste en esta poll" });
      }

      // Encuesta pública, pero si el votante igual tiene sesión de Neat,
      // capturamos su username (sin exigirlo) — así, si el creador habilitó
      // 'editar respuestas', luego puede identificarse para editar la suya.
      const header = req.headers.authorization;
      if (header) {
        try {
          const payload = jwt.verify(header.replace("Bearer ", ""), SECRET);
          if (!(payload.type === "oauth" && !payload.scopes?.includes("forms"))) {
            voterUsername = payload.username;
          }
        } catch { /* token inválido o vencido: se trata como voto anónimo, sin error */ }
      }
    }

    const result = resolveFormsAnswers(poll, answers);
    if (result.error) return res.status(400).json({ error: result.error });

    await database.collection("forms_votes").insertOne({
      pollId: req.params.id,
      voterUsername,
      voterName: resolvedVoterName,
      voterToken: poll.accessMode === "public" ? resolvedToken : null,
      answers: result.resolvedAnswers,
      createdAt: new Date()
    });

    res.status(201).json({ ok: true, voterToken: poll.accessMode === "public" ? resolvedToken : undefined });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// Editar mi propia respuesta — solo si el creador activó allowEditingResponses,
// y solo identificándote con cuenta de Neat (no aplica a votos anónimos por token).
app.put("/forms/polls/:id/vote", auth, async (req, res) => {
  try {
    const database = await getDb();
    const poll = await database.collection("forms_polls").findOne({ pollId: req.params.id });
    if (!poll) return res.status(404).json({ error: "Poll no encontrada" });
    if (!poll.allowEditingResponses)
      return res.status(403).json({ error: "Esta encuesta no permite editar respuestas" });
    if (poll.closed) return res.status(403).json({ error: "Poll cerrada" });
    if (poll.expiresAt && new Date() > new Date(poll.expiresAt))
      return res.status(403).json({ error: "Poll expirada" });

    if (req.user.type === "oauth" && !req.user.scopes?.includes("forms"))
      return res.status(403).json({ error: "Se requiere scope 'forms'" });

    const existingVote = await database.collection("forms_votes")
      .findOne({ pollId: req.params.id, voterUsername: req.user.username });
    if (!existingVote)
      return res.status(404).json({ error: "No tienes una respuesta registrada en esta encuesta" });

    const result = resolveFormsAnswers(poll, req.body.answers);
    if (result.error) return res.status(400).json({ error: result.error });

    await database.collection("forms_votes").updateOne(
      { _id: existingVote._id },
      { $set: { answers: result.resolvedAnswers, editedAt: new Date() } }
    );

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// Subir archivo para pregunta tipo file_upload — público, sin auth obligatorio
app.post("/forms/polls/:id/upload", upload.single("file"), async (req, res) => {
  try {
    if (!TELEGRAM_BOT_TOKEN) return res.status(503).json({ error: "TELEGRAM_BOT_TOKEN no configurado" });
    if (!req.file) return res.status(400).json({ error: "Archivo requerido" });

    const database = await getDb();
    const poll = await database.collection("forms_polls").findOne({ pollId: req.params.id });
    if (!poll) return res.status(404).json({ error: "Poll no encontrada" });

    const { questionId } = req.query;
    const question = poll.questions.find(q => q.id === questionId);
    if (!question) return res.status(400).json({ error: "questionId inválido o faltante" });
    if (question.questionType !== "file_upload") return res.status(400).json({ error: "Esa pregunta no acepta archivos" });

    // Límite: 20MB si el CREADOR es Plus, O si quien responde es Plus. 10MB si ninguno.
    let creatorHasPlus = false;
    const creatorIsAdmin = poll.creatorUsername === process.env.ADMIN_USER;
    if (creatorIsAdmin) {
      creatorHasPlus = true;
    } else {
      const creator = await database.collection("users")
        .findOne({ username: poll.creatorUsername }, { projection: { neatPlus: 1 } });
      creatorHasPlus = !!creator?.neatPlus;
    }

    let responderHasPlus = false;
    const header = req.headers.authorization;
    if (header) {
      try {
        const payload = jwt.verify(header.replace("Bearer ", ""), SECRET);
        if (payload.type === "oauth" && !payload.scopes?.includes("forms")) {
          // Token OAuth sin scope forms — no se usa para chequear plan, se ignora
        } else if (payload.role === "admin") {
          responderHasPlus = true;
        } else {
          const u = await database.collection("users").findOne({ username: payload.username }, { projection: { neatPlus: 1 } });
          responderHasPlus = !!u?.neatPlus;
        }
      } catch {}
    }

    const hasPlus = creatorHasPlus || responderHasPlus;
    const maxSize = hasPlus ? 20 * 1024 * 1024 : 10 * 1024 * 1024;
    if (req.file.size > maxSize)
      return res.status(413).json({ error: `Archivo demasiado grande. Máximo ${hasPlus ? 20 : 10}MB` });

    const STORAGE_CHAT_ID = process.env.TELEGRAM_STORAGE_CHAT_ID;
    if (!STORAGE_CHAT_ID) return res.status(503).json({ error: "TELEGRAM_STORAGE_CHAT_ID no configurado" });

    const form = new FormData();
    form.append("chat_id", STORAGE_CHAT_ID);
    form.append("document", req.file.buffer, {
      filename: req.file.originalname,
      contentType: req.file.mimetype,
    });

    const https = require("https");
    const formBuffer = form.getBuffer();
    const formHeaders = form.getHeaders();

    const tgResponse = await new Promise((resolve, reject) => {
      const options = {
        hostname: "api.telegram.org",
        path: `/bot${TELEGRAM_BOT_TOKEN}/sendDocument`,
        method: "POST",
        headers: { ...formHeaders, "Content-Length": formBuffer.length },
      };
      const reqTg = https.request(options, (resTg) => {
        let data = "";
        resTg.on("data", chunk => data += chunk);
        resTg.on("end", () => resolve(data));
      });
      reqTg.on("error", reject);
      reqTg.write(formBuffer);
      reqTg.end();
    });

    const tgData = JSON.parse(tgResponse);
    if (!tgData.ok) return res.status(500).json({ error: "Error subiendo a Telegram" });

    res.json({
      fileId: tgData.result.document.file_id,
      fileName: req.file.originalname,
      fileSize: req.file.size
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// Mis polls — requiere scope 'forms'
app.get("/forms/polls/me/list", auth, requireScope("forms"), async (req, res) => {
  try {
    const database = await getDb();
    const polls = await database.collection("forms_polls")
      .find({ creatorUsername: req.user.username })
      .sort({ createdAt: -1 }).toArray();
    res.json(polls);
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Editar poll — solo el creador (o admin), requiere scope 'forms'.
// Acepta el mismo body que crear (title, description, questions, sections, etc.)
// y reemplaza la encuesta completa. Si una pregunta/sección manda su "id"
// original y no cambió de tipo, conserva ese id para no romper las respuestas
// ya guardadas; si es nueva o cambió de tipo, se le asigna un id nuevo.
app.put("/forms/polls/:id", auth, requireScope("forms"), async (req, res) => {
  try {
    const database = await getDb();
    const poll = await database.collection("forms_polls").findOne({ pollId: req.params.id });
    if (!poll) return res.status(404).json({ error: "Poll no encontrada" });
    if (poll.creatorUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const {
      title, description, questions, sections,
      accessMode, anonymous, allowMultipleVotes, expiresAt,
      publicResults, allowEditingResponses
    } = req.body;

    if (!title) return res.status(400).json({ error: "title requerido" });

    const user = req.user.role === "admin" ? null :
      await database.collection("users").findOne({ username: req.user.username });
    const hasPlus = req.user.role === "admin" || !!user?.neatPlus;

    const sectionsResult = buildFormsSections(sections, hasPlus, poll.sections || []);
    if (sectionsResult.error) return res.status(sectionsResult.error.includes("Plus") ? 403 : 400).json({ error: sectionsResult.error });
    const { builtSections } = sectionsResult;

    const questionsResult = buildFormsQuestions(questions, builtSections, poll.questions || []);
    if (questionsResult.error) return res.status(400).json({ error: questionsResult.error });
    const { builtQuestions } = questionsResult;

    const update = {
      title,
      description: description || "",
      questions: builtQuestions,
      sections: builtSections,
      accessMode: ["public", "neat_only"].includes(accessMode) ? accessMode : poll.accessMode,
      anonymous: anonymous !== undefined ? !!anonymous : poll.anonymous,
      allowMultipleVotes: allowMultipleVotes !== undefined ? !!allowMultipleVotes : poll.allowMultipleVotes,
      publicResults: publicResults !== undefined ? !!publicResults : poll.publicResults,
      allowEditingResponses: allowEditingResponses !== undefined ? !!allowEditingResponses : !!poll.allowEditingResponses,
      expiresAt: expiresAt !== undefined ? (expiresAt ? new Date(expiresAt) : null) : poll.expiresAt,
      editedAt: new Date()
    };

    await database.collection("forms_polls").updateOne({ pollId: req.params.id }, { $set: update });
    const updatedPoll = await database.collection("forms_polls").findOne({ pollId: req.params.id });
    res.json(updatedPoll);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// Cerrar poll — requiere scope 'forms'
app.put("/forms/polls/:id/close", auth, requireScope("forms"), async (req, res) => {
  try {
    const database = await getDb();
    const poll = await database.collection("forms_polls").findOne({ pollId: req.params.id });
    if (!poll) return res.status(404).json({ error: "Poll no encontrada" });
    if (poll.creatorUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });
    await database.collection("forms_polls").updateOne(
      { pollId: req.params.id }, { $set: { closed: true } }
    );
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// Eliminar poll — requiere scope 'forms'
app.delete("/forms/polls/:id", auth, requireScope("forms"), async (req, res) => {
  try {
    const database = await getDb();
    const poll = await database.collection("forms_polls").findOne({ pollId: req.params.id });
    if (!poll) return res.status(404).json({ error: "Poll no encontrada" });
    if (poll.creatorUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });
    await database.collection("forms_polls").deleteOne({ pollId: req.params.id });
    await database.collection("forms_votes").deleteMany({ pollId: req.params.id });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Error interno" }); }
});

// ── Watch — Upload a Catbox ───────────────────────────────────────────────────
// POST /watch/upload/catbox
// Recibe un archivo, lo sube a catbox.moe y devuelve la URL pública permanente
app.post("/watch/upload/catbox", auth, requireScope("watch"), upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Archivo requerido" });

    const MAX = 200 * 1024 * 1024; // 200MB (límite de catbox)
    if (req.file.size > MAX)
      return res.status(413).json({ error: "Archivo demasiado grande (máx 200MB en Catbox)" });

    const form = new FormData();
    form.append("reqtype", "fileupload");
    form.append("fileToUpload", req.file.buffer, {
      filename: req.file.originalname,
      contentType: req.file.mimetype,
    });

    const response = await fetch("https://catbox.moe/user/api.php", {
      method: "POST",
      body: form,
      headers: form.getHeaders(),
    });

    const text = await response.text();

    // Catbox devuelve directamente la URL o un mensaje de error en texto plano
    if (!text.startsWith("https://")) {
      return res.status(500).json({ error: "Error de Catbox: " + text });
    }

    res.json({ ok: true, url: text.trim(), provider: "catbox" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// ── Watch — Upload a Archive.org ──────────────────────────────────────────────
// POST /watch/upload/archive
// Recibe un archivo, lo sube a archive.org con las credenciales del env y devuelve la URL
// Requiere ARCHIVE_ACCESS_KEY y ARCHIVE_SECRET_KEY en las variables de entorno
app.post("/watch/upload/archive", auth, requireScope("watch"), upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Archivo requerido" });

    const ACCESS_KEY = process.env.ARCHIVE_ACCESS_KEY;
    const SECRET_KEY = process.env.ARCHIVE_SECRET_KEY;
    if (!ACCESS_KEY || !SECRET_KEY)
      return res.status(503).json({ error: "Archive.org no configurado (faltan ARCHIVE_ACCESS_KEY y ARCHIVE_SECRET_KEY)" });

    // Generar un identifier único para el item en archive.org
    const crypto = require("crypto");
    const identifier = `neat-watch-${req.user.username}-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
    const filename = req.file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");

    // Archive.org S3-like API: PUT /<identifier>/<filename>
    const https = require("https");
    const uploadUrl = `https://s3.us.archive.org/${identifier}/${filename}`;

    const uploadRes = await fetch(uploadUrl, {
      method: "PUT",
      headers: {
        "Authorization": `LOW ${ACCESS_KEY}:${SECRET_KEY}`,
        "Content-Type": req.file.mimetype,
        "Content-Length": req.file.size,
        "x-archive-auto-make-bucket": "1",
        "x-archive-meta-mediatype": req.file.mimetype.startsWith("video/") ? "movies" : "data",
        "x-archive-meta-subject": "neat-watch",
        "x-archive-meta-creator": req.user.username,
        // hidden = no aparece en búsquedas de archive.org
        "x-archive-meta-noindex": "1",
      },
      body: req.file.buffer,
    });

    if (!uploadRes.ok) {
      const errText = await uploadRes.text();
      return res.status(500).json({ error: "Error subiendo a Archive.org", detail: errText });
    }

    // La URL del archivo en archive.org es predecible
    const fileUrl = `https://archive.org/download/${identifier}/${filename}`;
    const itemUrl = `https://archive.org/details/${identifier}`;

    res.json({ ok: true, url: fileUrl, itemUrl, identifier, provider: "archive" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

app.get("/watch/stream/:fileId", async (req, res) => {
  try {
    if (!TELEGRAM_BOT_TOKEN)
      return res.status(503).json({ error: "TELEGRAM_BOT_TOKEN no configurado" });

    const response = await fetch(
      `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getFile?file_id=${req.params.fileId}`
    );
    const data = await response.json();
    if (!data.ok) return res.status(404).json({ error: "Archivo no encontrado" });

    const fileUrl = `https://api.telegram.org/file/bot${TELEGRAM_BOT_TOKEN}/${data.result.file_path}`;
    res.redirect(302, fileUrl);
  } catch (err) {
    res.status(500).json({ error: "Error interno" });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// NEAT ID APPS — Endpoints nuevos
// Agregar en index.js junto al bloque OAuth2 existente
//
// Nuevas colecciones MongoDB:
//   id_apps         → apps registradas en Neat ID Apps (distinto a oauth_clients)
//   id_app_users    → usuarios locales por tenant
//   id_app_sessions → sesiones locales (para revocación)
//
// Cada id_app tiene DOS oauth_clients generados automáticamente:
//   1. client interno (PKCE, isPublic: true) → usado por la hosted login page
//   2. client del tenant (confidential) → para que el dev intercambie el code
//
// El flujo completo:
//   id.neat.qzz.io/?app=APP_SLUG&... → hosted login page
//   → usuario entra (local o con Neat global)
//   → Neat emite code al redirect_uri del tenant
//   → tenant intercambia code → access_token
//   → tenant llama /id/userinfo/:appSlug → datos del usuario local
// ══════════════════════════════════════════════════════════════════════════════

// ── Helpers ───────────────────────────────────────────────────────────────────

function generateClientId() {
  return "nid_" + crypto.randomBytes(12).toString("hex");
}

function generateClientSecret() {
  return crypto.randomBytes(32).toString("hex");
}

function generateAppSlug(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 30);
}

// Slugs que no pueden usarse como nombre de Tenant — colisionan con rutas
// reales que el frontend (Cloudflare Pages) ya sirve en ese mismo dominio
// (ej. /admin → admin.html), antes de que el fallback de SPA cargue
// login.html. Si agregas más páginas estáticas al mismo dominio, añádelas aquí.
const RESERVED_APP_SLUGS = new Set(["admin", "login", "id", "tenants", "api", "neat-callback", "favicon.ico", "robots.txt", ""]);

// App Key — credencial PÚBLICA de la app (distinta de client_id/client_secret).
// Va embebida en el JS de una app sin backend; identifica de qué Tenant es la
// petición, pero NUNCA es suficiente por sí sola para escribir el storage de
// un usuario — siempre se combina con el access_token del usuario en cuestión
// (igual que la "anon key" de Supabase + sus políticas RLS).
function generateAppKey() {
  return "nak_" + crypto.randomBytes(16).toString("hex");
}

// Crea un client OAuth interno de una app (id_app_clients) — esto es lo que
// permite que App X tenga varios clients propios (web, móvil, admin panel...)
// todos autenticando contra el mismo pool de usuarios de App X (id_app_users).
// isPublic=true → PKCE, sin secret. isPublic=false → confidential, con secret.
async function createIdAppClient(database, { appSlug, name, redirectUris, isPublic, isDefault }) {
  const client = {
    appSlug,
    clientId: generateClientId(),
    clientSecret: isPublic ? null : generateClientSecret(),
    name: name || (isDefault ? "Default" : "Client"),
    redirectUris,
    isPublic: !!isPublic,
    isDefault: !!isDefault,
    suspended: false,
    createdAt: new Date()
  };
  await database.collection("id_app_clients").insertOne(client);
  return client;
}

// Middleware: verifica que el request viene de un client registrado de la app
// (cualquiera de los clients en id_app_clients — web, móvil, admin panel, etc),
// usando client_id + client_secret. Solo clients confidential pueden usar esto
// (un client PKCE público no tiene secret, no calificaría para gestión admin).
// tenantAuth acepta DOS formas de autenticarse, según quién llama:
//  1. x-client-id + x-client-secret → un backend EXTERNO (el del dev) hablando
//     con la API. Esta es la forma "real" de OAuth, sin sesión de usuario.
//  2. Authorization: Bearer <jwt de sesión Neat> → el PROPIO panel admin,
//     usando la sesión normal del dueño de la app. No necesita credenciales
//     de client separadas porque ya probó quién es con su sesión Neat.
// Ambos casos dejan req.idApp poblado; el caso #2 no deja req.idAppClient
// (no aplica — no hay un client específico involucrado, es el dueño mismo).
async function tenantAuth(req, res, next) {
  const clientId = req.headers["x-client-id"] || req.body?.client_id;
  const clientSecret = req.headers["x-client-secret"] || req.body?.client_secret;

  try {
    const database = await getDb();

    if (clientId && clientSecret) {
      // Camino 1: credenciales de client (backend externo)
      const client = await database.collection("id_app_clients").findOne({
        clientId, clientSecret, isPublic: false
      });
      if (!client) return res.status(401).json({ error: "Credenciales inválidas" });
      if (client.suspended) return res.status(403).json({ error: "Client suspendido" });

      const app = await database.collection("id_apps").findOne({ slug: client.appSlug });
      if (!app) return res.status(401).json({ error: "App no encontrada" });
      if (app.suspended) return res.status(403).json({ error: "App suspendida" });

      req.idApp = app;
      req.idAppClient = client;
      return next();
    }

    // Camino 2: sesión Neat del dueño (panel admin)
    const header = req.headers.authorization;
    if (!header) {
      return res.status(401).json({ error: "Credenciales de tenant requeridas (x-client-id/x-client-secret, o sesión del dueño)" });
    }
    let sessionUser;
    try {
      sessionUser = jwt.verify(header.replace("Bearer ", ""), SECRET);
    } catch {
      return res.status(401).json({ error: "Sesión inválida" });
    }

    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.ownerUsername !== sessionUser.username && sessionUser.role !== "admin") {
      return res.status(403).json({ error: "No eres el dueño de esta app" });
    }
    if (app.suspended) return res.status(403).json({ error: "App suspendida" });

    req.idApp = app;
    req.idAppClient = null; // no aplica: es el dueño, no un client específico
    next();
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
}

// ── 1. REGISTRO DE APPS ───────────────────────────────────────────────────────
// POST /id/apps
// Cualquier usuario Neat registra su app en Neat ID Apps.
// Genera automáticamente:
//   - slug único
//   - client interno (PKCE público) → para la hosted login page
//   - client del tenant (confidential) → para el backend del dev
// El "Login con Neat" en la hosted page usa el client interno.
app.post("/id/apps", auth, requireAuth, async (req, res) => {
  try {
    const { name, description, redirectUris, logoUrl, primaryColor, homepageUrl } = req.body;

    if (!name || !redirectUris?.length)
      return res.status(400).json({ error: "name y redirectUris requeridos" });

    if (!/^[a-zA-Z0-9 _\-]{2,50}$/.test(name))
      return res.status(400).json({ error: "Nombre inválido (2-50 chars, letras/números/espacios)" });

    const database = await getDb();

    // Límite: 1 app gratis, ilimitado con Neat Plus
    const user = await database.collection("users").findOne({ username: req.user.username });
    const isAdmin = req.user.role === "admin";
    if (!isAdmin) {
      const myApps = await database.collection("id_apps").countDocuments({ ownerUsername: req.user.username });
      if (!user?.neatPlus && myApps >= 1)
        return res.status(403).json({ error: "Límite de 1 app gratis alcanzado. Necesitas Neat Plus para más apps." });
    }

    // Slug único — y nunca uno reservado (colisionaría con rutas reales
    // del frontend, ej. /admin)
    let slug = generateAppSlug(name);
    if (RESERVED_APP_SLUGS.has(slug)) slug = slug + "-" + crypto.randomBytes(3).toString("hex");
    const slugExists = await database.collection("id_apps").findOne({ slug });
    if (slugExists) slug = slug + "-" + crypto.randomBytes(3).toString("hex");

    // Client interno — PKCE, público, usado por id.neat.qzz.io/ (raíz)
    // redirect_uri interna fija: el propio servidor de Neat redirige el code al tenant
    const internalClient = {
      name,  // se muestra en la pantalla de aprobación de neat.qzz.io/oauth.html
      clientId: generateClientId(),
      clientSecret: null,  // PKCE público, no tiene secret
      redirectUris: [
        `https://neat-apps-b.vercel.app/id/callback`,        // login normal ("Continuar con Neat")
        `https://id.neat.qzz.io/${slug}/neat-callback`       // vincular Neat desde sesión local activa
      ],
      scopes: ["openid", "profile", "email"],
      isPublic: true,
      ownerUsername: req.user.username,
      internal: true,
      forAppSlug: slug,
      createdAt: new Date()
    };
    await database.collection("oauth_clients").insertOne(internalClient);

    const app = {
      slug,
      name,
      description: description || "",
      homepageUrl: homepageUrl || null,
      ownerUsername: isAdmin ? null : req.user.username,
      redirectUris,                     // redirect_uris del dev (su app) — usadas como default
      branding: {
        logoUrl: logoUrl || null,
        primaryColor: primaryColor || "#6366f1",
      },
      internalClientId: internalClient.clientId,  // ref al oauth_client interno
      appKey: generateAppKey(),  // credencial pública — KV storage desde apps sin backend
      suspended: false,
      requireEmailVerification: false,  // Neat Plus: obliga a los usuarios a verificar su email
      createdAt: new Date()
    };

    await database.collection("id_apps").insertOne(app);

    // Client por defecto de la app — vive en id_app_clients (no más tenantClient fijo).
    // Es confidential (con secret) para mantener compatibilidad con lo que ya
    // tenías documentado como "tenantClient". El dev puede crear más clients
    // después vía POST /id/apps/:slug/clients (ej. uno público con PKCE para móvil).
    const defaultClient = await createIdAppClient(database, {
      appSlug: slug,
      name: "Default",
      redirectUris,
      isPublic: false,
      isDefault: true
    });

    res.status(201).json({
      slug,
      name,
      description: app.description,
      branding: app.branding,
      redirectUris,
      defaultClient: {
        clientId: defaultClient.clientId,
        clientSecret: defaultClient.clientSecret,  // solo se devuelve una vez aquí
        isPublic: false
      },
      internalClientId: internalClient.clientId,
      appKey: app.appKey,  // pública — se puede ver de nuevo cuando quieras (a diferencia del secret)
      loginUrl: `https://id.neat.qzz.io/?app=${slug}`,
      createdAt: app.createdAt
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 2. LISTAR MIS APPS ────────────────────────────────────────────────────────
// GET /id/apps/me
app.get("/id/apps/me", auth, requireAuth, async (req, res) => {
  try {
    const database = await getDb();
    const filter = req.user.role === "admin" ? {} : { ownerUsername: req.user.username };
    const apps = await database.collection("id_apps")
      .find(filter)
      .sort({ createdAt: -1 }).toArray();
    res.json(apps);
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 3. INFO PÚBLICA DE UNA APP (para la hosted login page) ───────────────────
// GET /id/apps/:slug/public
// Sin auth — la hosted login page carga esto para saber nombre, logo, colores.
// internalClientId SÍ se expone (a diferencia de antes): es el client_id PKCE
// público que la hosted page necesita para armar el botón "Continuar con Neat".
// No es sensible — es público por diseño (igual que cualquier OAuth client_id).
app.get("/id/apps/:slug/public", async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.suspended) return res.status(403).json({ error: "App suspendida" });

    // Si la URL de login trae ?client_id=, exponemos el nombre de ESE client
    // específico (ej. "InnerNet Web", "InnerNet Móvil") para que la hosted
    // page pueda mostrar "Usa tu cuenta de {Tenant} para continuar en {Client}"
    // en vez de solo el nombre genérico del Tenant.
    let clientName = null;
    const { client_id } = req.query;
    if (client_id) {
      const client = await database.collection("id_app_clients").findOne({
        appSlug: req.params.slug, clientId: client_id
      });
      if (client && !client.suspended) clientName = client.name;
    }

    res.json({
      slug: app.slug,
      name: app.name,
      description: app.description,
      homepageUrl: app.homepageUrl,
      branding: app.branding,
      internalClientId: app.internalClientId,
      appKey: app.appKey,
      requireEmailVerification: !!app.requireEmailVerification,
      registrationsOpen: app.registrationsOpen !== false,
      kvLimitBytes: kvPrivateLimitForApp(app),
      kvPublicLimitBytes: kvPublicLimitForApp(app),
      clientName
    });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 4. ACTUALIZAR APP ─────────────────────────────────────────────────────────
// PUT /id/apps/:slug
app.put("/id/apps/:slug", auth, requireAuth, async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.ownerUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const { name, description, redirectUris, logoUrl, primaryColor, homepageUrl } = req.body;
    const update = {};
    if (name) update.name = name;
    if (description !== undefined) update.description = description;
    if (homepageUrl !== undefined) update.homepageUrl = homepageUrl;
    if (redirectUris?.length) {
      update.redirectUris = redirectUris;
      // Nota: esto solo actualiza el redirectUris "default" a nivel app.
      // Cada client en id_app_clients tiene sus propias redirectUris y se
      // gestionan por separado vía PUT /id/apps/:slug/clients/:clientId.
    }
    if (logoUrl !== undefined) update["branding.logoUrl"] = logoUrl;
    if (primaryColor !== undefined) update["branding.primaryColor"] = primaryColor;

    await database.collection("id_apps").updateOne({ slug: req.params.slug }, { $set: update });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── VERIFICACIÓN DE EMAIL ────────────────────────────────────────────────────
// GET /id/users/:slug/verify-email?token=...
// El usuario hace clic en el enlace del correo → marca emailVerified: true
app.get("/id/users/:slug/verify-email", async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).send("Token requerido");

    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).send("App no encontrada");

    const user = await database.collection("id_app_users").findOne({
      appSlug: req.params.slug,
      emailVerifToken: token
    });
    if (!user) return res.status(400).send("Token inválido o ya usado");
    if (new Date() > new Date(user.emailVerifExpiresAt))
      return res.status(400).send("El enlace de verificación expiró. Inicia sesión para solicitar uno nuevo.");

    await database.collection("id_app_users").updateOne(
      { _id: user._id },
      { $set: { emailVerified: true, emailVerifToken: null, emailVerifExpiresAt: null } }
    );

    // Redirigir a la página de login de la app con mensaje de éxito
    res.redirect(`https://id.neat.qzz.io/${req.params.slug}?verified=1`);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error interno");
  }
});

// POST /id/users/:slug/resend-verification
// El usuario pide un nuevo correo de verificación (token expirado o perdido)
app.post("/id/users/:slug/resend-verification", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "email requerido" });

    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app || app.suspended) return res.status(404).json({ error: "App no encontrada" });
    if (!app.requireEmailVerification) return res.status(400).json({ error: "Esta app no requiere verificación" });

    const user = await database.collection("id_app_users").findOne({
      appSlug: req.params.slug,
      email: email.toLowerCase()
    });
    // Respuesta genérica para no revelar si el email existe
    if (!user || user.emailVerified || user.email.endsWith("@neat.qzz.io"))
      return res.json({ ok: true });

    const newToken = crypto.randomBytes(32).toString("hex");
    const newExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await database.collection("id_app_users").updateOne(
      { _id: user._id },
      { $set: { emailVerifToken: newToken, emailVerifExpiresAt: newExpiry } }
    );

    const verifyUrl = `${NEAT_ID_BASE}/id/users/${req.params.slug}/verify-email?token=${newToken}`;
    await sendEmail({
      to: user.email,
      subject: `Verifica tu correo en ${app.name}`,
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto">
          <h2 style="color:#1f1f1f">Nuevo enlace de verificación</h2>
          <p>Hola <strong>${user.username}</strong>, aquí tienes un nuevo enlace para verificar tu correo en <strong>${app.name}</strong>:</p>
          <a href="${verifyUrl}" style="display:inline-block;margin:16px 0;padding:12px 24px;background:#0b57d0;color:#fff;border-radius:8px;text-decoration:none;font-weight:600">Verificar correo</a>
          <p style="color:#666;font-size:13px">Este enlace expira en 24 horas.</p>
        </div>
      `
    });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// PUT /id/apps/:slug/require-email-verification
// Activar/desactivar verificación de email obligatoria (requiere Neat Plus del dueño)
app.put("/id/apps/:slug/require-email-verification", auth, requireAuth, async (req, res) => {
  try {
    const { enabled } = req.body;
    if (typeof enabled !== "boolean") return res.status(400).json({ error: "enabled (boolean) requerido" });

    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.ownerUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    // Verificar Neat Plus del dueño (el admin siempre puede)
    if (req.user.role !== "admin" && enabled) {
      const owner = await database.collection("users").findOne({ username: req.user.username });
      const plusExpired = owner?.neatPlusExpiresAt && new Date() > new Date(owner.neatPlusExpiresAt);
      const hasPlus = !plusExpired && !!owner?.neatPlus;
      if (!hasPlus) return res.status(403).json({ error: "Necesitas Neat Plus para activar la verificación de email obligatoria" });
    }

    if (!enabled && !process.env.GMAIL_USER)
      return res.status(400).json({ error: "No hay servidor de correo configurado. Configura GMAIL_USER y GMAIL_PASS primero." });

    await database.collection("id_apps").updateOne(
      { slug: req.params.slug },
      { $set: { requireEmailVerification: enabled } }
    );
    res.json({ ok: true, requireEmailVerification: enabled });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// App X puede tener varios clients propios — web, móvil, admin panel, etc —
// cada uno con su client_id/client_secret (o PKCE público) independiente.
// TODOS autentican contra el mismo pool de usuarios de la app (id_app_users).
// Gestión por sesión Neat del dueño de la app (igual que el resto del panel).
// ══════════════════════════════════════════════════════════════════════════════

// ── 5a. CREAR CLIENT ──────────────────────────────────────────────────────────
// POST /id/apps/:slug/clients
// body: { name, redirectUris, isPublic }
app.post("/id/apps/:slug/clients", auth, requireAuth, async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.ownerUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const { name, redirectUris, isPublic } = req.body;
    if (!redirectUris?.length)
      return res.status(400).json({ error: "redirectUris requerido" });

    const client = await createIdAppClient(database, {
      appSlug: req.params.slug,
      name: name || "Client",
      redirectUris,
      isPublic: !!isPublic,
      isDefault: false
    });

    res.status(201).json({
      clientId: client.clientId,
      clientSecret: client.clientSecret,  // solo se devuelve una vez aquí (null si isPublic)
      name: client.name,
      redirectUris: client.redirectUris,
      isPublic: client.isPublic,
      createdAt: client.createdAt
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 5b. LISTAR CLIENTS ────────────────────────────────────────────────────────
// GET /id/apps/:slug/clients
app.get("/id/apps/:slug/clients", auth, requireAuth, async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.ownerUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const clients = await database.collection("id_app_clients")
      .find({ appSlug: req.params.slug }, { projection: { clientSecret: 0 } })
      .sort({ createdAt: 1 }).toArray();
    res.json(clients);
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 5c. ACTUALIZAR CLIENT ─────────────────────────────────────────────────────
// PUT /id/apps/:slug/clients/:clientId
app.put("/id/apps/:slug/clients/:clientId", auth, requireAuth, async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.ownerUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const client = await database.collection("id_app_clients")
      .findOne({ appSlug: req.params.slug, clientId: req.params.clientId });
    if (!client) return res.status(404).json({ error: "Client no encontrado" });

    const { name, redirectUris, suspended } = req.body;
    const update = {};
    if (name) update.name = name;
    if (redirectUris?.length) update.redirectUris = redirectUris;
    if (suspended !== undefined) update.suspended = !!suspended;

    await database.collection("id_app_clients").updateOne(
      { _id: client._id }, { $set: update }
    );
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 5d. ROTAR SECRET DE UN CLIENT ─────────────────────────────────────────────
// POST /id/apps/:slug/clients/:clientId/rotate-secret
// Solo aplica a clients confidential (isPublic: false). Un client PKCE no tiene secret.
app.post("/id/apps/:slug/clients/:clientId/rotate-secret", auth, requireAuth, async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.ownerUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const client = await database.collection("id_app_clients")
      .findOne({ appSlug: req.params.slug, clientId: req.params.clientId });
    if (!client) return res.status(404).json({ error: "Client no encontrado" });
    if (client.isPublic)
      return res.status(400).json({ error: "Este client usa PKCE, no tiene client_secret que rotar" });

    const newSecret = generateClientSecret();
    await database.collection("id_app_clients").updateOne(
      { _id: client._id }, { $set: { clientSecret: newSecret } }
    );

    res.json({ clientId: client.clientId, clientSecret: newSecret });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 5e. ELIMINAR CLIENT ───────────────────────────────────────────────────────
// DELETE /id/apps/:slug/clients/:clientId
// No se puede eliminar el último client de la app (siempre debe quedar al menos uno).
app.delete("/id/apps/:slug/clients/:clientId", auth, requireAuth, async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.ownerUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const totalClients = await database.collection("id_app_clients")
      .countDocuments({ appSlug: req.params.slug });
    if (totalClients <= 1)
      return res.status(400).json({ error: "No puedes eliminar el único client de la app" });

    const result = await database.collection("id_app_clients")
      .deleteOne({ appSlug: req.params.slug, clientId: req.params.clientId });
    if (result.deletedCount === 0) return res.status(404).json({ error: "Client no encontrado" });

    // Las sesiones emitidas por ese client quedan revocadas
    await database.collection("id_app_sessions").deleteMany({ clientId: req.params.clientId });

    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 6. ELIMINAR APP ───────────────────────────────────────────────────────────
// DELETE /id/apps/:slug
app.delete("/id/apps/:slug", auth, requireAuth, async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.ownerUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    // Eliminar todo lo relacionado
    await database.collection("id_apps").deleteOne({ slug: req.params.slug });
    await database.collection("oauth_clients").deleteOne({ clientId: app.internalClientId });
    await database.collection("id_app_clients").deleteMany({ appSlug: req.params.slug });
    await database.collection("id_app_users").deleteMany({ appSlug: req.params.slug });
    await database.collection("id_app_sessions").deleteMany({ appSlug: req.params.slug });

    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// USUARIOS LOCALES POR TENANT
// ══════════════════════════════════════════════════════════════════════════════

// ── 7. REGISTRO LOCAL ─────────────────────────────────────────────────────────
// POST /id/users/:slug/register
// La hosted login page llama esto cuando el usuario se registra en la app tenant.
// Solo accesible con el internalClientId (PKCE interno) — no público directo.
// El dev NO llama esto, es uso interno de la hosted page.
app.post("/id/users/:slug/register", async (req, res) => {
  try {
    const { email, password, username, internalToken, inviteToken } = req.body;

    // Verificar internalToken — JWT firmado por Neat con claim { internal: true, appSlug }
    // La hosted login page recibe este token al cargar la página
    let tokenPayload;
    try {
      tokenPayload = jwt.verify(internalToken, SECRET);
    } catch {
      return res.status(401).json({ error: "Token interno inválido" });
    }
    if (!tokenPayload.internal || tokenPayload.appSlug !== req.params.slug)
      return res.status(401).json({ error: "Token interno inválido para esta app" });

    if (!email || !password)
      return res.status(400).json({ error: "email y password requeridos" });
    if (password.length < 6)
      return res.status(400).json({ error: "Password mínimo 6 caracteres" });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: "Email inválido" });

    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app || app.suspended) return res.status(404).json({ error: "App no encontrada" });

    // Verificar si los registros están abiertos o si hay un inviteToken válido
    const registrationsOpen = app.registrationsOpen !== false; // default true
    let invitation = null;
    if (!registrationsOpen) {
      if (!inviteToken) return res.status(403).json({ error: "Los registros están cerrados. Necesitas una invitación." });
      invitation = await database.collection("id_app_invitations").findOne({
        appSlug: req.params.slug, token: inviteToken
      });
      if (!invitation) return res.status(404).json({ error: "Invitación no encontrada" });
      if (invitation.revoked) return res.status(410).json({ error: "Invitación revocada" });
      if (new Date() > invitation.expiresAt) return res.status(410).json({ error: "Invitación expirada" });
      if (invitation.maxUses !== null && invitation.uses >= invitation.maxUses)
        return res.status(410).json({ error: "Invitación agotada" });
    }

    // Email único por tenant
    const exists = await database.collection("id_app_users").findOne({
      appSlug: req.params.slug,
      email: email.toLowerCase()
    });
    if (exists) return res.status(409).json({ error: "Email ya registrado en esta app" });

    const passwordHash = await bcrypt.hash(password, 10);

    // Determinar estado de verificación inicial según tipo de email
    // - @neat.qzz.io → se verifica al hacer login con Neat, no por correo
    // - otro dominio → si el tenant requiere verificación, emitir token y mandar correo
    const isNeatEmail = email.toLowerCase().endsWith("@neat.qzz.io");
    let emailVerified = isNeatEmail ? false : true; // emails externos se marcan verificados por defecto salvo que el tenant exija verificación
    let emailVerifToken = null;
    let emailVerifExpiresAt = null;

    if (!isNeatEmail && app.requireEmailVerification) {
      emailVerified = false;
      emailVerifToken = crypto.randomBytes(32).toString("hex");
      emailVerifExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h
    }

    const result = await database.collection("id_app_users").insertOne({
      appSlug: req.params.slug,
      email: email.toLowerCase(),
      username: username || email.split("@")[0],
      passwordHash,
      neatUserId: null,
      emailVerified,
      emailVerifToken,
      emailVerifExpiresAt,
      suspended: false,
      createdAt: new Date()
    });

    // Mandar correo de verificación si aplica
    if (!isNeatEmail && app.requireEmailVerification) {
      const verifyUrl = `${NEAT_ID_BASE}/id/users/${req.params.slug}/verify-email?token=${emailVerifToken}`;
      await sendEmail({
        to: email.toLowerCase(),
        subject: `Verifica tu correo en ${app.name}`,
        html: `
          <div style="font-family:sans-serif;max-width:480px;margin:0 auto">
            <h2 style="color:#1f1f1f">Verifica tu correo</h2>
            <p>Hola <strong>${username || email.split("@")[0]}</strong>, gracias por registrarte en <strong>${app.name}</strong>.</p>
            <p>Para poder iniciar sesión, confirma tu correo haciendo clic en el botón:</p>
            <a href="${verifyUrl}" style="display:inline-block;margin:16px 0;padding:12px 24px;background:#0b57d0;color:#fff;border-radius:8px;text-decoration:none;font-weight:600">Verificar correo</a>
            <p style="color:#666;font-size:13px">Este enlace expira en 24 horas. Si no te registraste en ${app.name}, ignora este mensaje.</p>
          </div>
        `
      });
    }

    // Quemar uso de la invitación si aplica
    if (invitation) {
      await database.collection("id_app_invitations").updateOne(
        { _id: invitation._id },
        { $inc: { uses: 1 } }
      );
    }

    res.status(201).json({
      ok: true,
      userId: result.insertedId,
      emailVerified,
      requiresVerification: !emailVerified,
      verificationMethod: isNeatEmail ? "neat" : "email"
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 8. LOGIN LOCAL ────────────────────────────────────────────────────────────
// POST /id/users/:slug/login
// La hosted login page llama esto para autenticar al usuario local.
// Devuelve un code OAuth2 listo para que Neat lo redirija al tenant.
// Genera el code OAuth2 local (id_app_local) + pageSessionToken para un usuario
// ya autenticado. Se usa tanto en login directo (sin 2FA) como después de
// verificar el código TOTP (login con 2FA).
async function issueLocalOAuthCode(database, { user, appSlug, client, redirectUri, codeChallenge, codeChallengeMethod, state, type = "id_app_local" }) {
  const finalRedirectUri = redirectUri || client.redirectUris[0];
  if (!client.redirectUris.includes(finalRedirectUri)) {
    return { error: "redirect_uri no autorizada para este client" };
  }

  const code = crypto.randomBytes(32).toString("hex");
  await database.collection("oauth_codes").insertOne({
    code,
    clientId: client.clientId,
    username: null,
    idAppUserId: user._id.toString(),
    appSlug,
    redirectUri: finalRedirectUri,
    scopes: ["openid", "profile", "email"],
    codeChallenge: codeChallenge || null,
    codeChallengeMethod: codeChallengeMethod || "S256",
    expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    used: false,
    type
  });

  const pageSessionToken = jwt.sign(
    { type: "id_app_page_session", appSlug, idAppUserId: user._id.toString() },
    SECRET,
    { expiresIn: "10m" }
  );

  return { code, redirectUri: finalRedirectUri, state: state || null, pageSessionToken };
}

app.post("/id/users/:slug/login", async (req, res) => {
  try {
    const { email, password, internalToken, redirectUri, codeChallenge, codeChallengeMethod, state, clientId } = req.body;

    let tokenPayload;
    try {
      tokenPayload = jwt.verify(internalToken, SECRET);
    } catch {
      return res.status(401).json({ error: "Token interno inválido" });
    }
    if (!tokenPayload.internal || tokenPayload.appSlug !== req.params.slug)
      return res.status(401).json({ error: "Token interno inválido para esta app" });

    if (!email || !password)
      return res.status(400).json({ error: "email y password requeridos" });

    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app || app.suspended) return res.status(403).json({ error: "App suspendida o no encontrada" });

    // Resolver qué client de la app está pidiendo el login. Si no se especifica
    // clientId (apps viejas / integraciones simples), usamos el client default
    // de la app por compatibilidad.
    const client = clientId
      ? await database.collection("id_app_clients").findOne({ appSlug: req.params.slug, clientId })
      : await database.collection("id_app_clients").findOne({ appSlug: req.params.slug, isDefault: true });
    if (!client) return res.status(400).json({ error: "client_id inválido para esta app" });
    if (client.suspended) return res.status(403).json({ error: "Client suspendido" });

    const user = await database.collection("id_app_users").findOne({
      appSlug: req.params.slug,
      email: email.toLowerCase()
    });
    if (!user) return res.status(401).json({ error: "Credenciales inválidas" });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: "Credenciales inválidas" });
    if (user.suspended) return res.status(403).json({ error: "Cuenta suspendida en esta app" });

    // Bloquear si el tenant requiere verificación y el usuario aún no verificó
    if (app.requireEmailVerification && !user.emailVerified) {
      const isNeatEmail = user.email.endsWith("@neat.qzz.io");
      return res.status(403).json({
        error: "Email no verificado",
        requiresVerification: true,
        verificationMethod: isNeatEmail ? "neat" : "email",
        email: user.email
      });
    }

    // Si el usuario tiene 2FA activado, no emitimos el code todavía — devolvemos
    // un totp_pending_token con todos los datos OAuth guardados adentro, para
    // poder terminar el login después de verificar el código TOTP.
    if (user.totpEnabled) {
      const pendingToken = jwt.sign(
        {
          type: "totp_pending",
          appSlug: req.params.slug,
          sub: user._id.toString(),
          tokenType: "oauth_code",
          oauth: {
            clientId: client.clientId,
            redirectUri: redirectUri || null,
            codeChallenge: codeChallenge || null,
            codeChallengeMethod: codeChallengeMethod || "S256",
            state: state || null
          }
        },
        SECRET,
        { expiresIn: "5m" }
      );
      return res.json({ totp_required: true, totp_pending_token: pendingToken });
    }

    const result = await issueLocalOAuthCode(database, {
      user, appSlug: req.params.slug, client, redirectUri, codeChallenge, codeChallengeMethod, state
    });
    if (result.error) return res.status(400).json({ error: result.error });
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 9. TOKEN INTERNO DE PÁGINA ────────────────────────────────────────────────
// GET /id/apps/:slug/page-token
// La hosted login page (id.neat.qzz.io/?app=SLUG) llama esto al cargar
// para obtener el internalToken que autoriza registro y login local.
// Tiene TTL corto (15 min) y es de un solo uso por sesión de página.
app.get("/id/apps/:slug/page-token", async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app || app.suspended) return res.status(404).json({ error: "App no encontrada" });

    const token = jwt.sign(
      { internal: true, appSlug: req.params.slug },
      SECRET,
      { expiresIn: "15m" }
    );
    res.json({ token });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 10. CALLBACK INTERNO ──────────────────────────────────────────────────────
// GET /id/callback
// La hosted login page usa el client interno (PKCE) para el flujo "Login con Neat".
// Neat redirige aquí después de que el usuario Neat global aprueba.
// Neat convierte el code Neat → crea/actualiza id_app_user vinculado → emite code del tenant.
// El frontend de id.neat.qzz.io hace este intercambio internamente y redirige al tenant.
app.get("/id/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send("Parámetros faltantes");

    // state codifica: appSlug + clientId del tenant + redirectUri + codeChallenge
    let stateData;
    try {
      stateData = JSON.parse(Buffer.from(state, "base64url").toString());
    } catch {
      return res.status(400).send("State inválido");
    }
    const { appSlug, clientId: tenantClientId, redirectUri, codeChallenge, codeChallengeMethod, tenantState } = stateData;

    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: appSlug });
    if (!app) return res.status(404).send("App no encontrada");

    // Resolver el client del tenant que originó este login (default si no se especificó)
    const client = tenantClientId
      ? await database.collection("id_app_clients").findOne({ appSlug, clientId: tenantClientId })
      : await database.collection("id_app_clients").findOne({ appSlug, isDefault: true });
    if (!client) return res.status(400).send("client_id inválido para esta app");
    if (client.suspended) return res.status(403).send("Client suspendido");
    if (!client.redirectUris.includes(redirectUri))
      return res.status(400).send("redirect_uri no autorizada para este client");

    // Intercambiar el code Neat (interno, PKCE) → access_token Neat
    // code_verifier está en stateData (la hosted page lo generó y pasó en state)
    const tokenRes = await fetch("https://neat-apps-b.vercel.app/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code,
        client_id: app.internalClientId,
        redirect_uri: "https://neat-apps-b.vercel.app/id/callback",
        code_verifier: stateData.codeVerifier,
        grant_type: "authorization_code"
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return res.status(400).send("Error obteniendo token Neat");

    // Obtener datos del usuario Neat
    const userRes = await fetch("https://neat-apps-b.vercel.app/oauth/userinfo", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const neatUser = await userRes.json();
    if (!neatUser.sub) return res.status(400).send("Error obteniendo perfil Neat");

    // Crear o actualizar id_app_user vinculado a la cuenta Neat
    const existingUser = await database.collection("id_app_users").findOne({
      appSlug,
      neatUserId: neatUser.sub
    });

    // También buscar usuario local que tenga email @neat.qzz.io coincidente con este neatUsername
    // (se registró con ese email antes de vincular su cuenta Neat)
    const neatEmailMatch = await database.collection("id_app_users").findOne({
      appSlug,
      email: `${neatUser.username}@neat.qzz.io`,
      neatUserId: null  // no vinculado aún
    });

    let appUserId;
    if (existingUser) {
      if (existingUser.suspended)
        return res.redirect(`${redirectUri}?error=access_denied&error_description=${encodeURIComponent("Tu cuenta de esta app está suspendida, contacta el administrador de esta app para más información.")}`);
      appUserId = existingUser._id.toString();
      // El perfil LOCAL manda siempre que el usuario tenga password local —
      // nunca pisamos su username/email con los de Neat global, o lo dejamos
      // sin poder loguearse con su contraseña (el login local busca por email
      // exacto). Solo sincronizamos username/email desde Neat para usuarios
      // 100% Neat (sin password local, passwordHash null) — esos no tienen
      // una identidad local que proteger.
      const syncFields = existingUser.passwordHash
        ? { lastNeatSync: new Date() }
        : { email: neatUser.email || existingUser.email, username: neatUser.username, lastNeatSync: new Date() };
      // Si este usuario tenía email @neat.qzz.io sin verificar, lo marcamos verificado ahora
      if (!existingUser.emailVerified && existingUser.email.endsWith("@neat.qzz.io")) {
        syncFields.emailVerified = true;
        syncFields.emailVerifToken = null;
        syncFields.emailVerifExpiresAt = null;
      }
      await database.collection("id_app_users").updateOne(
        { _id: existingUser._id },
        { $set: syncFields }
      );
    } else if (neatEmailMatch) {
      // Usuario que se registró con su @neat.qzz.io antes de vincular Neat:
      // vinculamos su cuenta y la marcamos verificada
      if (neatEmailMatch.suspended)
        return res.redirect(`${redirectUri}?error=access_denied&error_description=${encodeURIComponent("Tu cuenta de esta app está suspendida.")}`);
      appUserId = neatEmailMatch._id.toString();
      await database.collection("id_app_users").updateOne(
        { _id: neatEmailMatch._id },
        { $set: {
          neatUserId: neatUser.sub,
          emailVerified: true,
          emailVerifToken: null,
          emailVerifExpiresAt: null,
          lastNeatSync: new Date()
        }}
      );
    } else {
      // Primer login con Neat en esta app → crear usuario nuevo, salvo que
      // el tenant tenga los registros cerrados. El flujo de invitaciones es
      // exclusivo del registro local (email/password); "Continuar con Neat"
      // no tiene forma de llevar un inviteToken, así que aquí no hay excepción.
      if (app.registrationsOpen === false) {
        return res.redirect(`${redirectUri}?error=access_denied&error_description=${encodeURIComponent("Los registros están cerrados para esta aplicación. Necesitas que un administrador te invite o cree tu cuenta.")}`);
      }
      const result = await database.collection("id_app_users").insertOne({
        appSlug,
        email: neatUser.email || `${neatUser.username}@neat.qzz.io`,
        username: neatUser.username,
        passwordHash: null,       // no tiene password local, entra solo con Neat
        neatUserId: neatUser.sub, // vinculado
        emailVerified: true,      // entrar con Neat es prueba suficiente de identidad
        verified: !!neatUser.verified,
        suspended: false,
        createdAt: new Date()
      });
      appUserId = result.insertedId.toString();
    }

    // Si el tenant requiere verificación, verificar que el usuario ya está verificado
    // (puede ocurrir si existingUser aún no verificó y su email no es @neat.qzz.io)
    const finalUser = await database.collection("id_app_users").findOne({ _id: new ObjectId(appUserId) });
    if (app.requireEmailVerification && !finalUser.emailVerified) {
      return res.redirect(`${redirectUri}?error=access_denied&error_description=${encodeURIComponent("Debes verificar tu correo electrónico antes de iniciar sesión.")}`);
    }

    // Emitir code del tenant — referencia al CLIENT específico que originó el login
    const tenantCode = crypto.randomBytes(32).toString("hex");
    await database.collection("oauth_codes").insertOne({
      code: tenantCode,
      clientId: client.clientId,
      username: null,
      idAppUserId: appUserId,
      appSlug,
      redirectUri,
      scopes: ["openid", "profile", "email"],
      codeChallenge: codeChallenge || null,
      codeChallengeMethod: codeChallengeMethod || "S256",
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
      used: false,
      type: "id_app_neat"   // entró con Neat global
    });

    // Redirigir al tenant con el code
    const params = new URLSearchParams({ code: tenantCode });
    if (tenantState) params.set("state", tenantState);
    res.redirect(`${redirectUri}?${params.toString()}`);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error interno");
  }
});

// ── 11. TOKEN DEL TENANT (intercambio de code) ────────────────────────────────
// POST /id/token
// El backend del dev llama esto para intercambiar el code por un access_token.
// Funciona para codes de tipo id_app_local e id_app_neat.
// Sobrecarga el /oauth/token existente — AGREGAR ANTES del handler de /oauth/token
// O usar este endpoint separado /id/token (recomendado para no romper nada).
app.post("/id/token", async (req, res) => {
  try {
    const code = req.body.code;
    const clientId = req.body.client_id || req.body.clientId;
    const clientSecret = req.body.client_secret || req.body.clientSecret;
    const redirectUri = req.body.redirect_uri || req.body.redirectUri;
    const codeVerifier = req.body.code_verifier || req.body.codeVerifier;

    if (!code || !clientId)
      return res.status(400).json({ error: "code y client_id requeridos" });

    const database = await getDb();
    const oauthCode = await database.collection("oauth_codes").findOne({
      code, clientId,
      type: { $in: ["id_app_local", "id_app_neat"] }
    });

    if (!oauthCode) return res.status(400).json({ error: "Código inválido o no es de Neat ID Apps" });
    if (oauthCode.used) return res.status(400).json({ error: "Código ya usado" });
    if (new Date() > oauthCode.expiresAt) return res.status(400).json({ error: "Código expirado" });
    if (oauthCode.redirectUri !== redirectUri) return res.status(400).json({ error: "redirect_uri no coincide" });

    // Verificar credenciales del client (secret confidential o PKCE público)
    const client = await database.collection("id_app_clients").findOne({ clientId });
    if (!client) return res.status(401).json({ error: "Cliente no encontrado" });
    if (client.suspended) return res.status(403).json({ error: "Client suspendido" });

    if (oauthCode.codeChallenge) {
      if (!codeVerifier) return res.status(400).json({ error: "code_verifier requerido" });
      const hash = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
      if (hash !== oauthCode.codeChallenge) return res.status(401).json({ error: "code_verifier inválido" });
    } else {
      if (client.isPublic)
        return res.status(400).json({ error: "Este client es público (PKCE) — falta code_challenge en el code original" });
      if (!clientSecret || client.clientSecret !== clientSecret)
        return res.status(401).json({ error: "client_secret inválido" });
    }

    await database.collection("oauth_codes").updateOne({ code }, { $set: { used: true } });

    // Cargar usuario local
    const appUser = await database.collection("id_app_users")
      .findOne({ _id: new ObjectId(oauthCode.idAppUserId) });
    if (!appUser) return res.status(404).json({ error: "Usuario no encontrado" });
    if (appUser.suspended) return res.status(403).json({ error: "Usuario suspendido" });

    // Cargar grupos del usuario en este tenant
    const memberships = await database.collection("id_app_memberships")
      .find({ appSlug: oauthCode.appSlug, userId: appUser._id.toString() })
      .toArray();
    const groups = Object.fromEntries(memberships.map(m => [m.groupKey, m.roles]));

    // Emitir access_token — payload de usuario local (no Neat global)
    const accessToken = jwt.sign(
      {
        type: "id_app",
        appSlug: oauthCode.appSlug,
        sub: appUser._id.toString(),
        username: appUser.username,
        email: appUser.email,
        neatUserId: appUser.neatUserId || null,
        isNeatUser: !!appUser.neatUserId,
        groups,
      },
      SECRET,
      { expiresIn: "24h" }
    );

    // id_token OIDC
    const idToken = jwt.sign(
      {
        iss: "https://id.neat.qzz.io",
        sub: appUser._id.toString(),
        aud: clientId,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 86400,
        email: appUser.email,
        username: appUser.username,
        neat_user: !!appUser.neatUserId,
        neat_user_id: appUser.neatUserId || undefined,
        groups,
      },
      SECRET,
      { algorithm: "HS256" }
    );

    // Guardar sesión
    await database.collection("id_app_sessions").insertOne({
      token: accessToken,
      appSlug: oauthCode.appSlug,
      clientId,
      userId: appUser._id.toString(),
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
    });

    res.json({
      access_token: accessToken,
      id_token: idToken,
      token_type: "Bearer",
      expires_in: 86400,
      scope: "openid profile email"
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 12. USERINFO DEL TENANT ───────────────────────────────────────────────────
// GET /id/userinfo
// El dev llama esto con el access_token de /id/token para obtener datos del usuario.
// Valida que el token es de tipo "id_app".
app.get("/id/userinfo", async (req, res) => {
  try {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: "Authorization requerido" });

    let payload;
    try {
      payload = jwt.verify(header.replace("Bearer ", ""), SECRET);
    } catch {
      return res.status(401).json({ error: "Token inválido" });
    }

    if (payload.type !== "id_app")
      return res.status(403).json({ error: "Token no es de Neat ID Apps" });

    const database = await getDb();
    const user = await database.collection("id_app_users")
      .findOne({ _id: new ObjectId(payload.sub) });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
    if (user.suspended) return res.status(403).json({ error: "Usuario suspendido" });

    const memberships = await database.collection("id_app_memberships")
      .find({ appSlug: user.appSlug, userId: user._id.toString() })
      .toArray();
    const groups = Object.fromEntries(memberships.map(m => [m.groupKey, m.roles]));

    res.json({
      sub: user._id.toString(),
      username: user.username,
      email: user.email,
      appSlug: user.appSlug,
      isNeatUser: !!user.neatUserId,
      neatUserId: user.neatUserId || null,
      verified: !!user.verified,
      createdAt: user.createdAt,
      groups
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 12.5 PANEL DE CUENTA (/SLUG/manage) ───────────────────────────────────────
// Estos endpoints son DELIBERADAMENTE independientes de OAuth2: no usan
// client_id, client_secret, code ni PKCE. El usuario entra con su email+pass
// directo, sin ningún client de por medio — porque ningún client (ni siquiera
// el internalClient público) debería poder generar acceso al panel de cuenta
// de otro usuario, y el panel mismo no es "una app más" que consume el
// sistema, es la gestión de la cuenta en sí.
//
// El token que emiten tiene type:"manage_session" — un tipo distinto al
// type:"id_app" que usan los access_token de OAuth. Esto es a propósito:
// un token de manage nunca debe servir en /id/userinfo, /id/token, ni en el
// KV storage (evita que un client externo reciba por error un token con
// estos privilegios). Y un access_token de OAuth normal tampoco sirve aquí
// (evita que cualquier client de cualquier tenant use su propio login para
// colarse en la gestión de cuenta).

function generateManageSessionToken(slug, userId) {
  return jwt.sign(
    { type: "manage_session", appSlug: slug, sub: userId },
    SECRET,
    { expiresIn: "30m" }
  );
}

// Middleware: valida un token de manage_session contra :slug de la URL.
async function manageSessionAuth(req, res, next) {
  try {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: "Authorization requerido" });

    let payload;
    try {
      payload = jwt.verify(header.replace("Bearer ", ""), SECRET);
    } catch {
      return res.status(401).json({ error: "Token inválido o expirado" });
    }
    if (payload.type !== "manage_session")
      return res.status(403).json({ error: "Token no es de sesión de cuenta" });
    if (payload.appSlug !== req.params.slug)
      return res.status(403).json({ error: "Token no corresponde a esta app" });

    const database = await getDb();
    const user = await database.collection("id_app_users").findOne({ _id: new ObjectId(payload.sub) });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
    if (user.suspended) return res.status(403).json({ error: "Cuenta suspendida" });

    req.manageUser = user;
    req.manageDb = database;
    req.manageRawToken = header.replace("Bearer ", "");
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
}

// POST /id/users/:slug/manage/login
// Login directo email+password. Sin client, sin code, sin OAuth.
app.post("/id/users/:slug/manage/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "email y password requeridos" });

    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app || app.suspended) return res.status(403).json({ error: "App suspendida o no encontrada" });

    const user = await database.collection("id_app_users").findOne({
      appSlug: req.params.slug,
      email: email.toLowerCase()
    });
    if (!user) return res.status(401).json({ error: "Credenciales inválidas" });
    if (!user.passwordHash)
      return res.status(401).json({ error: "Esta cuenta no tiene contraseña local (entra solo con Neat)" });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: "Credenciales inválidas" });
    if (user.suspended) return res.status(403).json({ error: "Cuenta suspendida en esta app" });

    return emitTokenOrRequire2fa(user, req.params.slug, res);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// GET /id/users/:slug/manage/me — equivalente a /userinfo pero para manage_session
// POST /id/users/:slug/manage/login-with-neat
// Segunda puerta de entrada al panel, para cuentas 100% Neat que NUNCA
// tuvieron password local — /manage/login (email+pass) las rechaza a propósito,
// así que necesitan entrar identificándose con su cuenta Neat en vez de una
// contraseña que nunca existió. Reusa el mismo intercambio que link-neat
// (neatCode + internalClientId + PKCE contra Neat global), pero en vez de
// vincular a un usuario YA logueado, busca quién es por neatUserId y le
// emite directamente su manage_session — sigue sin existir ningún
// client_id/secret propio de id_app_clients en este camino.
app.post("/id/users/:slug/manage/login-with-neat", async (req, res) => {
  try {
    const { neatCode, redirectUri, codeVerifier } = req.body;
    if (!neatCode || !codeVerifier)
      return res.status(400).json({ error: "neatCode y codeVerifier requeridos" });

    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app || app.suspended) return res.status(403).json({ error: "App suspendida o no encontrada" });

    const tokenRes = await fetch("https://neat-apps-b.vercel.app/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: neatCode,
        client_id: app.internalClientId,
        redirect_uri: redirectUri || "https://neat-apps-b.vercel.app/id/callback",
        code_verifier: codeVerifier,
        grant_type: "authorization_code"
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return res.status(400).json({ error: "Código Neat inválido" });

    const userRes = await fetch("https://neat-apps-b.vercel.app/oauth/userinfo", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const neatUser = await userRes.json();
    if (!neatUser.sub) return res.status(400).json({ error: "Error obteniendo perfil Neat" });

    let user = await database.collection("id_app_users").findOne({
      appSlug: req.params.slug,
      neatUserId: neatUser.sub
    });

    // Si no hay usuario vinculado, buscar por email @neat.qzz.io coincidente
    if (!user) {
      const neatEmailMatch = await database.collection("id_app_users").findOne({
        appSlug: req.params.slug,
        email: `${neatUser.username}@neat.qzz.io`,
        neatUserId: null
      });
      if (neatEmailMatch) {
        // Vincular y marcar verificado
        await database.collection("id_app_users").updateOne(
          { _id: neatEmailMatch._id },
          { $set: { neatUserId: neatUser.sub, emailVerified: true, emailVerifToken: null, emailVerifExpiresAt: null, lastNeatSync: new Date() } }
        );
        user = { ...neatEmailMatch, neatUserId: neatUser.sub, emailVerified: true };
      }
    }

    if (!user)
      return res.status(404).json({ error: "No hay cuenta vinculada a este Neat en esta app. Inicia sesión primero con 'Continuar con Neat' desde el login normal." });
    if (user.suspended) return res.status(403).json({ error: "Cuenta suspendida en esta app" });

    // Marcar emailVerified si es @neat.qzz.io y no estaba verificado
    if (!user.emailVerified && user.email.endsWith("@neat.qzz.io")) {
      await database.collection("id_app_users").updateOne(
        { _id: user._id },
        { $set: { emailVerified: true, emailVerifToken: null, emailVerifExpiresAt: null } }
      );
    }

    // Entrar con "Continuar con Neat" ya es una verificación de identidad
    // fuerte (pasó por el login de Neat mismo) — no se exige TOTP encima.
    return emitTokenOrRequire2fa(user, req.params.slug, res, { skip2fa: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// GET /id/users/:slug/manage/me — equivalente a /userinfo pero para manage_session
app.get("/id/users/:slug/manage/me", manageSessionAuth, async (req, res) => {
  const user = req.manageUser;
  res.json({
    sub: user._id.toString(),
    username: user.username,
    email: user.email,
    isNeatUser: !!user.neatUserId,
    neatUserId: user.neatUserId || null,
    hasPassword: !!user.passwordHash,
    totp2faEnabled: !!user.totpEnabled,
    verified: !!user.verified,
    createdAt: user.createdAt
  });
});

// PUT /id/users/:slug/manage/password — cambiar o establecer contraseña
app.put("/id/users/:slug/manage/password", manageSessionAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!newPassword || newPassword.length < 8)
      return res.status(400).json({ error: "La contraseña nueva debe tener al menos 8 caracteres" });

    const user = req.manageUser;
    if (user.passwordHash) {
      if (!currentPassword) return res.status(400).json({ error: "Contraseña actual requerida" });
      const valid = await bcrypt.compare(currentPassword, user.passwordHash);
      if (!valid) return res.status(401).json({ error: "Contraseña actual incorrecta" });
    }
    // Si user.passwordHash no existe (cuenta 100% Neat), se permite
    // establecer una contraseña nueva sin pedir la "actual" (no existe).

    const newHash = await bcrypt.hash(newPassword, 10);
    await req.manageDb.collection("id_app_users").updateOne(
      { _id: user._id },
      { $set: { passwordHash: newHash } }
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// GET /id/users/:slug/manage/sessions — sesiones OAuth activas del usuario (por client)
app.get("/id/users/:slug/manage/sessions", manageSessionAuth, async (req, res) => {
  try {
    const sessions = await req.manageDb.collection("id_app_sessions").find({
      appSlug: req.params.slug,
      userId: req.manageUser._id.toString(),
      expiresAt: { $gt: new Date() }
    }).toArray();

    const clientIds = [...new Set(sessions.map(s => s.clientId))];
    const clients = await req.manageDb.collection("id_app_clients")
      .find({ clientId: { $in: clientIds } }).toArray();
    const clientNameById = Object.fromEntries(clients.map(c => [c.clientId, c.name || c.clientId]));

    // Nota: la sesión de manage (este mismo token) nunca aparece en
    // id_app_sessions — esa colección solo guarda access_token tipo "id_app"
    // emitidos por /id/token vía OAuth. isCurrent queda siempre en false
    // porque ninguna de estas filas puede ser "esta misma sesión de manage".
    res.json({
      sessions: sessions.map(s => ({
        id: s._id.toString(),
        clientId: s.clientId,
        clientName: clientNameById[s.clientId] || "App desconocida",
        createdAt: s.createdAt,
        expiresAt: s.expiresAt,
        isCurrent: false
      }))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// DELETE /id/users/:slug/manage/sessions/:sessionId — revocar una sesión propia
app.delete("/id/users/:slug/manage/sessions/:sessionId", manageSessionAuth, async (req, res) => {
  try {
    let sessionObjId;
    try { sessionObjId = new ObjectId(req.params.sessionId); }
    catch { return res.status(400).json({ error: "sessionId inválido" }); }

    const result = await req.manageDb.collection("id_app_sessions").deleteOne({
      _id: sessionObjId,
      appSlug: req.params.slug,
      userId: req.manageUser._id.toString()   // solo puede borrar SUS propias sesiones
    });
    if (result.deletedCount === 0) return res.status(404).json({ error: "Sesión no encontrada" });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 13. VINCULAR CUENTA NEAT A USUARIO LOCAL ──────────────────────────────────
// POST /id/users/:slug/link-neat
// Un usuario que entró con email+pass local puede vincular su cuenta Neat.
// Después podrá entrar con ambos métodos.
// El dev redirige al usuario a neat.qzz.io/oauth con el scope "openid profile email"
// usando el internalClientId, y cuando vuelve llama este endpoint.
app.post("/id/users/:slug/link-neat", async (req, res) => {
  try {
    const { neatCode, localAccessToken, redirectUri, codeVerifier } = req.body;
    if (!neatCode || !localAccessToken || !codeVerifier)
      return res.status(400).json({ error: "neatCode, localAccessToken y codeVerifier requeridos" });

    // Acepta tres tipos de token:
    //  - "id_app": sesión real emitida por /id/token (el dev la usa desde su backend/app)
    //  - "id_app_page_session": token corto (10 min) emitido por /id/users/:slug/login,
    //    usado SOLO por la hosted login page para vincular Neat en el mismo flujo,
    //    sin que el code/credenciales del tenant entren en juego.
    //  - "manage_session": sesión del panel de cuenta (/SLUG/manage), emitida por
    //    /id/users/:slug/manage/login — login directo, sin client de por medio.
    let localPayload;
    try {
      localPayload = jwt.verify(localAccessToken, SECRET);
    } catch {
      return res.status(401).json({ error: "Token local inválido" });
    }
    const validTypes = ["id_app", "id_app_page_session", "manage_session"];
    if (!validTypes.includes(localPayload.type) || localPayload.appSlug !== req.params.slug)
      return res.status(401).json({ error: "Token no corresponde a esta app" });

    // Normalizamos el id de usuario local según el tipo de token
    const localUserId = localPayload.type === "id_app_page_session" ? localPayload.idAppUserId : localPayload.sub;

    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });

    // Intercambiar neatCode → token Neat usando el internalClientId (PKCE)
    const tokenRes = await fetch("https://neat-apps-b.vercel.app/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: neatCode,
        client_id: app.internalClientId,
        redirect_uri: redirectUri || "https://neat-apps-b.vercel.app/id/callback",
        code_verifier: codeVerifier,
        grant_type: "authorization_code"
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return res.status(400).json({ error: "Código Neat inválido" });

    // Obtener perfil Neat
    const userRes = await fetch("https://neat-apps-b.vercel.app/oauth/userinfo", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const neatUser = await userRes.json();
    if (!neatUser.sub) return res.status(400).json({ error: "Error obteniendo perfil Neat" });

    // Verificar que ese Neat ID no esté ya vinculado a otro usuario en esta app
    const alreadyLinked = await database.collection("id_app_users").findOne({
      appSlug: req.params.slug,
      neatUserId: neatUser.sub,
      _id: { $ne: new ObjectId(localUserId) }
    });
    if (alreadyLinked) return res.status(409).json({ error: "Esa cuenta Neat ya está vinculada a otro usuario en esta app" });

    // Vincular
    await database.collection("id_app_users").updateOne(
      { _id: new ObjectId(localUserId) },
      { $set: { neatUserId: neatUser.sub, lastNeatSync: new Date() } }
    );

    res.json({ ok: true, neatUserId: neatUser.sub, neatUsername: neatUser.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 14. DESVINCULAR CUENTA NEAT ───────────────────────────────────────────────
// DELETE /id/users/:slug/link-neat
// Solo si el usuario tiene password local (si no, no puede desvincular o quedaría sin acceso)
app.delete("/id/users/:slug/link-neat", async (req, res) => {
  try {
    const header = req.headers.authorization;
    let payload;
    try {
      payload = jwt.verify(header?.replace("Bearer ", ""), SECRET);
    } catch {
      return res.status(401).json({ error: "Token inválido" });
    }
    if (!["id_app", "manage_session"].includes(payload.type) || payload.appSlug !== req.params.slug)
      return res.status(403).json({ error: "Token no corresponde a esta app" });

    const database = await getDb();
    const user = await database.collection("id_app_users")
      .findOne({ _id: new ObjectId(payload.sub) });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
    if (!user.passwordHash)
      return res.status(400).json({ error: "No puedes desvincular Neat si no tienes contraseña local. Crea una primero." });

    await database.collection("id_app_users").updateOne(
      { _id: new ObjectId(payload.sub) },
      { $set: { neatUserId: null } }
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Error interno" });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// KV STORAGE — para que apps SIN backend tengan persistencia de datos
// ══════════════════════════════════════════════════════════════════════════════
// Dos espacios de almacenamiento por Tenant:
//   - id_app_user_kv:   un blob JSON por usuario (privado, límite configurable
//                       por tenant — ver kvPrivateLimitForApp más abajo)
//   - id_app_public_kv: un blob JSON por app (público en LECTURA, cualquiera
//                       lo lee sin auth — pero solo el BACKEND puede escribirlo;
//                       límite configurable por separado — ver kvPublicLimitForApp)
//
// MODELO DE CONFIANZA (igual que la "anon key" + RLS de Supabase):
//   La App Key (pública, va en el navegador) NUNCA es suficiente por sí sola
//   para escribir el KV PRIVADO de un usuario. Esa escritura exige TAMBIÉN el
//   access_token del usuario en cuestión — así, aunque alguien copie la App
//   Key, solo puede actuar como un usuario que YA demostró ser quien dice ser
//   con su propio token firmado por el servidor (nunca puede falsificar ser
//   otro usuario).
//
// KV privado — dos caminos para escribir, igual que ya existe para login:
//   1. App Key + access_token de usuario → app sin backend, solo SU dato.
//   2. x-client-id + x-client-secret      → backend del dev, cualquier usuario.
//
// KV público — UN solo camino para escribir, a propósito:
//   x-client-id + x-client-secret → SOLO el backend del dev. Es una sola
//   fuente de verdad compartida por toda la app (config, leaderboard, etc.),
//   así que la App Key —que vive en el navegador de cualquier usuario— NUNCA
//   puede escribirlo: dejarla haría que cualquier visitante corrompiera el
//   dato de todos, no solo el suyo. Si tu app no tiene backend, este storage
//   es de solo lectura para ella.

const KV_PRIVATE_DEFAULT_BYTES = 25 * 1024;       // 25KB por usuario — default si el tenant no configuró nada
const KV_PRIVATE_HARD_CAP_BYTES = 1024 * 1024;     // 1MB por usuario — techo absoluto

// El público es UN solo blob por tenant (no se multiplica por usuario como el
// privado), así que puede tener un presupuesto más grande sin que el riesgo
// crezca con la cantidad de usuarios.
const KV_PUBLIC_DEFAULT_BYTES = 100 * 1024;        // 100KB — default si el tenant no configuró nada
const KV_PUBLIC_HARD_CAP_BYTES = 5 * 1024 * 1024;  // 5MB — techo absoluto

function kvPrivateLimitForApp(app) {
  return (typeof app?.kvLimitBytes === "number" && app.kvLimitBytes > 0)
    ? app.kvLimitBytes
    : KV_PRIVATE_DEFAULT_BYTES;
}

function kvPublicLimitForApp(app) {
  return (typeof app?.kvPublicLimitBytes === "number" && app.kvPublicLimitBytes > 0)
    ? app.kvPublicLimitBytes
    : KV_PUBLIC_DEFAULT_BYTES;
}

function kvSizeOk(value, limitBytes) {
  return Buffer.byteLength(JSON.stringify(value ?? {}), "utf8") <= (limitBytes ?? KV_PRIVATE_DEFAULT_BYTES);
}

// Resuelve quién está escribiendo el KV privado: o un usuario autenticado
// (vía App Key + su propio access_token), o el backend del tenant (vía
// client_id/client_secret, que puede tocar el KV de cualquier usuario).
// Deja req.kvApp y, si aplica, req.kvTargetUserId ya resuelto.
async function kvUserAuth(req, res, next) {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.suspended) return res.status(403).json({ error: "App suspendida" });
    req.kvApp = app;

    const clientId = req.headers["x-client-id"] || req.body?.client_id;
    const clientSecret = req.headers["x-client-secret"] || req.body?.client_secret;

    if (clientId && clientSecret) {
      // Camino backend: puede escribir el KV de CUALQUIER usuario (vía :userId en la ruta)
      const client = await database.collection("id_app_clients").findOne({
        appSlug: req.params.slug, clientId, clientSecret, isPublic: false
      });
      if (!client) return res.status(401).json({ error: "Credenciales de client inválidas" });
      if (client.suspended) return res.status(403).json({ error: "Client suspendido" });
      req.kvAsBackend = true;
      return next();
    }

    // Camino app-sin-backend: App Key (header) + access_token del propio usuario
    const appKey = req.headers["x-app-key"];
    if (!appKey || appKey !== app.appKey)
      return res.status(401).json({ error: "x-app-key inválida o ausente" });

    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Authorization (access_token del usuario) requerido" });
    let payload;
    try {
      payload = jwt.verify(authHeader.replace("Bearer ", ""), SECRET);
    } catch {
      return res.status(401).json({ error: "access_token inválido" });
    }
    if (payload.type !== "id_app" || payload.appSlug !== req.params.slug)
      return res.status(403).json({ error: "Token no corresponde a esta app" });

    const targetUser = await database.collection("id_app_users").findOne({ _id: new ObjectId(payload.sub) });
    if (!targetUser) return res.status(404).json({ error: "Usuario no encontrado" });
    if (targetUser.suspended) return res.status(403).json({ error: "Usuario suspendido" });

    req.kvAsBackend = false;
    req.kvTargetUserId = payload.sub; // SOLO puede tocar su propio storage
    next();
  } catch (err) {
    res.status(500).json({ error: "Error interno" });
  }
}

// ── KV PRIVADO POR USUARIO ───────────────────────────────────────────────────
// GET /id/apps/:slug/kv/:userId — leer el storage de un usuario.
// :userId es el _id de Mongo del id_app_user (el mismo "sub" del access_token
// y de /id/userinfo) — no el username ni el email.
// El propio usuario lee con su access_token (sin necesitar App Key — su JWT
// ya prueba quién es). El backend del tenant también puede leer cualquier
// usuario con client_id/secret.
app.get("/id/apps/:slug/kv/:userId", async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.userId))
      return res.status(400).json({ error: "userId inválido" });
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });

    const clientId = req.headers["x-client-id"];
    const clientSecret = req.headers["x-client-secret"];
    if (clientId && clientSecret) {
      const client = await database.collection("id_app_clients").findOne({
        appSlug: req.params.slug, clientId, clientSecret, isPublic: false
      });
      if (!client) return res.status(401).json({ error: "Credenciales de client inválidas" });
    } else {
      const authHeader = req.headers.authorization;
      if (!authHeader) return res.status(401).json({ error: "Authorization requerido" });
      let payload;
      try {
        payload = jwt.verify(authHeader.replace("Bearer ", ""), SECRET);
      } catch {
        return res.status(401).json({ error: "access_token inválido" });
      }
      if (payload.type !== "id_app" || payload.appSlug !== req.params.slug || payload.sub !== req.params.userId)
        return res.status(403).json({ error: "Solo puedes leer tu propio storage" });
      const targetUser = await database.collection("id_app_users").findOne({ _id: new ObjectId(req.params.userId) });
      if (targetUser?.suspended) return res.status(403).json({ error: "Usuario suspendido" });
    }

    const doc = await database.collection("id_app_user_kv").findOne({
      appSlug: req.params.slug, userId: req.params.userId
    });
    res.json({ data: doc?.data ?? {}, updatedAt: doc?.updatedAt ?? null });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// PUT /id/apps/:slug/kv/:userId — escribir/reemplazar el storage de un usuario.
// Requiere (App Key + access_token DE ESE MISMO usuario) o (client_id/secret).
app.put("/id/apps/:slug/kv/:userId", kvUserAuth, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.userId))
      return res.status(400).json({ error: "userId inválido" });
    if (!req.kvAsBackend && req.kvTargetUserId !== req.params.userId)
      return res.status(403).json({ error: "Solo puedes escribir tu propio storage" });

    const { data } = req.body;
    if (data === undefined) return res.status(400).json({ error: "data requerido" });
    const limitBytes = kvPrivateLimitForApp(req.kvApp);
    if (!kvSizeOk(data, limitBytes))
      return res.status(413).json({ error: `data excede el límite de ${Math.round(limitBytes / 1024)}KB por usuario` });

    const database = await getDb();
    await database.collection("id_app_user_kv").updateOne(
      { appSlug: req.params.slug, userId: req.params.userId },
      { $set: { data, updatedAt: new Date() } },
      { upsert: true }
    );
    res.json({ ok: true, updatedAt: new Date() });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// POST /id/apps/:slug/kv/:userId/items — agrega un item a un array dentro de
// data, sin tener que mandar el blob completo. Pensado para casos tipo
// "lista de notas": cada nota se agrega sola, con su propio id generado aquí.
// body: { field: "notas" (default "items"), item: {...lo que sea} }
app.post("/id/apps/:slug/kv/:userId/items", kvUserAuth, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.userId))
      return res.status(400).json({ error: "userId inválido" });
    if (!req.kvAsBackend && req.kvTargetUserId !== req.params.userId)
      return res.status(403).json({ error: "Solo puedes escribir tu propio storage" });

    const { field = "items", item } = req.body;
    if (item === undefined) return res.status(400).json({ error: "item requerido" });
    if (typeof field !== "string" || !/^[a-zA-Z0-9_]+$/.test(field))
      return res.status(400).json({ error: "field debe ser alfanumérico (sin espacios ni puntos)" });

    const database = await getDb();
    const doc = await database.collection("id_app_user_kv").findOne({
      appSlug: req.params.slug, userId: req.params.userId
    });
    const currentData = doc?.data ?? {};
    const currentArray = Array.isArray(currentData[field]) ? currentData[field] : [];

    const itemId = crypto.randomBytes(8).toString("hex");
    const newItem = (item && typeof item === "object" && !Array.isArray(item))
      ? { ...item, id: itemId }
      : { id: itemId, value: item };

    const newData = { ...currentData, [field]: [...currentArray, newItem] };
    const limitBytes = kvPrivateLimitForApp(req.kvApp);
    if (!kvSizeOk(newData, limitBytes))
      return res.status(413).json({ error: `data excede el límite de ${Math.round(limitBytes / 1024)}KB por usuario` });

    await database.collection("id_app_user_kv").updateOne(
      { appSlug: req.params.slug, userId: req.params.userId },
      { $set: { data: newData, updatedAt: new Date() } },
      { upsert: true }
    );
    res.status(201).json({ ok: true, item: newItem, updatedAt: new Date() });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// DELETE /id/apps/:slug/kv/:userId/items/:itemId — quita un item (por su id)
// de un array dentro de data, sin tener que mandar el blob completo.
// query: ?field=notas (default "items")
app.delete("/id/apps/:slug/kv/:userId/items/:itemId", kvUserAuth, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.userId))
      return res.status(400).json({ error: "userId inválido" });
    if (!req.kvAsBackend && req.kvTargetUserId !== req.params.userId)
      return res.status(403).json({ error: "Solo puedes escribir tu propio storage" });

    const field = req.query.field || "items";
    if (typeof field !== "string" || !/^[a-zA-Z0-9_]+$/.test(field))
      return res.status(400).json({ error: "field debe ser alfanumérico (sin espacios ni puntos)" });

    const database = await getDb();
    const doc = await database.collection("id_app_user_kv").findOne({
      appSlug: req.params.slug, userId: req.params.userId
    });
    const currentData = doc?.data ?? {};
    const currentArray = Array.isArray(currentData[field]) ? currentData[field] : [];
    const filtered = currentArray.filter(it => it?.id !== req.params.itemId);

    if (filtered.length === currentArray.length)
      return res.status(404).json({ error: "Item no encontrado" });

    const newData = { ...currentData, [field]: filtered };
    await database.collection("id_app_user_kv").updateOne(
      { appSlug: req.params.slug, userId: req.params.userId },
      { $set: { data: newData, updatedAt: new Date() } },
      { upsert: true }
    );
    res.json({ ok: true, updatedAt: new Date() });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── KV PÚBLICO DEL TENANT ────────────────────────────────────────────────────
// GET /id/apps/:slug/public-kv — cualquiera lo lee, sin auth (config/datos
// compartidos de la app, ej. un leaderboard o ajustes globales).
app.get("/id/apps/:slug/public-kv", async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    const doc = await database.collection("id_app_public_kv").findOne({ appSlug: req.params.slug });
    res.json({ data: doc?.data ?? {}, updatedAt: doc?.updatedAt ?? null });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// PUT /id/apps/:slug/public-kv — escribir el storage público.
// SOLO el backend del tenant puede escribir aquí (x-client-id + x-client-secret,
// client confidencial). A diferencia del KV privado por usuario, este storage
// es una sola fuente de verdad compartida por TODA la app — dejar que la App
// Key (pública, vive en el navegador de cualquier usuario) lo escriba directo
// significaría que cualquier visitante podría corromper el dato de todos, no
// solo el suyo. Por eso aquí NO existe el camino "App Key sola": si tu app no
// tiene backend, este storage es de solo lectura para ella.
app.put("/id/apps/:slug/public-kv", async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.suspended) return res.status(403).json({ error: "App suspendida" });

    const clientId = req.headers["x-client-id"] || req.body?.client_id;
    const clientSecret = req.headers["x-client-secret"] || req.body?.client_secret;
    if (!clientId || !clientSecret)
      return res.status(401).json({ error: "x-client-id y x-client-secret requeridos — el storage público solo lo escribe el backend del tenant" });

    const client = await database.collection("id_app_clients").findOne({
      appSlug: req.params.slug, clientId, clientSecret, isPublic: false
    });
    if (!client) return res.status(401).json({ error: "Credenciales de client inválidas" });
    if (client.suspended) return res.status(403).json({ error: "Client suspendido" });

    const { data } = req.body;
    if (data === undefined) return res.status(400).json({ error: "data requerido" });
    const limitBytes = kvPublicLimitForApp(app);
    if (!kvSizeOk(data, limitBytes))
      return res.status(413).json({ error: `data excede el límite de ${Math.round(limitBytes / 1024)}KB` });

    await database.collection("id_app_public_kv").updateOne(
      { appSlug: req.params.slug },
      { $set: { data, updatedAt: new Date() } },
      { upsert: true }
    );
    res.json({ ok: true, updatedAt: new Date() });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});


// ── 15. GESTIÓN DE USUARIOS DEL TENANT (para el dev) ─────────────────────────
// GET /id/apps/:slug/users
// El dev ve sus usuarios. Autenticado con x-client-id + x-client-secret.
app.get("/id/apps/:slug/users", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const database = await getDb();
    const { limit = 50, skip = 0, q } = req.query;
    const filter = { appSlug: req.params.slug };
    if (q) {
      const re = new RegExp(q.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
      filter.$or = [{ email: re }, { username: re }];
    }

    const users = await database.collection("id_app_users")
      .find(filter, { projection: { passwordHash: 0 } })
      .sort({ createdAt: -1 })
      .skip(parseInt(skip))
      .limit(parseInt(limit))
      .toArray();

    const total = await database.collection("id_app_users").countDocuments(filter);
    res.json({ users, total, limit: parseInt(limit), skip: parseInt(skip) });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 16. DETALLE DE USUARIO DEL TENANT ────────────────────────────────────────
// GET /id/apps/:slug/users/:userId
app.get("/id/apps/:slug/users/:userId", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const database = await getDb();
    const user = await database.collection("id_app_users")
      .findOne({ _id: new ObjectId(req.params.userId), appSlug: req.params.slug },
        { projection: { passwordHash: 0 } });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
    res.json(user);
  } catch {
    res.status(400).json({ error: "ID inválido" });
  }
});

// ── 17. SUSPENDER/REACTIVAR USUARIO DEL TENANT ───────────────────────────────
// PUT /id/apps/:slug/users/:userId/suspend
app.put("/id/apps/:slug/users/:userId/suspend", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const { suspended, reason } = req.body;
    const database = await getDb();
    await database.collection("id_app_users").updateOne(
      { _id: new ObjectId(req.params.userId), appSlug: req.params.slug },
      { $set: { suspended: !!suspended, suspendedReason: reason || null } }
    );
    // Revocar sesiones activas si se suspende
    if (suspended) {
      await database.collection("id_app_sessions").deleteMany({
        userId: req.params.userId, appSlug: req.params.slug
      });
    }
    res.json({ ok: true, suspended: !!suspended });
  } catch {
    res.status(400).json({ error: "ID inválido" });
  }
});

// ── 18. ELIMINAR USUARIO DEL TENANT ──────────────────────────────────────────
// DELETE /id/apps/:slug/users/:userId
app.delete("/id/apps/:slug/users/:userId", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const database = await getDb();
    await database.collection("id_app_users").deleteOne(
      { _id: new ObjectId(req.params.userId), appSlug: req.params.slug }
    );
    await database.collection("id_app_sessions").deleteMany(
      { userId: req.params.userId, appSlug: req.params.slug }
    );
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "ID inválido" });
  }
});

// ── 19. ESTADÍSTICAS DEL TENANT ───────────────────────────────────────────────
// GET /id/apps/:slug/stats
app.get("/id/apps/:slug/stats", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const database = await getDb();
    const slug = req.params.slug;

    const [totalUsers, neatUsers, localUsers, activeSessions, recentUsers] = await Promise.all([
      database.collection("id_app_users").countDocuments({ appSlug: slug }),
      database.collection("id_app_users").countDocuments({ appSlug: slug, neatUserId: { $ne: null } }),
      database.collection("id_app_users").countDocuments({ appSlug: slug, neatUserId: null }),
      database.collection("id_app_sessions").countDocuments({ appSlug: slug, expiresAt: { $gt: new Date() } }),
      database.collection("id_app_users")
        .find({ appSlug: slug }, { projection: { passwordHash: 0 } })
        .sort({ createdAt: -1 }).limit(5).toArray()
    ]);

    res.json({ totalUsers, neatUsers, localUsers, activeSessions, recentUsers });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 20. REVOCAR TOKEN DE USUARIO (del tenant) ─────────────────────────────────
// POST /id/apps/:slug/revoke
// El dev puede revocar el token de un usuario (logout forzado).
app.post("/id/apps/:slug/revoke", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const { token, userId } = req.body;
    if (!token && !userId) return res.status(400).json({ error: "token o userId requerido" });

    const database = await getDb();
    const filter = { appSlug: req.params.slug };
    if (token) filter.token = token;
    if (userId) filter.userId = userId;

    await database.collection("id_app_sessions").deleteMany(filter);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 21. ADMIN — LISTAR TODAS LAS APPS ────────────────────────────────────────
// GET /id/apps (solo admin)
app.get("/id/apps", adminAuth, async (req, res) => {
  try {
    const database = await getDb();
    const apps = await database.collection("id_apps")
      .find({})
      .sort({ createdAt: -1 }).toArray();
    res.json(apps);
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 22. ADMIN — SUSPENDER APP ─────────────────────────────────────────────────
// PUT /id/apps/:slug/suspend (solo admin)
app.put("/id/apps/:slug/suspend", adminAuth, async (req, res) => {
  try {
    const { suspended, reason } = req.body;
    const database = await getDb();
    await database.collection("id_apps").updateOne(
      { slug: req.params.slug },
      { $set: { suspended: !!suspended, suspendedReason: reason || null } }
    );
    res.json({ ok: true, suspended: !!suspended });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── 23. OPENID CONFIGURATION DE NEAT ID APPS ─────────────────────────────────
// GET /id/.well-known/openid-configuration
// Separado del OIDC de Neat global. Apunta a los endpoints /id/
app.get("/id/.well-known/openid-configuration", (req, res) => {
  const base = "https://id.neat.qzz.io";
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/`,           // hosted login page (frontend, raíz)
    token_endpoint: `${base}/id/token`,
    userinfo_endpoint: `${base}/id/userinfo`,
    jwks_uri: `${base}/id/.well-known/jwks.json`,
    scopes_supported: ["openid", "profile", "email"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["HS256"],
    claims_supported: ["sub", "username", "email", "neat_user", "neat_user_id"]
  });
});

// GET /tenants/:tenant/.well-known/openid-configuration
// Discovery POR TENANT. El protocolo OIDC asume que un issuer = una sola
// base de usuarios — pero Neat ID Apps sirve N tenants desde un solo dominio,
// cada uno con su propio pool de id_app_users. Este endpoint hace ese hecho
// explícito: cada tenant tiene su propio "issuer" lógico (path-based, sin
// necesitar un dominio físico separado), su propio authorization_endpoint
// con el slug ya en el path, y su propio token_endpoint con el client
// implícito a ese tenant (igual que el patrón de WorkOS/Clerk para
// multi-tenancy, no el de "un dominio Auth0 por cliente").
app.get("/tenants/:tenant/.well-known/openid-configuration", async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.tenant });
    if (!app) return res.status(404).json({ error: "Tenant no encontrado" });

    const base = "https://id.neat.qzz.io";
    const apiBase = "https://neat-apps-b.vercel.app";
    res.json({
      issuer: `${base}/${app.slug}`,
      authorization_endpoint: `${base}/${app.slug}`,
      token_endpoint: `${apiBase}/id/token`,
      userinfo_endpoint: `${apiBase}/id/userinfo`,
      jwks_uri: `${apiBase}/id/.well-known/jwks.json`,
      scopes_supported: ["openid", "profile", "email"],
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["HS256"],
      claims_supported: ["sub", "username", "email", "neat_user", "neat_user_id"],
      // Específico de este tenant — no es parte del estándar OIDC, pero útil
      // para que un dev integre rápido sin tener que pedir el resto a mano.
      tenant_name: app.name,
      tenant_branding: app.branding || null
    });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

app.get("/id/.well-known/jwks.json", (req, res) => {
  res.json({ keys: [] });
});

// ── MIGRACIÓN TEMPORAL — agregar redirectUri de "vincular Neat" a apps viejas ──
// POST /id/_migrate/fix-internal-redirects
// Las apps creadas ANTES de este fix solo tienen registrada la redirectUri de
// login normal (.../id/callback) en su internalClient — la de "vincular Neat"
// (id.neat.qzz.io/{slug}/neat-callback) nunca se agregó, así que ese flujo
// rebotaba con "redirect_uri no autorizado". Este endpoint recorre todas las
// id_apps, localiza su internalClient en oauth_clients, agrega la URL de
// vinculación con ruta dedicada si falta, y limpia la variante vieja basada
// en query param (?linking=1) si quedó de una corrida anterior de esta misma
// migración — un solo formato vigente, sin acumular redirect_uris muertas.
// Idempotente — seguro correrlo varias veces. Solo admin. BORRAR este
// endpoint una vez migradas todas las apps existentes.
app.post("/id/_migrate/fix-internal-redirects", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ error: "Solo admin" });

    const database = await getDb();
    const apps = await database.collection("id_apps").find({}).toArray();

    const results = [];
    for (const app of apps) {
      if (!app.internalClientId) {
        results.push({ slug: app.slug, status: "skip", reason: "sin internalClientId" });
        continue;
      }
      const linkingUri = `https://id.neat.qzz.io/${app.slug}/neat-callback`;
      const oldLinkingUri = `https://id.neat.qzz.io/${app.slug}?linking=1`;
      const client = await database.collection("oauth_clients").findOne({ clientId: app.internalClientId });
      if (!client) {
        results.push({ slug: app.slug, status: "skip", reason: "internalClient no encontrado" });
        continue;
      }

      const hadNew = client.redirectUris?.includes(linkingUri);
      const hadOld = client.redirectUris?.includes(oldLinkingUri);
      if (hadNew && !hadOld) {
        results.push({ slug: app.slug, status: "already-ok" });
        continue;
      }

      // OJO: $addToSet y $pull sobre el MISMO campo en una sola updateOne no
      // está permitido por MongoDB (lanza error) — se separan en dos pasos.
      await database.collection("oauth_clients").updateOne(
        { clientId: app.internalClientId },
        { $addToSet: { redirectUris: linkingUri } }
      );
      if (hadOld) {
        await database.collection("oauth_clients").updateOne(
          { clientId: app.internalClientId },
          { $pull: { redirectUris: oldLinkingUri } }
        );
      }
      results.push({ slug: app.slug, status: "fixed", addedUri: linkingUri, removedOldUri: hadOld ? oldLinkingUri : null });
    }

    res.json({ ok: true, totalApps: apps.length, results });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno", detail: err.message });
  }
});

// ── Apps (público — sin cambios para Neat Astore) ─────────────────────────────
app.get("/apps", async (req, res) => {
  const database = await getDb();
  const list = await database.collection("apps").find().sort({ createdAt: -1 }).toArray();
  res.json(list);
});

app.get("/apps/:id", async (req, res) => {
  try {
    const database = await getDb();
    const item = await database.collection("apps").findOne({ _id: new ObjectId(req.params.id) });
    if (!item) return res.status(404).json({ error: "Not found" });
    res.json(item);
  } catch {
    res.status(400).json({ error: "Invalid id" });
  }
});

// ── Apps ───────────────────────────────────────────────────────────────────────
// GET es público. POST/PUT/DELETE requieren admin.
app.post("/apps", adminAuth, async (req, res) => {
  const { name, description, icon, url, category } = req.body;
  if (!name || !url) return res.status(400).json({ error: "name and url required" });
  const database = await getDb();
  const result = await database.collection("apps").insertOne({
    name, description, icon, url, category, createdAt: new Date()
  });
  res.status(201).json({ _id: result.insertedId, name, description, icon, url, category });
});

app.put("/apps/:id", adminAuth, async (req, res) => {
  try {
    const database = await getDb();
    const { _id, ...data } = req.body;
    await database.collection("apps").updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: data }
    );
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "Invalid id" });
  }
});

app.delete("/apps/:id", adminAuth, async (req, res) => {
  try {
    const database = await getDb();
    await database.collection("apps").deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "Invalid id" });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// RECUPERACIÓN DE CONTRASEÑA
// Dos caminos:
//   - email @neat.qzz.io → se les dice que entren con Neat desde /manage
//   - otro email → token de 1h enviado por correo, formulario para nueva pass
// ══════════════════════════════════════════════════════════════════════════════

// POST /id/users/:slug/forgot-password
// Pide reset por email. Respuesta siempre genérica para no revelar si el email existe.
app.post("/id/users/:slug/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "email requerido" });

    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app || app.suspended) return res.status(404).json({ error: "App no encontrada" });

    const user = await database.collection("id_app_users").findOne({
      appSlug: req.params.slug, email: email.toLowerCase()
    });

    // Siempre respondemos ok para no revelar si el email existe
    if (!user || !user.passwordHash) return res.json({ ok: true });

    // @neat.qzz.io no puede recibir correos — no enviamos nada,
    // el frontend ya les habrá dicho que entren con Neat
    if (user.email.endsWith("@neat.qzz.io")) return res.json({ ok: true });

    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetExpiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1h
    await database.collection("id_app_users").updateOne(
      { _id: user._id },
      { $set: { passwordResetToken: resetToken, passwordResetExpiresAt: resetExpiresAt } }
    );

    const resetUrl = `${NEAT_ID_BASE}/${req.params.slug}?reset_token=${resetToken}`;
    await sendEmail({
      to: user.email,
      subject: `Recupera tu contraseña en ${app.name}`,
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto">
          <h2 style="color:#1f1f1f">Recuperar contraseña</h2>
          <p>Hola <strong>${user.username}</strong>, recibimos una solicitud para restablecer tu contraseña en <strong>${app.name}</strong>.</p>
          <p>Haz clic en el botón para elegir una nueva contraseña:</p>
          <a href="${resetUrl}" style="display:inline-block;margin:16px 0;padding:12px 24px;background:#0b57d0;color:#fff;border-radius:8px;text-decoration:none;font-weight:600">Restablecer contraseña</a>
          <p style="color:#666;font-size:13px">Este enlace expira en 1 hora. Si no solicitaste esto, ignora este mensaje.</p>
        </div>
      `
    });

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// POST /id/users/:slug/reset-password
// Canjea el token de reset y establece la nueva contraseña
app.post("/id/users/:slug/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: "token y newPassword requeridos" });
    if (newPassword.length < 8) return res.status(400).json({ error: "Mínimo 8 caracteres" });

    const database = await getDb();
    const user = await database.collection("id_app_users").findOne({
      appSlug: req.params.slug,
      passwordResetToken: token
    });
    if (!user) return res.status(400).json({ error: "Token inválido o ya usado" });
    if (new Date() > new Date(user.passwordResetExpiresAt))
      return res.status(400).json({ error: "El enlace expiró. Solicita uno nuevo." });

    const newHash = await bcrypt.hash(newPassword, 10);
    await database.collection("id_app_users").updateOne(
      { _id: user._id },
      { $set: { passwordHash: newHash, passwordResetToken: null, passwordResetExpiresAt: null } }
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// 2FA / TOTP
// - Opcional por defecto, forzable por tenant (require2fa en id_apps)
// - Aplica a login local Y a "Continuar con Neat"
// - Setup: genera secret + QR URI, el usuario escanea y confirma con un código
// - Backup codes: 8 códigos de un solo uso para recuperación
// - Endpoints de gestión en /manage (requieren manage_session)
// - Login con 2FA: emite un totp_pending_token (5 min) en vez del token final,
//   el frontend pide el código y lo canjea por el token real
// ══════════════════════════════════════════════════════════════════════════════

let _otplib = null;
function getOtplib() {
  if (!_otplib) {
    try { _otplib = require("otplib"); } catch {
      throw new Error("otplib no instalado. Ejecuta: npm install otplib");
    }
  }
  return _otplib;
}

function generateBackupCodes() {
  return Array.from({ length: 8 }, () => crypto.randomBytes(4).toString("hex").toUpperCase());
}

// Middleware: si el usuario tiene 2FA activo (o el tenant lo requiere y el
// usuario lo tiene configurado), en vez de emitir el token final emite un
// totp_pending_token de 5 min. El frontend lo intercepta y muestra el paso de 2FA.
// Se usa en manage/login y en el login normal de usuario final.
//
// skip2fa: true cuando la autenticación ya vino verificada por un proveedor
// externo de identidad (Neat, o un proveedor social vía OIDC) — entrar con
// ese proveedor ya es una prueba de identidad fuerte, así que no se pide TOTP
// encima. Si el mismo usuario entra con email+contraseña local, sí se le pide.
function emitTokenOrRequire2fa(user, appSlug, res, { tokenType = "manage_session", skip2fa = false } = {}) {
  const needs2fa = !skip2fa && (user.totpEnabled || false);
  if (needs2fa) {
    const pendingToken = jwt.sign(
      { type: "totp_pending", appSlug, sub: user._id.toString(), tokenType },
      SECRET,
      { expiresIn: "5m" }
    );
    return res.json({ totp_required: true, totp_pending_token: pendingToken });
  }
  if (tokenType === "manage_session") {
    const sessionToken = generateManageSessionToken(appSlug, user._id.toString());
    return res.json({ access_token: sessionToken, expires_in: 1800 });
  }
  // Para el flujo OAuth (callback de Neat) no usamos esta función — se maneja aparte
}

// POST /id/users/:slug/manage/2fa/setup
// Genera un nuevo secret TOTP y devuelve la URI para el QR. No activa 2FA todavía.
app.post("/id/users/:slug/manage/2fa/setup", manageSessionAuth, async (req, res) => {
  try {
    const { authenticator } = getOtplib();
    const secret = authenticator.generateSecret();
    const user = req.manageUser;
    const app = await req.manageDb.collection("id_apps").findOne({ slug: req.params.slug });

    // Guardamos el secret pendiente (no activo aún — se activa al verificar)
    await req.manageDb.collection("id_app_users").updateOne(
      { _id: user._id },
      { $set: { totpSecretPending: secret } }
    );

    const issuer = app?.name || "Neat ID";
    const otpauth = authenticator.keyuri(user.email, issuer, secret);
    res.json({ secret, otpauth });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Error interno" });
  }
});

// POST /id/users/:slug/manage/2fa/verify
// Confirma el código del autenticador y activa 2FA. Devuelve los backup codes.
app.post("/id/users/:slug/manage/2fa/verify", manageSessionAuth, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: "code requerido" });

    const { authenticator } = getOtplib();
    const user = req.manageUser;
    if (!user.totpSecretPending)
      return res.status(400).json({ error: "Inicia el setup primero" });

    const valid = authenticator.verify({ token: code.replace(/\s/g, ""), secret: user.totpSecretPending });
    if (!valid) return res.status(401).json({ error: "Código incorrecto" });

    const backupCodes = generateBackupCodes();
    const backupHashes = await Promise.all(backupCodes.map(c => bcrypt.hash(c, 8)));

    await req.manageDb.collection("id_app_users").updateOne(
      { _id: user._id },
      { $set: {
        totpSecret: user.totpSecretPending,
        totpSecretPending: null,
        totpEnabled: true,
        totpBackupCodes: backupHashes
      }}
    );
    res.json({ ok: true, backupCodes }); // solo se muestran una vez
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Error interno" });
  }
});

// POST /id/users/:slug/manage/2fa/disable
// Desactiva 2FA. Requiere el código actual del autenticador (o un backup code).
app.post("/id/users/:slug/manage/2fa/disable", manageSessionAuth, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: "code requerido" });

    const { authenticator } = getOtplib();
    const user = req.manageUser;
    if (!user.totpEnabled) return res.status(400).json({ error: "2FA no está activado" });

    const totpValid = authenticator.verify({ token: code.replace(/\s/g, ""), secret: user.totpSecret });
    let backupValid = false;
    let usedBackupIdx = -1;
    if (!totpValid && user.totpBackupCodes?.length) {
      for (let i = 0; i < user.totpBackupCodes.length; i++) {
        if (await bcrypt.compare(code.replace(/\s/g, "").toUpperCase(), user.totpBackupCodes[i])) {
          backupValid = true; usedBackupIdx = i; break;
        }
      }
    }
    if (!totpValid && !backupValid) return res.status(401).json({ error: "Código incorrecto" });

    await req.manageDb.collection("id_app_users").updateOne(
      { _id: user._id },
      { $set: { totpSecret: null, totpEnabled: false, totpBackupCodes: [], totpSecretPending: null } }
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Error interno" });
  }
});

// POST /id/users/:slug/manage/2fa/totp
// Canjea un totp_pending_token + código TOTP (o backup code) por el manage_session real
app.post("/id/users/:slug/manage/2fa/totp", async (req, res) => {
  try {
    const { totp_pending_token, code } = req.body;
    if (!totp_pending_token || !code) return res.status(400).json({ error: "totp_pending_token y code requeridos" });

    let payload;
    try {
      payload = jwt.verify(totp_pending_token, SECRET);
    } catch { return res.status(401).json({ error: "Token expirado o inválido" }); }

    if (payload.type !== "totp_pending" || payload.appSlug !== req.params.slug)
      return res.status(401).json({ error: "Token inválido para esta app" });

    const database = await getDb();
    const user = await database.collection("id_app_users").findOne({ _id: new ObjectId(payload.sub) });
    if (!user || user.suspended) return res.status(403).json({ error: "Usuario no disponible" });

    const { authenticator } = getOtplib();
    const totpValid = authenticator.verify({ token: code.replace(/\s/g, ""), secret: user.totpSecret });
    let backupValid = false;
    let usedBackupIdx = -1;
    if (!totpValid && user.totpBackupCodes?.length) {
      for (let i = 0; i < user.totpBackupCodes.length; i++) {
        if (await bcrypt.compare(code.replace(/\s/g, "").toUpperCase(), user.totpBackupCodes[i])) {
          backupValid = true; usedBackupIdx = i; break;
        }
      }
    }
    if (!totpValid && !backupValid) return res.status(401).json({ error: "Código incorrecto" });

    // Invalidar backup code usado
    if (backupValid && usedBackupIdx >= 0) {
      const newBackups = [...user.totpBackupCodes];
      newBackups.splice(usedBackupIdx, 1);
      await database.collection("id_app_users").updateOne(
        { _id: user._id }, { $set: { totpBackupCodes: newBackups } }
      );
    }

    // Según qué inició el flujo de 2FA, emitimos lo que corresponde:
    // - "manage_session" → sesión del panel /manage del dueño del tenant
    // - "oauth_code" → code OAuth2 para el login normal de un usuario final
    if (payload.tokenType === "oauth_code") {
      const oauth = payload.oauth || {};
      const client = await database.collection("id_app_clients").findOne({
        appSlug: req.params.slug, clientId: oauth.clientId
      });
      if (!client || client.suspended) return res.status(400).json({ error: "Client inválido o suspendido" });

      const result = await issueLocalOAuthCode(database, {
        user, appSlug: req.params.slug, client,
        redirectUri: oauth.redirectUri,
        codeChallenge: oauth.codeChallenge,
        codeChallengeMethod: oauth.codeChallengeMethod,
        state: oauth.state
      });
      if (result.error) return res.status(400).json({ error: result.error });
      return res.json(result);
    }

    const sessionToken = generateManageSessionToken(req.params.slug, user._id.toString());
    res.json({ access_token: sessionToken, expires_in: 1800 });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Error interno" });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// SOCIAL LOGIN (OIDC genérico, vía discovery URL) ──────────────────────────────
//
// Dos tipos de provider:
// - GLOBAL (social_providers_global): los configura el dueño de Neat (admin).
//   Pueden tener client_secret (confidential) porque el secret es de Neat, no
//   de un tercero — se guarda una sola vez, no por cada tenant.
// - TENANT (social_providers_tenant): cada dueño de app pone su propio
//   provider (ej. su propio Google). SIEMPRE PKCE, SIN client_secret —
//   Neat nunca guarda secrets ajenos. Sin excepciones, ni para Neat Plus.
//
// Ambos se configuran dando solo la discovery URL
// (.../.well-known/openid-configuration); Neat resuelve authorization_endpoint,
// token_endpoint y userinfo_endpoint automáticamente.
// ══════════════════════════════════════════════════════════════════════════════

// Cache simple en memoria del documento OIDC por discovery URL (60 min) —
// evita golpear el .well-known en cada login.
const oidcDiscoveryCache = new Map();

async function fetchOidcDiscovery(discoveryUrl) {
  const cached = oidcDiscoveryCache.get(discoveryUrl);
  if (cached && cached.expiresAt > Date.now()) return cached.doc;

  const res = await fetch(discoveryUrl);
  if (!res.ok) throw new Error("No se pudo leer la discovery URL (" + res.status + ")");
  const doc = await res.json();
  if (!doc.authorization_endpoint || !doc.token_endpoint)
    throw new Error("La discovery URL no parece un documento OIDC válido");

  oidcDiscoveryCache.set(discoveryUrl, { doc, expiresAt: Date.now() + 60 * 60 * 1000 });
  return doc;
}

function generatePkcePair() {
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  return { codeVerifier, codeChallenge };
}

// ── REGISTROS ABIERTOS/CERRADOS ───────────────────────────────────────────────
// PUT /id/apps/:slug/registrations
// Abre o cierra el registro público del tenant.
app.put("/id/apps/:slug/registrations", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const { open } = req.body;
    if (typeof open !== "boolean")
      return res.status(400).json({ error: "El campo 'open' debe ser booleano" });

    const database = await getDb();
    await database.collection("id_apps").updateOne(
      { slug: req.params.slug },
      { $set: { registrationsOpen: open } }
    );
    res.json({ ok: true, registrationsOpen: open });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── LÍMITE DE KV STORAGE POR TENANT ───────────────────────────────────────────
// PUT /id/apps/:slug/kv-limit
// El dueño del tenant ajusta el espacio de KV de su tenant. Son dos límites
// independientes porque tienen naturaleza distinta:
//   - limitKb       → KV privado, POR USUARIO (id_app_user_kv).
//                     Default: KV_PRIVATE_DEFAULT_BYTES (25KB). Techo: KV_PRIVATE_HARD_CAP_BYTES (1MB).
//   - publicLimitKb → KV público, UN SOLO blob por tenant (id_app_public_kv).
//                     No se multiplica por usuario, así que puede ser más generoso.
//                     Default: KV_PUBLIC_DEFAULT_BYTES (100KB). Techo: KV_PUBLIC_HARD_CAP_BYTES (5MB).
// Ninguno de los dos techos se puede pasar — protegen contra abuso/costos
// descontrolados a nivel de toda la plataforma, no solo de este tenant.
// body: { limitKb?: number, publicLimitKb?: number } — al menos uno de los dos.
// Los números van en KB (más cómodo desde el frontend); se guardan en bytes.
app.put("/id/apps/:slug/kv-limit", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const { limitKb, publicLimitKb } = req.body;
    if (limitKb === undefined && publicLimitKb === undefined)
      return res.status(400).json({ error: "Manda limitKb y/o publicLimitKb" });

    const $set = {};

    if (limitKb !== undefined) {
      const limitBytes = Number(limitKb) * 1024;
      if (!Number.isFinite(limitBytes) || limitBytes <= 0)
        return res.status(400).json({ error: "limitKb debe ser un número positivo" });
      if (limitBytes > KV_PRIVATE_HARD_CAP_BYTES)
        return res.status(400).json({ error: `limitKb no puede superar ${KV_PRIVATE_HARD_CAP_BYTES / 1024}KB` });
      $set.kvLimitBytes = Math.round(limitBytes);
    }

    if (publicLimitKb !== undefined) {
      const publicLimitBytes = Number(publicLimitKb) * 1024;
      if (!Number.isFinite(publicLimitBytes) || publicLimitBytes <= 0)
        return res.status(400).json({ error: "publicLimitKb debe ser un número positivo" });
      if (publicLimitBytes > KV_PUBLIC_HARD_CAP_BYTES)
        return res.status(400).json({ error: `publicLimitKb no puede superar ${KV_PUBLIC_HARD_CAP_BYTES / 1024}KB` });
      $set.kvPublicLimitBytes = Math.round(publicLimitBytes);
    }

    const database = await getDb();
    await database.collection("id_apps").updateOne(
      { slug: req.params.slug },
      { $set }
    );
    res.json({
      ok: true,
      kvLimitBytes: $set.kvLimitBytes ?? req.idApp.kvLimitBytes ?? KV_PRIVATE_DEFAULT_BYTES,
      kvPublicLimitBytes: $set.kvPublicLimitBytes ?? req.idApp.kvPublicLimitBytes ?? KV_PUBLIC_DEFAULT_BYTES
    });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── CREAR USUARIO DIRECTO (admin del tenant) ──────────────────────────────────
// POST /id/apps/:slug/users
// El admin crea un usuario sin que este se registre solo.
app.post("/id/apps/:slug/users", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const { email, password, username } = req.body;
    if (!email || !password) return res.status(400).json({ error: "email y password requeridos" });
    if (password.length < 6) return res.status(400).json({ error: "Password mínimo 6 caracteres" });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: "Email inválido" });

    const database = await getDb();
    const exists = await database.collection("id_app_users").findOne({
      appSlug: req.params.slug, email: email.toLowerCase()
    });
    if (exists) return res.status(409).json({ error: "Email ya registrado en esta app" });

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await database.collection("id_app_users").insertOne({
      appSlug: req.params.slug,
      email: email.toLowerCase(),
      username: username || email.split("@")[0],
      passwordHash,
      neatUserId: null,
      emailVerified: true, // creado por admin = verificado
      emailVerifToken: null,
      emailVerifExpiresAt: null,
      suspended: false,
      createdAt: new Date(),
      createdByAdmin: true
    });

    res.status(201).json({ ok: true, userId: result.insertedId });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── INVITACIONES POR LINK ─────────────────────────────────────────────────────
// POST /id/apps/:slug/invitations — crear invitación
// body: { expiresIn: "24h"|"48h"|"7d", maxUses: null|number } (null = ilimitado)
app.post("/id/apps/:slug/invitations", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const { expiresIn = "48h", maxUses } = req.body;

    const msMap = { "24h": 24*60*60*1000, "48h": 48*60*60*1000, "7d": 7*24*60*60*1000 };
    if (!msMap[expiresIn]) return res.status(400).json({ error: "expiresIn debe ser 24h, 48h o 7d" });

    // maxUses: null = ilimitado, 1 = único, N = N usos
    let parsedMaxUses = null;
    if (maxUses !== undefined && maxUses !== null) {
      parsedMaxUses = parseInt(maxUses);
      if (isNaN(parsedMaxUses) || parsedMaxUses < 1)
        return res.status(400).json({ error: "maxUses debe ser un número positivo o null" });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const database = await getDb();
    await database.collection("id_app_invitations").insertOne({
      appSlug: req.params.slug,
      token,
      maxUses: parsedMaxUses,
      uses: 0,
      expiresAt: new Date(Date.now() + msMap[expiresIn]),
      createdAt: new Date(),
      revoked: false
    });

    res.status(201).json({ ok: true, token, inviteUrl: `https://id.neat.qzz.io/${req.params.slug}?inviteToken=${token}` });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// GET /id/apps/:slug/invitations — listar invitaciones activas
app.get("/id/apps/:slug/invitations", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const database = await getDb();
    const invitations = await database.collection("id_app_invitations")
      .find({ appSlug: req.params.slug })
      .sort({ createdAt: -1 })
      .toArray();

    res.json({ invitations });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// DELETE /id/apps/:slug/invitations/:token — revocar invitación
app.delete("/id/apps/:slug/invitations/:token", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const database = await getDb();
    await database.collection("id_app_invitations").updateOne(
      { appSlug: req.params.slug, token: req.params.token },
      { $set: { revoked: true } }
    );
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// GET /id/apps/:slug/invitations/:token/validate — valida un token de invitación (público, lo llama el frontend)
app.get("/id/apps/:slug/invitations/:token/validate", async (req, res) => {
  try {
    const database = await getDb();
    const inv = await database.collection("id_app_invitations").findOne({
      appSlug: req.params.slug, token: req.params.token
    });
    if (!inv) return res.status(404).json({ error: "Invitación no encontrada" });
    if (inv.revoked) return res.status(410).json({ error: "Invitación revocada" });
    if (new Date() > inv.expiresAt) return res.status(410).json({ error: "Invitación expirada" });
    if (inv.maxUses !== null && inv.uses >= inv.maxUses)
      return res.status(410).json({ error: "Invitación agotada" });

    res.json({ ok: true, appSlug: req.params.slug });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── GRUPOS CON ROLES ──────────────────────────────────────────────────────────
// POST /id/apps/:slug/groups — crear grupo
// body: { name, key, description }
app.post("/id/apps/:slug/groups", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const { name, key, description } = req.body;
    if (!name || !key) return res.status(400).json({ error: "name y key requeridos" });
    if (!/^[a-z0-9-]+$/.test(key))
      return res.status(400).json({ error: "key solo puede contener letras minúsculas, números y guiones" });

    const database = await getDb();
    const exists = await database.collection("id_app_groups").findOne({
      appSlug: req.params.slug, key
    });
    if (exists) return res.status(409).json({ error: "Ya existe un grupo con ese key" });

    await database.collection("id_app_groups").insertOne({
      appSlug: req.params.slug,
      name,
      key,
      description: description || null,
      createdAt: new Date()
    });

    res.status(201).json({ ok: true });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// GET /id/apps/:slug/groups — listar grupos del tenant
app.get("/id/apps/:slug/groups", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const database = await getDb();
    const groups = await database.collection("id_app_groups")
      .find({ appSlug: req.params.slug })
      .sort({ createdAt: 1 })
      .toArray();

    res.json({ groups });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// PUT /id/apps/:slug/groups/:key — editar nombre/descripción de un grupo
app.put("/id/apps/:slug/groups/:key", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const { name, description } = req.body;
    const database = await getDb();
    await database.collection("id_app_groups").updateOne(
      { appSlug: req.params.slug, key: req.params.key },
      { $set: { name, description: description || null } }
    );
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// DELETE /id/apps/:slug/groups/:key — eliminar grupo y sus membresías
app.delete("/id/apps/:slug/groups/:key", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const database = await getDb();
    await database.collection("id_app_groups").deleteOne({ appSlug: req.params.slug, key: req.params.key });
    await database.collection("id_app_memberships").deleteMany({ appSlug: req.params.slug, groupKey: req.params.key });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// GET /id/apps/:slug/groups/:key/members — listar miembros de un grupo
app.get("/id/apps/:slug/groups/:key/members", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const database = await getDb();
    const memberships = await database.collection("id_app_memberships")
      .find({ appSlug: req.params.slug, groupKey: req.params.key })
      .toArray();

    // Enriquecer con datos del usuario
    const userIds = memberships.map(m => new ObjectId(m.userId));
    const users = await database.collection("id_app_users")
      .find({ _id: { $in: userIds } }, { projection: { passwordHash: 0 } })
      .toArray();
    const userMap = Object.fromEntries(users.map(u => [u._id.toString(), u]));

    const result = memberships.map(m => ({
      ...m,
      user: userMap[m.userId] || null
    }));

    res.json({ members: result });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// PUT /id/apps/:slug/groups/:key/members/:userId — agregar o actualizar roles de un miembro
// body: { roles: ["admin", "member", ...] }
app.put("/id/apps/:slug/groups/:key/members/:userId", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const { roles = [] } = req.body;
    if (!Array.isArray(roles)) return res.status(400).json({ error: "roles debe ser un array" });

    const database = await getDb();

    // Verificar que el grupo y el usuario existen en este tenant
    const group = await database.collection("id_app_groups").findOne({ appSlug: req.params.slug, key: req.params.key });
    if (!group) return res.status(404).json({ error: "Grupo no encontrado" });

    const user = await database.collection("id_app_users").findOne({
      _id: new ObjectId(req.params.userId), appSlug: req.params.slug
    });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    await database.collection("id_app_memberships").updateOne(
      { appSlug: req.params.slug, groupKey: req.params.key, userId: req.params.userId },
      { $set: { roles, updatedAt: new Date() }, $setOnInsert: { createdAt: new Date() } },
      { upsert: true }
    );

    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "ID inválido" });
  }
});

// DELETE /id/apps/:slug/groups/:key/members/:userId — quitar miembro del grupo
app.delete("/id/apps/:slug/groups/:key/members/:userId", tenantAuth, async (req, res) => {
  try {
    if (req.idApp.slug !== req.params.slug)
      return res.status(403).json({ error: "Credenciales no corresponden a esta app" });

    const database = await getDb();
    await database.collection("id_app_memberships").deleteOne({
      appSlug: req.params.slug, groupKey: req.params.key, userId: req.params.userId
    });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── Providers GLOBALES (los configura el dueño de Neat) ──────────────────────

// POST /id/social/global — crear/configurar un provider global. Solo admin.
// body: { key, name, discoveryUrl, clientId, clientSecret, scope }
app.post("/id/social/global", auth, requireAuth, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ error: "Solo el admin de Neat puede configurar providers globales" });

    const { key, name, discoveryUrl, clientId, clientSecret, scope } = req.body;
    if (!key || !name || !discoveryUrl || !clientId)
      return res.status(400).json({ error: "key, name, discoveryUrl y clientId son requeridos" });

    let discovery;
    try {
      discovery = await fetchOidcDiscovery(discoveryUrl);
    } catch (e) {
      return res.status(400).json({ error: "Discovery URL inválida: " + e.message });
    }

    const database = await getDb();
    await database.collection("social_providers_global").updateOne(
      { key },
      {
        $set: {
          key, name, discoveryUrl,
          authorizationEndpoint: discovery.authorization_endpoint,
          tokenEndpoint: discovery.token_endpoint,
          userinfoEndpoint: discovery.userinfo_endpoint || null,
          clientId,
          clientSecret: clientSecret || null,  // confidential si se da, si no actúa como público
          scope: scope || "openid profile email",
          enabled: true,
          updatedAt: new Date()
        },
        $setOnInsert: { createdAt: new Date() }
      },
      { upsert: true }
    );
    res.json({ ok: true, key });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// GET /id/social/global — listar providers globales (sin el secret), para que
// cualquier tenant vea cuáles puede activar.
app.get("/id/social/global", auth, requireAuth, async (req, res) => {
  try {
    const database = await getDb();
    const providers = await database.collection("social_providers_global")
      .find({}, { projection: { clientSecret: 0 } }).toArray();
    res.json(providers);
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// DELETE /id/social/global/:key — solo admin
app.delete("/id/social/global/:key", auth, requireAuth, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ error: "Solo el admin de Neat puede hacer esto" });
    const database = await getDb();
    await database.collection("social_providers_global").deleteOne({ key: req.params.key });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── Providers POR TENANT (cada dueño de app pone el suyo) ────────────────────
// SIEMPRE PKCE — nunca se acepta ni se guarda client_secret aquí.

// POST /id/apps/:slug/social — crear provider propio del tenant
// body: { key, name, discoveryUrl, clientId, scope }
app.post("/id/apps/:slug/social", auth, requireAuth, async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.ownerUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const { key, name, discoveryUrl, clientId, scope } = req.body;
    if (!key || !name || !discoveryUrl || !clientId)
      return res.status(400).json({ error: "key, name, discoveryUrl y clientId son requeridos" });

    let discovery;
    try {
      discovery = await fetchOidcDiscovery(discoveryUrl);
    } catch (e) {
      return res.status(400).json({ error: "Discovery URL inválida: " + e.message });
    }

    await database.collection("social_providers_tenant").updateOne(
      { appSlug: req.params.slug, key },
      {
        $set: {
          appSlug: req.params.slug, key, name, discoveryUrl,
          authorizationEndpoint: discovery.authorization_endpoint,
          tokenEndpoint: discovery.token_endpoint,
          userinfoEndpoint: discovery.userinfo_endpoint || null,
          clientId,
          // Nunca clientSecret aquí — PKCE siempre, sin excepción.
          scope: scope || "openid profile email",
          enabled: true,
          updatedAt: new Date()
        },
        $setOnInsert: { createdAt: new Date() }
      },
      { upsert: true }
    );
    res.json({ ok: true, key });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// GET /id/apps/:slug/social — listar providers propios del tenant
app.get("/id/apps/:slug/social", auth, requireAuth, async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.ownerUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const providers = await database.collection("social_providers_tenant")
      .find({ appSlug: req.params.slug }).toArray();
    res.json(providers);
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// PUT /id/apps/:slug/social/:key — activar/desactivar (propio o un global que el tenant adoptó)
app.put("/id/apps/:slug/social/:key", auth, requireAuth, async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.ownerUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    const { enabled } = req.body;
    const tenantProvider = await database.collection("social_providers_tenant")
      .findOne({ appSlug: req.params.slug, key: req.params.key });

    if (tenantProvider) {
      await database.collection("social_providers_tenant").updateOne(
        { _id: tenantProvider._id }, { $set: { enabled: !!enabled } }
      );
      return res.json({ ok: true });
    }

    // Si no es un provider propio, es la activación de un GLOBAL para este tenant
    await database.collection("id_apps").updateOne(
      { slug: req.params.slug },
      enabled
        ? { $addToSet: { enabledGlobalProviders: req.params.key } }
        : { $pull: { enabledGlobalProviders: req.params.key } }
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// DELETE /id/apps/:slug/social/:key — elimina un provider propio del tenant
app.delete("/id/apps/:slug/social/:key", auth, requireAuth, async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });
    if (app.ownerUsername !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ error: "Sin permisos" });

    await database.collection("social_providers_tenant")
      .deleteOne({ appSlug: req.params.slug, key: req.params.key });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// Resuelve un provider activo (global o de tenant) para un appSlug+key dado.
// Devuelve { provider, isGlobal } o null.
async function resolveActiveSocialProvider(database, appSlug, key) {
  const tenantProvider = await database.collection("social_providers_tenant")
    .findOne({ appSlug, key, enabled: true });
  if (tenantProvider) return { provider: tenantProvider, isGlobal: false };

  const app = await database.collection("id_apps").findOne({ slug: appSlug });
  if (app?.enabledGlobalProviders?.includes(key)) {
    const globalProvider = await database.collection("social_providers_global")
      .findOne({ key, enabled: true });
    if (globalProvider) return { provider: globalProvider, isGlobal: true };
  }
  return null;
}

// GET /id/apps/:slug/social/available — providers activos para el LOGIN
// (combina los propios del tenant + los globales que activó), sin datos
// sensibles. Lo usa la hosted login page para mostrar los botones.
app.get("/id/apps/:slug/social/available", async (req, res) => {
  try {
    const database = await getDb();
    const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
    if (!app) return res.status(404).json({ error: "App no encontrada" });

    const tenantProviders = await database.collection("social_providers_tenant")
      .find({ appSlug: req.params.slug, enabled: true }, { projection: { name: 1, key: 1 } }).toArray();

    let globalProviders = [];
    if (app.enabledGlobalProviders?.length) {
      globalProviders = await database.collection("social_providers_global")
        .find({ key: { $in: app.enabledGlobalProviders }, enabled: true }, { projection: { name: 1, key: 1 } }).toArray();
    }

    res.json([
      ...tenantProviders.map(p => ({ key: p.key, name: p.name })),
      ...globalProviders.map(p => ({ key: p.key, name: p.name }))
    ]);
  } catch {
    res.status(500).json({ error: "Error interno" });
  }
});

// ── Flujo de login social (PKCE siempre hacia el provider) ───────────────────

// GET /id/users/:slug/social/:key/start
// Redirige al authorization_endpoint del provider. Guarda el code_verifier y
// los datos OAuth del tenant en una cookie-less "social_login_state" en Mongo
// (más simple y sin depender de sesión de navegador para el state).
// query: redirectUri, clientId (del tenant), codeChallenge, codeChallengeMethod, state
app.get("/id/users/:slug/social/:key/start", async (req, res) => {
  try {
    const database = await getDb();
    const resolved = await resolveActiveSocialProvider(database, req.params.slug, req.params.key);
    if (!resolved) return res.status(404).send("Provider social no disponible para esta app");
    const { provider, isGlobal } = resolved;

    const { codeVerifier, codeChallenge } = generatePkcePair();
    const flowId = crypto.randomBytes(24).toString("hex");
    const callbackUri = `${NEAT_ID_BASE}/id/users/${req.params.slug}/social/${req.params.key}/callback`;

    await database.collection("social_login_flows").insertOne({
      flowId,
      appSlug: req.params.slug,
      providerKey: req.params.key,
      codeVerifier,
      // Datos OAuth del TENANT que originó este login — para emitir su code al volver
      tenant: {
        clientId: req.query.clientId || null,
        redirectUri: req.query.redirectUri || null,
        codeChallenge: req.query.codeChallenge || null,
        codeChallengeMethod: req.query.codeChallengeMethod || "S256",
        state: req.query.state || null
      },
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    });

    const params = new URLSearchParams({
      response_type: "code",
      client_id: provider.clientId,
      redirect_uri: callbackUri,
      scope: provider.scope || "openid profile email",
      state: flowId,
      code_challenge: codeChallenge,
      code_challenge_method: "S256"
    });
    res.redirect(`${provider.authorizationEndpoint}?${params.toString()}`);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error interno");
  }
});

// GET /id/users/:slug/social/:key/callback
// El provider redirige aquí. Canjea el code, obtiene el perfil, y resuelve la
// cuenta local — igual patrón que el callback de Neat (/id/callback).
app.get("/id/users/:slug/social/:key/callback", async (req, res) => {
  try {
    const { code, state: flowId } = req.query;
    if (!code || !flowId) return res.status(400).send("Parámetros faltantes");

    const database = await getDb();
    const flow = await database.collection("social_login_flows").findOne({ flowId });
    if (!flow || flow.expiresAt < new Date()) return res.status(400).send("El intento de login expiró, intenta de nuevo");

    const resolved = await resolveActiveSocialProvider(database, req.params.slug, req.params.key);
    if (!resolved) return res.status(404).send("Provider social no disponible para esta app");
    const { provider } = resolved;

    const callbackUri = `${NEAT_ID_BASE}/id/users/${req.params.slug}/social/${req.params.key}/callback`;

    // Intercambiar code → access_token. PKCE siempre; client_secret solo si
    // el provider lo tiene configurado (únicamente posible en globales).
    const tokenBody = {
      grant_type: "authorization_code",
      code,
      redirect_uri: callbackUri,
      client_id: provider.clientId,
      code_verifier: flow.codeVerifier
    };
    if (provider.clientSecret) tokenBody.client_secret = provider.clientSecret;

    const tokenRes = await fetch(provider.tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(tokenBody)
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      console.error("Token endpoint error:", tokenData);
      return res.status(400).send("No se pudo completar el login con " + provider.name);
    }

    let profile = {};
    if (provider.userinfoEndpoint) {
      const userinfoRes = await fetch(provider.userinfoEndpoint, {
        headers: { Authorization: `Bearer ${tokenData.access_token}` }
      });
      profile = await userinfoRes.json();
    }
    const providerSub = profile.sub || profile.id;
    if (!providerSub) return res.status(400).send("El proveedor no devolvió un identificador de usuario");

    await database.collection("social_login_flows").deleteOne({ _id: flow._id });

    const { tenant } = flow;
    const client = tenant.clientId
      ? await database.collection("id_app_clients").findOne({ appSlug: req.params.slug, clientId: tenant.clientId })
      : await database.collection("id_app_clients").findOne({ appSlug: req.params.slug, isDefault: true });
    if (!client) return res.status(400).send("client_id inválido para esta app");
    if (!tenant.redirectUri || !client.redirectUris.includes(tenant.redirectUri))
      return res.status(400).send("redirect_uri no autorizada para este client");

    const providerIdField = `social_${req.params.key}_sub`;

    let user = await database.collection("id_app_users").findOne({
      appSlug: req.params.slug,
      [providerIdField]: providerSub
    });

    if (!user && profile.email) {
      // Hay una cuenta local con el mismo email pero sin vincular este
      // provider todavía. No vinculamos automático — el usuario debe
      // confirmar con su contraseña local (paso separado, ver
      // /social/:key/link-existing). Por ahora lo mandamos a esa pantalla.
      const emailMatch = await database.collection("id_app_users").findOne({
        appSlug: req.params.slug,
        email: profile.email.toLowerCase(),
        [providerIdField]: { $exists: false }
      });
      if (emailMatch && emailMatch.passwordHash) {
        const linkToken = jwt.sign(
          {
            type: "social_link_pending", appSlug: req.params.slug,
            existingUserId: emailMatch._id.toString(),
            providerKey: req.params.key, providerSub, profileEmail: profile.email,
            tenant
          },
          SECRET, { expiresIn: "10m" }
        );
        const params = new URLSearchParams({ link_token: linkToken, email: profile.email });
        return res.redirect(`/${req.params.slug}?${params.toString()}`);
      }
    }

    if (!user) {
      // Sin cuenta previa → crear una nueva, vinculada a este provider, salvo
      // que el tenant tenga los registros cerrados. Igual que con "Continuar
      // con Neat", el login social no tiene forma de llevar un inviteToken,
      // así que aquí tampoco hay excepción por invitación.
      const app = await database.collection("id_apps").findOne({ slug: req.params.slug });
      if (app && app.registrationsOpen === false) {
        return res.redirect(`${tenant.redirectUri}?error=access_denied&error_description=${encodeURIComponent("Los registros están cerrados para esta aplicación. Necesitas que un administrador te invite o cree tu cuenta.")}`);
      }
      const result = await database.collection("id_app_users").insertOne({
        appSlug: req.params.slug,
        email: (profile.email || `${providerSub}@${req.params.key}.social`).toLowerCase(),
        username: profile.name || profile.preferred_username || profile.email || providerSub,
        passwordHash: null,
        [providerIdField]: providerSub,
        // Entrar con un proveedor social ya es una verificación de identidad
        // suficiente — nunca se manda correo de verificación para esto,
        // sin importar el ajuste de verificación obligatoria del tenant.
        emailVerified: true,
        suspended: false,
        createdAt: new Date()
      });
      user = await database.collection("id_app_users").findOne({ _id: result.insertedId });
    }

    if (user.suspended)
      return res.redirect(`${tenant.redirectUri}?error=access_denied&error_description=${encodeURIComponent("Tu cuenta de esta app está suspendida.")}`);

    const oauthResult = await issueLocalOAuthCode(database, {
      user, appSlug: req.params.slug, client,
      redirectUri: tenant.redirectUri,
      codeChallenge: tenant.codeChallenge,
      codeChallengeMethod: tenant.codeChallengeMethod,
      state: tenant.state,
      type: "id_app_social"
    });
    if (oauthResult.error)
      return res.redirect(`${tenant.redirectUri}?error=invalid_request&error_description=${encodeURIComponent(oauthResult.error)}`);

    // El navegador vuelve directo al tenant (no a esta página), así que el
    // pageSessionToken no tiene dónde guardarse para "vincular Neat" después
    // en el mismo flujo — eso es exclusivo de la hosted login page cuando el
    // login ocurre ahí mismo (local/TOTP). El social login redirige fuera, así
    // que esa oferta simplemente no aplica aquí; el code y el redirect sí.
    const params = new URLSearchParams({ code: oauthResult.code });
    if (oauthResult.state) params.set("state", oauthResult.state);
    res.redirect(`${oauthResult.redirectUri}?${params.toString()}`);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error interno");
  }
});

// POST /id/users/:slug/social/link-existing
// Confirma con la contraseña LOCAL de la cuenta existente que el usuario es
// quien dice ser, y vincula el provider social a esa cuenta.
// body: { link_token, password }
app.post("/id/users/:slug/social/link-existing", async (req, res) => {
  try {
    const { link_token, password } = req.body;
    if (!link_token || !password) return res.status(400).json({ error: "link_token y password requeridos" });

    let payload;
    try { payload = jwt.verify(link_token, SECRET); }
    catch { return res.status(401).json({ error: "El enlace de vinculación expiró, inicia el login de nuevo" }); }
    if (payload.type !== "social_link_pending" || payload.appSlug !== req.params.slug)
      return res.status(401).json({ error: "Token inválido para esta app" });

    const database = await getDb();
    const user = await database.collection("id_app_users").findOne({ _id: new ObjectId(payload.existingUserId) });
    if (!user) return res.status(404).json({ error: "Cuenta no encontrada" });

    const valid = await bcrypt.compare(password, user.passwordHash || "");
    if (!valid) return res.status(401).json({ error: "Contraseña incorrecta" });
    if (user.suspended) return res.status(403).json({ error: "Cuenta suspendida en esta app" });

    const providerIdField = `social_${payload.providerKey}_sub`;
    await database.collection("id_app_users").updateOne(
      { _id: user._id },
      { $set: { [providerIdField]: payload.providerSub, emailVerified: true } }
    );

    const client = payload.tenant.clientId
      ? await database.collection("id_app_clients").findOne({ appSlug: req.params.slug, clientId: payload.tenant.clientId })
      : await database.collection("id_app_clients").findOne({ appSlug: req.params.slug, isDefault: true });
    if (!client) return res.status(400).json({ error: "client_id inválido para esta app" });

    const result = await issueLocalOAuthCode(database, {
      user, appSlug: req.params.slug, client,
      redirectUri: payload.tenant.redirectUri,
      codeChallenge: payload.tenant.codeChallenge,
      codeChallengeMethod: payload.tenant.codeChallengeMethod,
      state: payload.tenant.state,
      type: "id_app_social"
    });
    if (result.error) return res.status(400).json({ error: result.error });

    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// ── Health ─────────────────────────────────────────────────────────────────────
app.get("/", (req, res) => res.json({ status: "ok", service: "neat-api", version: "2.0" }));


// ═══════════════════════════════════════════════════════════════════
// AGENTES — gateway agents.neat.qzz.io (v0)
// INSTRUCCIONES: pegar este bloque en neat-apps-b/index.js (al final,
// antes de app.listen). Es 100% ADITIVO: no toca nada existente.
// Variables de entorno requeridas en Vercel:
//   NEAT_INTERNAL_SECRET  (secreto compartido Worker↔Vercel)
//   AGENTS_WORKER_URL     (default https://agents.neat.qzz.io)
// ═══════════════════════════════════════════════════════════════════

const AGENTS_WORKER_URL = process.env.AGENTS_WORKER_URL || "https://agents.neat.qzz.io";

// Solo llamadas del Worker con el secreto interno. FAIL-CLOSED: si el
// secreto no está configurado en Vercel, NIEGA TODO (no modo abierto).
function internalAuth(req, res, next) {
  const expected = process.env.NEAT_INTERNAL_SECRET;
  const got = req.headers["x-neat-internal"];
  if (!expected) return res.status(503).json({ success: false, error: { code: "NOT_CONFIGURED", message: "Gateway de agentes no configurado.", fix: "El admin debe definir NEAT_INTERNAL_SECRET en Vercel." } });
  if (!got || got !== expected) return res.status(403).json({ success: false, error: { code: "FORBIDDEN", message: "Secreto interno inválido.", fix: "Este endpoint solo lo llama el gateway de agentes." } });
  next();
}
function agentUser(req) {
  const u = req.headers["x-agent-user"];
  return /^[a-zA-Z0-9_]{3,30}$/.test(u || "") ? u : null;
}

// ── Provisioning de keys (humano autenticado → Worker) ──
app.post("/agents/keys", auth, requireAuth, async (req, res) => {
  try {
    const label = (req.body?.label || "").slice(0, 60) || null;
    const r = await fetch(`${AGENTS_WORKER_URL}/admin/keys`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-neat-internal": process.env.NEAT_INTERNAL_SECRET || "" },
      body: JSON.stringify({ username: req.user.username, label }),
    });
    const j = await r.json().catch(() => null);
    if (!r.ok || !j?.success) return res.status(502).json({ success: false, error: { code: "WORKER_ERROR", message: "El gateway de agentes respondió error.", fix: "Reintenta en unos segundos; si persiste, revisa AGENTS_WORKER_URL y NEAT_INTERNAL_SECRET." } });
    res.status(201).json(j); // incluye la key en claro UNA sola vez — mostrar al humano y no persistir
  } catch (e) { console.error("[agents/keys]", e.message); res.status(502).json({ success: false, error: { code: "WORKER_UNREACHABLE", message: "No se pudo contactar el gateway.", fix: "Reintenta en unos segundos." } }); }
});

app.get("/agents/keys", auth, requireAuth, async (req, res) => {
  try {
    const r = await fetch(`${AGENTS_WORKER_URL}/admin/keys?username=${encodeURIComponent(req.user.username)}`, {
      headers: { "x-neat-internal": process.env.NEAT_INTERNAL_SECRET || "" },
    });
    const j = await r.json().catch(() => null);
    res.json(j || { success: false, error: { code: "WORKER_ERROR", message: "Respuesta inválida del gateway.", fix: "Reintenta." } });
  } catch { res.status(502).json({ success: false, error: { code: "WORKER_UNREACHABLE", message: "No se pudo contactar el gateway.", fix: "Reintenta en unos segundos." } }); }
});

app.delete("/agents/keys/:id", auth, requireAuth, async (req, res) => {
  try {
    const r = await fetch(`${AGENTS_WORKER_URL}/admin/keys/${encodeURIComponent(req.params.id)}`, {
      method: "DELETE",
      headers: { "x-neat-internal": process.env.NEAT_INTERNAL_SECRET || "" },
    });
    const j = await r.json().catch(() => null);
    res.json(j || { success: false, error: { code: "WORKER_ERROR", message: "Respuesta inválida del gateway.", fix: "Reintenta." } });
  } catch { res.status(502).json({ success: false, error: { code: "WORKER_UNREACHABLE", message: "No se pudo contactar el gateway.", fix: "Reintenta en unos segundos." } }); }
});

// ── Datos internos (SOLO el Worker: internalAuth + X-Agent-User) ──
// Notas de agentes nacen visibility=private, marcadas con via:'agent'.

app.post("/agents/internal/notes", internalAuth, async (req, res) => {
  try {
    const username = agentUser(req);
    if (!username) return res.status(400).json({ success: false, error: { code: "BAD_AGENT_USER", message: "X-Agent-User inválido.", fix: "Header requerido, 3-30 chars alfanumérico/_." } });
    const { title, content, visibility: vis, tags } = req.body || {};
    if (!content || typeof content !== "string") return res.status(400).json({ success: false, error: { code: "NO_CONTENT", message: "content requerido (string).", fix: "Envía {content: '...'} en Markdown." } });
    if (content.length > 65536) return res.status(413).json({ success: false, error: { code: "TOO_BIG", message: "Máximo 64 KB por nota.", fix: "Divide la nota en varias." } });

    const database = await getDb();
    let noteId = randomNoteId();
    while (await database.collection("notes").findOne({ noteId })) noteId = randomNoteId();
    const visibility = ["public", "unlisted", "private"].includes(vis) ? vis : "private";
    const note = {
      noteId, title: title || null, content,
      tags: Array.isArray(tags) ? tags.slice(0, 10).map(String) : [],
      authorUsername: username, via: "agent",
      visibility, passwordHash: null, hasPassword: false,
      history: [], createdAt: new Date(), updatedAt: new Date(),
    };
    await database.collection("notes").insertOne(note);
    res.status(201).json({ success: true, data: { noteId, title: note.title, visibility, createdAt: note.createdAt } });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: { code: "INTERNAL", message: "Error interno.", fix: "Reintenta con backoff (1s, 5s, 30s)." } }); }
});

app.get("/agents/internal/notes", internalAuth, async (req, res) => {
  try {
    const username = agentUser(req);
    if (!username) return res.status(400).json({ success: false, error: { code: "BAD_AGENT_USER", message: "X-Agent-User inválido.", fix: "Header requerido." } });
    const limit = Math.min(parseInt(req.query.limit || "20", 10) || 20, 100);
    const offset = parseInt(req.query.offset || "0", 10) || 0;
    const filter = { authorUsername: username };
    if (req.query.updated_since) {
      const since = new Date(req.query.updated_since);
      if (!isNaN(since)) filter.updatedAt = { $gt: since };
    }
    if (req.query.tag) filter.tags = String(req.query.tag);
    if (req.query.q) {
      const q = String(req.query.q).slice(0, 100);
      filter.$or = [{ title: { $regex: q, $options: "i" } }, { content: { $regex: q, $options: "i" } }];
    }
    const projection = { passwordHash: 0, history: 0 };
    if (req.query.expand !== "content") projection.content = 0;
    const database = await getDb();
    const [notes, total] = await Promise.all([
      database.collection("notes").find(filter, { projection }).sort({ updatedAt: -1 }).skip(offset).limit(limit).toArray(),
      database.collection("notes").countDocuments(filter),
    ]);
    res.json({ success: true, data: { notes, total } });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: { code: "INTERNAL", message: "Error interno.", fix: "Reintenta con backoff (1s, 5s, 30s)." } }); }
});

app.get("/agents/internal/notes/:id", internalAuth, async (req, res) => {
  try {
    const username = agentUser(req);
    if (!username) return res.status(400).json({ success: false, error: { code: "BAD_AGENT_USER", message: "X-Agent-User inválido.", fix: "Header requerido." } });
    const database = await getDb();
    const note = await database.collection("notes").findOne({ noteId: req.params.id, authorUsername: username }, { projection: { passwordHash: 0 } });
    if (!note) return res.status(404).json({ success: false, error: { code: "NOT_FOUND", message: "Nota no encontrada.", fix: "Verifica el id; lista las tuyas con GET /api/v1/notes." } });
    const { _id, ...safe } = note;
    res.json({ success: true, data: safe });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: { code: "INTERNAL", message: "Error interno.", fix: "Reintenta con backoff." } }); }
});

app.patch("/agents/internal/notes/:id", internalAuth, async (req, res) => {
  try {
    const username = agentUser(req);
    if (!username) return res.status(400).json({ success: false, error: { code: "BAD_AGENT_USER", message: "X-Agent-User inválido.", fix: "Header requerido." } });
    const database = await getDb();
    const note = await database.collection("notes").findOne({ noteId: req.params.id, authorUsername: username });
    if (!note) return res.status(404).json({ success: false, error: { code: "NOT_FOUND", message: "Nota no encontrada.", fix: "Verifica el id con GET /api/v1/notes." } });

    const { title, content, visibility: vis, tags } = req.body || {};
    if (content !== undefined && (typeof content !== "string" || content.length > 65536))
      return res.status(413).json({ success: false, error: { code: "TOO_BIG", message: "content debe ser string ≤64 KB.", fix: "Divide la nota." } });
    const historyEntry = { title: note.title, content: note.content, savedAt: note.updatedAt };
    const update = { updatedAt: new Date(), history: [historyEntry, ...(note.history || [])].slice(0, 2) };
    if (title !== undefined) update.title = title;
    if (content !== undefined) update.content = content;
    if (tags !== undefined) update.tags = Array.isArray(tags) ? tags.slice(0, 10).map(String) : [];
    if (vis !== undefined) {
      if (!["public", "unlisted", "private"].includes(vis))
        return res.status(400).json({ success: false, error: { code: "BAD_VISIBILITY", message: "visibility inválido.", fix: "Usa public, unlisted o private." } });
      update.visibility = vis;
    }
    await database.collection("notes").updateOne({ noteId: req.params.id }, { $set: update });
    res.json({ success: true, data: { noteId: req.params.id, updatedAt: update.updatedAt } });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: { code: "INTERNAL", message: "Error interno.", fix: "Reintenta con backoff." } }); }
});

app.delete("/agents/internal/notes/:id", internalAuth, async (req, res) => {
  try {
    const username = agentUser(req);
    if (!username) return res.status(400).json({ success: false, error: { code: "BAD_AGENT_USER", message: "X-Agent-User inválido.", fix: "Header requerido." } });
    const database = await getDb();
    const r = await database.collection("notes").deleteOne({ noteId: req.params.id, authorUsername: username });
    if (!r.deletedCount) return res.status(404).json({ success: false, error: { code: "NOT_FOUND", message: "Nota no encontrada.", fix: "Verifica el id con GET /api/v1/notes." } });
    res.json({ success: true, tip: "Nota eliminada permanentemente." });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: { code: "INTERNAL", message: "Error interno.", fix: "Reintenta con backoff." } }); }
});


// ── Nudge: el agente notifica a su humano (agents.neat.qzz.io v0.2) ──
app.post("/agents/internal/nudge", internalAuth, async (req, res) => {
  try {
    const username = agentUser(req);
    if (!username) return res.status(400).json({ success: false, error: { code: "BAD_AGENT_USER", message: "X-Agent-User inválido.", fix: "Header requerido." } });
    const { message } = req.body || {};
    if (!message || typeof message !== "string" || !message.trim())
      return res.status(400).json({ success: false, error: { code: "NO_MESSAGE", message: "message requerido (string).", fix: "Envía {message: 'texto corto'}." } });
    const text = message.trim().slice(0, 300);

    const database = await getDb();
    const user = await database.collection("users").findOne({ username });
    if (!user?.ntfyTopic)
      return res.status(404).json({ success: false, error: { code: "NO_NTFY", message: "Este humano no tiene notificaciones activadas.", fix: "El humano debe activar Ntfy en su app (actualmente requiere Neat Plus)." } });

    // El topic vive en el mismo servidor ntfy que usa el resto de la app (push.tchncs.de).
    // NTFY_BASE permite apuntar a otro servidor self-hosted sin tocar código.
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(user.ntfyTopic))
      return res.status(500).json({ success: false, error: { code: "BAD_TOPIC", message: "ntfyTopic con formato inesperado.", fix: "Re-genera el topic con /ntfy/setup." } });
    // ntfy "JSON publish": los headers HTTP planos NO aceptan UTF-8 (undici tira
    // TypeError con el 🦞). El JSON publish es la vía oficial de ntfy para no-ASCII:
    // POST al root del servidor con el topic dentro del body JSON (UTF-8 seguro).
    const ntfyBase = (process.env.NTFY_BASE || "https://push.tchncs.de").replace(/\/+$/, "");
    const nr = await fetch(ntfyBase, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ topic: user.ntfyTopic, title: `🦞 Agente de ${username}`, tags: ["robot"], message: text }),
    });
    if (!nr.ok) return res.status(502).json({ success: false, error: { code: "NTFY_ERROR", message: "El servidor ntfy respondió error.", fix: "Reintenta en unos segundos." } });

    await database.collection("agent_nudges").insertOne({ username, message: text, via: "agent", createdAt: new Date() });
    res.json({ success: true, tip: "Nudge entregado a tu humano 📣" });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: { code: "INTERNAL", message: "Error interno.", fix: "Reintenta con backoff." } }); }
});

// ── Chatter para agentes (puerta del gateway scope chatter, v0.3) ──
// Emula el modelo humano existente: chats.participants=[usernames], messages.chatId=string.
// Reglas: provenance siempre (via:"agent" + prefijo 🦞 visible en cualquier cliente),
// membership estricta, y reutiliza notifyParticipants (push ntfy/web-push ya existente).

app.get("/agents/internal/chatter/chats", internalAuth, async (req, res) => {
  try {
    const username = agentUser(req);
    if (!username) return res.status(400).json({ success: false, error: { code: "BAD_AGENT_USER", message: "X-Agent-User inválido.", fix: "Header requerido." } });
    const database = await getDb();
    const chats = await database.collection("chats")
      .find({ participants: username })
      .sort({ updatedAt: -1 }).limit(50).toArray();
    res.json({ success: true, data: chats.map((c) => ({
      chatId: String(c._id), name: c.name, type: c.type,
      participants: c.participants, lastMessage: c.lastMessage || null, updatedAt: c.updatedAt,
    })), tip: chats.length ? "Usa GET /chats/{chatId}/messages?since= para leer lo nuevo." : "Sin chats aún. Tu humano puede crear uno en la app de Chatter." });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: { code: "INTERNAL", message: "Error interno.", fix: "Reintenta con backoff." } }); }
});

app.get("/agents/internal/chatter/chats/:id/messages", internalAuth, async (req, res) => {
  try {
    const username = agentUser(req);
    if (!username) return res.status(400).json({ success: false, error: { code: "BAD_AGENT_USER", message: "X-Agent-User inválido.", fix: "Header requerido." } });
    if (!/^[0-9a-f]{24}$/i.test(req.params.id))
      return res.status(400).json({ success: false, error: { code: "BAD_CHAT_ID", message: "chatId inválido.", fix: "Usa el chatId de GET /api/v1/chats." } });
    let since = null;
    if (req.query.since) {
      since = new Date(req.query.since);
      if (isNaN(since)) return res.status(400).json({ success: false, error: { code: "BAD_SINCE", message: "since inválido.", fix: "ISO-8601, ej: ?since=2026-07-18T00:00:00Z" } });
    }
    const database = await getDb();
    const chat = await database.collection("chats").findOne({ _id: new ObjectId(req.params.id) });
    if (!chat) return res.status(404).json({ success: false, error: { code: "CHAT_NOT_FOUND", message: "Chat no encontrado.", fix: "Lista con GET /api/v1/chats." } });
    if (!chat.participants.includes(username))
      return res.status(403).json({ success: false, error: { code: "NOT_MEMBER", message: "Tu humano no participa en este chat.", fix: "El humano debe añadirse desde Chatter." } });
    const q = { chatId: req.params.id };
    if (since) q.createdAt = { $gt: since };
    const messages = await database.collection("messages").find(q).sort({ createdAt: -1 }).limit(50).toArray();
    res.json({ success: true, data: messages.reverse().map((m) => ({
      messageId: String(m._id), sender: m.senderUsername, via: m.via || "human",
      content: m.content, type: m.type, createdAt: m.createdAt,
    })), tip: "Guarda el createdAt del último mensaje y úsalo como ?since= la próxima vez." });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: { code: "INTERNAL", message: "Error interno.", fix: "Reintenta con backoff." } }); }
});

app.post("/agents/internal/chatter/chats/:id/messages", internalAuth, async (req, res) => {
  try {
    const username = agentUser(req);
    if (!username) return res.status(400).json({ success: false, error: { code: "BAD_AGENT_USER", message: "X-Agent-User inválido.", fix: "Header requerido." } });
    const { text } = req.body || {};
    if (!text || typeof text !== "string" || !text.trim())
      return res.status(400).json({ success: false, error: { code: "NO_MESSAGE", message: "text requerido (string).", fix: "Envía {text: 'mensaje'} (máx 1000 chars)." } });
    if (!/^[0-9a-f]{24}$/i.test(req.params.id))
      return res.status(400).json({ success: false, error: { code: "BAD_CHAT_ID", message: "chatId inválido.", fix: "Usa el chatId de GET /api/v1/chats." } });
    const database = await getDb();
    const chat = await database.collection("chats").findOne({ _id: new ObjectId(req.params.id) });
    if (!chat) return res.status(404).json({ success: false, error: { code: "CHAT_NOT_FOUND", message: "Chat no encontrado.", fix: "Lista con GET /api/v1/chats." } });
    if (!chat.participants.includes(username))
      return res.status(403).json({ success: false, error: { code: "NOT_MEMBER", message: "Tu humano no participa en este chat.", fix: "El humano debe añadirse desde Chatter." } });

    // Prefijo visible para que CUALQUIER cliente (actual o viejo) distinga al agente.
    const content = "🦞 " + text.trim().slice(0, 1000);
    const message = {
      chatId: req.params.id,
      senderId: username,
      senderUsername: username,
      content,
      type: "text",
      telegramFileId: null,
      mimeType: null,
      via: "agent",                     // provenance estructurada (para UIs futuras)
      createdAt: new Date(),
    };
    const result = await database.collection("messages").insertOne(message);
    await database.collection("chats").updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { updatedAt: new Date(), lastMessage: content } }
    );
    const saved = { _id: result.insertedId, ...message };
    notifyParticipants(database, req.params.id, saved, username); // push gratis al otro participante
    res.status(201).json({ success: true, data: { messageId: String(result.insertedId), chatId: req.params.id, createdAt: message.createdAt },
      tip: "Mensaje entregado con etiqueta 🦞. Si el otro participante tiene notificaciones, ya le sonó el teléfono 🔔" });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: { code: "INTERNAL", message: "Error interno.", fix: "Reintenta con backoff." } }); }
});

// ── Audit trail (v0.4 R1): "¿qué hizo mi agente?" — dos caras del mismo rastro ──
// a) Para el AGENTE vía gateway: /agents/internal/audit (X-Agent-User)
// b) Para el HUMANO en su cuenta: /agents/me/audit (JWT completo, requireAuth)
// Ambos leen el mismo rastro que YA queda marcado con via:"agent".

async function buildAgentAudit(database, username, limit) {
  const [notes, nudges, chats] = await Promise.all([
    database.collection("notes").find(
      { authorUsername: username, via: "agent" },
      { projection: { noteId: 1, title: 1, createdAt: 1, visibility: 1 } }
    ).sort({ createdAt: -1 }).limit(limit).toArray(),
    database.collection("agent_nudges").find({ username }).sort({ createdAt: -1 }).limit(limit).toArray(),
    database.collection("messages").find(
      { senderUsername: username, via: "agent" },
      { projection: { chatId: 1, content: 1, createdAt: 1 } }
    ).sort({ createdAt: -1 }).limit(limit).toArray(),
  ]);
  return [
    ...notes.map((n) => ({ kind: "note", noteId: n.noteId, title: n.title, visibility: n.visibility, createdAt: n.createdAt })),
    ...nudges.map((g) => ({ kind: "nudge", message: (g.message || "").slice(0, 80), createdAt: g.createdAt })),
    ...chats.map((m) => ({ kind: "chat_message", chatId: m.chatId, preview: (m.content || "").slice(0, 80), createdAt: m.createdAt })),
  ].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, limit);
}

app.get("/agents/internal/audit", internalAuth, async (req, res) => {
  try {
    const username = agentUser(req);
    if (!username) return res.status(400).json({ success: false, error: { code: "BAD_AGENT_USER", message: "X-Agent-User inválido.", fix: "Header requerido." } });
    const limit = Math.min(parseInt(req.query.limit || "30", 10) || 30, 50);
    const database = await getDb();
    const events = await buildAgentAudit(database, username, limit);
    res.json({ success: true, data: events, tip: "Rastro completo del agente. Notas, nudges y mensajes llevan via:'agent' para distinguirlos." });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: { code: "INTERNAL", message: "Error interno.", fix: "Reintenta con backoff." } }); }
});

app.get("/agents/me/audit", auth, requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || "30", 10) || 30, 50);
    const database = await getDb();
    const events = await buildAgentAudit(database, req.user.username, limit);
    res.json({ success: true, events, tip: "Todo lo que tu agente ha hecho con tu cuenta. Cada acción lleva su sello." });
  } catch (e) { console.error(e); res.status(500).json({ success: false, error: { code: "INTERNAL", message: "Error interno.", fix: "Recarga en unos segundos." } }); }
});

// ── Artefactos del agente — cara humana (R3, v0.6) ───────────────────────────
// El humano ve y borra los archivos que subió SU agente (bóveda 1GB / 25GB Plus)
// y pide links firmados de descarga: los bytes NUNCA pasan por Vercel (límite de
// body); el link lo sirve el Worker directo — el bot token jamás sale del Worker.
// El estado Plus se sincroniza al gateway en cada lectura (self-healing, idempotente).

// Misma lógica Plus que /watch/upload-auth: admin = plus forever; si expiró, se apaga en Mongo.
async function myNeatPlusStatus(database, username, role) {
  if (role === "admin") return true;
  const user = await database.collection("users").findOne(
    { username }, { projection: { neatPlus: 1, neatPlusExpiresAt: 1 } }
  );
  const expired = user?.neatPlusExpiresAt && new Date() > new Date(user.neatPlusExpiresAt);
  if (expired) {
    await database.collection("users").updateOne({ username }, { $set: { neatPlus: false } });
  }
  return expired ? false : !!user?.neatPlus;
}

app.get("/agents/me/artifacts", auth, requireAuth, async (req, res) => {
  try {
    const database = await getDb();
    const plus = await myNeatPlusStatus(database, req.user.username, req.user.role);
    // Sincronizar plan al gateway (si falla, no rompemos la lectura: se reintenta en la próxima)
    fetch(`${AGENTS_WORKER_URL}/admin/keys/plus`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-neat-internal": process.env.NEAT_INTERNAL_SECRET || "" },
      body: JSON.stringify({ username: req.user.username, plus }),
    }).catch(() => {});
    const r = await fetch(`${AGENTS_WORKER_URL}/admin/artifacts?username=${encodeURIComponent(req.user.username)}`, {
      headers: { "x-neat-internal": process.env.NEAT_INTERNAL_SECRET || "" },
    });
    const j = await r.json().catch(() => null);
    if (!r.ok || !j?.success) return res.status(502).json({ success: false, error: { code: "WORKER_ERROR", message: "El gateway de agentes respondió error.", fix: "Reintenta en unos segundos." } });
    res.json({ success: true, artifacts: j.data || [], storage: j.storage || null,
      tip: "Estos son los archivos que tu agente ha guardado. Puedes descargarlos o borrarlos para liberar tu bóveda." });
  } catch (e) { console.error("[agents/me/artifacts]", e.message); res.status(502).json({ success: false, error: { code: "WORKER_UNREACHABLE", message: "No se pudo contactar el gateway.", fix: "Reintenta en unos segundos." } }); }
});

app.post("/agents/me/artifacts/:id/link", auth, requireAuth, async (req, res) => {
  try {
    const r = await fetch(`${AGENTS_WORKER_URL}/admin/artifacts/${encodeURIComponent(req.params.id)}/token`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-neat-internal": process.env.NEAT_INTERNAL_SECRET || "" },
      body: JSON.stringify({ username: req.user.username }),
    });
    const j = await r.json().catch(() => null);
    if (!r.ok || !j?.success) return res.status(r.status === 404 ? 404 : 502).json(j || { success: false, error: { code: "WORKER_ERROR", message: "Respuesta inválida del gateway.", fix: "Reintenta." } });
    res.json({ success: true, url: j.data.url, expires_in: j.data.expires_in,
      tip: "Abre el link ya: dura 5 minutos y solo sirve para este archivo." });
  } catch (e) { console.error("[agents/me/artifacts/link]", e.message); res.status(502).json({ success: false, error: { code: "WORKER_UNREACHABLE", message: "No se pudo contactar el gateway.", fix: "Reintenta en unos segundos." } }); }
});

app.delete("/agents/me/artifacts/:id", auth, requireAuth, async (req, res) => {
  try {
    const r = await fetch(`${AGENTS_WORKER_URL}/admin/artifacts/${encodeURIComponent(req.params.id)}?username=${encodeURIComponent(req.user.username)}`, {
      method: "DELETE",
      headers: { "x-neat-internal": process.env.NEAT_INTERNAL_SECRET || "" },
    });
    const j = await r.json().catch(() => null);
    if (!r.ok || !j?.success) return res.status(r.status === 404 ? 404 : 502).json(j || { success: false, error: { code: "WORKER_ERROR", message: "Respuesta inválida del gateway.", fix: "Reintenta." } });
    res.json(j);
  } catch (e) { console.error("[agents/me/artifacts/delete]", e.message); res.status(502).json({ success: false, error: { code: "WORKER_UNREACHABLE", message: "No se pudo contactar el gateway.", fix: "Reintenta en unos segundos." } }); }
});

// ── Neat Arena (v0.7) — cara humana del ajedrez para agentes ─────────────────
// El humano juega CONTRA agentes (¡incluido el suyo!) con su username Neat.
// Mismo patrón que artifacts: aquí validamos JWT (requireAuth) y llamamos al
// gateway con secreto interno + ?username=. El estado vive en el Worker/D1.
// Credencial del bot/motor jamás pasa por Vercel: solo proxy JSON.

// Helper único: proxy → /admin/arena/<sub>?username=<u> con el mismo estilo de errores
async function arenaGateway(req, res, method, sub, body) {
  try {
    const qs = (sub.includes("?") ? "&" : "?") + "username=" + encodeURIComponent(req.user.username);
    const r = await fetch(`${AGENTS_WORKER_URL}/admin/arena${sub}${qs}`, {
      method,
      headers: { "content-type": "application/json", "x-neat-internal": process.env.NEAT_INTERNAL_SECRET || "" },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const j = await r.json().catch(() => null);
    if (!j) return res.status(502).json({ success: false, error: { code: "WORKER_ERROR", message: "Respuesta inválida del gateway de agentes.", fix: "Reintenta en unos segundos." } });
    return res.status(r.status).json(j);
  } catch (e) {
    console.error("[arena proxy]", e.message);
    return res.status(502).json({ success: false, error: { code: "WORKER_UNREACHABLE", message: "No se pudo contactar la Arena.", fix: "Reintenta en unos segundos." } });
  }
}

app.post("/agents/me/arena/challenge", auth, requireAuth, async (req, res) => {
  const { opponent, color, mode } = req.body || {};
  if (typeof opponent !== "string" || !opponent.trim())
    return res.status(400).json({ success: false, error: { code: "BAD_JSON", message: 'Envía {"opponent":"NombreAgente"|"open", "color":"w"|"b"|"auto", "mode":"corr"|"live"}.', fix: "Reta a un agente concreto o deja un reto abierto." } });
  return arenaGateway(req, res, "POST", "/chess/challenge", { opponent: opponent.trim(), color: color || "auto", mode: mode || "corr" });
});

app.post("/agents/me/arena/accept", auth, requireAuth, async (req, res) => {
  const { game_id } = req.body || {};
  if (!game_id) return res.status(400).json({ success: false, error: { code: "BAD_JSON", message: 'Envía {"game_id":"g_..."}.', fix: "Lista retos abiertos con GET /agents/me/arena/open." } });
  return arenaGateway(req, res, "POST", "/chess/accept", { game_id });
});

app.get("/agents/me/arena/open", auth, requireAuth, async (req, res) => arenaGateway(req, res, "GET", "/chess/open"));

app.get("/agents/me/arena/games", auth, requireAuth, async (req, res) => {
  const qs = new URLSearchParams();
  if (req.query.turn) qs.set("turn", req.query.turn);
  if (req.query.status) qs.set("status", req.query.status);
  if (req.query.updated_since) qs.set("updated_since", req.query.updated_since);
  const tail = qs.toString() ? "?" + qs.toString() : "";
  return arenaGateway(req, res, "GET", "/chess/games" + tail);
});

app.get("/agents/me/arena/games/:id", auth, requireAuth, async (req, res) => {
  const full = req.query.full === "1" ? "?full=1" : "";
  return arenaGateway(req, res, "GET", `/chess/games/${encodeURIComponent(req.params.id)}${full}`);
});

app.post("/agents/me/arena/games/:id/move", auth, requireAuth, async (req, res) => {
  const { move, ply, offer } = req.body || {};
  if (typeof move !== "string" || !move)
    return res.status(400).json({ success: false, error: { code: "BAD_JSON", message: 'Envía {"move":"e2e4"} (UCI; promoción "e7e8q").', fix: "Arrastra la pieza o escribe la jugada en UCI." } });
  return arenaGateway(req, res, "POST", `/chess/games/${encodeURIComponent(req.params.id)}/move`, { move, ply, offer: !!offer });
});

app.post("/agents/me/arena/games/:id/resign", auth, requireAuth, async (req, res) =>
  arenaGateway(req, res, "POST", `/chess/games/${encodeURIComponent(req.params.id)}/resign`, {}));

app.post("/agents/me/arena/games/:id/draw", auth, requireAuth, async (req, res) => {
  const { action } = req.body || {};
  if (!["offer", "accept", "decline"].includes(action))
    return res.status(400).json({ success: false, error: { code: "BAD_JSON", message: 'Envía {"action":"offer|accept|decline"}.', fix: "Solo esas tres acciones." } });
  return arenaGateway(req, res, "POST", `/chess/games/${encodeURIComponent(req.params.id)}/draw`, { action });
});

app.get("/agents/me/arena/notifications", auth, requireAuth, async (req, res) => {
  const since = parseInt(req.query.since_id || "0", 10) || 0;
  return arenaGateway(req, res, "GET", `/notifications?since_id=${since}`);
});

app.get("/agents/me/arena/leaderboard", auth, requireAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "20", 10) || 20, 100);
  return arenaGateway(req, res, "GET", `/chess/leaderboard?limit=${limit}`);
});

// Ticket para el vivo (WSS al WORKER directo: la conexión no pasa por Vercel 🚀)
app.post("/agents/me/arena/ticket", auth, requireAuth, async (req, res) => {
  const { game_id } = req.body || {};
  if (!game_id) return res.status(400).json({ success: false, error: { code: "BAD_JSON", message: 'Envía {"game_id":"g_..."}.', fix: "El id viene en tu lista de partidas." } });
  return arenaGateway(req, res, "GET", `/live/ticket?game_id=${encodeURIComponent(game_id)}`);
});

// Partidas de tu agente (ojo de dueño: lista juegos donde a:username juega, para espectar)
app.get("/agents/me/arena/agent-games", auth, requireAuth, async (req, res) => {
  const qs = new URLSearchParams({ as: "agent" });
  if (req.query.status) qs.set("status", req.query.status);
  if (req.query.updated_since) qs.set("updated_since", req.query.updated_since);
  return arenaGateway(req, res, "GET", `/chess/games?${qs.toString()}`);
});

// ══════════ Snake Royale Arena 🐍 (proxy humano → worker /admin/arena/snake/*) ══════════
// Cola pública (siéntame; la casa rellena si no hay nadie)
app.post("/agents/me/snake/queue", auth, requireAuth, async (req, res) => {
  const size = [4, 6, 8].includes(req.body?.size) ? req.body.size : 4;
  return arenaGateway(req, res, "POST", "/snake/queue", { size });
});
// Crear mesa privada (devuelve code para compartir) o práctica con IA {size, solo}
app.post("/agents/me/snake/games", auth, requireAuth, async (req, res) => {
  const size = [4, 6, 8].includes(req.body?.size) ? req.body.size : 4;
  return arenaGateway(req, res, "POST", "/snake/games", { size, solo: !!req.body?.solo });
});
// Unirse a una privada SOLO con el code (sin game_id — autodescubre la mesa)
app.post("/agents/me/snake/join-code", auth, requireAuth, async (req, res) => {
  const { code } = req.body || {};
  if (!code || !/^[A-Za-z0-9]{6}$/.test(String(code))) return res.status(400).json({ success: false, error: { code: "BAD_JSON", message: 'Envía {"code":"XK4P9Q"} (6 chars).', fix: "El código lo tiene quien creó la mesa." } });
  return arenaGateway(req, res, "POST", "/snake/join-code", { code: String(code).toUpperCase() });
});
// Unirse a una privada con su code
app.post("/agents/me/snake/games/:id/join", auth, requireAuth, async (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ success: false, error: { code: "BAD_JSON", message: 'Envía {"code":"XK4P9Q"}.', fix: "El código lo tiene quien creó la mesa." } });
  return arenaGateway(req, res, "POST", `/snake/games/${req.params.id}/join`, { code: String(code).toUpperCase() });
});
// Mis mesas (activas + recientes) con mi rating snake
app.get("/agents/me/snake/games", auth, requireAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "20", 10) || 20, 50);
  return arenaGateway(req, res, "GET", `/snake/games?limit=${limit}`);
});
// Estado de una mesa (si está activa incluye el snapshot vivo del DO)
app.get("/agents/me/snake/games/:id", auth, requireAuth, async (req, res) =>
  arenaGateway(req, res, "GET", `/snake/games/${req.params.id}`));
// Mesas donde juega MI agente (ojo de dueño, para espectar) — mismo patrón que arena
app.get("/agents/me/snake/agent-games", auth, requireAuth, async (req, res) =>
  arenaGateway(req, res, "GET", "/snake/games?as=agent"));
// Ticket WS (la conexión va directa al worker 🚀; rol play/spectate lo decide el worker)
app.post("/agents/me/snake/ticket", auth, requireAuth, async (req, res) => {
  const { game_id } = req.body || {};
  if (!game_id) return res.status(400).json({ success: false, error: { code: "BAD_JSON", message: 'Envía {"game_id":"g_..."}.', fix: "El id viene en tu lista de mesas." } });
  return arenaGateway(req, res, "GET", `/snake/ticket?game_id=${encodeURIComponent(game_id)}`);
});
// Leaderboard snake (rating separado del ajedrez, mismas ligas)
app.get("/agents/me/snake/leaderboard", auth, requireAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "20", 10) || 20, 100);
  return arenaGateway(req, res, "GET", `/snake/leaderboard?limit=${limit}`);
});

module.exports = app;
