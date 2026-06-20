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
app.post("/chat/register", async (req, res) => {
  try {
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

    const database = await getDb();
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
});


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
    const { name, redirectUris, scopes } = req.body;
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

    const { name, redirectUris, scopes } = req.body;
    if (!name || !redirectUris?.length) return res.status(400).json({ error: "name y redirectUris requeridos" });

    await database.collection("oauth_clients").updateOne(
      { clientId: req.params.clientId },
      { $set: { name, redirectUris, scopes: scopes || ["profile"] } }
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

// ── Health ─────────────────────────────────────────────────────────────────────
app.get("/", (req, res) => res.json({ status: "ok", service: "neat-api", version: "2.0" }));

module.exports = app;
