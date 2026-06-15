const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { MongoClient, ObjectId } = require("mongodb");
// ── Agregar al inicio del archivo junto a las otras constantes ─────────────────
const webpush = require("web-push");

const app = express();
app.use(express.json());
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
}

// ── Guardar suscripción push del browser ───────────────────────────────────────
app.post("/chat/push/subscribe", auth, async (req, res) => {
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
app.delete("/chat/push/subscribe", auth, async (req, res) => {
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

app.post("/chat/telegram/upload", auth, upload.single("file"), async (req, res) => {
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

// Actualizar perfil (bio + foto de perfil vía Telegram file_id)
app.put("/chat/me", auth, async (req, res) => {
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
app.get("/chat/me", auth, async (req, res) => {
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
app.get("/chat/chats", auth, async (req, res) => {
  const database = await getDb();
  const identifier = req.user.username;
const chats = await database.collection("chats")
  .find({ participants: identifier })
    .sort({ updatedAt: -1 })
    .toArray();
  res.json(chats);
});

// Crear chat
app.post("/chat/chats", auth, async (req, res) => {
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

    const database = await getDb();
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
app.get("/chat/chats/:id", auth, async (req, res) => {
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
app.get("/chat/messages/:chatId", auth, async (req, res) => {
  try {
    const database = await getDb();
    const chat = await database.collection("chats").findOne({ _id: new ObjectId(req.params.chatId) });
    if (!chat) return res.status(404).json({ error: "Chat no encontrado" });

    const identifier = req.user.userId || req.user.username;
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
app.post("/chat/messages/:chatId", auth, async (req, res) => {
  try {
    const { content, type = "text", telegramFileId = null, mimeType = null } = req.body;
    if (!content && !telegramFileId)
      return res.status(400).json({ error: "content o telegramFileId requerido" });

    const database = await getDb();
    const chat = await database.collection("chats").findOne({ _id: new ObjectId(req.params.chatId) });
    if (!chat) return res.status(404).json({ error: "Chat no encontrado" });

    const identifier = req.user.userId || req.user.username;
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
app.get("/chat/messages/:chatId/since", auth, async (req, res) => {
  try {
    const { since } = req.query;
    if (!since) return res.status(400).json({ error: "since requerido" });

    const database = await getDb();
    const chat = await database.collection("chats").findOne({ _id: new ObjectId(req.params.chatId) });
    if (!chat) return res.status(404).json({ error: "Chat no encontrado" });

    const identifier = req.user.userId || req.user.username;
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
app.get("/chat/telegram/file/:fileId", auth, async (req, res) => {
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

app.post("/watch/videos", auth, async (req, res) => {
  try {
    const { title, description, fileId, thumbnailFileId, duration, category } = req.body;
    if (!title || !fileId) return res.status(400).json({ error: "title y fileId requeridos" });

    const identifier = req.user.userId || req.user.username;
    const database = await getDb();
    const result = await database.collection("watch_videos").insertOne({
      title, description, fileId, thumbnailFileId: thumbnailFileId || null,
      duration: duration || null, category: category || null,
      uploadedBy: identifier, uploaderUsername: req.user.username,
      likes: [], views: 0, createdAt: new Date()
    });
    res.status(201).json({ _id: result.insertedId, title, fileId });
  } catch (err) {
    res.status(500).json({ error: "Error interno" });
  }
});

app.get("/watch/videos", async (req, res) => {
  try {
    const database = await getDb();
    const { category, uploader, quick, limit = 20, before } = req.query;
    const filter = {};
    if (category) filter.category = category;
    if (uploader) filter.uploaderUsername = uploader;
    if (quick === "true") filter.duration = { $lte: 120 };
    if (quick === "false") filter.duration = { $gt: 120 };
    if (before) filter.createdAt = { $lt: new Date(before) };

    const videos = await database.collection("watch_videos")
      .find(filter).sort({ createdAt: -1 }).limit(parseInt(limit)).toArray();
    res.json(videos);
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

app.put("/watch/videos/:id", auth, async (req, res) => {
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

app.delete("/watch/videos/:id", auth, async (req, res) => {
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

app.post("/watch/videos/:id/like", auth, async (req, res) => {
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

app.post("/watch/videos/:id/comments", auth, async (req, res) => {
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
    res.json(comments);
  } catch {
    res.status(400).json({ error: "Error" });
  }
});

app.delete("/watch/comments/:id", auth, async (req, res) => {
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

app.post("/watch/channels/:userId/subscribe", auth, async (req, res) => {
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
    res.json({ userId: req.params.userId, videos, subscriberCount });
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

// ── Apps (admin — sin cambios) ─────────────────────────────────────────────────
// Nota: usa `auth` (no `adminAuth`) para mantener compatibilidad con Neat Astore
// que ya tenía tokens sin campo `role`. Tokens viejos siguen funcionando.
app.post("/apps", auth, async (req, res) => {
  const { name, description, icon, url, category } = req.body;
  if (!name || !url) return res.status(400).json({ error: "name and url required" });
  const database = await getDb();
  const result = await database.collection("apps").insertOne({
    name, description, icon, url, category, createdAt: new Date()
  });
  res.status(201).json({ _id: result.insertedId, name, description, icon, url, category });
});

app.put("/apps/:id", auth, async (req, res) => {
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

app.delete("/apps/:id", auth, async (req, res) => {
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
