// ================================
// 🧩 MI STORE - BACKEND PRODUCCIÓN (FINAL - LOGIN TRAD + RESET PASS)
// ================================

import express from "express";
import session from "express-session";
import bcrypt from "bcrypt";
import cors from "cors";
import dotenv from "dotenv";
import helmet from "helmet";
import fs, { createReadStream } from "fs";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import multer from "multer";
import crypto from "crypto";
import { v2 as cloudinary } from "cloudinary";
import db from "./db.js";
import path from "path";
import { fileURLToPath } from "url";
import SibApiV3Sdk from "@sendinblue/client";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 4000;
const BASE_URL = process.env.BASE_URL || "https://my-store-lwl1.onrender.com";

// ================================
// ⚙️ CONFIGURACIÓN BASE
// ================================
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.static(path.join(__dirname, "public")));

// ================================
// ⚙️ RATE LIMIT
// ================================
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  message: "Demasiadas solicitudes. Intenta más tarde.",
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// ================================
// ⚙️ SESIONES
// ================================
app.use(
  session({
    secret: process.env.SESSION_SECRET || "mi-store-secret",
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

// ================================
// ☁️ CLOUDINARY
// ================================
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});
console.log("✅ Cloudinary configurado correctamente");

// ================================
// 📧 SENDINBLUE / BREVO
// ================================
if (!process.env.SENDINBLUE_API_KEY) {
  console.warn("⚠️ SENDINBLUE_API_KEY no definido — los emails de reset NO funcionarán hasta configurarlo.");
}

const sibClient = new SibApiV3Sdk.TransactionalEmailsApi();
sibClient.authentications.apiKey.apiKey = process.env.SENDINBLUE_API_KEY;

// ================================
// ✅ Asegurar columnas necesarias en tabla users (reset_token, reset_expires)
// ================================
(async function ensureUserColumns() {
  try {
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token TEXT;`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_expires BIGINT;`);
    console.log("✅ Columnas reset_token/reset_expires aseguradas en users (si no existían).");
  } catch (err) {
    console.warn("⚠️ No se pudo asegurar columnas en users:", err.message);
  }
})();

// ================================
// 🏠 Páginas estáticas / root
// ================================
app.get("/", (req, res) => {
  if (!req.session.user) return res.redirect("/login.html");
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ================================
// 🧑‍💼 Crear admin (primera vez)
// ================================
app.get("/create-admin", async (req, res) => {
  try {
    const admin = await db.query("SELECT * FROM users WHERE role = 'admin'");
    if (admin.rows.length > 0) return res.json({ message: "✅ Ya existe un usuario admin." });

    const hashed = await bcrypt.hash("admin123", 10);
    await db.query(
      `INSERT INTO users (username, email, password_hash, role, created_at)
       VALUES ($1, $2, $3, 'admin', NOW())`,
      ["admin", "admin@mystore.com", hashed]
    );
    res.json({ message: "✅ Usuario admin creado (usuario: admin / contraseña: admin123)" });
  } catch (err) {
    console.error("❌ Error creando admin:", err);
    res.status(500).json({ message: "Error al crear admin" });
  }
});

// ================================
// 🔐 LOGIN
// ================================
async function handleLoginLogic(email, password) {
  const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
  if (result.rows.length === 0) return { success: false, message: "Usuario no encontrado" };
  const user = result.rows[0];
  const valid = await bcrypt.compare(password, user.password_hash || "");
  if (!valid) return { success: false, message: "Contraseña incorrecta" };
  return { success: true, user };
}

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const r = await handleLoginLogic(email, password);
    if (!r.success) return res.json(r);
    req.session.user = { id: r.user.id, username: r.user.username, role: r.user.role };
    res.json({ success: true, message: "Inicio de sesión correcto" });
  } catch (err) {
    console.error("❌ /login error:", err);
    res.status(500).json({ success: false, message: "Error interno" });
  }
});

// ================================
// 🆕 REGISTRO
// ================================
async function handleRegisterLogic(username, email, password) {
  const exists = await db.query("SELECT id FROM users WHERE username = $1 OR email = $2", [username, email]);
  if (exists.rows.length > 0) return { success: false, message: "Usuario o correo ya existe." };
  const hashed = await bcrypt.hash(password, 10);
  await db.query(
    `INSERT INTO users (username, email, password_hash, role, created_at)
     VALUES ($1, $2, $3, 'user', NOW())`,
    [username, email, hashed]
  );
  return { success: true, message: "Usuario registrado correctamente." };
}

app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    const username = req.body.username || email.split("@")[0];
    const r = await handleRegisterLogic(username, email, password);
    res.json(r);
  } catch (err) {
    console.error("❌ /register error:", err);
    res.status(500).json({ success: false, message: "Error interno" });
  }
});

// ================================
// 🔄 OLVIDÉ MI CONTRASEÑA (Sendinblue)
// ================================
app.post("/forgot", async (req, res) => {
  try {
    const { email } = req.body;
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0)
      return res.json({ message: "Si el correo existe, se enviará un enlace de recuperación." });

    const user = result.rows[0];
    const token = crypto.randomBytes(32).toString("hex");
    const expires = Date.now() + 15 * 60 * 1000;

    await db.query("UPDATE users SET reset_token=$1, reset_expires=$2 WHERE id=$3", [token, expires, user.id]);

    const resetLink = `${BASE_URL}/reset.html?token=${token}`;

    await sibClient.sendTransacEmail({
      sender: { email: "no-reply@mystore.com", name: "Mi Store" },
      to: [{ email }],
      subject: "🔐 Recupera tu contraseña - Mi Store",
      htmlContent: `
        <div style="font-family: Arial, sans-serif; max-width: 480px; margin:auto; border:1px solid #ddd; border-radius:10px; padding:20px;">
          <h2 style="color:#6b21a8;">Mi Store</h2>
          <p>Hola <b>${user.username}</b>,</p>
          <p>Has solicitado recuperar tu contraseña. Haz clic en el siguiente botón para restablecerla:</p>
          <p style="text-align:center; margin:30px 0;">
            <a href="${resetLink}" style="background:#6b21a8; color:white; padding:10px 20px; border-radius:5px; text-decoration:none;">Restablecer contraseña</a>
          </p>
          <p>Este enlace expirará en 15 minutos.</p>
          <p>Si no solicitaste este cambio, puedes ignorar este correo.</p>
        </div>
      `,
    });

    res.json({ message: "Si el correo existe, se enviará un enlace para restablecer la contraseña." });
  } catch (err) {
    console.error("❌ /forgot error:", err);
    res.status(500).json({ message: "Error al enviar correo de recuperación." });
  }
});

// ================================
// 🔁 RESTABLECER CONTRASEÑA
// ================================
app.post("/reset", async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) return res.json({ message: "Faltan datos." });

    const result = await db.query("SELECT * FROM users WHERE reset_token = $1", [token]);
    if (result.rows.length === 0) return res.json({ message: "Token inválido o expirado." });

    const user = result.rows[0];
    if (Number(user.reset_expires) < Date.now()) return res.json({ message: "Token expirado." });

    const hashed = await bcrypt.hash(password, 10);
    await db.query("UPDATE users SET password_hash=$1, reset_token=NULL, reset_expires=NULL WHERE id=$2", [
      hashed,
      user.id,
    ]);

    res.json({ message: "Contraseña actualizada correctamente." });
  } catch (err) {
    console.error("❌ /reset error:", err);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

// ================================
// 🚀 SUBIDA DE APPS (Cloudinary + Multer)
// ================================
const uploadDir = "./uploads";
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
});

const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/") || file.mimetype === "application/vnd.android.package-archive")
      cb(null, true);
    else cb(new Error("Tipo de archivo no permitido"));
  },
});

app.post("/upload", upload.fields([{ name: "image" }, { name: "apk" }]), async (req, res) => {
  try {
    const { name, description, category, is_paid } = req.body;
    if (!req.files?.image || !req.files?.apk)
      return res.status(400).json({ message: "Faltan archivos." });

    const imageUpload = await cloudinary.uploader.upload(req.files.image[0].path, { folder: "mi_store/apps" });

    const apkUpload = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream({ resource_type: "raw", folder: "mi_store/apks" }, (err, result) =>
        err ? reject(err) : resolve(result)
      );
      createReadStream(req.files.apk[0].path).pipe(stream);
    });

    fs.unlinkSync(req.files.image[0].path);
    fs.unlinkSync(req.files.apk[0].path);

    await db.query(
      `INSERT INTO apps (name, description, image, apk, category, is_paid, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,NOW())`,
      [name, description, imageUpload.secure_url, apkUpload.secure_url, category, is_paid === "true"]
    );

    res.json({ message: "App subida con éxito" });
  } catch (err) {
    console.error("❌ /upload error:", err);
    res.status(500).json({ message: "Error al subir aplicación" });
  }
});

// ================================
// 📋 LISTAR APPS
// ================================
app.get("/api/apps", async (req, res) => {
  try {
    const result = await db.query(`
      SELECT a.*, COALESCE(AVG(r.rating), 0)::numeric(2,1) AS average_rating
      FROM apps a
      LEFT JOIN ratings r ON a.id = r.app_id
      GROUP BY a.id
      ORDER BY a.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error("❌ /api/apps error:", err);
    res.status(500).json({ message: "Error al obtener apps" });
  }
});

// ================================
// 🚀 INICIAR SERVIDOR
// ================================
app.listen(PORT, () => console.log(`🚀 Servidor corriendo en puerto ${PORT}`));
