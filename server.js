// ================================
// 🧩 MI STORE - BACKEND PRODUCCIÓN (FINAL CON LOGIN TRADICIONAL + RECUPERAR CONTRASEÑA)
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
import { OAuth2Client } from "google-auth-library";
import multer from "multer";
import nodemailer from "nodemailer";
import crypto from "crypto";
import { v2 as cloudinary } from "cloudinary";
import db from "./db.js"; // conexión PostgreSQL

dotenv.config();
const app = express();
const PORT = process.env.PORT || 4000;

// ================================
// ⚙️ CONFIGURACIÓN BASE
// ================================
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));
app.use(helmet());
app.use(express.static("public"));

// ================================
// ⚙️ RATE LIMIT
// ================================
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: "Demasiadas solicitudes. Intenta más tarde.",
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
// 🔐 GOOGLE CLIENT
// ================================
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ================================
// 📧 NODEMAILER CONFIG
// ================================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ================================
// 🏠 PÁGINA PRINCIPAL
// ================================
app.get("/", (req, res) => {
  res.sendFile("index.html", { root: "./public" });
});

// ================================
// 🧑‍💼 CREAR ADMIN
// ================================
app.get("/create-admin", async (req, res) => {
  try {
    const admin = await db.query("SELECT * FROM users WHERE role = 'admin'");
    if (admin.rows.length > 0)
      return res.json({ message: "✅ Ya existe un usuario admin." });

    const hashed = await bcrypt.hash("admin123", 10);
    await db.query(
      `INSERT INTO users (username, email, password_hash, role, created_at)
       VALUES ('admin', 'admin@mystore.com', $1, 'admin', NOW())`,
      [hashed]
    );
    res.json({
      message: "✅ Usuario admin creado (usuario: admin / contraseña: admin123)",
    });
  } catch (err) {
    console.error("❌ Error al crear admin:", err);
    res.status(500).json({ message: "Error al crear admin" });
  }
});

// ================================
// 🔐 LOGIN LOCAL
// ================================
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0)
      return res.json({ success: false, message: "Usuario no encontrado" });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.json({ success: false, message: "Contraseña incorrecta" });

    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.json({ success: true, username: user.username });
  } catch (err) {
    console.error("❌ Error al iniciar sesión:", err);
    res.status(500).json({ success: false, message: "Error interno" });
  }
});

// ================================
// 🆕 REGISTRO
// ================================
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const exists = await db.query(
      "SELECT * FROM users WHERE username = $1 OR email = $2",
      [username, email]
    );
    if (exists.rows.length > 0)
      return res.json({ success: false, message: "Usuario o correo ya registrado." });

    const hashed = await bcrypt.hash(password, 10);
    await db.query(
      `INSERT INTO users (username, email, password_hash, role, created_at)
       VALUES ($1, $2, $3, 'user', NOW())`,
      [username, email, hashed]
    );

    res.json({ success: true, message: "Usuario registrado correctamente." });
  } catch (err) {
    console.error("❌ Error al registrar:", err);
    res.status(500).json({ success: false, message: "Error al registrar usuario." });
  }
});

// ================================
// 🔄 OLVIDÉ MI CONTRASEÑA
// ================================
app.post("/api/forgot", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (user.rows.length === 0)
      return res.json({ message: "Si el correo existe, se enviará un enlace." });

    const token = crypto.randomBytes(32).toString("hex");
    const expires = Date.now() + 3600000;

    await db.query(
      "UPDATE users SET reset_token = $1, reset_expires = $2 WHERE email = $3",
      [token, expires, email]
    );

    const link = `https://my-store-lwl1.onrender.com/reset.html?token=${token}`;
    await transporter.sendMail({
      to: email,
      subject: "Restablecer contraseña - MyStore",
      html: `<p>Haz clic aquí para restablecer tu contraseña:</p><a href="${link}">${link}</a>`,
    });

    res.json({ message: "Se ha enviado un enlace a tu correo." });
  } catch (err) {
    console.error("❌ Error en forgot:", err);
    res.status(500).json({ message: "Error al procesar la solicitud." });
  }
});

// ================================
// 🔁 RESTABLECER CONTRASEÑA
// ================================
app.post("/api/reset", async (req, res) => {
  try {
    const { token, password } = req.body;
    const result = await db.query("SELECT * FROM users WHERE reset_token = $1", [token]);
    if (result.rows.length === 0)
      return res.json({ message: "Token inválido o expirado." });

    const user = result.rows[0];
    if (user.reset_expires < Date.now())
      return res.json({ message: "Token expirado." });

    const hashed = await bcrypt.hash(password, 10);
    await db.query(
      "UPDATE users SET password_hash = $1, reset_token = NULL, reset_expires = NULL WHERE id = $2",
      [hashed, user.id]
    );

    res.json({ message: "Contraseña actualizada correctamente." });
  } catch (err) {
    console.error("❌ Error al restablecer:", err);
    res.status(500).json({ message: "Error al actualizar contraseña." });
  }
});

// ================================
// 🚀 SUBIDA DE APPS
// ================================
const uploadDir = "./uploads";
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
});
const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype.startsWith("image/") ||
      file.mimetype === "application/vnd.android.package-archive"
    )
      cb(null, true);
    else cb(new Error("Tipo de archivo no permitido"));
  },
});

app.post("/upload", upload.fields([{ name: "image" }, { name: "apk" }]), async (req, res) => {
  try {
    const { name, description, category, is_paid } = req.body;
    if (!req.files?.image || !req.files?.apk)
      return res.status(400).json({ message: "Faltan archivos." });

    const imageUpload = await cloudinary.uploader.upload(req.files.image[0].path, {
      folder: "mi_store/apps",
    });
    const apkUpload = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { resource_type: "raw", folder: "mi_store/apks" },
        (err, result) => (err ? reject(err) : resolve(result))
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
    console.error("❌ Error al subir app:", err);
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
    console.error("❌ Error al obtener apps:", err);
    res.status(500).json({ message: "Error al obtener apps" });
  }
});

// ================================
// 🚀 INICIAR SERVIDOR
// ================================
app.listen(PORT, () => console.log(`🚀 Servidor corriendo en puerto ${PORT}`));
