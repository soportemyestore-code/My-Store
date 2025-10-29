// ================================
// 🧩 MI STORE - BACKEND PRODUCCIÓN
// ================================

import express from "express";
import session from "express-session";
import bcrypt from "bcrypt";
import cors from "cors";
import dotenv from "dotenv";
import helmet from "helmet";
import fs from "fs";
import { createReadStream } from "fs";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import { OAuth2Client } from "google-auth-library";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import db from "./db.js"; // conexión PostgreSQL

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

app.set("trust proxy", 1);

// ================================
// ⚙️ MIDDLEWARES
// ================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));
app.use(helmet());
app.use(express.static("public"));

// Limitar solicitudes (previene ataques)
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: "Demasiadas solicitudes. Intenta más tarde.",
});
app.use(limiter);

// ================================
// ⚙️ CONFIGURAR SESIONES
// ================================
app.use(
  session({
    secret: process.env.SESSION_SECRET || "mi-store-secret",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 },
  })
);

// ================================
// ☁️ CONFIGURAR CLOUDINARY
// ================================
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});
console.log("✅ Cloudinary configurado correctamente");

// ================================
// 🔐 CONFIGURAR GOOGLE OAUTH
// ================================
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

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
    if (admin.rows.length > 0) {
      return res.json({ message: "✅ Ya existe un usuario admin." });
    }

    const plainPassword = "admin123";
    const hashed = await bcrypt.hash(plainPassword, 10);

    await db.query(
      `INSERT INTO users (username, password_hash, role, created_at)
       VALUES ($1, $2, $3, NOW())`,
      ["admin", hashed, "admin"]
    );

    res.json({
      message: "✅ Usuario admin creado (usuario: admin / contraseña: admin123)",
    });
  } catch (error) {
    console.error("❌ Error al crear admin:", error);
    res.status(500).json({ message: "Error al crear admin", error: error.message });
  }
});

// ================================
// 🔐 LOGIN LOCAL
// ================================
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);
    if (result.rows.length === 0) {
      return res.json({ success: false, message: "Usuario no encontrado" });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.json({ success: false, message: "Contraseña incorrecta" });

    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.json({ success: true, username: user.username, role: user.role });
  } catch (error) {
    console.error("❌ Error al iniciar sesión:", error);
    res.status(500).json({ success: false, message: "Error interno del servidor" });
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
    if (exists.rows.length > 0) {
      return res.json({ success: false, message: "Usuario o correo ya existe." });
    }

    const hashed = await bcrypt.hash(password, 10);
    await db.query(
      `INSERT INTO users (username, email, password_hash, role, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [username, email, hashed, "user"]
    );

    res.json({ success: true, message: "Usuario registrado correctamente." });
  } catch (error) {
    console.error("❌ Error al registrar:", error);
    res.status(500).json({ success: false, message: "Error al registrar usuario." });
  }
});

// ================================
// 🔐 LOGIN CON GOOGLE
// ================================
app.post("/api/google-login", async (req, res) => {
  try {
    const { credential } = req.body;

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const email = payload.email;
    const username = payload.name;

    // Buscar si ya existe
    let result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    let user;
    if (result.rows.length === 0) {
      // Registrar nuevo usuario con Google
      user = await db.query(
        `INSERT INTO users (username, email, role, created_at)
         VALUES ($1, $2, $3, NOW()) RETURNING *`,
        [username, email, "user"]
      );
      user = user.rows[0];
    } else {
      user = result.rows[0];
    }

    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.json({ success: true, username: user.username, role: user.role });
  } catch (error) {
    console.error("❌ Error con Google Login:", error);
    res.status(500).json({ success: false, message: "Error al autenticar con Google" });
  }
});

// ================================
// 🚀 SUBIDA DE APPS (IMAGEN + APK)
// ================================
const uploadDir = "./uploads";
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + "-" + file.originalname.replace(/\s+/g, "_");
    cb(null, uniqueName);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 }, // 25 MB máximo
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype.startsWith("image/") ||
      file.mimetype === "application/vnd.android.package-archive"
    ) cb(null, true);
    else cb(new Error("Tipo de archivo no permitido"));
  },
});

app.post("/upload", upload.fields([{ name: "image" }, { name: "apk" }]), async (req, res) => {
  try {
    const { name, description, category, is_paid } = req.body;
    if (!req.files?.image || !req.files?.apk) {
      return res.status(400).json({ message: "Faltan archivos." });
    }

    const imageUpload = await cloudinary.uploader.upload(req.files.image[0].path, {
      folder: "mi_store/apps",
    });

    const apkUpload = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { resource_type: "raw", folder: "mi_store/apks" },
        (error, result) => (error ? reject(error) : resolve(result))
      );
      createReadStream(req.files.apk[0].path).pipe(stream);
    });

    fs.unlinkSync(req.files.image[0].path);
    fs.unlinkSync(req.files.apk[0].path);

    await db.query(
      `INSERT INTO apps (name, description, image, apk, category, is_paid, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
      [name, description, imageUpload.secure_url, apkUpload.secure_url, category, is_paid === "true"]
    );

    res.json({ message: "App subida con éxito" });
  } catch (error) {
    console.error("❌ Error al subir app:", error);
    res.status(500).json({ message: "Error al subir aplicación", error: error.message });
  }
});

// ================================
// 📋 LISTAR APPS
// ================================
app.get("/api/apps", async (req, res) => {
  try {
    const result = await db.query(`
      SELECT 
        a.*, 
        COALESCE(AVG(r.rating), 0)::numeric(2,1) AS average_rating
      FROM apps a
      LEFT JOIN ratings r ON a.id = r.app_id
      GROUP BY a.id
      ORDER BY a.created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error("❌ Error al obtener apps:", error);
    res.status(500).json({ message: "Error al obtener apps" });
  }
});

// ================================
// ⚙️ INICIAR SERVIDOR
// ================================
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en el puerto ${PORT}`);
});

