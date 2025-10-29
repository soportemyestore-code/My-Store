// ================================
// 🧩 MI STORE - BACKEND COMPLETO (Google Login Integrado)
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
import { v2 as cloudinary } from "cloudinary";
import { PrismaClient } from "@prisma/client";
import db from "./db.js"; // conexión PostgreSQL
import { OAuth2Client } from "google-auth-library";

dotenv.config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 4000;
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ================================
// ⚙️ MIDDLEWARES
// ================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static("public"));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "mi-store-secret",
    resave: false,
    saveUninitialized: true,
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
    res.json({ success: true, role: user.role, username: user.username });
  } catch (error) {
    console.error("❌ Error al iniciar sesión:", error);
    res.status(500).json({ success: false, message: "Error interno del servidor" });
  }
});

// ================================
// 🔑 LOGIN CON GOOGLE
// ================================
app.post("/api/google-login", async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) {
      return res.status(400).json({ success: false, message: "Falta el token de Google" });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const email = payload.email;
    const name = payload.name || email.split("@")[0];
    const picture = payload.picture || null;

    // Buscar o crear usuario
    const existingUser = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    let user;
    if (existingUser.rows.length > 0) {
      user = existingUser.rows[0];
    } else {
      const insert = await db.query(
        `INSERT INTO users (username, email, role, created_at)
         VALUES ($1, $2, $3, NOW())
         RETURNING *`,
        [name, email, "user"]
      );
      user = insert.rows[0];
    }

    // Guardar sesión
    req.session.user = { id: user.id, username: user.username, role: user.role };

    res.json({
      success: true,
      username: user.username,
      role: user.role,
      picture,
    });
  } catch (error) {
    console.error("❌ Error en /api/google-login:", error);
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
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype.startsWith("image/") ||
      file.mimetype === "application/vnd.android.package-archive"
    ) {
      cb(null, true);
    } else {
      cb(new Error("Tipo de archivo no permitido"));
    }
  },
});

app.post("/upload", upload.fields([{ name: "image" }, { name: "apk" }]), async (req, res) => {
  try {
    const { name, description, category, is_paid } = req.body;
    if (!req.files?.image || !req.files?.apk) {
      return res.status(400).json({ message: "Faltan archivos." });
    }

    const imagePath = req.files.image[0].path;
    const apkPath = req.files.apk[0].path;

    const imageUpload = await cloudinary.uploader.upload(imagePath, {
      folder: "mi_store/apps",
    });

    const apkUpload = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { resource_type: "raw", folder: "mi_store/apks" },
        (error, result) => (error ? reject(error) : resolve(result))
      );
      createReadStream(apkPath).pipe(stream);
    });

    fs.unlinkSync(imagePath);
    fs.unlinkSync(apkPath);

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
      SELECT a.*, COALESCE(AVG(r.rating), 0)::numeric(2,1) AS average_rating
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
// 🌟 VALORAR UNA APP
// ================================
app.post("/api/rate/:appId", async (req, res) => {
  try {
    const { rating } = req.body;
    const { appId } = req.params;

    if (!req.session.user) {
      return res.status(401).json({ message: "Debes iniciar sesión para valorar una app" });
    }

    const userId = req.session.user.id;
    const valid = rating >= 1 && rating <= 5;
    if (!valid) return res.status(400).json({ message: "La valoración debe ser entre 1 y 5" });

    await db.query(
      `INSERT INTO ratings (user_id, app_id, rating, created_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id, app_id)
       DO UPDATE SET rating = EXCLUDED.rating, created_at = NOW()`,
      [userId, appId, rating]
    );

    res.json({ message: "Valoración registrada correctamente" });
  } catch (error) {
    console.error("❌ Error al valorar app:", error);
    res.status(500).json({ message: "Error al valorar app", error: error.message });
  }
});

// ================================
// ⭐ RESEÑAS DE APPS
// ================================
app.get("/api/apps/:id/reviews", async (req, res) => {
  try {
    const { id } = req.params;
    const result = await db.query(
      "SELECT username, rating, comment, created_at FROM app_reviews WHERE app_id = $1 ORDER BY created_at DESC",
      [id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error("❌ Error al obtener reseñas:", error);
    res.status(500).json({ message: "Error al obtener reseñas" });
  }
});

app.post("/api/apps/:id/reviews", async (req, res) => {
  try {
    const { id } = req.params;
    const { username, rating, comment } = req.body;

    if (!username || !rating)
      return res.status(400).json({ message: "Faltan datos obligatorios" });

    await db.query(
      `INSERT INTO app_reviews (app_id, username, rating, comment)
       VALUES ($1, $2, $3, $4)`,
      [id, username, rating, comment]
    );

    res.json({ message: "Reseña agregada con éxito" });
  } catch (error) {
    console.error("❌ Error al agregar reseña:", error);
    res.status(500).json({ message: "Error al agregar reseña" });
  }
});

// ================================
// ⚙️ INICIAR SERVIDOR
// ================================
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en el puerto ${PORT}`);
});
