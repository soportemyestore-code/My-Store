// ================================
// 🧩 MI STORE - BACKEND PRODUCCIÓN (CON SESIONES Y ROLES)
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

// ================================
// 📧 CONFIGURAR BREVO (SENDINBLUE)
// ================================
const brevo = new SibApiV3Sdk.TransactionalEmailsApi();
brevo.setApiKey(SibApiV3Sdk.TransactionalEmailsApiApiKeys.apiKey, process.env.BREVO_API_KEY);

// ================================
// 📁 CONFIGURACIONES BÁSICAS
// ================================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 4000;
const BASE_URL = process.env.BASE_URL || "https://my-store-lwl1.onrender.com";

// ================================
// ⚙️ MIDDLEWARES BASE
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
      maxAge: 24 * 60 * 60 * 1000, // 1 día
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
// ✅ ASEGURAR COLUMNAS DE RESET PASS
// ================================
(async function ensureUserColumns() {
  try {
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token TEXT;`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_expires BIGINT;`);
    console.log("✅ Columnas reset_token/reset_expires aseguradas en users.");
  } catch (err) {
    console.warn("⚠️ No se pudo asegurar columnas en users:", err.message);
  }
})();

// ================================
// 🛡️ MIDDLEWARES DE AUTENTICACIÓN
// ================================
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ message: "No autorizado. Inicia sesión." });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ message: "Acceso denegado. Solo administradores." });
  }
  next();
}

// ================================
// 🏠 RUTA PRINCIPAL
// ================================
app.get("/", (req, res) => {
  if (!req.session.user) return res.redirect("/login.html");
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ================================
// 🧑‍💼 CREAR ADMIN (SOLO 1 VEZ)
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
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0)
      return res.json({ success: false, message: "Usuario no encontrado" });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash || "");
    if (!valid) return res.json({ success: false, message: "Contraseña incorrecta" });

    // 🔥 NUEVO: guardar la sesión
    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      email: user.email,
    };

    // 🔥 NUEVO: determinar redirección según el rol
    const redirect = user.role === "admin" ? "/admin.html" : "/index.html";

    res.json({
      success: true,
      message: "Inicio de sesión correcto",
      user: req.session.user,
      redirect,
    });
  } catch (err) {
    console.error("❌ /login error:", err);
    res.status(500).json({ success: false, message: "Error interno" });
  }
});

// ================================
// 🚪 LOGOUT
// ================================
app.post("/logout", (req, res) => { // 🔥 ruta corregida (coherente con frontend)
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ success: true, message: "Sesión cerrada correctamente" });
  });
});

// ================================
// 🔎 CONSULTAR SESIÓN ACTUAL
// ================================
app.get("/api/session", (req, res) => {
  if (req.session.user)
    return res.json({
      loggedIn: true,
      ...req.session.user,
    });
  res.json({ loggedIn: false });
});

// ================================
// 🆕 REGISTRO
// ================================
app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const exists = await db.query("SELECT id FROM users WHERE username=$1 OR email=$2", [
      username,
      email,
    ]);
    if (exists.rows.length > 0)
      return res.json({ success: false, message: "Usuario o correo ya existe." });

    const hashed = await bcrypt.hash(password, 10);
    await db.query(
      `INSERT INTO users (username, email, password_hash, role, created_at)
       VALUES ($1, $2, $3, 'user', NOW())`,
      [username || email.split("@")[0], email, hashed]
    );
    res.json({ success: true, message: "Usuario registrado correctamente." });
  } catch (err) {
    console.error("❌ /register error:", err);
    res.status(500).json({ success: false, message: "Error interno" });
  }
});

// ===========================
// 📁 CATEGORÍAS API ENDPOINTS
// ===========================
const express = require("express");
const app = express();
app.use(express.json());

let categories = [
  { id: 1, name: "Juegos" },
  { id: 2, name: "Educación" },
  { id: 3, name: "Productividad" },
  { id: 4, name: "Entretenimiento" },
];

// ✅ Obtener todas las categorías
app.get("/api/categories", (req, res) => {
  res.json(categories);
});

// ✅ Crear nueva categoría
app.post("/api/categories", (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ message: "El nombre es obligatorio" });

  const exists = categories.find((c) => c.name.toLowerCase() === name.toLowerCase());
  if (exists) return res.status(400).json({ message: "Ya existe una categoría con ese nombre" });

  const newCat = { id: Date.now(), name };
  categories.push(newCat);
  res.status(201).json(newCat);
});

// ✅ Eliminar categoría por id
app.delete("/api/categories/:id", (req, res) => {
  const id = parseInt(req.params.id);
  const idx = categories.findIndex((c) => c.id === id);
  if (idx === -1) return res.status(404).json({ message: "Categoría no encontrada" });

  categories.splice(idx, 1);
  res.json({ message: "Categoría eliminada" });
});


// ================================
// 🚀 SUBIDA DE APPS (solo admin)
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

// --- Ruta para crear app con gallery (images[] up to 5) ---
app.post(
  "/api/apps",            // ruta RESTful coherente
  requireAdmin,
  upload.fields([
    { name: "images" },   // varios archivos: images[]
    { name: "apk", maxCount: 1 } // apk único
  ]),
  async (req, res) => {
    try {
      const { name, description, category, is_paid, version } = req.body;

      // Validaciones básicas
      const filesImages = req.files?.images || [];
      const apkFiles = req.files?.apk || [];

      if (!name) return res.status(400).json({ message: "El nombre es obligatorio." });
      if (!apkFiles.length) return res.status(400).json({ message: "APK requerido." });

      // Validar cantidad de imágenes (mín 3 - máx 5)
      if (filesImages.length < 3) return res.status(400).json({ message: "Sube al menos 3 imágenes de muestra." });
      if (filesImages.length > 5) return res.status(400).json({ message: "Máximo 5 imágenes permitidas." });

      // Subir imágenes a Cloudinary (en paralelo)
      const uploadImagePromises = filesImages.map(f =>
        cloudinary.uploader.upload(f.path, { folder: "mi_store/apps" })
      );
      const imagesResults = await Promise.all(uploadImagePromises);
      const imageUrls = imagesResults.map(r => r.secure_url);

      // Subir APK (como raw) por stream
      const apkUpload = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { resource_type: "raw", folder: "mi_store/apks" },
          (err, result) => (err ? reject(err) : resolve(result))
        );
        createReadStream(apkFiles[0].path).pipe(stream);
      });

      // Limpiar archivos temporales
      filesImages.forEach(f => { try { fs.unlinkSync(f.path); } catch(e){/* ignore */} });
      try { fs.unlinkSync(apkFiles[0].path); } catch(e){}

      // Insertar en DB: guardamos images como JSONB (arreglo de URLs) y version
      const insert = await db.query(
        `INSERT INTO apps (name, description, image, images, apk, category, is_paid, version, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
         RETURNING *`,
        [
          name,
          description,
          imageUrls[0] || null,       // mantén un "main image" por compatibilidad (primer elemento)
          JSON.stringify(imageUrls),  // images como JSON array
          apkUpload.secure_url,
          category,
          is_paid === "true",
          version || null
        ]
      );

      res.json({ message: "App subida con éxito", app: insert.rows[0] });
    } catch (err) {
      console.error("❌ /api/apps POST error:", err);
      res.status(500).json({ message: "Error al subir aplicación" });
    }
  }
);

app.put(
  "/api/apps/:id",
  requireAdmin,
  upload.fields([
    { name: "images" }, // opcional
    { name: "apk", maxCount: 1 } // opcional
  ]),
  async (req, res) => {
    try {
      const id = req.params.id;
      const { name, description, category, is_paid, version } = req.body;
      const filesImages = req.files?.images || [];
      const apkFiles = req.files?.apk || [];

      // Obtener app actual
      const cur = await db.query("SELECT * FROM apps WHERE id = $1", [id]);
      if (cur.rows.length === 0) return res.status(404).json({ message: "App no encontrada" });
      const appRow = cur.rows[0];

      let imageUrls = appRow.images || []; // existing array (JSONB)
      if (typeof imageUrls === 'string') {
        try { imageUrls = JSON.parse(imageUrls); } catch(e){ imageUrls = []; }
      }

      // Si suben nuevas imágenes, reemplazamos (validar 3-5)
      if (filesImages.length) {
        if (filesImages.length < 3) return res.status(400).json({ message: "Sube al menos 3 imágenes de muestra." });
        if (filesImages.length > 5) return res.status(400).json({ message: "Máximo 5 imágenes permitidas." });

        const uploadImagePromises = filesImages.map(f =>
          cloudinary.uploader.upload(f.path, { folder: "mi_store/apps" })
        );
        const imagesResults = await Promise.all(uploadImagePromises);
        imageUrls = imagesResults.map(r => r.secure_url);

        // limpiar temporales
        filesImages.forEach(f => { try { fs.unlinkSync(f.path); } catch(e){} });
      }

      // Si suben APK, reemplazar
      let apkUrl = appRow.apk;
      if (apkFiles.length) {
        const apkUpload = await new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { resource_type: "raw", folder: "mi_store/apks" },
            (err, result) => (err ? reject(err) : resolve(result))
          );
          createReadStream(apkFiles[0].path).pipe(stream);
        });
        apkUrl = apkUpload.secure_url;
        try { fs.unlinkSync(apkFiles[0].path); } catch(e){}
      }

      // Actualizar row (incluye version y images JSONB)
      const updated = await db.query(
        `UPDATE apps SET name=$1, description=$2, image=$3, images=$4, apk=$5, category=$6, is_paid=$7, version=$8, updated_at=NOW()
         WHERE id=$9 RETURNING *`,
        [
          name ?? appRow.name,
          description ?? appRow.description,
          imageUrls[0] ?? appRow.image,
          JSON.stringify(imageUrls),
          apkUrl,
          category ?? appRow.category,
          (typeof is_paid !== 'undefined') ? (is_paid === 'true') : appRow.is_paid,
          version ?? appRow.version,
          id
        ]
      );

      res.json({ message: "App actualizada", app: updated.rows[0] });
    } catch (err) {
      console.error("❌ /api/apps/:id PUT error:", err);
      res.status(500).json({ message: "Error al actualizar aplicación" });
    }
  }
);


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
app.listen(PORT, () => {
  console.log(`🚀 Servidor ejecutándose en http://localhost:${PORT}`);
});


