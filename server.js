// ================================
// 🧩 MI STORE - BACKEND PRODUCCIÓN (ESM) - UN SOLO ARCHIVO
// ================================

import express from "express";
import fetch from "node-fetch";
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
import db from "./db.js"; // tu pool exportado (lo llamaste pool en db.js)
import path from "path";
import { fileURLToPath } from "url";
import SibApiV3Sdk from "@sendinblue/client";

dotenv.config();

// ================================
// 📧 CONFIGURAR BREVO (SENDINBLUE)
// ================================
const brevo = new SibApiV3Sdk.TransactionalEmailsApi();
if (process.env.BREVO_API_KEY) {
  brevo.setApiKey(SibApiV3Sdk.TransactionalEmailsApiApiKeys.apiKey, process.env.BREVO_API_KEY);
}

// ================================
// 📁 CONFIGURACIONES BÁSICAS
// ================================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 4000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

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
// ✅ ASEGURAR COLUMNAS Y TABLAS NECESARIAS
// ================================
(async function ensureSchema() {
  try {
    // users reset columns (ya lo tenías)
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token TEXT;`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_expires BIGINT;`);

    // asegurar tabla categories (si ya existe, la instrucción no rompe)
    await db.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT
      );
    `);

    // asegurar columnas básicas en apps (evita errores si faltan columnas)
    // Esto no cambiará tipos si ya existen, solo las agrega si faltan.
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS image TEXT;`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS images JSONB;`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS apk TEXT;`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS is_paid BOOLEAN DEFAULT false;`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS price NUMERIC(10,2) DEFAULT 0;`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS version TEXT;`);
    console.log("✅ Esquema (columns/tables) verificado/creado si era necesario.");
  } catch (err) {
    console.warn("⚠️ No se pudo asegurar esquema:", err.message);
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

    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      email: user.email,
    };

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
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ success: true, message: "Sesión cerrada correctamente" });
  });
});

// ================================
// 🔎 CONSULTAR SESIÓN ACTUAL
// ================================
app.get("/api/session", (req, res) => {
  if (req.session.user) return res.json({ loggedIn: true, ...req.session.user });
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

// Credenciales
const CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const SECRET = process.env.PAYPAL_SECRET;

// URLs de PayPal (LIVE)
const PAYPAL_API = "https://api-m.paypal.com";  // para pruebas usa api-m.sandbox.paypal.com

// Función para generar token de acceso
async function generateAccessToken() {
  const auth = Buffer.from(`${CLIENT_ID}:${SECRET}`).toString("base64");

  const response = await fetch(`${PAYPAL_API}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      "Authorization": `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: "grant_type=client_credentials"
  });

  const data = await response.json();
  return data.access_token;
}

// 1) Crear orden
app.post("/api/orders", async (req, res) => {
  try {
    const { amount } = req.body;

    const access_token = await generateAccessToken();

    const response = await fetch(`${PAYPAL_API}/v2/checkout/orders`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${access_token}`
      },
      body: JSON.stringify({
        intent: "CAPTURE",
        purchase_units: [
          {
            amount: { value: amount }
          }
        ]
      })
    });

    const data = await response.json();
    res.json(data);

  } catch (error) {
    console.error("Error creando orden:", error);
    res.status(500).json({ error: "Error creando orden" });
  }
});

// 2) Capturar orden
app.post("/api/orders/:orderId/capture", async (req, res) => {
  try {
    const { orderId } = req.params;

    const access_token = await generateAccessToken();

    const response = await fetch(`${PAYPAL_API}/v2/checkout/orders/${orderId}/capture`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${access_token}`
      }
    });

    const data = await response.json();
    res.json(data);

  } catch (error) {
    console.error("Error capturando orden:", error);
    res.status(500).json({ error: "Error capturando orden" });
  }
});


// ================================
// 📂 RUTAS CATEGORIES (CRUD) - protegidas para escritura
// ================================
app.get("/api/categories", async (req, res) => {
  try {
    const result = await db.query("SELECT id, name, description FROM categories ORDER BY name ASC");
    res.json(result.rows);
  } catch (err) {
    console.error("❌ Error al obtener categorías:", err);
    res.status(500).json({ message: "Error al obtener categorías" });
  }
});

app.post("/api/categories", requireAdmin, async (req, res) => {
  try {
    const { name, description } = req.body;
    if (!name) return res.status(400).json({ message: "El nombre es obligatorio" });

    // evitar duplicados
    const exists = await db.query("SELECT id FROM categories WHERE LOWER(name) = LOWER($1)", [name]);
    if (exists.rows.length > 0) return res.status(400).json({ message: "Ya existe esa categoría" });

    const result = await db.query(
      "INSERT INTO categories (name, description) VALUES ($1, $2) RETURNING id, name, description",
      [name, description || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("❌ Error creando categoría:", err);
    res.status(500).json({ message: "Error al crear categoría" });
  }
});

app.put("/api/categories/:id", requireAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { name, description } = req.body;
    if (!name) return res.status(400).json({ message: "El nombre es obligatorio" });

    const updated = await db.query(
      "UPDATE categories SET name=$1, description=$2 WHERE id=$3 RETURNING id, name, description",
      [name, description || null, id]
    );
    if (updated.rows.length === 0) return res.status(404).json({ message: "Categoría no encontrada" });
    res.json(updated.rows[0]);
  } catch (err) {
    console.error("❌ Error actualizando categoría:", err);
    res.status(500).json({ message: "Error al actualizar categoría" });
  }
});

app.delete("/api/categories/:id", requireAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const exists = await db.query("SELECT id FROM categories WHERE id = $1", [id]);
    if (exists.rows.length === 0) return res.status(404).json({ message: "Categoría no encontrada" });

    // opcional: podrías reasignar apps a null category antes de eliminar
    await db.query("DELETE FROM categories WHERE id = $1", [id]);
    res.json({ message: "Categoría eliminada" });
  } catch (err) {
    console.error("❌ Error eliminando categoría:", err);
    res.status(500).json({ message: "Error al eliminar categoría" });
  }
});

// ================================
// 🚀 SUBIDA DE APPS (solo admin)
// ================================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "./uploads"),
  filename: (req, file, cb) =>
    cb(null, `${Date.now()}-${file.originalname.replace(/\s+/g, "_")}`),
});
if (!fs.existsSync("./uploads")) fs.mkdirSync("./uploads", { recursive: true });

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/") || file.mimetype === "application/vnd.android.package-archive")
      cb(null, true);
    else cb(new Error("Tipo de archivo no permitido"));
  },
});

// --- Ruta para crear app con gallery (images[] up to 5) ---
app.post(
  "/api/apps",
  requireAdmin,
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "images", maxCount: 5 },
    { name: "apk", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { name, description, category, is_paid, price, version } = req.body;

      // files
      const mainImageFile = req.files?.image?.[0];
      const galleryFiles = req.files?.images || [];
      const apkFile = req.files?.apk?.[0];

      // validations
      if (!name) return res.status(400).json({ message: "El nombre es obligatorio." });
      if (!apkFile) return res.status(400).json({ message: "APK requerido." });
      if (galleryFiles.length < 3) return res.status(400).json({ message: "Sube al menos 3 imágenes de muestra." });
      if (galleryFiles.length > 5) return res.status(400).json({ message: "Máximo 5 imágenes permitidas." });

      // upload main image (optional)
      let mainImageUrl = null;
      if (mainImageFile) {
        const mainRes = await cloudinary.uploader.upload(mainImageFile.path, {
          folder: "mi_store/apps/main",
        });
        mainImageUrl = mainRes.secure_url;
      }

      // upload gallery in parallel
      const galleryPromises = galleryFiles.map(f => cloudinary.uploader.upload(f.path, { folder: "mi_store/apps/gallery" }));
      const galleryResults = await Promise.all(galleryPromises);
      const galleryUrls = galleryResults.map(r => r.secure_url);

      // upload apk as raw
      const apkUpload = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { resource_type: "raw", folder: "mi_store/apks" },
          (err, result) => (err ? reject(err) : resolve(result))
        );
        createReadStream(apkFile.path).pipe(stream);
      });

      // cleanup local files
      const toUnlink = [mainImageFile, ...galleryFiles, apkFile].filter(Boolean);
      for (const f of toUnlink) {
        try { fs.unlinkSync(f.path); } catch (_) {}
      }

      // store in DB
      const insert = await db.query(
        `INSERT INTO apps (name, description, image, images, apk, category, is_paid, price, version, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),NOW())
         RETURNING *`,
        [
          name,
          description || null,
          mainImageUrl || galleryUrls[0] || null,
          JSON.stringify(galleryUrls),
          apkUpload.secure_url,
          category || null,
          is_paid === "true",
          price ? Number(price) : 0,
          version || null,
        ]
      );

      res.status(201).json({ message: "App subida con éxito", app: insert.rows[0] });
    } catch (err) {
      console.error("❌ /api/apps POST error:", err);
      res.status(500).json({ message: err.message || "Error al subir aplicación" });
    }
  }
);

// ---------- ACTUALIZAR APP ----------
app.put(
  "/api/apps/:id",
  requireAdmin,
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "images", maxCount: 5 },
    { name: "apk", maxCount: 1 },
  ]),
  async (req, res) => {
    const { id } = req.params;
    const { name, description, version, category, is_paid, price, existing_images } = req.body;

    try {
      // 1) obtener app actual
      const cur = await db.query("SELECT * FROM apps WHERE id = $1", [id]);
      if (cur.rows.length === 0) return res.status(404).json({ message: "App no encontrada" });
      const appRow = cur.rows[0];

      // 2) procesar imagen principal (si suben nueva)
      const mainImageFile = req.files?.image?.[0];
      let mainImageUrl = appRow.image || null;
      if (mainImageFile) {
        const imgRes = await cloudinary.uploader.upload(mainImageFile.path, {
          folder: "mi_store/apps/main",
        });
        mainImageUrl = imgRes.secure_url;
      }

      // 3) procesar galería: combinar existing_images (enviado desde frontend) + nuevos uploads
      let imagesArray = [];
      if (existing_images) {
        try {
          const parsed = JSON.parse(existing_images);
          if (Array.isArray(parsed)) imagesArray = parsed;
        } catch (e) {
          imagesArray = [];
        }
      } else {
        try {
          imagesArray = appRow.images && typeof appRow.images === "string"
            ? JSON.parse(appRow.images)
            : (Array.isArray(appRow.images) ? appRow.images : []);
        } catch (e) {
          imagesArray = Array.isArray(appRow.images) ? appRow.images : [];
        }
      }

      // upload new gallery files if any
      const galleryFiles = req.files?.images || [];
      if (galleryFiles.length) {
        const uploadPromises = galleryFiles.map(f => cloudinary.uploader.upload(f.path, { folder: "mi_store/apps/gallery" }));
        const results = await Promise.all(uploadPromises);
        const newUrls = results.map(r => r.secure_url);
        imagesArray = imagesArray.concat(newUrls);
      }

      // enforce max 5 images
      if (imagesArray.length > 5) imagesArray = imagesArray.slice(0, 5);

      // 4) procesar APK (si suben nuevo)
      let apkUrl = appRow.apk || null;
      const apkFile = req.files?.apk?.[0];
      if (apkFile) {
        const apkUpload = await new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { resource_type: "raw", folder: "mi_store/apks" },
            (err, result) => (err ? reject(err) : resolve(result))
          );
          createReadStream(apkFile.path).pipe(stream);
        });
        apkUrl = apkUpload.secure_url;
      }

      // 5) cleanup temporary files
      const tmpFiles = [];
      if (mainImageFile) tmpFiles.push(mainImageFile.path);
      if (galleryFiles.length) galleryFiles.forEach(f => tmpFiles.push(f.path));
      if (apkFile) tmpFiles.push(apkFile.path);
      for (const p of tmpFiles) {
        try { fs.unlinkSync(p); } catch (e) { /* ignore */ }
      }

      // 6) validate gallery minimum
      if (!imagesArray || imagesArray.length < 3) {
        return res.status(400).json({ message: "La galería debe tener al menos 3 imágenes." });
      }

      // 7) actualizar DB
      const updated = await db.query(
        `UPDATE apps SET
           name = $1,
           description = $2,
           version = $3,
           category = $4,
           is_paid = $5,
           price = $6,
           image = $7,
           images = $8,
           apk = $9,
           updated_at = NOW()
         WHERE id = $10
         RETURNING *`,
        [
          name ?? appRow.name,
          description ?? appRow.description,
          version ?? appRow.version,
          category ?? appRow.category,
          typeof is_paid !== "undefined" ? (is_paid === "true") : appRow.is_paid,
          (typeof price !== "undefined" && price !== "") ? price : appRow.price,
          mainImageUrl ?? appRow.image,
          JSON.stringify(imagesArray),
          apkUrl ?? appRow.apk,
          id,
        ]
      );

      res.json({ message: "App actualizada", app: updated.rows[0] });
    } catch (err) {
      console.error("❌ PUT /api/apps error:", err);
      res.status(500).json({ message: "Error al actualizar la app" });
    }
  }
);

// ================================
// 🗑️ ELIMINAR APP (solo admin)
// ================================
app.delete("/api/apps/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;

    // Verificar si existe
    const existing = await db.query("SELECT * FROM apps WHERE id = $1", [id]);
    if (existing.rows.length === 0)
      return res.status(404).json({ message: "App no encontrada." });

    // Opcional: podrías intentar borrar recursos en Cloudinary aquí (no lo hago automáticamente)
    await db.query("DELETE FROM apps WHERE id = $1", [id]);
    res.json({ message: "App eliminada correctamente." });
  } catch (err) {
    console.error("❌ /api/apps/:id DELETE error:", err);
    res.status(500).json({ message: "Error al eliminar la app." });
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

// opcional: obtener una app por id (útil)
app.get("/api/apps/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const result = await db.query("SELECT * FROM apps WHERE id = $1", [id]);
    if (result.rows.length === 0) return res.status(404).json({ message: "App no encontrada" });
    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ GET /api/apps/:id error:", err);
    res.status(500).json({ message: "Error al obtener la app" });
  }
});

// ================================
// 🚀 INICIAR SERVIDOR
// ================================
app.listen(PORT, () => {
  console.log(`🚀 Servidor ejecutándose en http://localhost:${PORT}`);
});



