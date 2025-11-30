// server.js - merged and corrected version
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
import db from "./db.js";
import path from "path";
import { fileURLToPath } from "url";
import SibApiV3Sdk from "@sendinblue/client";
import paypal from '@paypal/checkout-server-sdk';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = Number(process.env.PORT) || 4000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const router = express.Router();
//const paypal = require('@paypal/checkout-server-sdk');

const brevo = new SibApiV3Sdk.TransactionalEmailsApi();
if (process.env.BREVO_API_KEY) {
  brevo.setApiKey(SibApiV3Sdk.TransactionalEmailsApiApiKeys.apiKey, process.env.BREVO_API_KEY);
}

app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const allowedOrigin = process.env.FRONTEND_ORIGIN || process.env.BASE_URL || true;
app.use(cors({
  origin: allowedOrigin,
  credentials: true,
  methods: ["GET","POST","PUT","DELETE","OPTIONS"]
}));

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.static(path.join(__dirname, "public")));

const limiter = rateLimit({ windowMs: 60*1000, max: 120, message: "Demasiadas solicitudes. Intenta más tarde." });
app.use(limiter);

app.use(session({
  secret: process.env.SESSION_SECRET || "mi-store-secret",
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    httpOnly: true,
    maxAge: 24*60*60*1000
  }
}));

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});
console.log("✅ Cloudinary configurado correctamente");

(async function ensureSchema(){
  try {
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token TEXT;`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_expires BIGINT;`);
    await db.query(`CREATE TABLE IF NOT EXISTS categories ( id SERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT );`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS image TEXT;`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS images JSONB;`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS apk TEXT;`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS is_paid BOOLEAN DEFAULT false;`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS price NUMERIC(10,2) DEFAULT 0;`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS version TEXT;`);
    console.log("✅ Esquema verificado/creado si era necesario.");
  } catch (err) {
    console.warn("⚠️ No se pudo asegurar esquema:", err.message || err);
  }
})();

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ message: "No autorizado. Inicia sesión." });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") return res.status(403).json({ message: "Acceso denegado." });
  next();
}

// Basic routes
app.get("/", (req, res) => {
  if (!req.session.user) return res.redirect("/login.html");
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) return res.json({ success: false, message: "Usuario no encontrado" });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash || "");
    if (!valid) return res.json({ success: false, message: "Contraseña incorrecta" });
    req.session.user = { id: user.id, username: user.username, role: user.role, email: user.email };
    const redirect = user.role === "admin" ? "/admin.html" : "/index.html";
    res.json({ success: true, message: "Inicio de sesión correcto", user: req.session.user, redirect });
  } catch (err) {
    console.error("❌ /login error:", err);
    res.status(500).json({ success: false, message: "Error interno" });
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ success: true, message: "Sesión cerrada correctamente" });
  });
});

app.get("/api/session", (req, res) => {
  if (req.session.user) return res.json({ loggedIn: true, ...req.session.user });
  res.json({ loggedIn: false });
});

app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const exists = await db.query("SELECT id FROM users WHERE username=$1 OR email=$2", [username, email]);
    if (exists.rows.length > 0) return res.json({ success: false, message: "Usuario o correo ya existe." });
    const hashed = await bcrypt.hash(password, 10);
    await db.query(`INSERT INTO users (username, email, password_hash, role, created_at) VALUES ($1, $2, $3, 'user', NOW())`, [username || email.split("@")[0], email, hashed]);
    res.json({ success: true, message: "Usuario registrado correctamente." });
  } catch (err) {
    console.error("❌ /register error:", err);
    res.status(500).json({ success: false, message: "Error interno" });
  }
});

// PAYPAL
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;
const PAYPAL_ENV = process.env.PAYPAL_ENV || "sandbox";
const PAYPAL_API_BASE = process.env.PAYPAL_API_BASE || (PAYPAL_ENV === "live" ? "https://api-m.paypal.com" : "https://api-m.sandbox.paypal.com");

async function generateAccessToken() {
  if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
    const err = new Error("PayPal credentials missing. Set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET in env.");
    console.error(err);
    throw err;
  }
  const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString("base64");
  const response = await fetch(`${PAYPAL_API_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials"
  });
  if (!response.ok) {
    const txt = await response.text();
    console.error("PayPal token error:", response.status, txt);
    throw new Error("Failed to obtain PayPal token");
  }
  const data = await response.json();
  return data.access_token;
}

// Helper GET for debugging
app.get("/api/orders", (req, res) => {
  res.json({ message: "Use POST /api/orders to create an order. See docs." });
});

app.post("/api/orders", async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount || isNaN(Number(amount)) || Number(amount) <= 0) return res.status(400).json({ error: "Invalid amount" });
    const accessToken = await generateAccessToken();
    const response = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders`, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ intent: "CAPTURE", purchase_units: [{ amount: { currency_code: "USD", value: Number(amount).toFixed(2) } }] })
    });
    const data = await response.json();
    if (!response.ok) {
      console.error("Error creating PayPal order:", response.status, data);
      return res.status(500).json({ error: "create-order-failed", details: data });
    }
    res.json(data);
  } catch (err) {
    console.error("Error creando orden:", err);
    res.status(500).json({ error: "create-order-failed", details: err.message || err });
  }
});

app.post("/api/orders/:orderID/capture", async (req, res) => {
  try {
    const orderID = req.params.orderID;
    if (!orderID) return res.status(400).json({ error: "orderID required" });
    const accessToken = await generateAccessToken();
    const response = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders/${orderID}/capture`, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    });
    const data = await response.json();
    if (!response.ok) {
      console.error("Error capturing PayPal order:", response.status, data);
      return res.status(500).json({ error: "capture-failed", details: data });
    }
    console.log("PayPal capture result:", data);
    res.json(data);
  } catch (err) {
    console.error("Error capturando orden:", err);
    res.status(500).json({ error: "capture-failed", details: err.message || err });
  }
});

// CATEGORIES CRUD (copied from original)
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
    const exists = await db.query("SELECT id FROM categories WHERE LOWER(name) = LOWER($1)", [name]);
    if (exists.rows.length > 0) return res.status(400).json({ message: "Ya existe esa categoría" });
    const result = await db.query("INSERT INTO categories (name, description) VALUES ($1, $2) RETURNING id, name, description", [name, description || null]);
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
    const updated = await db.query("UPDATE categories SET name=$1, description=$2 WHERE id=$3 RETURNING id, name, description", [name, description || null, id]);
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
    await db.query("DELETE FROM categories WHERE id = $1", [id]);
    res.json({ message: "Categoría eliminada" });
  } catch (err) {
    console.error("❌ Error eliminando categoría:", err);
    res.status(500).json({ message: "Error al eliminar categoría" });
  }
});

// UPLOADS / APPS HANDLERS (carried from original)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "./uploads"),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/\s+/g, "_")}`),
});
if (!fs.existsSync("./uploads")) fs.mkdirSync("./uploads", { recursive: true });

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/") || file.mimetype === "application/vnd.android.package-archive") cb(null, true);
    else cb(new Error("Tipo de archivo no permitido"));
  },
});

app.post("/api/apps", requireAdmin, upload.fields([
  { name: "image", maxCount: 1 },
  { name: "images", maxCount: 5 },
  { name: "apk", maxCount: 1 },
]), async (req, res) => {
  try {
    const { name, description, category, is_paid, price, version } = req.body;
    const mainImageFile = req.files?.image?.[0];
    const galleryFiles = req.files?.images || [];
    const apkFile = req.files?.apk?.[0];
    if (!name) return res.status(400).json({ message: "El nombre es obligatorio." });
    if (!apkFile) return res.status(400).json({ message: "APK requerido." });
    if (galleryFiles.length < 3) return res.status(400).json({ message: "Sube al menos 3 imágenes de muestra." });
    if (galleryFiles.length > 5) return res.status(400).json({ message: "Máximo 5 imágenes permitidas." });
    let mainImageUrl = null;
    if (mainImageFile) {
      const mainRes = await cloudinary.uploader.upload(mainImageFile.path, { folder: "mi_store/apps/main" });
      mainImageUrl = mainRes.secure_url;
    }
    const galleryPromises = galleryFiles.map(f => cloudinary.uploader.upload(f.path, { folder: "mi_store/apps/gallery" }));
    const galleryResults = await Promise.all(galleryPromises);
    const galleryUrls = galleryResults.map(r => r.secure_url);
    const apkUpload = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream({ resource_type: "raw", folder: "mi_store/apks" }, (err, result) => (err ? reject(err) : resolve(result)));
      createReadStream(apkFile.path).pipe(stream);
    });
    const toUnlink = [mainImageFile, ...galleryFiles, apkFile].filter(Boolean);
    for (const f of toUnlink) { try { fs.unlinkSync(f.path); } catch (_) {} }
    const insert = await db.query(`INSERT INTO apps (name, description, image, images, apk, category, is_paid, price, version, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),NOW()) RETURNING *`, [ name, description || null, mainImageUrl || galleryUrls[0] || null, JSON.stringify(galleryUrls), apkUpload.secure_url, category || null, is_paid === "true", price ? Number(price) : 0, version || null ]);
    res.status(201).json({ message: "App subida con éxito", app: insert.rows[0] });
  } catch (err) {
    console.error("❌ /api/apps POST error:", err);
    res.status(500).json({ message: err.message || "Error al subir aplicación" });
  }
});

app.put("/api/apps/:id", requireAdmin, upload.fields([
  { name: "image", maxCount: 1 },
  { name: "images", maxCount: 5 },
  { name: "apk", maxCount: 1 },
]), async (req, res) => {
  const { id } = req.params;
  const { name, description, version, category, is_paid, price, existing_images } = req.body;
  try {
    const cur = await db.query("SELECT * FROM apps WHERE id = $1", [id]);
    if (cur.rows.length === 0) return res.status(404).json({ message: "App no encontrada" });
    const appRow = cur.rows[0];
    const mainImageFile = req.files?.image?.[0];
    let mainImageUrl = appRow.image || null;
    if (mainImageFile) {
      const imgRes = await cloudinary.uploader.upload(mainImageFile.path, { folder: "mi_store/apps/main" });
      mainImageUrl = imgRes.secure_url;
    }
    let imagesArray = [];
    if (existing_images) {
      try { const parsed = JSON.parse(existing_images); if (Array.isArray(parsed)) imagesArray = parsed; } catch (e) { imagesArray = []; }
    } else {
      try { imagesArray = appRow.images && typeof appRow.images === "string" ? JSON.parse(appRow.images) : (Array.isArray(appRow.images) ? appRow.images : []); } catch (e) { imagesArray = Array.isArray(appRow.images) ? appRow.images : []; }
    }
    const galleryFiles = req.files?.images || [];
    if (galleryFiles.length) {
      const uploadPromises = galleryFiles.map(f => cloudinary.uploader.upload(f.path, { folder: "mi_store/apps/gallery" }));
      const results = await Promise.all(uploadPromises);
      const newUrls = results.map(r => r.secure_url);
      imagesArray = imagesArray.concat(newUrls);
    }
    if (imagesArray.length > 5) imagesArray = imagesArray.slice(0,5);
    let apkUrl = appRow.apk || null;
    const apkFile = req.files?.apk?.[0];
    if (apkFile) {
      const apkUpload = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream({ resource_type: "raw", folder: "mi_store/apks" }, (err, result) => (err ? reject(err) : resolve(result)));
        createReadStream(apkFile.path).pipe(stream);
      });
      apkUrl = apkUpload.secure_url;
    }
    const tmpFiles = [];
    if (mainImageFile) tmpFiles.push(mainImageFile.path);
    if (galleryFiles.length) galleryFiles.forEach(f => tmpFiles.push(f.path));
    if (apkFile) tmpFiles.push(apkFile.path);
    for (const p of tmpFiles) { try { fs.unlinkSync(p); } catch (e) {} }
    if (!imagesArray || imagesArray.length < 3) return res.status(400).json({ message: "La galería debe tener al menos 3 imágenes." });
    const updated = await db.query(`UPDATE apps SET name = $1, description = $2, version = $3, category = $4, is_paid = $5, price = $6, image = $7, images = $8, apk = $9, updated_at = NOW() WHERE id = $10 RETURNING *`, [ name ?? appRow.name, description ?? appRow.description, version ?? appRow.version, category ?? appRow.category, typeof is_paid !== "undefined" ? (is_paid === "true") : appRow.is_paid, (typeof price !== "undefined" && price !== "") ? price : appRow.price, mainImageUrl ?? appRow.image, JSON.stringify(imagesArray), apkUrl ?? appRow.apk, id ]);
    res.json({ message: "App actualizada", app: updated.rows[0] });
  } catch (err) {
    console.error("❌ PUT /api/apps error:", err);
    res.status(500).json({ message: "Error al actualizar la app" });
  }
});

app.delete("/api/apps/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const existing = await db.query("SELECT * FROM apps WHERE id = $1", [id]);
    if (existing.rows.length === 0) return res.status(404).json({ message: "App no encontrada." });
    await db.query("DELETE FROM apps WHERE id = $1", [id]);
    res.json({ message: "App eliminada correctamente." });
  } catch (err) {
    console.error("❌ /api/apps/:id DELETE error:", err);
    res.status(500).json({ message: "Error al eliminar la app." });
  }
});

app.get("/api/apps", async (req, res) => {
  try {
    const result = await db.query(`SELECT a.*, COALESCE(AVG(r.rating), 0)::numeric(2,1) AS average_rating FROM apps a LEFT JOIN ratings r ON a.id = r.app_id GROUP BY a.id ORDER BY a.created_at DESC`);
    res.json(result.rows);
  } catch (err) {
    console.error("❌ /api/apps error:", err);
    res.status(500).json({ message: "Error al obtener apps" });
  }
});

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

//-----------------------------------------

// Configuración del cliente PayPal (LIVE)
function environment() {
  const clientId = process.env.PAYPAL_CLIENT_ID;
  const clientSecret = process.env.PAYPAL_CLIENT_SECRET;

  if (process.env.PAYPAL_MODE === 'live') {
    return new paypal.core.LiveEnvironment(clientId, clientSecret);
  } else {
    return new paypal.core.SandboxEnvironment(clientId, clientSecret);
  }
}

function client() {
  return new paypal.core.PayPalHttpClient(environment());
}

// Ruta para crear una orden de pago
router.post('/create-order', async (req, res) => {
  const { appId, amount, currency = 'USD' } = req.body;
  const username = req.session?.username || req.body.username;

  if (!username) {
    return res.status(401).json({ error: 'Usuario no autenticado' });
  }

  if (!appId || !amount) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }

  try {
    const request = new paypal.orders.OrdersCreateRequest();
    request.prefer("return=representation");
    request.requestBody({
      intent: 'CAPTURE',
      purchase_units: [{
        reference_id: `app_${appId}_user_${username}`,
        description: `Compra de App #${appId}`,
        amount: {
          currency_code: currency,
          value: amount.toFixed(2)
        }
      }],
      application_context: {
        brand_name: 'Tu Tienda de Apps',
        landing_page: 'NO_PREFERENCE',
        user_action: 'PAY_NOW',
        return_url: `${process.env.SERVER_URL}/app-details.html?id=${appId}`,
        cancel_url: `${process.env.SERVER_URL}/app-details.html?id=${appId}`
      }
    });

    const order = await client().execute(request);
    res.json({ orderID: order.result.id });
  } catch (error) {
    console.error('Error al crear orden:', error);
    res.status(500).json({ error: 'Error al crear la orden de pago' });
  }
});

// Ruta para capturar el pago
router.post('/capture-order', async (req, res) => {
  const { orderID, appId } = req.body;
  const username = req.session?.username || req.body.username;

  if (!username) {
    return res.status(401).json({ error: 'Usuario no autenticado' });
  }

  try {
    const request = new paypal.orders.OrdersCaptureRequest(orderID);
    request.requestBody({});

    const capture = await client().execute(request);
    const captureData = capture.result;

    if (captureData.status === 'COMPLETED') {
      const purchaseUnit = captureData.purchase_units[0];
      const captureId = purchaseUnit.payments.captures[0].id;
      const amount = parseFloat(purchaseUnit.payments.captures[0].amount.value);
      const payerEmail = captureData.payer.email_address;

      const userResult = await req.db.query(
        'SELECT id FROM users WHERE username = $1',
        [username]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      const userId = userResult.rows[0].id;

      const existingPurchase = await req.db.query(
        'SELECT id FROM purchases WHERE transaction_id = $1',
        [captureId]
      );

      if (existingPurchase.rows.length > 0) {
        return res.status(400).json({ error: 'Esta transacción ya fue registrada' });
      }

      await req.db.query(
        `INSERT INTO purchases (user_id, app_id, transaction_id, amount, currency, payer_email, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [userId, appId, captureId, amount, 'USD', payerEmail, 'completed']
      );

      res.json({
        success: true,
        message: 'Pago completado exitosamente',
        transactionId: captureId
      });
    } else {
      res.status(400).json({ error: 'El pago no se completó correctamente' });
    }
  } catch (error) {
    console.error('Error al capturar orden:', error);
    res.status(500).json({ error: 'Error al procesar el pago' });
  }
});

// Ruta para verificar si el usuario ya compró una app
router.get('/check-purchase/:appId', async (req, res) => {
  const { appId } = req.params;
  const username = req.session?.username || req.query.username;

  if (!username) {
    return res.json({ purchased: false });
  }

  try {
    const userResult = await req.db.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    if (userResult.rows.length === 0) {
      return res.json({ purchased: false });
    }

    const userId = userResult.rows[0].id;

    const result = await req.db.query(
      `SELECT id, downloaded, transaction_id FROM purchases 
       WHERE user_id = $1 AND app_id = $2 AND status = 'completed'
       LIMIT 1`,
      [userId, appId]
    );

    if (result.rows.length > 0) {
      return res.json({
        purchased: true,
        downloaded: result.rows[0].downloaded,
        transactionId: result.rows[0].transaction_id
      });
    }

    res.json({ purchased: false });
  } catch (error) {
    console.error('Error al verificar compra:', error);
    res.status(500).json({ error: 'Error al verificar la compra' });
  }
});

// Ruta para registrar la descarga
router.post('/register-download', async (req, res) => {
  const { appId } = req.body;
  const username = req.session?.username || req.body.username;

  if (!username) {
    return res.status(401).json({ error: 'Usuario no autenticado' });
  }

  try {
    const userResult = await req.db.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const userId = userResult.rows[0].id;

    const purchaseResult = await req.db.query(
      `SELECT id, downloaded FROM purchases 
       WHERE user_id = $1 AND app_id = $2 AND status = 'completed'
       LIMIT 1`,
      [userId, appId]
    );

    if (purchaseResult.rows.length === 0) {
      return res.status(403).json({ error: 'No has comprado esta app' });
    }

    const purchase = purchaseResult.rows[0];

    if (purchase.downloaded) {
      return res.status(403).json({
        error: 'Ya has descargado esta app anteriormente',
        alreadyDownloaded: true
      });
    }

    await req.db.query(
      `UPDATE purchases 
       SET downloaded = true, download_date = CURRENT_TIMESTAMP
       WHERE id = $1`,
      [purchase.id]
    );

    res.json({ success: true, message: 'Descarga registrada' });
  } catch (error) {
    console.error('Error al registrar descarga:', error);
    res.status(500).json({ error: 'Error al registrar la descarga' });
  }
});

// En ES Modules, exportación:
export default router;



app.listen(PORT, () => {
  console.log(`🚀 Servidor ejecutándose en http://localhost:${PORT}`);
  console.log(`→ BASE_URL: ${BASE_URL}`);
});



