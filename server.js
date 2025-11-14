// ================================
// 🧩 MI STORE - BACKEND PRODUCCIÓN (ESM) - UN SOLO ARCHIVO (MODIFICADO PARA DEPURACIÓN)
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

// ===== DEBUG / INFO al iniciar (no imprimir secretos) =====
console.log("🚀 Iniciando servidor (modo debug). Revisa estos valores:");
console.log("PORT ->", process.env.PORT ? process.env.PORT : "(no definido, usando fallback)");
console.log("PAYPAL_CLIENT_ID ->", process.env.PAYPAL_CLIENT_ID ? "OK" : "MISSING");
console.log("PAYPAL_SECRET ->", process.env.PAYPAL_SECRET ? "OK" : "MISSING");
console.log("NODE_ENV ->", process.env.NODE_ENV || "development");

// ================================
// ⚙️ MIDDLEWARES BASE
// ================================
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));
app.use(helmet({ contentSecurityPolicy: false }));
// Nota: express.static antes o después de rutas puede afectar solo a GET estáticos.
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
console.log("✅ Cloudinary configurado (si las variables están presentes)");

// ================================
// ✅ ASEGURAR COLUMNAS Y TABLAS NECESARIAS
// ================================
(async function ensureSchema() {
  try {
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token TEXT;`);
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_expires BIGINT;`);

    await db.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT
      );
    `);

    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS image TEXT;`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS images JSONB;`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS apk TEXT;`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS is_paid BOOLEAN DEFAULT false;`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS price NUMERIC(10,2) DEFAULT 0;`);
    await db.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS version TEXT;`);
    console.log("✅ Esquema verificado/creado si era necesario.");
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
// HEALTHCHECK y DEBUG ROUTES (temporal)
// ================================
app.get("/health", (req, res) => res.json({ ok: true, timestamp: Date.now() }));

// Para debugging: si visitas GET /api/orders verás una respuesta clara
app.get("/api/orders", (req, res) => {
  return res.status(200).json({ message: "Endpoint OK — use POST to create orders" });
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
// Credenciales PayPal y helpers
// ================================
const CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const SECRET = process.env.PAYPAL_SECRET;
const PAYPAL_API = "https://api-m.paypal.com"; // LIVE (cambiar a sandbox si pruebas)

async function generateAccessToken() {
  try {
    if (!CLIENT_ID || !SECRET) throw new Error("Faltan credenciales de PayPal en variables de entorno");

    const auth = Buffer.from(`${CLIENT_ID}:${SECRET}`).toString("base64");

    const response = await fetch(`${PAYPAL_API}/v1/oauth2/token`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${auth}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: "grant_type=client_credentials",
    });

    const text = await response.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      console.error("generateAccessToken: respuesta no JSON:", text);
      throw new Error("Respuesta inesperada al generar token de PayPal");
    }

    if (!response.ok) {
      console.error("generateAccessToken: PayPal error:", data);
      throw new Error(data.error || JSON.stringify(data));
    }

    return data.access_token;
  } catch (err) {
    console.error("Error generando access token:", err.message || err);
    throw err;
  }
}

// ================================
// 1) Crear orden (POST /api/orders)
// ================================
app.post("/api/orders", async (req, res) => {
  console.log("📩 POST /api/orders recibida", { bodyPreview: req.body && typeof req.body === 'object' ? JSON.stringify(req.body).slice(0,200) : req.body });
  try {
    const { amount } = req.body;
    if (!amount) return res.status(400).json({ error: "Amount missing" });

    const access_token = await generateAccessToken();

    const response = await fetch(`${PAYPAL_API}/v2/checkout/orders`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${access_token}`,
      },
      body: JSON.stringify({
        intent: "CAPTURE",
        purchase_units: [
          {
            amount: {
            currency_code: "USD",
            value: amount
          },
          },
        ],
      }),
    });

    const data = await response.json();
    console.log("📤 PayPal create order response:", { status: response.status, bodyPreview: JSON.stringify(data).slice(0,1000) });

    if (!response.ok) return res.status(response.status).json(data);

    res.json(data);
  } catch (error) {
    console.error("Error creando orden:", error && error.message ? error.message : error);
    res.status(500).json({ error: "Error creando orden" });
  }
});

// ================================
// 2) Capturar orden (POST /api/orders/:orderId/capture)
// ================================
app.post("/api/orders/:orderId/capture", async (req, res) => {
  const orderId = req.params.orderId || req.params.orderID || req.body.orderID || req.body.orderId;
  console.log("🔎 POST /api/orders/:orderId/capture recibida", { orderId });
  try {
    if (!orderId) return res.status(400).json({ error: "orderId missing in params or body" });

    const access_token = await generateAccessToken();

    const response = await fetch(`${PAYPAL_API}/v2/checkout/orders/${orderId}/capture`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${access_token}`,
      },
    });

    const data = await response.json();
    console.log("📥 PayPal capture response:", { status: response.status, bodyPreview: JSON.stringify(data).slice(0,1000) });

    if (!response.ok) return res.status(response.status).json(data);

    res.json(data);
  } catch (error) {
    console.error("Error capturando orden:", error && error.message ? error.message : error);
    res.status(500).json({ error: "Error capturando orden" });
  }
});

// ================================
// Resto de rutas (categories, apps, etc.)
// (NO modifiqué lógicas de negocio, solo añadí logs y endpoints de debug)
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

// (mantengo el resto de rutas unchanged — para ahorrar espacio en este diff no las repito, pero en tu archivo
// real ya están presentes. Si quieres que incluya cambios específicos en otras rutas dímelo.)

// ================================
// 🚀 INICIAR SERVIDOR
// ================================
app.listen(PORT, () => {
  console.log(`🚀 Servidor ejecutándose en puerto ${PORT}`);
});
