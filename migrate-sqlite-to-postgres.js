// migrate-sqlite-to-postgres.js
require('dotenv').config();
const Database = require('better-sqlite3');
const { Pool } = require('pg');
const path = require('path');

const sqlitePath = path.join(__dirname, 'store.db');
const sqlite = new Database(sqlitePath);
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false });

(async () => {
  try {
    const rows = sqlite.prepare('SELECT id, nombre, descripcion, imagen, archivo, created_at FROM apps').all();
    console.log('Rows in sqlite:', rows.length);
    for (const r of rows) {
      // if imagen or archivo are local paths, you should upload them to S3 first; this script assumes URLs are already public.
      await pool.query('INSERT INTO apps (nombre, descripcion, imagen, archivo, created_at) VALUES ($1,$2,$3,$4,$5)', [r.nombre, r.descripcion, r.imagen, r.archivo, r.created_at]);
    }
    console.log('Migration completed.');
    process.exit(0);
  } catch (err) {
    console.error('Migration error', err);
    process.exit(1);
  }
})();
