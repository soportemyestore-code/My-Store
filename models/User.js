const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, index: true },
  email: { type: String, required: true, unique: true, lowercase: true, index: true },
  passwordHash: { type: String }, // vacío para OAuth
  provider: { type: String, enum: ['local','google','facebook'], default: 'local' },
  providerId: { type: String }, // id desde Google/Facebook
  role: { type: String, enum: ['user','admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
