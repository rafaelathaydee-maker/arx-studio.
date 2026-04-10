const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema(
  {
    nome: String,
    email: String,
    whatsapp: String,
    plano: String,
    senha: String,
    status: {
      type: String,
      default: 'Pedido novo'
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model('User', UserSchema);