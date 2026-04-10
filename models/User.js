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
    },
    pagamentoAprovado: {
      type: Boolean,
      default: false
    },
    ultimoPagamentoId: {
      type: String,
      default: ''
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model('User', UserSchema);