require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();

/* =========================
   CONFIG BASICA
========================= */
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: true, limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* =========================
   RATE LIMIT
========================= */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas tentativas. Tente novamente em alguns minutos.' },
});

app.use('/login', authLimiter);
app.use('/register', authLimiter);

/* =========================
   HELPERS
========================= */
function sanitizeText(value) {
  if (typeof value !== 'string') return '';
  return value.trim().replace(/\s+/g, ' ').slice(0, 200);
}

function sanitizeEmail(value) {
  return sanitizeText(value).toLowerCase();
}

function sanitizeWhatsapp(value) {
  return String(value || '').replace(/\D/g, '').slice(0, 15);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPlano(plano) {
  return ['Starter', 'Pro', 'Elite'].includes(plano);
}

function isValidStatus(status) {
  return ['Pedido novo', 'Recebido', 'Entregue'].includes(status);
}

/* =========================
   BANCO
========================= */
const User = require('./models/User');

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('🔥 Mongo conectado'))
  .catch((err) => {
    console.error('❌ Erro Mongo:', err.message);
  });

/* =========================
   ROTAS FRONT
========================= */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/cadastro', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'cadastro.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'cliente.html'));
});

/* =========================
   CADASTRO
========================= */
app.post('/register', async (req, res) => {
  try {
    const nome = sanitizeText(req.body.nome);
    const email = sanitizeEmail(req.body.email);
    const whatsapp = sanitizeWhatsapp(req.body.whatsapp);
    const plano = sanitizeText(req.body.plano);
    const senha = String(req.body.senha || '');

    if (!nome || !email || !whatsapp || !plano || !senha) {
      return res.status(400).json({ error: 'Preencha todos os campos.' });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Email inválido.' });
    }

    if (!isValidPlano(plano)) {
      return res.status(400).json({ error: 'Plano inválido.' });
    }

    if (senha.length < 8) {
      return res.status(400).json({ error: 'A senha precisa ter pelo menos 8 caracteres.' });
    }

    const existe = await User.findOne({ email });
    if (existe) {
      return res.status(400).json({ error: 'Esse email já está cadastrado.' });
    }

    const senhaHash = await bcrypt.hash(senha, 12);

    const user = new User({
      nome,
      email,
      whatsapp,
      plano,
      senha: senhaHash,
      status: 'Pedido novo',
    });

    await user.save();

    return res.json({ ok: true });
  } catch (err) {
    console.error('❌ Erro em /register:', err);
    return res.status(500).json({ error: 'Erro interno no cadastro.' });
  }
});

/* =========================
   LOGIN
========================= */
app.post('/login', async (req, res) => {
  try {
    const email = sanitizeEmail(req.body.email);
    const senha = String(req.body.senha || '');

    if (!email || !senha) {
      return res.status(400).json({ error: 'Preencha email e senha.' });
    }

    if (
      email === String(process.env.ADMIN_EMAIL || '').toLowerCase() &&
      senha === String(process.env.ADMIN_PASS || '')
    ) {
      return res.json({
        admin: true,
        adminUser: {
          nome: 'Rafael Athayde',
          email: process.env.ADMIN_EMAIL,
          whatsapp: '11968304041',
          plano: 'Administrador',
        },
      });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    const senhaValida = await bcrypt.compare(senha, user.senha);
    if (!senhaValida) {
      return res.status(401).json({ error: 'Senha incorreta.' });
    }

    return res.json({
      user: {
        _id: user._id,
        nome: user.nome,
        email: user.email,
        whatsapp: user.whatsapp,
        plano: user.plano,
        status: user.status,
      },
    });
  } catch (err) {
    console.error('❌ Erro em /login:', err);
    return res.status(500).json({ error: 'Erro interno no login.' });
  }
});

/* =========================
   CLIENTES
========================= */
app.get('/clientes', async (req, res) => {
  try {
    const users = await User.find({}, { senha: 0 }).sort({ createdAt: -1, _id: -1 });
    return res.json(users);
  } catch (err) {
    console.error('❌ Erro em /clientes:', err);
    return res.status(500).json({ error: 'Erro ao buscar clientes.' });
  }
});

/* =========================
   BUSCAR CLIENTE POR ID
========================= */
app.get('/clientes/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id, { senha: 0 });
    if (!user) {
      return res.status(404).json({ error: 'Cliente não encontrado.' });
    }
    return res.json(user);
  } catch (err) {
    console.error('❌ Erro em /clientes/:id:', err);
    return res.status(500).json({ error: 'Erro ao buscar cliente.' });
  }
});

/* =========================
   ATUALIZAR STATUS
========================= */
app.patch('/clientes/:id/status', async (req, res) => {
  try {
    const status = sanitizeText(req.body.status);

    if (!isValidStatus(status)) {
      return res.status(400).json({ error: 'Status inválido.' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true, projection: { senha: 0 } }
    );

    if (!user) {
      return res.status(404).json({ error: 'Cliente não encontrado.' });
    }

    return res.json({ ok: true, user });
  } catch (err) {
    console.error('❌ Erro em PATCH /clientes/:id/status:', err);
    return res.status(500).json({ error: 'Erro ao atualizar status.' });
  }
});

/* =========================
   404
========================= */
app.use((req, res) => {
  res.status(404).json({ error: 'Rota não encontrada.' });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🔥 ARX PRO rodando em http://localhost:${PORT}`);
});