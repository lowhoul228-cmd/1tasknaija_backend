const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const axios = require('axios');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'tasknaija-secret-12345-xyz';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@tasknaija.com';
const ADMIN_PASS = process.env.ADMIN_PASS || 'Admin12345!';
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY || '';

const db = new sqlite3.Database('./tasknaija.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  db.run(`CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, description TEXT, category TEXT, price REAL, location TEXT, user_id INTEGER, status TEXT DEFAULT 'open', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
});

// Check backend is live
app.get('/', (req, res) => {
  res.json({ ok: true, app: 'TaskNaija API' });
});

// Auth middleware
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// REGISTER
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Fill all fields' });
  const hashed = await bcrypt.hash(password, 10);
  const role = email.toLowerCase() === ADMIN_EMAIL.toLowerCase() ? 'admin' : 'user';
  db.run('INSERT INTO users (name, email, password, role) VALUES (?,?,?,?)', [name, email.toLowerCase(), hashed, role], function(err) {
    if (err) return res.status(400).json({ error: 'Email already exists' });
    const token = jwt.sign({ id: this.lastID, email: email.toLowerCase(), role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: this.lastID, name, email, role } });
  });
});

// LOGIN
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email=?', [email.toLowerCase()], async (err, user) => {
    if (!user) return res.status(400).json({ error: 'User not found' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Wrong password' });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  });
});

// GET TASKS
app.get('/api/tasks', (req, res) => {
  db.all('SELECT * FROM tasks ORDER BY id DESC', [], (err, rows) => {
    res.json(rows || []);
  });
});

// CREATE TASK
app.post('/api/tasks', auth, (req, res) => {
  const { title, description, category, price, location } = req.body;
  db.run('INSERT INTO tasks (title, description, category, price, location, user_id) VALUES (?,?,?,?,?,?)', [title, description, category, price, location, req.user.id], function(err) {
    if (err) return res.status(500).json({ error: 'Could not create task' });
    res.json({ id: this.lastID, title, description, category, price, location, status: 'open' });
  });
});

// PAYSTACK VERIFY
app.get('/api/paystack/verify/:ref', async (req, res) => {
  try {
    const r = await axios.get('https://api.paystack.co/transaction/verify/' + req.params.ref, { headers: { Authorization: 'Bearer ' + PAYSTACK_SECRET } });
    res.json(r.data);
  } catch (e) {
    res.status(400).json({ error: 'Verify failed' });
  }
});

// ADMIN - GET ALL USERS
app.get('/api/admin/users', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  db.all('SELECT id, name, email, role, created_at FROM users', [], (err, rows) => res.json(rows || []));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Running on ' + PORT));
