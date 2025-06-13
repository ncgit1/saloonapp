const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const SECRET = process.env.JWT_SECRET || 'secret123';

// Register endpoint
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  const hashed = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email, hashed]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(400).json({ error: e.detail || e.message });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  if (!user.rows.length) return res.status(400).json({ error: 'User not found' });
  const valid = await bcrypt.compare(password, user.rows[0].password);
  if (!valid) return res.status(401).json({ error: 'Invalid password' });
  const token = jwt.sign({ id: user.rows[0].id, name: user.rows[0].name }, SECRET);
  res.json({ token, name: user.rows[0].name, id: user.rows[0].id });
});

// Create appointment
app.post('/appointments', async (req, res) => {
  const { userId, name, service, date } = req.body;
  if (!userId || !name || !service || !date) return res.status(400).json({ error: 'Missing fields' });
  try {
    const result = await pool.query(
      'INSERT INTO appointments (user_id, name, service, date) VALUES ($1, $2, $3, $4) RETURNING *',
      [userId, name, service, date]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Get appointments by user
app.get('/appointments', async (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ error: 'Missing userId' });
  try {
    const result = await pool.query(
      'SELECT * FROM appointments WHERE user_id = $1 ORDER BY date ASC',
      [userId]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
