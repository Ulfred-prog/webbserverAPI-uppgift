const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'api_db',
  port: 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

async function testConnection() {
  try {
    const connection = await pool.getConnection();
    console.log('✅ MySQL connected successfully');
    connection.release();
  } catch (error) {
    console.error('❌ MySQL connection failed:', error.message);
  }
}

app.get('/', (req, res) => {
  res.type('text/html').status(200).send(`
    <!DOCTYPE html>
    <html>
    <head><title>Users REST API</title><style>body{font-family:Arial;max-width:800px;margin:50px auto;padding:20px;background:#f5f5f5;}h1{color:#333;}ul{list-style:none;padding:0;}li{margin:10px 0;padding:10px;background:white;border-radius:5px;box-shadow:0 2px 5px rgba(0,0,0,0.1);}</style></head>
    <body>
      <h1>👤 Users REST API with Login</h1>
      <ul>
        <li><strong>GET /users</strong> – List all users (id, username)</li>
        <li><strong>GET /users/:id</strong> – Single user by ID (no password, 404 if not found)</li>
        <li><strong>POST /users</strong> – Register: {"username":"newuser","password":"pass123"} → 201</li>
        <li><strong>POST /login</strong> – Login: {"username":"user1","password":"password123"} → 200 user</li>
      </ul>
      <p><em>bcrypt hashed. Test: user1/pass: password123, user2: secret. Port ${PORT}</em></p>
    </body>
    </html>
  `);
});

app.get('/users', async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT id, username, created_at FROM users ORDER BY id DESC');
    res.status(200).json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.execute('SELECT id, username, created_at FROM users WHERE id = ?', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(200).json(rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

app.post('/users', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password || password.length < 6) {
      return res.status(400).json({ error: 'Username and password (min 6 chars) required' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword]
    );
    const [newUser] = await pool.execute('SELECT id, username, created_at FROM users WHERE id = ?', [result.insertId]);
    res.status(201).json(newUser[0]);
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Username already exists' });
    }
    console.error(error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const { password: _, ...safeUser } = user;
    res.status(200).json({ message: 'Login successful', user: safeUser });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((error, req, res, next) => {
  console.error(error.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log('📚 Visit / for documentation');
  testConnection();
});

