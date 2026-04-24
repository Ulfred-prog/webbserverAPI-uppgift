const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-in-production';
const JWT_EXPIRES_IN = '1h'; 

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

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; 
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired. Please log in again.' });
    }
    return res.status(403).json({ error: 'Invalid token.' });
  }
}

app.get('/', (req, res) => {
  res.type('text/html').status(200).send(`
    <!DOCTYPE html>
    <html>
    <head><title>Users REST API</title><style>
      body{font-family:Arial;max-width:900px;margin:50px auto;padding:20px;background:#f5f5f5;}
      h1,h2{color:#333;}
      ul{list-style:none;padding:0;}
      li{margin:10px 0;padding:12px;background:white;border-radius:5px;box-shadow:0 2px 5px rgba(0,0,0,0.1);}
      .badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:12px;font-weight:bold;margin-right:8px;}
      .get{background:#61affe;color:white;}
      .post{background:#49cc90;color:white;}
      .lock{color:#e53935;}
    </style></head>
    <body>
      <h1>👤 Users REST API with JWT Auth</h1>

      <h2>🔓 Public Routes</h2>
      <ul>
        <li><span class="badge post">POST</span> <strong>/users</strong> – Register: {"username":"newuser","password":"pass123"} → 201 + JWT token</li>
        <li><span class="badge post">POST</span> <strong>/login</strong> – Login: {"username":"user1","password":"password123"} → 200 + JWT token</li>
      </ul>

      <h2>🔒 Protected Routes <span class="lock">(Require: Authorization: Bearer &lt;token&gt;)</span></h2>
      <ul>
        <li><span class="badge get">GET</span> <strong>/users</strong> – List all users (id, username)</li>
        <li><span class="badge get">GET</span> <strong>/users/:id</strong> – Single user by ID (404 if not found)</li>
        <li><span class="badge get">GET</span> <strong>/me</strong> – Returns the currently authenticated user's profile</li>
        <li><span class="badge put" style="background:#fca130;color:white;">PUT</span> <strong>/users/:id</strong> – Update own account: {"username":"newname","password":"newpass"} → 200 + updated user (owner only)</li>
      </ul>

      <p><em>Tokens expire after ${JWT_EXPIRES_IN}. Test credentials: user1 / password123, user2 / secret. Port ${PORT}</em></p>
    </body>
    </html>
  `);
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

    const [newUser] = await pool.execute(
      'SELECT id, username, created_at FROM users WHERE id = ?',
      [result.insertId]
    );

    const token = jwt.sign(
      { id: newUser[0].id, username: newUser[0].username },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.status(201).json({ user: newUser[0], token });
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

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    const { password: _, ...safeUser } = user;
    res.status(200).json({ message: 'Login successful', user: safeUser, token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/users', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT id, username, created_at FROM users ORDER BY id DESC');
    res.status(200).json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.execute(
      'SELECT id, username, created_at FROM users WHERE id = ?',
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json(rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

app.put('/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { username, password } = req.body;

    if (req.user.id !== parseInt(id)) {
      return res.status(403).json({ error: 'You can only update your own account.' });
    }

    const [existing] = await pool.execute('SELECT id FROM users WHERE id = ?', [id]);
    if (existing.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!username && !password) {
      return res.status(400).json({ error: 'Provide at least one field to update: username or password' });
    }

    if (password && password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const fields = [];
    const values = [];

    if (username) {
      fields.push('username = ?');
      values.push(username);
    }

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      fields.push('password = ?');
      values.push(hashedPassword);
    }

    values.push(id);

    await pool.execute(
      `UPDATE users SET ${fields.join(', ')} WHERE id = ?`,
      values
    );

    const [updated] = await pool.execute(
      'SELECT id, username, created_at FROM users WHERE id = ?',
      [id]
    );

    res.status(200).json({ message: 'User updated successfully', user: updated[0] });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Username already exists' });
    }
    console.error(error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

app.get('/me', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT id, username, created_at FROM users WHERE id = ?',
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json(rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch profile' });
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
