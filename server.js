const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;


app.use(cors());
app.use(express.json());

// Databas
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect((err) => {
  if (err) {
    console.error('Database connection failed:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

// Verifiera JWT Token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; 

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = decoded;
    next();
  });
};

// Routes

// Root route 
app.get('/', (req, res) => {
  res.json({
    message: 'REST API Documentation',
    version: '1.0.0',
    routes: {
      'GET /': 'This documentation',
      'GET /users': 'Get all users (requires JWT)',
      'GET /users/:id': 'Get user by ID (requires JWT)',
      'POST /users': 'Create new user (requires JWT)',
      'PUT /users/:id': 'Update user by ID (requires JWT)',
      'POST /login': 'Login and get JWT token'
    },
    authentication: 'Use POST /login to get JWT token. Include in header: Authorization: Bearer <token>'
  });
});

// Login route
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password_hash;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  const query = `SELECT id, username, password_hash FROM users WHERE username = ?`;
  console.log(query);
  db.query(query, [username], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }

    console.log(results);
    console.log(results.length);
    if (results.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    let user = results[0];
    user.password_hash = user.password_hash.slice(0,user.password_hash.length-1);
    

    bcrypt.compare(password, user.password_hash, (err, isMatch) => {
      if (err) {
        return res.status(500).json({ message: 'Internal server error' });
      }

      if (!isMatch) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      return res.status(200).json({message: 'Succé!'});
      
      // JWT token
     // const token = jwt.sign(
      //  { id: user.id, username: user.username },
       // process.env.JWT_SECRET,
       // { expiresIn: '1h' }
     // );

     // res.status(200).json({ message: 'Login successful', token });
    });
    /*
   if (user.password_hash == password) {
    res.status(200).json({ message: 'Login successful' });
   }
   else {
    return res.status(401).json({ message: 'Invalid credentials' });
   }*/
  });
});

// cryptering test
bcrypt.compare(
  'test123',
  '$2b$10$rivVUV7jodRZuNsM07EwGODXvSeOXUe2nZLSsvknFDT52H1zt8pTS',
  (err, result) => console.log("BCRYPT TEST:", result)
);


// User router

app.get('/users', verifyToken, (req, res) => {
  const query = 'SELECT id, username, created_at FROM users';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
    res.status(200).json(results);
  });
});

app.get('/users/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const query = 'SELECT id, username, created_at FROM users WHERE id = ?';
  db.query(query, [id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json(results[0]);
  });
});


app.post('/users', verifyToken, (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username, and password required' });
  }

  // Lösen
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error('Bcrypt error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }

    const query = 'INSERT INTO users (username, password_hash) VALUES (?, ?, ?)';
    db.query(query, [username, hash], (err, result) => {
      if (err) {
        console.error('Database error:', err);
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ message: 'Username already exists' });
        }
        return res.status(500).json({ message: 'Internal server error' });
      }

      const newUser = {
        id: result.insertId,
        username,
        created_at: new Date()
      };

      res.status(201).json(newUser);
    });
  });
});


app.put('/users/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const { username, password } = req.body;

  if (!username && !password) {
    return res.status(400).json({ message: 'At least one field to update required' });
  }

  // om användare finns
  const checkQuery = 'SELECT id FROM users WHERE id = ?';
  db.query(checkQuery, [id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Dynamisk uppdatering
    let updateFields = [];
    let values = [];

    if (username) {
      updateFields.push('username = ?');
      values.push(username);
    }
 
    if (password) {
      bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
          console.error('Bcrypt error:', err);
          return res.status(500).json({ message: 'Internal server error' });
        }
        updateFields.push('password_hash = ?');
        values.push(hash);
        executeUpdate();
      });
      return; 
    }

    executeUpdate();

    function executeUpdate() {
      values.push(id);
      const query = `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`;
      db.query(query, values, (err, result) => {
        if (err) {
          console.error('Database error:', err);
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Username  already exists' });
          }
          return res.status(500).json({ message: 'Internal server error' });
        }

        // Hämta uppdaterad användare
        const selectQuery = 'SELECT id, username, created_at FROM users WHERE id = ?';
        db.query(selectQuery, [id], (err, results) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Internal server error' });
          }
          res.status(200).json(results[0]);
        });
      });
    }
  });
});

// Starta server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
