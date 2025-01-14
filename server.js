const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database(':memory:');

// 初始化数据库
db.serialize(() => {
  db.run('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, is_admin INTEGER)');
  db.run('CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, content TEXT, FOREIGN KEY(user_id) REFERENCES users(id))');
  db.run('CREATE TABLE replies (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER, user_id INTEGER, content TEXT, FOREIGN KEY(message_id) REFERENCES messages(id), FOREIGN KEY(user_id) REFERENCES users(id))');

  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync('20220440915', salt);
  db.run('INSERT INTO users (username, password, is_admin) VALUES (?,?,?)', ['zyb', hashedPassword, 1]);
});

// 用户注册
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);

  db.run('INSERT INTO users (username, password) VALUES (?,?)', [username, hashedPassword], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({ message: 'User registered successfully' });
  });
});

// 用户登录
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username =?', [username], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (row && bcrypt.compareSync(password, row.password)) {
      console.log('is_admin value from database:', row.is_admin);
      const token = jwt.sign({ id: row.id, username: row.username, is_admin: row.is_admin }, 'secret_key', { expiresIn: '1h' });
      console.log('Generated token:', token);
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Invalid username or password' });
    }
  });
});

// 中间件：验证 JWT
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// 发表留言，需要 JWT 验证
app.post('/messages', authenticateToken, (req, res) => {
  const { content } = req.body;
  const user_id = req.user.id;

  db.run('INSERT INTO messages (user_id, content) VALUES (?,?)', [user_id, content], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({ message: 'Message posted successfully' });
  });
});

// 查看留言，不需要 JWT 验证
app.get('/messages', (req, res) => {
  db.all(`
    SELECT messages.id, messages.user_id, messages.content, users.username 
    FROM messages 
    JOIN users ON messages.user_id = users.id
  `, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// 编辑留言，需要 JWT 验证
app.put('/messages/:id', authenticateToken, (req, res) => {
  const { content } = req.body;
  const message_id = req.params.id;
  const user_id = req.user.id;

  db.run('UPDATE messages SET content =? WHERE id =? AND user_id =?', [content, message_id, user_id], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Message updated successfully' });
  });
});

// 删除留言，需要 JWT 验证
app.delete('/messages/:id', authenticateToken, (req, res) => {
  const message_id = req.params.id;
  const user_id = req.user.id;

  db.run('DELETE FROM messages WHERE id =? AND user_id =?', [message_id, user_id], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Message deleted successfully' });
  });
});

// 发表回复，需要 JWT 验证
app.post('/messages/:message_id/replies', authenticateToken, (req, res) => {
  const { content } = req.body;
  const message_id = req.params.message_id;
  const user_id = req.user.id;

  db.run('INSERT INTO replies (message_id, user_id, content) VALUES (?,?,?)', [message_id, user_id, content], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({ message: 'Reply posted successfully' });
  });
});

// 查看回复，不需要 JWT 验证
app.get('/messages/:messageid/replies', (req, res) => {
  const messageid = req.params.messageid;

  db.all(
    `SELECT replies.id, replies.content, replies.message_id, replies.user_id, users.username
     FROM replies
     INNER JOIN users ON replies.user_id = users.id
     WHERE replies.message_id =?`,
    [messageid],
    (err, rows) => {
      if (err) {
        res.status(400).json({ error: err.message });
        return;
      }
      console.log("Returning replies data:", rows);
      res.json(rows);
    }
  );
});

// 编辑回复，需要 JWT 验证
app.put('/replies/:id', authenticateToken, (req, res) => {
  const { content } = req.body;
  const reply_id = req.params.id;
  const user_id = req.user.id;

  db.run('UPDATE replies SET content =? WHERE id =? AND user_id =?', [content, reply_id, user_id], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Reply updated successfully' });
  });
});

// 删除回复，需要 JWT 验证
app.delete('/replies/:id', authenticateToken, (req, res) => {
  const reply_id = req.params.id;
  const user_id = req.user.id;

  db.run('DELETE FROM replies WHERE id =? AND user_id =?', [reply_id, user_id], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Reply deleted successfully' });
  });
});

// 获取用户信息，需要 JWT 验证
app.get('/api/user', authenticateToken, (req, res) => {
  const user_id = req.user.id;

  db.get('SELECT username FROM users WHERE id =?', [user_id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(row);
  });
});

// 更新用户信息，需要 JWT 验证
app.put('/api/user', authenticateToken, (req, res) => {
  const { username, password } = req.body;
  const user_id = req.user.id;

  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);

  db.run('UPDATE users SET username =?, password =? WHERE id =?', [username, hashedPassword, user_id], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'User information updated successfully' });
  });
});

// 获取所有用户信息，需要管理员权限
app.get('/api/users', authenticateToken, (req, res) => {
  const user_id = req.user.id;
  db.get('SELECT is_admin FROM users WHERE id =?', [user_id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (row && row.is_admin) {
      // 当用户是管理员时，查询所有用户信息
      db.all('SELECT username FROM users', [], (err, rows) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res.json(rows);
      });
    } else {
      res.status(403).json({ error: 'Access denied' });
    }
  });
});


app.listen(3001, () => {
  console.log('Server is running on port 3001');
});