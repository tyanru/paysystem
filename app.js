const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({ secret: 'secret-key', resave: false, saveUninitialized: true }));

const db = new sqlite3.Database('database.db');

// ユーザーテーブルが存在しない場合は作成
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL,
      password TEXT NOT NULL,
      balance INTEGER DEFAULT 0,
      isCompany INTEGER DEFAULT 0
    )
  `);
});

// ハッシュ化された管理者パスワードを環境変数から取得
const hashedAdminPassword = process.env.HASHED_ADMIN_PASSWORD;

// ルートエンドポイント
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/views/index.html');
});

// ログイン
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      console.error(err.message);
      return;
    }

    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.userId = user.id;
      res.redirect('/dashboard');
    } else {
      res.redirect('/');
    }
  });
});

// ダッシュボード
app.get('/dashboard', (req, res) => {
  const userId = req.session.userId;
  if (!userId) {
    res.redirect('/');
    return;
  }

  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      console.error(err.message);
      return;
    }

    res.render(__dirname + '/views/dashboard.html', { user });
  });
});

// 送金
app.post('/transfer', (req, res) => {
  const userId = req.session.userId;
  const recipient = req.body.recipient;
  const amount = parseInt(req.body.amount);

  if (!userId || isNaN(amount) || amount <= 0) {
    res.redirect('/dashboard');
    return;
  }

  db.serialize(() => {
    db.get('SELECT * FROM users WHERE id = ?', [userId], (err, sender) => {
      if (err) {
        console.error(err.message);
        return;
      }

      if (sender.balance >= amount) {
        db.get('SELECT * FROM users WHERE username = ?', [recipient], (err, receiver) => {
          if (err) {
            console.error(err.message);
            return;
          }

          if (receiver) {
            db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, sender.id], (err) => {
              if (err) {
                console.error(err.message);
                return;
              }

              db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, receiver.id], (err) => {
                if (err) {
                  console.error(err.message);
                  return;
                }

                res.redirect('/dashboard');
              });
            });
          } else {
            res.redirect('/dashboard');
          }
        });
      } else {
        res.redirect('/dashboard');
      }
    });
  });
});

// ログアウト
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err.message);
      return;
    }
    res.redirect('/');
  });
});

// アカウント作成
app.post('/signup', (req, res) => {
  const signupUsername = req.body.signupUsername;
  const signupPassword = req.body.signupPassword;
  const adminPasswordInput = req.body.adminPassword;

  // 管理者パスワードが正しいか確認
  bcrypt.compare(adminPasswordInput, hashedAdminPassword, (err, result) => {
    if (err || !result) {
      res.redirect('/');
      return;
    }

    // 既存のユーザーかどうかを確認
    db.get('SELECT * FROM users WHERE username = ?', [signupUsername], (err, existingUser) => {
      if (err) {
        console.error(err.message);
        return;
      }

      if (existingUser) {
        res.redirect('/');
        return;
      }

      const hashedPassword = bcrypt.hashSync(signupPassword, 10);

      db.run('INSERT INTO users (username, password) VALUES (?, ?)', [signupUsername, hashedPassword], (err) => {
        if (err) {
          console.error(err.message);
          return;
        }

        res.redirect('/');
      });
    });
  });
});

// サーバーを起動
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
