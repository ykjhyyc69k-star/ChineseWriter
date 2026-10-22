const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const cors = require('cors');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database(process.env.DB_PATH || 'data.db');

// Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT,
    google_id TEXT UNIQUE,
    role TEXT DEFAULT 'student',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    content TEXT DEFAULT '',
    is_shared INTEGER DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, name),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS list_assignments (
    list_id INTEGER NOT NULL,
    student_id INTEGER NOT NULL,
    PRIMARY KEY (list_id, student_id),
    FOREIGN KEY (list_id) REFERENCES lists(id) ON DELETE CASCADE,
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    character TEXT NOT NULL,
    word TEXT,
    practiced INTEGER DEFAULT 0,
    correct INTEGER DEFAULT 0,
    mastery INTEGER DEFAULT 0, -- 0-5 simple score
    next_review DATETIME,
    last_practiced DATETIME,
    UNIQUE(user_id, character),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS supervisors (
    student_id INTEGER NOT NULL,
    supervisor_id INTEGER NOT NULL,
    relationship TEXT DEFAULT 'parent',
    PRIMARY KEY (student_id, supervisor_id),
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (supervisor_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS streaks (
    user_id INTEGER PRIMARY KEY,
    current_streak INTEGER DEFAULT 0,
    last_practice_date TEXT,
    daily_goal INTEGER DEFAULT 10,
    today_count INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    supervisor_id INTEGER NOT NULL,
    student_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (supervisor_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);

// Email transporter (optional)
let transporter = null;
if (process.env.SMTP_HOST) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT || 587,
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

// Ensure at least one parent
const parentCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'parent'").get().c;
if (parentCount === 0) {
  const first = db.prepare('SELECT id FROM users ORDER BY id LIMIT 1').get();
  if (first) db.prepare("UPDATE users SET role = 'parent' WHERE id = ?").run(first.id);
}

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 30
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// Google OAuth (only if credentials are set)
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || `http://localhost:${PORT}/auth/google/callback`
  }, (accessToken, refreshToken, profile, done) => {
    let user = db.prepare('SELECT * FROM users WHERE google_id = ? OR email = ?').get(profile.id, profile.emails?.[0]?.value);
    if (!user) {
      const email = profile.emails?.[0]?.value || null;
      const info = db.prepare('INSERT INTO users (google_id, email, username, role) VALUES (?, ?, ?, ?)').run(
        profile.id, email, profile.displayName || email, 'student'
      );
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    } else if (!user.google_id) {
      db.prepare('UPDATE users SET google_id = ? WHERE id = ?').run(profile.id, user.id);
    }
    return done(null, user);
  }));
}

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  done(null, user);
});

app.use(express.static(path.join(__dirname, 'public')));

// Auth helpers
function requireAuth(req, res, next) {
  if (!req.session.userId && !req.user) return res.status(401).json({ error: 'Not logged in' });
  next();
}

// Google routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  req.session.userId = req.user.id;
  req.session.username = req.user.username || req.user.email;
  req.session.role = req.user.role;
  res.redirect('/');
});

// Password reset request
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.json({ ok: true }); // don't reveal existence
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 1000 * 60 * 30).toISOString(); // 30 min
  db.prepare('INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)').run(user.id, token, expires);
  // In production configure SMTP. For now the token is returned if no mailer, or emailed.
  const resetUrl = `${req.protocol}://${req.get('host')}/?reset=${token}`;
  if (transporter) {
    try {
      await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: email,
        subject: 'Password reset – Chinese Character Writer',
        text: `Reset your password: ${resetUrl}\n\nThis link expires in 30 minutes.`
      });
    } catch (err) {
      console.error('Email send failed', err);
    }
  }
  res.json({ ok: true, message: 'If the email exists, a reset link was sent.', resetUrl: process.env.NODE_ENV !== 'production' ? resetUrl : undefined });
});

// Reset password with token
app.post('/api/reset-password', (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword || newPassword.length < 4) return res.status(400).json({ error: 'Token and password (min 4) required' });
  const row = db.prepare('SELECT * FROM reset_tokens WHERE token = ? AND expires_at > datetime("now")').get(token);
  if (!row) return res.status(400).json({ error: 'Invalid or expired token' });
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, row.user_id);
  db.prepare('DELETE FROM reset_tokens WHERE token = ?').run(token);
  res.json({ ok: true });
});

// ... rest of existing routes remain, but update register/login to support email ...

// Register (only until first parent; supports email)
app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || username.length < 2 || password.length < 4) {
    return res.status(400).json({ error: 'Username and password required (min 4 chars)' });
  }
  const parentCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'parent'").get().c;
  if (parentCount > 0) {
    return res.status(403).json({ error: 'Registration closed. Ask a parent/teacher to create your account.' });
  }
  try {
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'parent')").run(username, email || null, hash);
    req.session.userId = info.lastInsertRowid;
    req.session.username = username;
    req.session.role = 'parent';
    res.json({ ok: true, username, role: 'parent' });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(400).json({ error: 'Username or email already taken' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Login (username or email)
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(username, username);
  if (!user || !user.password || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  req.session.userId = user.id;
  req.session.username = user.username || user.email;
  req.session.role = user.role;
  res.json({ ok: true, username: user.username || user.email, role: user.role });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// Current user
app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(req.session.userId);
  res.json({ user: user ? { id: user.id, username: user.username, role: user.role } : null });
});

function requireParent(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.role !== 'parent') return res.status(403).json({ error: 'Parent/Teacher only' });
  next();
}

// Parent/Teacher: create student and optionally link self
app.post('/api/parent/create-student', requireParent, (req, res) => {
  const { username, password, relationship = 'parent' } = req.body;
  if (!username || !password || username.length < 2 || password.length < 4) {
    return res.status(400).json({ error: 'Username and password (min 4) required' });
  }
  try {
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, 'student')").run(username, hash);
    const studentId = info.lastInsertRowid;
    // Link the creator as a supervisor
    db.prepare('INSERT OR IGNORE INTO supervisors (student_id, supervisor_id, relationship) VALUES (?, ?, ?)').run(studentId, req.session.userId, relationship);
    res.json({ ok: true, id: studentId, username });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(400).json({ error: 'Username already taken' });
    res.status(500).json({ error: 'Failed to create student' });
  }
});

// Link an existing student to the current supervisor
app.post('/api/parent/link-student', requireParent, (req, res) => {
  const { username, relationship = 'teacher' } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required' });
  const student = db.prepare("SELECT id FROM users WHERE username = ? AND role = 'student'").get(username);
  if (!student) return res.status(404).json({ error: 'Student not found' });
  db.prepare('INSERT OR IGNORE INTO supervisors (student_id, supervisor_id, relationship) VALUES (?, ?, ?)').run(student.id, req.session.userId, relationship);
  res.json({ ok: true });
});

// List students linked to the current supervisor
app.get('/api/parent/students', requireParent, (req, res) => {
  const students = db.prepare(`
    SELECT u.id, u.username, u.created_at, s.relationship,
           COUNT(DISTINCT p.character) as characters_practiced,
           COALESCE(SUM(p.practiced), 0) as total_practices
    FROM supervisors s
    JOIN users u ON u.id = s.student_id
    LEFT JOIN progress p ON p.user_id = u.id
    WHERE s.supervisor_id = ?
    GROUP BY u.id
    ORDER BY u.created_at DESC
  `).all(req.session.userId);
  res.json(students);
});

// Reset password only for linked students
app.post('/api/parent/reset-password', requireParent, (req, res) => {
  const { username, newPassword } = req.body;
  if (!username || !newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: 'Username and new password (min 4) required' });
  }
  const student = db.prepare("SELECT id FROM users WHERE username = ? AND role = 'student'").get(username);
  if (!student) return res.status(404).json({ error: 'Student not found' });
  const link = db.prepare('SELECT 1 FROM supervisors WHERE student_id = ? AND supervisor_id = ?').get(student.id, req.session.userId);
  if (!link) return res.status(403).json({ error: 'You are not linked to this student' });
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, student.id);
  res.json({ ok: true });
});

// Lists
app.get('/api/lists', requireAuth, (req, res) => {
  const lists = db.prepare('SELECT id, name, content, updated_at FROM lists WHERE user_id = ? ORDER BY updated_at DESC').all(req.session.userId);
  res.json(lists);
});

app.post('/api/lists', requireAuth, (req, res) => {
  const { name, content = '' } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name required' });
  try {
    const info = db.prepare('INSERT INTO lists (user_id, name, content) VALUES (?, ?, ?)').run(req.session.userId, name.trim(), content);
    res.json({ id: info.lastInsertRowid, name: name.trim(), content });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(400).json({ error: 'List name already exists' });
    res.status(500).json({ error: 'Failed to create list' });
  }
});

app.put('/api/lists/:id', requireAuth, (req, res) => {
  const { content, name } = req.body;
  const list = db.prepare('SELECT id FROM lists WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!list) return res.status(404).json({ error: 'List not found' });
  if (name) {
    db.prepare('UPDATE lists SET name = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(name.trim(), content ?? '', req.params.id);
  } else {
    db.prepare('UPDATE lists SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(content ?? '', req.params.id);
  }
  res.json({ ok: true });
});

app.delete('/api/lists/:id', requireAuth, (req, res) => {
  const info = db.prepare('DELETE FROM lists WHERE id = ? AND user_id = ?').run(req.params.id, req.session.userId);
  if (info.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// Update streak on practice
function updateStreak(userId) {
  const today = new Date().toISOString().slice(0, 10);
  let s = db.prepare('SELECT * FROM streaks WHERE user_id = ?').get(userId);
  if (!s) {
    db.prepare('INSERT INTO streaks (user_id, current_streak, last_practice_date, today_count) VALUES (?, 1, ?, 1)').run(userId, today);
    return;
  }
  if (s.last_practice_date === today) {
    db.prepare('UPDATE streaks SET today_count = today_count + 1 WHERE user_id = ?').run(userId);
  } else {
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    const newStreak = s.last_practice_date === yesterday ? s.current_streak + 1 : 1;
    db.prepare('UPDATE streaks SET current_streak = ?, last_practice_date = ?, today_count = 1 WHERE user_id = ?').run(newStreak, today, userId);
  }
}

// Progress recording with simple spaced repetition + streak
app.post('/api/progress', requireAuth, (req, res) => {
  const { character, word, correct = true } = req.body;
  if (!character) return res.status(400).json({ error: 'character required' });
  const userId = req.session.userId || req.user?.id;
  updateStreak(userId);
  const existing = db.prepare('SELECT * FROM progress WHERE user_id = ? AND character = ?').get(userId, character);
  const now = new Date().toISOString();
  let mastery = existing ? existing.mastery : 0;
  let nextReview = new Date(Date.now() + 24 * 60 * 60 * 1000);
  if (correct) {
    mastery = Math.min(5, mastery + 1);
    const days = [1, 2, 4, 7, 14, 30][mastery] || 30;
    nextReview = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  } else {
    mastery = Math.max(0, mastery - 1);
    nextReview = new Date(Date.now() + 4 * 60 * 60 * 1000);
  }
  if (existing) {
    db.prepare(`
      UPDATE progress SET practiced = practiced + 1, correct = correct + ?,
        word = COALESCE(?, word), mastery = ?, next_review = ?, last_practiced = ?
      WHERE user_id = ? AND character = ?
    `).run(correct ? 1 : 0, word || null, mastery, nextReview.toISOString(), now, userId, character);
  } else {
    db.prepare(`
      INSERT INTO progress (user_id, character, word, practiced, correct, mastery, next_review, last_practiced)
      VALUES (?, ?, ?, 1, ?, ?, ?, ?)
    `).run(userId, character, word || null, correct ? 1 : 0, mastery, nextReview.toISOString(), now);
  }
  res.json({ ok: true, mastery, nextReview: nextReview.toISOString() });
});

// Streak info
app.get('/api/streak', requireAuth, (req, res) => {
  const userId = req.session.userId || req.user?.id;
  const s = db.prepare('SELECT * FROM streaks WHERE user_id = ?').get(userId) || { current_streak: 0, today_count: 0, daily_goal: 10 };
  res.json(s);
});

// Needs practice (due now)
app.get('/api/progress/due', requireAuth, (req, res) => {
  const userId = req.session.userId || req.user?.id;
  const due = db.prepare('SELECT * FROM progress WHERE user_id = ? AND (next_review IS NULL OR next_review <= datetime("now")) ORDER BY next_review').all(userId);
  res.json(due);
});

// Supervisor view of student progress
app.get('/api/parent/student-progress/:username', requireAuth, (req, res) => {
  const student = db.prepare("SELECT id FROM users WHERE username = ? AND role = 'student'").get(req.params.username);
  if (!student) return res.status(404).json({ error: 'Student not found' });
  const link = db.prepare('SELECT 1 FROM supervisors WHERE student_id = ? AND supervisor_id = ?').get(student.id, req.session.userId || req.user?.id);
  if (!link) return res.status(403).json({ error: 'Not linked' });
  const progress = db.prepare('SELECT * FROM progress WHERE user_id = ? ORDER BY last_practiced DESC').all(student.id);
  const streak = db.prepare('SELECT * FROM streaks WHERE user_id = ?').get(student.id) || {};
  res.json({ progress, streak });
});

// Announcements
app.post('/api/announcements', requireAuth, (req, res) => {
  const { studentUsername, message } = req.body;
  if (!studentUsername || !message) return res.status(400).json({ error: 'Required' });
  const student = db.prepare("SELECT id FROM users WHERE username = ? AND role = 'student'").get(studentUsername);
  if (!student) return res.status(404).json({ error: 'Student not found' });
  const link = db.prepare('SELECT 1 FROM supervisors WHERE student_id = ? AND supervisor_id = ?').get(student.id, req.session.userId || req.user?.id);
  if (!link) return res.status(403).json({ error: 'Not linked' });
  db.prepare('INSERT INTO announcements (supervisor_id, student_id, message) VALUES (?, ?, ?)').run(req.session.userId || req.user?.id, student.id, message);
  res.json({ ok: true });
});

app.get('/api/announcements', requireAuth, (req, res) => {
  const userId = req.session.userId || req.user?.id;
  const notes = db.prepare(`
    SELECT a.message, a.created_at, u.username as from_user
    FROM announcements a
    JOIN users u ON u.id = a.supervisor_id
    WHERE a.student_id = ?
    ORDER BY a.created_at DESC LIMIT 20
  `).all(userId);
  res.json(notes);
});

// Export lists
app.get('/api/export/lists', requireAuth, (req, res) => {
  const userId = req.session.userId || req.user?.id;
  const lists = db.prepare('SELECT name, content FROM lists WHERE user_id = ?').all(userId);
  let csv = 'list_name,content\n';
  lists.forEach(l => {
    csv += `"${l.name}","${(l.content || '').replace(/"/g, '""')}"\n`;
  });
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="lists.csv"');
  res.send(csv);
});

// Export progress as CSV
app.get('/api/export/progress', requireAuth, (req, res) => {
  const userId = req.session.userId || req.user?.id;
  const rows = db.prepare('SELECT character, word, practiced, correct, mastery, last_practiced, next_review FROM progress WHERE user_id = ?').all(userId);
  let csv = 'character,word,practiced,correct,mastery,last_practiced,next_review\n';
  rows.forEach(r => {
    csv += `"${r.character}","${r.word || ''}",${r.practiced},${r.correct},${r.mastery},"${r.last_practiced || ''}","${r.next_review || ''}"\n`;
  });
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="progress.csv"');
  res.send(csv);
});

// Shared lists: assign a list to a student (supervisor only)
app.post('/api/lists/:id/assign', requireAuth, (req, res) => {
  const { studentUsername } = req.body;
  const list = db.prepare('SELECT * FROM lists WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId || req.user?.id);
  if (!list) return res.status(404).json({ error: 'List not found' });
  const student = db.prepare("SELECT id FROM users WHERE username = ? AND role = 'student'").get(studentUsername);
  if (!student) return res.status(404).json({ error: 'Student not found' });
  // Check link
  const link = db.prepare('SELECT 1 FROM supervisors WHERE student_id = ? AND supervisor_id = ?').get(student.id, req.session.userId || req.user?.id);
  if (!link) return res.status(403).json({ error: 'Not linked to this student' });
  db.prepare('INSERT OR IGNORE INTO list_assignments (list_id, student_id) VALUES (?, ?)').run(list.id, student.id);
  db.prepare('UPDATE lists SET is_shared = 1 WHERE id = ?').run(list.id);
  res.json({ ok: true });
});

// Students can see assigned lists
app.get('/api/assigned-lists', requireAuth, (req, res) => {
  const userId = req.session.userId || req.user?.id;
  const lists = db.prepare(`
    SELECT l.id, l.name, l.content, l.updated_at
    FROM list_assignments la
    JOIN lists l ON l.id = la.list_id
    WHERE la.student_id = ?
  `).all(userId);
  res.json(lists);
});

// Fallback to index.html for SPA-style
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Chinese Character Writer running on http://localhost:${PORT}`);
});
