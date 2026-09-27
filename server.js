const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

const USERS_FILE = path.join(__dirname, 'users.json');
const CHATS_FILE = path.join(__dirname, 'chats.json');
const PROFILE_DIR = path.join(__dirname, 'public', 'profilepictures');
const ATTACHMENTS_DIR = path.join(__dirname, 'public', 'attachments');

const ENCRYPTION_KEY = crypto.scryptSync('my-super-secret-key-change-this', 'salt', 32);
const IV_LENGTH = 16;

function encrypt(text) {
  if (!text) return '';
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
  if (!text || !text.includes(':')) return text;
  try {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    return '';
  }
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, originalHash] = stored.split(':');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return hash === originalHash;
}

const loginAttempts = {};

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function readJSON(filePath, defaultValue) {
  if (fs.existsSync(filePath)) {
    try {
      const content = fs.readFileSync(filePath, 'utf8').trim();
      if (!content) return defaultValue;
      return JSON.parse(content);
    } catch (e) {
      console.error(`Error reading ${filePath}:`, e.message);
    }
  }
  return defaultValue;
}

function writeJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function getCookie(req, name) {
  const rc = req.headers.cookie;
  if (!rc) return null;
  const cookies = rc.split(';');
  for (let c of cookies) {
    const [k, v] = c.trim().split('=');
    if (k === name) return decodeURIComponent(v);
  }
  return null;
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/me', (req, res) => {
  const user = getCookie(req, 'currentUser');
  const users = readJSON(USERS_FILE, {});
  if (user && users[user]) {
    const userData = { ...users[user], apiKey: decrypt(users[user].apiKey) };
    delete userData.password;
    return res.json({ username: user, ...userData });
  }
  res.status(401).json({ error: 'Not logged in' });
});

app.post('/api/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username & password required' });
  
  const users = readJSON(USERS_FILE, {});
  if (users[username]) return res.status(400).json({ error: 'User already exists' });

  users[username] = { 
    password: hashPassword(password), 
    apiKey: '', 
    isLightMode: false 
  };
  writeJSON(USERS_FILE, users);

  res.setHeader('Set-Cookie', `currentUser=${encodeURIComponent(username)}; Path=/; HttpOnly`);
  res.json({ username, isLightMode: false, apiKey: '' });
});

app.post('/api/login', (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();

  if (!loginAttempts[ip]) {
    loginAttempts[ip] = { count: 0, lockoutUntil: 0, penaltySeconds: 3 };
  }

  const tracker = loginAttempts[ip];

  if (now < tracker.lockoutUntil) {
    const waitSeconds = Math.ceil((tracker.lockoutUntil - now) / 1000);
    return res.status(429).json({ 
      error: `Too many failed attempts. Wait ${waitSeconds}s before trying again.` 
    });
  }

  const { username, password } = req.body;
  const users = readJSON(USERS_FILE, {});
  
  if (users[username] && verifyPassword(password, users[username].password)) {
    delete loginAttempts[ip];
    res.setHeader('Set-Cookie', `currentUser=${encodeURIComponent(username)}; Path=/; HttpOnly`);
    const userData = { ...users[username], apiKey: decrypt(users[username].apiKey) };
    delete userData.password;
    return res.json({ username, ...userData });
  } else {
    tracker.count++;
    
    if (tracker.count >= 3) {
      tracker.lockoutUntil = now + (tracker.penaltySeconds * 1000);
      const lockedTime = tracker.penaltySeconds;
      tracker.penaltySeconds *= 2; 
      tracker.count = 0;

      return res.status(429).json({ 
        error: `Wrong credentials! Locked out for ${lockedTime} seconds.` 
      });
    }

    const remaining = 3 - tracker.count;
    return res.status(400).json({ 
      error: `Invalid username or password. ${remaining} attempts left before lockout.` 
    });
  }
});

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'currentUser=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
  res.json({ success: true });
});

app.post('/api/delete-account', (req, res) => {
  const { username } = req.body;
  const users = readJSON(USERS_FILE, {});

  if (!users[username]) {
    return res.status(400).json({ error: 'User not found' });
  }

  delete users[username];
  writeJSON(USERS_FILE, users);

  const chats = readJSON(CHATS_FILE, {});
  if (chats[username]) {
    delete chats[username];
    writeJSON(CHATS_FILE, chats);
  }

  const pfpPath = path.join(PROFILE_DIR, `${username}.png`);
  if (fs.existsSync(pfpPath)) {
    try { fs.unlinkSync(pfpPath); } catch(e) {}
  }

  res.setHeader('Set-Cookie', 'currentUser=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
  res.json({ success: true });
});

app.post('/api/theme', (req, res) => {
  let fileData = req.body;
  const { username, isLightMode } = req.body;
  const users = readJSON(USERS_FILE, {});
  if (users[username]) {
    users[username].isLightMode = isLightMode;
    writeJSON(USERS_FILE, users);
  }
  res.json({ success: true });
});

app.post('/api/apikey', (req, res) => {
  const { username, apiKey } = req.body;
  const users = readJSON(USERS_FILE, {});
  if (users[username]) {
    users[username].apiKey = encrypt(apiKey);
    writeJSON(USERS_FILE, users);
  }
  res.json({ success: true });
});

app.post('/api/change-username', (req, res) => {
  const { oldUsername, newUsername } = req.body;
  if (!newUsername) return res.status(400).json({ error: 'New username required' });

  const users = readJSON(USERS_FILE, {});
  const chats = readJSON(CHATS_FILE, {});

  if (users[newUsername]) return res.status(400).json({ error: 'Username already taken' });

  if (users[oldUsername]) {
    users[newUsername] = users[oldUsername];
    delete users[oldUsername];
    writeJSON(USERS_FILE, users);

    if (chats[oldUsername]) {
      chats[newUsername] = chats[oldUsername];
      delete chats[oldUsername];
      writeJSON(CHATS_FILE, chats);
    }

    const oldPfp = path.join(PROFILE_DIR, `${oldUsername}.png`);
    const newPfp = path.join(PROFILE_DIR, `${newUsername}.png`);
    if (fs.existsSync(oldPfp)) {
      try { fs.renameSync(oldPfp, newPfp); } catch(e) {}
    }

    res.setHeader('Set-Cookie', `currentUser=${encodeURIComponent(newUsername)}; Path=/; HttpOnly`);
    res.json({ newUsername });
  } else {
    res.status(400).json({ error: 'User not found' });
  }
});

app.post('/api/change-password', (req, res) => {
  const { username, oldPassword, newPassword, confirmPassword } = req.body;
  const users = readJSON(USERS_FILE, {});

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'New passwords do not match' });
  }

  if (users[username] && verifyPassword(oldPassword, users[username].password)) {
    users[username].password = hashPassword(newPassword);
    writeJSON(USERS_FILE, users);
    res.json({ message: 'Password updated successfully!' });
  } else {
    return res.status(400).json({ error: 'Incorrect old password' });
  }
});

app.get('/api/profile/:username', (req, res) => {
  const pfpPath = path.join(PROFILE_DIR, `${req.params.username}.png`);
  if (fs.existsSync(pfpPath)) {
    return res.json({ avatarUrl: `/profilepictures/${req.params.username}.png` });
  }
  res.json({ avatarUrl: '' });
});

app.post('/api/profile/:username', (req, res) => {
  const { imageBase64 } = req.body;
  if (!fs.existsSync(PROFILE_DIR)) fs.mkdirSync(PROFILE_DIR, { recursive: true });

  const base64Data = imageBase64.replace(/^data:image\/\w+;base64,/, '');
  const pfpPath = path.join(PROFILE_DIR, `${req.params.username}.png`);

  fs.writeFileSync(pfpPath, base64Data, 'base64');
  res.json({ success: true, avatarUrl: `/profilepictures/${req.params.username}.png` });
});

app.get('/api/chats/:username', (req, res) => {
  const chats = readJSON(CHATS_FILE, {});
  res.json(chats[req.params.username] || []);
});

app.post('/api/chats/:username', (req, res) => {
  const chats = readJSON(CHATS_FILE, {});
  const userChats = req.body.chats;

  if (!fs.existsSync(ATTACHMENTS_DIR)) {
    fs.mkdirSync(ATTACHMENTS_DIR, { recursive: true });
  }

  // Handle file uploads and prevent name collisions by giving unique numbers/ids
  if (Array.isArray(userChats)) {
    userChats.forEach(chat => {
      if (Array.isArray(chat.history)) {
        chat.history.forEach(msg => {
          if (Array.isArray(msg.files)) {
            msg.files.forEach(fileObj => {
              if (fileObj.data && fileObj.data.startsWith('data:')) {
                const matches = fileObj.data.match(/^data:(.+);base64,(.+)$/);
                if (matches) {
                  const ext = path.extname(fileObj.name) || '';
                  const uniqueId = Date.now() + '_' + Math.floor(Math.random() * 100000);
                  const savedFilename = `${uniqueId}${ext}`;
                  const filePath = path.join(ATTACHMENTS_DIR, savedFilename);

                  fs.writeFileSync(filePath, Buffer.from(matches[2], 'base64'));

                  fileObj.url = `/attachments/${savedFilename}`;
                  delete fileObj.data; // keep chats.json light
                }
              }
            });
          }
        });
      }
    });
  }

  chats[req.params.username] = userChats;
  writeJSON(CHATS_FILE, chats);
  res.json({ success: true });
});

app.post('/api/generate', async (req, res) => {
  try {
    const { contents, model = 'gemini-1.5-flash' } = req.body;
    const apiKey = process.env.GEMINI_API_KEY || 'YOUR_FALLBACK_API_KEY_HERE';

    if (!apiKey || apiKey === 'YOUR_FALLBACK_API_KEY_HERE') {
      return res.status(400).json({ 
        error: 'No server api key set up yet fr. put one in server.js' 
      });
    }

    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents })
    });

    const data = await response.json();
    if (!response.ok) {
      return res.status(response.status).json(data);
    }
    res.json(data);
  } catch (err) {
    console.error('error generating content:', err);
    res.status(500).json({ error: 'rip something broke on backend' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});