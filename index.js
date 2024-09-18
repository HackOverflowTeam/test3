require('dotenv').config(); // Load environment variables
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());

const usersFile = 'users.json';
const deletedUsersFile = 'deleted_users.json';

// Encryption key and initialization vector for AES
const encryptionKey = crypto.randomBytes(32); // 32 bytes = 256 bits key
const iv = crypto.randomBytes(16); // AES block size

// Middleware to restrict requests based on the ALLOWED_ORIGIN_DB environment variable
const allowedOrigin = process.env.ALLOWED_ORIGIN_DB || 'https://example.com'; // Default if env variable is missing
const corsOptions = {
  origin: allowedOrigin,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Function to encrypt a string (e.g., password)
function encrypt(text) {
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Function to decrypt a string (e.g., password)
function decrypt(text) {
  const textParts = text.split(':');
  const iv = Buffer.from(textParts.shift(), 'hex');
  const encryptedText = Buffer.from(textParts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(encryptionKey), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// POST /adduser - Adds a new user
app.post('/adduser', (req, res) => {
  const { name, phone, email, password, rollNo, schoolId } = req.body;

  if (!name || !phone || !email || !password || !rollNo || !schoolId) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  // Encrypt the password before saving
  const encryptedPassword = encrypt(password);

  const newUser = {
    name,
    phone,
    email,
    password: encryptedPassword,
    rollNo,
    schoolId
  };

  // Read existing users
  fs.readFile(usersFile, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).json({ message: 'Error reading users file' });
    }

    let users = [];
    if (data) {
      users = JSON.parse(data);
    }

    users.push(newUser);

    // Save the updated user list
    fs.writeFile(usersFile, JSON.stringify(users, null, 2), (err) => {
      if (err) {
        return res.status(500).json({ message: 'Error saving user' });
      }

      res.status(201).json({ message: 'User added successfully' });
    });
  });
});

// GET /viewuser - Get user by phone or email
app.get('/viewuser', (req, res) => {
  const { phone, email } = req.query;

  if (!phone && !email) {
    return res.status(400).json({ message: 'Please provide a phone number or email' });
  }

  // Read users from the file
  fs.readFile(usersFile, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).json({ message: 'Error reading users file' });
    }

    let users = JSON.parse(data || '[]');
    const user = users.find(u => u.phone === phone || u.email === email);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user);
  });
});

// DELETE /deleteuser - Deletes a user by phone or email and stores the data in deleted_users.json
app.delete('/deleteuser', (req, res) => {
  const { phone, email } = req.body;

  if (!phone && !email) {
    return res.status(400).json({ message: 'Please provide a phone number or email' });
  }

  fs.readFile(usersFile, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).json({ message: 'Error reading users file' });
    }

    let users = JSON.parse(data || '[]');
    const userIndex = users.findIndex(u => u.phone === phone || u.email === email);

    if (userIndex === -1) {
      return res.status(404).json({ message: 'User not found' });
    }

    const deletedUser = users.splice(userIndex, 1)[0];

    fs.writeFile(usersFile, JSON.stringify(users, null, 2), (err) => {
      if (err) {
        return res.status(500).json({ message: 'Error updating users file' });
      }

      // Move the deleted user to deleted_users.json
      fs.readFile(deletedUsersFile, 'utf8', (err, deletedData) => {
        let deletedUsers = JSON.parse(deletedData || '[]');
        deletedUsers.push(deletedUser);

        fs.writeFile(deletedUsersFile, JSON.stringify(deletedUsers, null, 2), (err) => {
          if (err) {
            return res.status(500).json({ message: 'Error saving deleted user' });
          }

          res.json({ message: 'User deleted successfully', deletedUser });
        });
      });
    });
  });
});

// GET /decryptpassword - Decrypts a user's password
app.get('/decryptpassword', (req, res) => {
  const { email, phone } = req.query;

  if (!email && !phone) {
    return res.status(400).json({ message: 'Please provide email or phone' });
  }

  fs.readFile(usersFile, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).json({ message: 'Error reading users file' });
    }

    let users = JSON.parse(data || '[]');
    const user = users.find(u => u.email === email || u.phone === phone);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const decryptedPassword = decrypt(user.password);

    res.json({ password: decryptedPassword });
  });
});

// Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
