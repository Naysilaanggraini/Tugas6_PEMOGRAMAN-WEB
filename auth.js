const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../db');

// Render Halaman Register
router.get('/register', (req, res) => {
    if (req.session.user) {
        // jika sudah login, redirect ke profil
        return res.redirect('/auth/profile');
    }
    res.render('register');
});

// Proses register user
router.post('/register', (req, res) => {
    const { username, email, password } = req.body;

    // Hash password
    const hashedPassword = bcrypt.hashSync(password, 10);

    const query = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
    db.query(query, [username, email, hashedPassword], (err, result) => {
        if (err) throw err;
        res.redirect('/auth/login');
    });
});

// Render Halaman Login
router.get('/login', (req, res) => {
    if (req.session.user) {
        // jika sudah login, redirect ke profil
        return res.redirect('/auth/profile');
    }
    res.render('login');
});

// Proses login user
router.post('/login', (req, res) => {
    const { username, password } = req.body; // Diperbaiki dari res.body menjadi req.body

    const query = "SELECT * FROM users WHERE username = ?";
    db.query(query, [username], (err, result) => {
        if (err) throw err;

        if (result.length > 0) {
            const user = result[0];

            // Periksa apakah password cocok
            if (bcrypt.compareSync(password, user.password)) {
                req.session.user = user; // Simpan user di session
                res.redirect('/auth/profile');
            } else {
                res.send('Password salah.'); // Perbaikan dari "Incorect" menjadi "Incorrect"
            }
        } else {
            res.send('User tidak ditemukan.');
        }
    });
});

// Render halaman profil user
router.get('/profile', (req, res) => {
    if (req.session.user) {
        res.render('profile', { user: req.session.user });
    } else {
        res.redirect('/auth/login');
    }
});

// Proses Log-Out
router.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/auth/login');
});

module.exports = router;
