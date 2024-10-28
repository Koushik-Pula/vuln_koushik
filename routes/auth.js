const express = require('express');
const router = express.Router();
const pool = require('../config'); 

const vulnerabilityLog = []; 

const checkNotLoggedIn = (req, res, next) => {
    if (req.session.userId) {
        return res.redirect(req.session.role === 'admin' ? '/admin' : '/user');
    }
    next();
};

const preventBackButtonCache = (req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
};

router.get('/login', checkNotLoggedIn, preventBackButtonCache, (req, res) => {
    res.render('login', { error: null });
});

function logVulnerability(type, input) {
    vulnerabilityLog.push({ type, input, timestamp: new Date() });
    console.log(`Vulnerability detected: ${type} on input "${input}"`);
}
function checkSpecialCharacters(input) {
    const specialChars = /['"&+=<>]/;
    return specialChars.test(input);
}
function checkSQLKeywords(input) {
    const sqlKeywords = /(union|select|intersect|insert|update|delete|drop|truncate)/i;
    return sqlKeywords.test(input);
}
function checkBooleanKeywords(input) {
    const booleanKeywords = /\b(or|and)\b/i;
    return booleanKeywords.test(input);
}
function checkVulnerability(input) {
    if (checkSpecialCharacters(input)) {
        logVulnerability('Special Character', input);
        return 'attack';
    }
    if (checkSQLKeywords(input)) {
        logVulnerability('SQL Keyword', input);
        return 'attack';
    }
    if (checkBooleanKeywords(input)) {
        logVulnerability('Boolean Keyword', input);
        return 'attack';
    }
    return 'free';
}

function resetFormStatus(req) {
    req.session.loginAttempts = 0;
}

router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (checkVulnerability(username) === 'attack' || checkVulnerability(password) === 'attack') {
        return res.render('login', { error: 'Invalid input detected' });
    }
    try {
        const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
        const params = [username, password];
        const rows = await pool.query(query, params);

        if (rows.length > 0) {
            const user = rows[0];
            const match = password === user.password;

            if (match) { 
                req.session.userId = user.id;
                req.session.role = user.role;

                if (user.role === 'admin') {
                    return res.redirect('/admin');
                } else {
                    return res.redirect('/user');
                }
            } else {
                return res.render('login', { error: 'Incorrect password' });
            }
        } else {
            return res.render('login', { error: 'User not found' });
        }
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).send('Server error');
    }
});

router.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Could not log out');
        }
        resetFormStatus(req); 
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        res.redirect('/login');
    });
});

module.exports = router;
