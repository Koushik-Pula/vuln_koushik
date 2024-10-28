const express = require('express');
const pool = require('../config');
const router = express.Router();

// User homepage (restricted to authenticated end users)
router.get('/', async (req, res) => {
    if (req.session.role !== 'end_user') return res.redirect('/login');

    try {
        const rows = await pool.query('SELECT * FROM data');
        res.render('user', { data: rows });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

module.exports = router;
