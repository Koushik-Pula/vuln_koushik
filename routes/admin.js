const express = require('express');
const pool = require('../config');
const router = express.Router();

// Admin homepage (view and modify tables)
router.get('/', async (req, res) => {
    if (req.session.role !== 'admin') return res.redirect('/login');

    try {
        const rows = await pool.query('SELECT * FROM data');
        res.render('admin', { data: rows });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// Admin can modify (add/edit/delete) data
router.post('/modify', async (req, res) => {
    const { action, id, data_entry } = req.body;

    if (req.session.role !== 'admin') return res.redirect('/login');

    try {
        if (action === 'add') {
            // SQL injection prevented with parameterized query
            await pool.query('INSERT INTO data (data_entry) VALUES (?)', [data_entry]);
        } else if (action === 'edit') {
            await pool.query('UPDATE data SET data_entry = ? WHERE id = ?', [data_entry, id]);
        } else if (action === 'delete') {
            await pool.query('DELETE FROM data WHERE id = ?', [id]);
        }
        res.redirect('/admin');
    } catch (err) {
        res.status(500).send('Server error');
    }
});

module.exports = router;
