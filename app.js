const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const pool = require('./config'); // Import MariaDB pool

const app = express();  
const port = 3000;

// Middlewares
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));
app.use(session({
    secret: "secret",
    resave: false,
    saveUninitialized: true,
}));

app.set("view engine", "ejs");



// Routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const adminRoutes = require('./routes/admin');

// Apply authentication check to restricted routes
app.use('/user', userRoutes);
app.use('/admin', adminRoutes);
app.use('/', authRoutes);

app.listen(port, () => {
    console.log(`App running on http://localhost:${port}/login`);
});
