require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const port = process.env.APP_PORT || 3000;
const APP_NAME = process.env.APP_NAME || 'changeme';

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASS,
    port: process.env.DB_PORT || 5432,
    ssl: {
        rejectUnauthorized: false
    }
});

pool.connect((err, client, release) => {
    if (err) {
        return console.error('Error acquiring client', err.stack);
    }
    console.log('Database connected');
    release();
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

app.use((req, res, next) => {
    res.locals.APP_NAME = APP_NAME;
    res.locals.user = req.session.user || null;
    next();
});

app.get('/', (req, res) => {
    if (req.session.user) {
        res.render('index');
    } else {
        res.redirect('/login');
    }
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                delete user.password;
                req.session.user = user;
                res.redirect('/');
            } else {
                res.render('login', { error: 'Invalid security token' });
            }
        } else {
            res.render('login', { error: 'Identity not found' });
        }
    } catch (err) {
        console.error(err);
        res.render('login', { error: 'Uplink failure (DB Error)' });
    }
});

app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const cpu = process.env.DEFAULT_CPU || 100;
        const ram = process.env.DEFAULT_RAM || 2048;
        const disk = process.env.DEFAULT_DISK || 10240;
        const time = process.env.DEFAULT_TIME || '5h';

        const sql = 'INSERT INTO users (username, email, password, cpu, ram, disk, time) VALUES ($1, $2, $3, $4, $5, $6, $7)';
        await pool.query(sql, [username, email, hashedPassword, cpu, ram, disk, time]);
        res.redirect('/login');
    } catch (err) {
        if (err.code === '23505') { 
            return res.render('register', { error: 'Identifier already claimed' });
        }
        res.render('register', { error: 'Registration protocols failed' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.listen(port, () => {
    console.log(`${APP_NAME} is online on port ${port}`);
});