require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// CORS Configuration - Specifically set up so EdgeOne frontend is not blocked
app.use(cors({
    origin: '*', // Allows requests from https://pages.edgeone.ai and local testing
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// MySQL / TiDB Connection Pool
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 4000,
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
    },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const JWT_SECRET = process.env.JWT_SECRET || 'webuy_secret_key_2026';

// Middleware to verify JWT and check user identity
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access token missing' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
};

// --- API ENDPOINTS ---

// 1. Health Check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'WeBuy API is running smoothly.' });
});

// 2. User Registration (Buyer or Seller)
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    if (!['buyer', 'seller'].includes(role.toLowerCase())) {
        return res.status(400).json({ error: 'Role must be either buyer or seller.' });
    }

    try {
        const [existing] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email already registered.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.query(
            'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
            [name, email, hashedPassword, role.toLowerCase()]
        );

        res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

// 3. User Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(400).json({ error: 'Invalid email or password.' });
        }

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid email or password.' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, name: user.name },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role }
        });
    } catch (err) {
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

// 4. Fetch All Products (Accessible to everyone)
app.get('/api/products', async (req, res) => {
    try {
        const [products] = await db.query(`
            SELECT p.id, p.title, p.description, p.price, p.image_url, p.created_at, u.name AS seller_name 
            FROM products p 
            JOIN users u ON p.seller_id = u.id 
            ORDER BY p.created_at DESC
        `);
        res.json(products);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch products', details: err.message });
    }
});

// 5. Create a Product Listing (Sellers Only)
app.post('/api/products', authenticateToken, async (req, res) => {
    if (req.user.role !== 'seller') {
        return res.status(403).json({ error: 'Only registered sellers can create listings.' });
    }

    const { title, description, price, image_url } = req.body;
    if (!title || !price) {
        return res.status(400).json({ error: 'Title and price are required.' });
    }

    try {
        const [result] = await db.query(
            'INSERT INTO products (seller_id, title, description, price, image_url) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, title, description, price, image_url || '/uploads/logo.jpg']
        );
        res.status(201).json({ message: 'Product listed successfully', productId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

// 6. Buy a Product (Buyers Only)
app.post('/api/orders', authenticateToken, async (req, res) => {
    if (req.user.role !== 'buyer') {
        return res.status(403).json({ error: 'Only buyers can make purchases.' });
    }

    const { product_id } = req.body;
    if (!product_id) {
        return res.status(400).json({ error: 'Product ID is required.' });
    }

    try {
        const [result] = await db.query(
            'INSERT INTO orders (buyer_id, product_id, status) VALUES (?, ?, ?)',
            [req.user.id, product_id, 'completed']
        );
        res.status(201).json({ message: 'Purchase completed successfully', orderId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

// 7. Get User Purchases/Sales History
app.get('/api/orders/user', authenticateToken, async (req, res) => {
    try {
        let query = '';
        if (req.user.role === 'buyer') {
            query = `
                SELECT o.id AS order_id, o.status, o.created_at, p.title, p.price, u.name AS seller_name
                FROM orders o
                JOIN products p ON o.product_id = p.id
                JOIN users u ON p.seller_id = u.id
                WHERE o.buyer_id = ?
            `;
        } else {
            query = `
                SELECT o.id AS order_id, o.status, o.created_at, p.title, p.price, u.name AS buyer_name
                FROM orders o
                JOIN products p ON o.product_id = p.id
                JOIN users u ON o.buyer_id = u.id
                WHERE p.seller_id = ?
            `;
        }
        const [orders] = await db.query(query, [req.user.id]);
        res.json(orders);
    } catch (err) {
        res.status(500).json({ error: 'Failed to retrieve orders', details: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`WeBuy server running on port ${PORT}`);
});