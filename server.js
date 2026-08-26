require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();

// Enable CORS for EdgeOne and external clients
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// TiDB / MySQL Database Connection Pool
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'webuy',
    port: process.env.DB_PORT || 4000,
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: false // Prevents SSL certificate verification crashes on Render
    },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const JWT_SECRET = process.env.JWT_SECRET || 'webuy_secret_key_2026';
const PAYAT_SYSTEM_ID = process.env.PAYAT_SYSTEM_ID || 'WEBUY001';
const PAYAT_SECRET_KEY = process.env.PAYAT_SECRET_KEY || 'payat_secret_key_sample';

// Auto-Initialize Database Tables on Startup
async function initDatabase() {
    try {
        const connection = await db.getConnection();
        console.log('Successfully connected to TiDB/MySQL database.');

        await connection.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role ENUM('buyer', 'seller') NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS products (
                id INT AUTO_INCREMENT PRIMARY KEY,
                seller_id INT NOT NULL,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                price DECIMAL(10, 2) NOT NULL,
                image_url VARCHAR(500) DEFAULT 'logo.jpg',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE CASCADE
            );
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id INT AUTO_INCREMENT PRIMARY KEY,
                buyer_id INT NOT NULL,
                product_id INT NOT NULL,
                status ENUM('pending', 'completed', 'cancelled') DEFAULT 'pending',
                payment_ref VARCHAR(255),
                payment_status ENUM('unpaid', 'paid', 'failed') DEFAULT 'unpaid',
                payment_method VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (buyer_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
            );
        `);

        connection.release();
        console.log('Database tables verified successfully.');
    } catch (err) {
        console.error('DATABASE INITIALIZATION ERROR:', err.message);
    }
}

initDatabase();

// Authentication Middleware
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

// --- AUTH & USER ENDPOINTS ---

app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'WeBuy API with Pay@ Integration operational.' });
});

app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
        return res.status(400).json({ error: 'All fields are required.' });
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
        console.error('REGISTER ERROR:', err);
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

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
        console.error('LOGIN ERROR:', err);
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

// --- MARKETPLACE ENDPOINTS ---

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
        console.error('PRODUCTS FETCH ERROR:', err);
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

app.post('/api/products', authenticateToken, async (req, res) => {
    if (req.user.role !== 'seller') {
        return res.status(403).json({ error: 'Only sellers can list products.' });
    }

    const { title, description, price, image_url } = req.body;
    try {
        const [result] = await db.query(
            'INSERT INTO products (seller_id, title, description, price, image_url) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, title, description, price, image_url || 'logo.jpg']
        );
        res.status(201).json({ message: 'Product created', productId: result.insertId });
    } catch (err) {
        console.error('CREATE PRODUCT ERROR:', err);
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

// --- PAY@ INTEGRATION ENDPOINTS ---

// 1. Create Order and Generate Pay@ Reference Number
app.post('/api/payat/create-checkout', authenticateToken, async (req, res) => {
    if (req.user.role !== 'buyer') {
        return res.status(403).json({ error: 'Only buyers can make purchases.' });
    }

    const { product_id, payment_option } = req.body; 
    // Options: 'retail_store' (Shoprite/Checkers/Pick n Pay/PEP/Boxer), 'qr' (Masterpass/SnapScan/Zapper), 'card', 'eft'

    try {
        const [products] = await db.query('SELECT * FROM products WHERE id = ?', [product_id]);
        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found.' });
        }

        const product = products[0];

        // Unique Pay@ Reference Generation (Format: WEBUY + Timestamp + Order Randomizer)
        const payatReference = `10101${Date.now().toString().slice(-6)}${Math.floor(10 + Math.random() * 90)}`;

        const [orderResult] = await db.query(
            'INSERT INTO orders (buyer_id, product_id, status, payment_ref, payment_status, payment_method) VALUES (?, ?, ?, ?, ?, ?)',
            [req.user.id, product_id, 'pending', payatReference, 'unpaid', payment_option || 'payat_multi']
        );

        // Standard Pay@ Web Portal Redirect URL or Retail Reference Output
        const payatPaymentUrl = `https://payat.io/pay/${payatReference}?amount=${product.price}&sys=${PAYAT_SYSTEM_ID}`;

        res.status(201).json({
            message: 'Pay@ Checkout initialized',
            orderId: orderResult.insertId,
            payatReference: payatReference,
            amount: product.price,
            paymentUrl: payatPaymentUrl,
            supportedStores: ['Shoprite', 'Checkers', 'Pick n Pay', 'PEP', 'Boxer', 'Usave', 'Spar'],
            supportedDigital: ['SnapScan', 'Zapper', 'Masterpass', 'Capitec Pay', 'Instant EFT', 'Visa/Mastercard']
        });
    } catch (err) {
        console.error('PAYAT CHECKOUT ERROR:', err);
        res.status(500).json({ error: 'Checkout initialization failed', details: err.message });
    }
});

// 2. Pay@ Webhook / IPN Notification Endpoint
app.post('/api/payat/notification', async (req, res) => {
    const { payat_reference, amount, status, transaction_id, checksum } = req.body;

    try {
        if (status === 'PAID' || status === 'SUCCESS') {
            await db.query(
                'UPDATE orders SET status = ?, payment_status = ? WHERE payment_ref = ?',
                ['completed', 'paid', payat_reference]
            );
            console.log(`Pay@ Payment Received for Ref: ${payat_reference}`);
        }

        // Pay@ requires a standard 200 OK acknowledgement response
        res.status(200).json({ response: 'OK', reference: payat_reference });
    } catch (err) {
        console.error('PAYAT NOTIFICATION ERROR:', err);
        res.status(500).json({ error: 'Notification processing failed' });
    }
});

// 3. Check Order Payment Status
app.get('/api/payat/status/:reference', authenticateToken, async (req, res) => {
    try {
        const [orders] = await db.query('SELECT id, status, payment_status, payment_ref FROM orders WHERE payment_ref = ?', [req.params.reference]);
        if (orders.length === 0) return res.status(404).json({ error: 'Order reference not found' });

        res.json(orders[0]);
    } catch (err) {
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`WeBuy server running on port ${PORT}`);
});