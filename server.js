require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' })); // Allows larger payloads for multiple image URLs

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'webuy',
    port: process.env.DB_PORT || 4000,
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: false },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const JWT_SECRET = process.env.JWT_SECRET || 'webuy_secret_key_2026';

// Auto-create missing tables on launch
async function initDatabase() {
    try {
        const conn = await db.getConnection();
        await conn.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role ENUM('buyer', 'seller') NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await conn.query(`
            CREATE TABLE IF NOT EXISTS products (
                id INT AUTO_INCREMENT PRIMARY KEY,
                seller_id INT NOT NULL,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                price DECIMAL(10, 2) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE CASCADE
            );
        `);

        await conn.query(`
            CREATE TABLE IF NOT EXISTS product_images (
                id INT AUTO_INCREMENT PRIMARY KEY,
                product_id INT NOT NULL,
                image_url TEXT NOT NULL,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
            );
        `);

        await conn.query(`
            CREATE TABLE IF NOT EXISTS cart_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                buyer_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (buyer_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
            );
        `);

        await conn.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id INT AUTO_INCREMENT PRIMARY KEY,
                buyer_id INT NOT NULL,
                total_amount DECIMAL(10, 2) NOT NULL,
                status ENUM('pending', 'completed', 'cancelled') DEFAULT 'pending',
                payment_ref VARCHAR(255),
                payment_status ENUM('unpaid', 'paid', 'failed') DEFAULT 'unpaid',
                payment_method VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (buyer_id) REFERENCES users(id) ON DELETE CASCADE
            );
        `);

        await conn.query(`
            CREATE TABLE IF NOT EXISTS order_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                order_id INT NOT NULL,
                product_id INT NOT NULL,
                price DECIMAL(10, 2) NOT NULL,
                quantity INT DEFAULT 1,
                FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
            );
        `);

        conn.release();
        console.log('Database tables verified.');
    } catch (err) {
        console.error('INIT DB ERROR:', err.message);
    }
}
initDatabase();

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token missing' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// --- AUTH ---
app.get('/api/health', (req, res) => res.json({ status: 'OK' }));

app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    try {
        const [existing] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) return res.status(400).json({ error: 'Email already exists' });

        const hash = await bcrypt.hash(password, 10);
        const [resDb] = await db.query('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)', [name, email, hash, role.toLowerCase()]);
        res.status(201).json({ message: 'Registered', userId: resDb.insertId });
    } catch (err) {
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) return res.status(400).json({ error: 'Invalid credentials' });

        const user = users[0];
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    } catch (err) {
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

// --- PRODUCTS (UP TO 10 IMAGES) ---
app.get('/api/products', async (req, res) => {
    try {
        const [products] = await db.query(`
            SELECT p.id, p.title, p.description, p.price, p.created_at, u.name AS seller_name 
            FROM products p 
            JOIN users u ON p.seller_id = u.id 
            ORDER BY p.created_at DESC
        `);

        for (let p of products) {
            const [imgs] = await db.query('SELECT image_url FROM product_images WHERE product_id = ?', [p.id]);
            p.images = imgs.map(i => i.image_url);
            if (p.images.length === 0) p.images = ['logo.jpg'];
        }

        res.json(products);
    } catch (err) {
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

app.post('/api/products', authenticateToken, async (req, res) => {
    if (req.user.role !== 'seller') return res.status(403).json({ error: 'Sellers only' });
    const { title, description, price, images } = req.body; // images array (max 10)

    if (!title || !price) return res.status(400).json({ error: 'Title and price are required' });

    try {
        const [pRes] = await db.query('INSERT INTO products (seller_id, title, description, price) VALUES (?, ?, ?, ?)', [req.user.id, title, description, price]);
        const productId = pRes.insertId;

        const imgList = Array.isArray(images) && images.length > 0 ? images.slice(0, 10) : ['logo.jpg'];
        for (let img of imgList) {
            if (img && img.trim() !== '') {
                await db.query('INSERT INTO product_images (product_id, image_url) VALUES (?, ?)', [productId, img.trim()]);
            }
        }

        res.status(201).json({ message: 'Product created', productId });
    } catch (err) {
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

// --- CART ENDPOINTS ---
app.get('/api/cart', authenticateToken, async (req, res) => {
    try {
        const [cart] = await db.query(`
            SELECT c.id AS cart_id, c.quantity, p.id AS product_id, p.title, p.price,
                   (SELECT image_url FROM product_images WHERE product_id = p.id LIMIT 1) AS image_url
            FROM cart_items c
            JOIN products p ON c.product_id = p.id
            WHERE c.buyer_id = ?
        `, [req.user.id]);
        res.json(cart);
    } catch (err) {
        res.status(500).json({ error: 'Cart fetch error', details: err.message });
    }
});

app.post('/api/cart', authenticateToken, async (req, res) => {
    if (req.user.role !== 'buyer') return res.status(403).json({ error: 'Buyers only' });
    const { product_id } = req.body;

    try {
        const [existing] = await db.query('SELECT id, quantity FROM cart_items WHERE buyer_id = ? AND product_id = ?', [req.user.id, product_id]);
        if (existing.length > 0) {
            await db.query('UPDATE cart_items SET quantity = quantity + 1 WHERE id = ?', [existing[0].id]);
        } else {
            await db.query('INSERT INTO cart_items (buyer_id, product_id, quantity) VALUES (?, ?, 1)', [req.user.id, product_id]);
        }
        res.json({ message: 'Added to cart' });
    } catch (err) {
        res.status(500).json({ error: 'Cart error', details: err.message });
    }
});

app.delete('/api/cart/:id', authenticateToken, async (req, res) => {
    try {
        await db.query('DELETE FROM cart_items WHERE id = ? AND buyer_id = ?', [req.params.id, req.user.id]);
        res.json({ message: 'Item removed' });
    } catch (err) {
        res.status(500).json({ error: 'Remove error', details: err.message });
    }
});

// --- PAY@ CHECKOUT ENDPOINT ---
app.post('/api/payat/checkout', authenticateToken, async (req, res) => {
    if (req.user.role !== 'buyer') return res.status(403).json({ error: 'Buyers only' });
    const { payment_method } = req.body; // 'retail_store', 'qr', 'card', 'eft'

    try {
        const [cartItems] = await db.query(`
            SELECT c.product_id, c.quantity, p.price 
            FROM cart_items c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.buyer_id = ?
        `, [req.user.id]);

        if (cartItems.length === 0) return res.status(400).json({ error: 'Cart is empty' });

        let totalAmount = cartItems.reduce((sum, item) => sum + (parseFloat(item.price) * item.quantity), 0);
        const payatRef = `10101${Date.now().toString().slice(-6)}${Math.floor(10 + Math.random() * 90)}`;

        const [orderRes] = await db.query(
            'INSERT INTO orders (buyer_id, total_amount, status, payment_ref, payment_status, payment_method) VALUES (?, ?, ?, ?, ?, ?)',
            [req.user.id, totalAmount, 'pending', payatRef, 'unpaid', payment_method || 'payat_retail']
        );
        const orderId = orderRes.insertId;

        for (let item of cartItems) {
            await db.query('INSERT INTO order_items (order_id, product_id, price, quantity) VALUES (?, ?, ?, ?)', [orderId, item.product_id, item.price, item.quantity]);
        }

        // Clear user cart after order generation
        await db.query('DELETE FROM cart_items WHERE buyer_id = ?', [req.user.id]);

        res.status(201).json({
            message: 'Pay@ Order Generated',
            orderId,
            payatReference: payatRef,
            totalAmount: totalAmount.toFixed(2),
            paymentUrl: `https://payat.io/pay/${payatRef}?amount=${totalAmount.toFixed(2)}`,
            payatDetails: {
                retailStores: ['Shoprite', 'Checkers', 'Pick n Pay', 'PEP', 'Boxer', 'Usave', 'Spar'],
                qrApps: ['SnapScan', 'Zapper', 'Masterpass', 'Capitec Pay'],
                digitalOptions: ['Visa / Mastercard', 'Instant EFT']
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Checkout error', details: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`WeBuy API running on port ${PORT}`));