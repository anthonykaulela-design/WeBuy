requirequire('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

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
const PAYAT_SYSTEM_ID = process.env.PAYAT_SYSTEM_ID || 'WEBUY001';

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

async function initDatabase() {
    try {
        const conn = await db.getConnection();
        console.log('Connected to TiDB/MySQL database.');

        await conn.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role ENUM('buyer', 'seller') NOT NULL,
                business_cert LONGTEXT NULL,
                delivery_preference ENUM('self', 'platform') NULL,
                accepted_tc TINYINT(1) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Migration for existing tables
        const sellerColumns = [
            'ALTER TABLE users ADD COLUMN business_cert LONGTEXT NULL;',
            "ALTER TABLE users ADD COLUMN delivery_preference ENUM('self', 'platform') NULL;",
            'ALTER TABLE users ADD COLUMN accepted_tc TINYINT(1) DEFAULT 0;'
        ];
        for (let q of sellerColumns) {
            try { await conn.query(q); } catch (e) {}
        }

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
                image_url LONGTEXT NOT NULL,
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
                full_name VARCHAR(255),
                company_name VARCHAR(255),
                address TEXT,
                city VARCHAR(100),
                province VARCHAR(100),
                postal_code VARCHAR(20),
                phone_number VARCHAR(50),
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
        console.log('Database schema verified.');
    } catch (err) {
        console.error('DATABASE INIT ERROR:', err.message);
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

// --- AUTHENTICATION ---

app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role, businessCert, deliveryPreference, acceptedTC } = req.body;

    if (!name || !email || !password || !role) {
        return res.status(400).json({ error: 'All primary fields are required.' });
    }

    if (role === 'seller') {
        if (!businessCert) {
            return res.status(400).json({ error: 'Business registration certificate is required for sellers.' });
        }
        if (!deliveryPreference) {
            return res.status(400).json({ error: 'Please specify your delivery handling preference.' });
        }
        if (!acceptedTC) {
            return res.status(400).json({ error: 'You must accept the Terms and Conditions to register as a seller.' });
        }
    }

    try {
        const [existing] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email already registered.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.query(
            `INSERT INTO users (name, email, password, role, business_cert, delivery_preference, accepted_tc) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                name, 
                email, 
                hashedPassword, 
                role.toLowerCase(), 
                role === 'seller' ? businessCert : null, 
                role === 'seller' ? deliveryPreference : null, 
                role === 'seller' ? (acceptedTC ? 1 : 0) : 0
            ]
        );

        res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) return res.status(400).json({ error: 'Invalid credentials.' });

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid credentials.' });

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

// --- MARKETPLACE & PRODUCTS (WITH SEARCH) ---

app.get('/api/products', async (req, res) => {
    const search = req.query.search || '';
    try {
        let query = `
            SELECT p.id, p.title, p.description, p.price, p.created_at, u.name AS seller_name 
            FROM products p 
            JOIN users u ON p.seller_id = u.id 
        `;
        let queryParams = [];

        if (search.trim() !== '') {
            query += ` WHERE p.title LIKE ? OR p.description LIKE ?`;
            const searchTerm = `%${search.trim()}%`;
            queryParams.push(searchTerm, searchTerm);
        }

        query += ` ORDER BY p.created_at DESC`;

        const [products] = await db.query(query, queryParams);

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

app.get('/api/products/:id', async (req, res) => {
    try {
        const [products] = await db.query(`
            SELECT p.id, p.title, p.description, p.price, p.created_at, u.name AS seller_name 
            FROM products p 
            JOIN users u ON p.seller_id = u.id 
            WHERE p.id = ?
        `, [req.params.id]);

        if (products.length === 0) return res.status(404).json({ error: 'Product not found.' });

        const product = products[0];
        const [imgs] = await db.query('SELECT image_url FROM product_images WHERE product_id = ?', [product.id]);
        product.images = imgs.map(i => i.image_url);
        if (product.images.length === 0) product.images = ['logo.jpg'];

        res.json(product);
    } catch (err) {
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

app.post('/api/products', authenticateToken, async (req, res) => {
    if (req.user.role !== 'seller') {
        return res.status(403).json({ error: 'Only sellers can list products.' });
    }

    const { title, description, price, images } = req.body;
    if (!title || !price) return res.status(400).json({ error: 'Title and price are required.' });

    try {
        const [pRes] = await db.query(
            'INSERT INTO products (seller_id, title, description, price) VALUES (?, ?, ?, ?)',
            [req.user.id, title, description, price]
        );
        const productId = pRes.insertId;

        const imgList = Array.isArray(images) && images.length > 0 ? images.slice(0, 10) : ['logo.jpg'];
        for (let img of imgList) {
            if (img && img.trim() !== '') {
                await db.query('INSERT INTO product_images (product_id, image_url) VALUES (?, ?)', [productId, img.trim()]);
            }
        }

        res.status(201).json({ message: 'Product created successfully', productId });
    } catch (err) {
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

// --- CART & CHECKOUT ---

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
    if (req.user.role !== 'buyer') return res.status(403).json({ error: 'Only buyers can add items to cart.' });
    const { product_id } = req.body;

    try {
        const [existing] = await db.query('SELECT id FROM cart_items WHERE buyer_id = ? AND product_id = ?', [req.user.id, product_id]);
        if (existing.length > 0) {
            await db.query('UPDATE cart_items SET quantity = quantity + 1 WHERE id = ?', [existing[0].id]);
        } else {
            await db.query('INSERT INTO cart_items (buyer_id, product_id, quantity) VALUES (?, ?, 1)', [req.user.id, product_id]);
        }
        res.json({ message: 'Item added to cart' });
    } catch (err) {
        res.status(500).json({ error: 'Cart error', details: err.message });
    }
});

app.delete('/api/cart/:id', authenticateToken, async (req, res) => {
    try {
        await db.query('DELETE FROM cart_items WHERE id = ? AND buyer_id = ?', [req.params.id, req.user.id]);
        res.json({ message: 'Item removed from cart' });
    } catch (err) {
        res.status(500).json({ error: 'Remove error', details: err.message });
    }
});

app.post('/api/payat/checkout', authenticateToken, async (req, res) => {
    if (req.user.role !== 'buyer') return res.status(403).json({ error: 'Only buyers can perform checkout.' });
    const { payment_method, full_name, company_name, address, city, province, postal_code, phone_number } = req.body;

    if (!full_name || !address || !city || !province || !postal_code || !phone_number) {
        return res.status(400).json({ error: 'Delivery details required.' });
    }

    try {
        const [cartItems] = await db.query(`
            SELECT c.product_id, c.quantity, p.price 
            FROM cart_items c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.buyer_id = ?
        `, [req.user.id]);

        if (cartItems.length === 0) return res.status(400).json({ error: 'Your cart is empty.' });

        let totalAmount = cartItems.reduce((sum, item) => sum + (parseFloat(item.price) * item.quantity), 0);
        const payatRef = `10101${Date.now().toString().slice(-6)}${Math.floor(10 + Math.random() * 90)}`;

        const [orderRes] = await db.query(
            `INSERT INTO orders 
            (buyer_id, total_amount, status, payment_ref, payment_status, payment_method, full_name, company_name, address, city, province, postal_code, phone_number) 
            VALUES (?, ?, 'pending', ?, 'unpaid', ?, ?, ?, ?, ?, ?, ?, ?)`,
            [req.user.id, totalAmount, payatRef, payment_method || 'retail_store', full_name, company_name || null, address, city, province, postal_code, phone_number]
        );

        for (let item of cartItems) {
            await db.query('INSERT INTO order_items (order_id, product_id, price, quantity) VALUES (?, ?, ?, ?)', [orderRes.insertId, item.product_id, item.price, item.quantity]);
        }

        await db.query('DELETE FROM cart_items WHERE buyer_id = ?', [req.user.id]);

        res.status(201).json({
            message: 'Order created',
            orderId: orderRes.insertId,
            payatReference: payatRef,
            totalAmount: totalAmount.toFixed(2),
            paymentUrl: `https://payat.io/pay/${payatRef}?amount=${totalAmount.toFixed(2)}&sys=${PAYAT_SYSTEM_ID}`
        });
    } catch (err) {
        res.status(500).json({ error: 'Checkout failed', details: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`WeBuy API running on port ${PORT}`));