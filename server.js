require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());

// Database Connection Pool
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 4000,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: { rejectUnauthorized: false }
});

db.getConnection()
    .then(conn => {
        console.log('Successfully connected to TiDB/MySQL database');
        conn.release();
    })
    .catch(err => console.error('Database connection error:', err.message));

// Safe Image Parser Helper
const parseImages = (imagesData) => {
    if (!imagesData) return [];
    if (Array.isArray(imagesData)) return imagesData;
    if (typeof imagesData === 'string') {
        try { 
            const parsed = JSON.parse(imagesData);
            return Array.isArray(parsed) ? parsed : [parsed];
        } catch (e) { 
            return [imagesData]; 
        }
    }
    return [];
};

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access token required. Please log in.' });

    try {
        const secret = process.env.JWT_SECRET || 'fallback_secret';
        const decoded = jwt.verify(token, secret);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token. Please log in again.' });
    }
};

// HEALTH
app.get('/api/health', async (req, res) => {
    try {
        const conn = await db.getConnection();
        conn.release();
        res.json({ status: 'online', database: 'connected', service: 'WeBuy API' });
    } catch (err) {
        res.status(500).json({ status: 'degraded', database: 'disconnected', error: err.message });
    }
});

// AUTHENTICATION
app.post(['/api/auth/register', '/api/register'], async (req, res) => {
    try {
        const { name, email, password, role, business_cert, delivery_preference, pricing_preference } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Name, email, and password are required.' });
        }

        const [existing] = await db.execute('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) return res.status(400).json({ error: 'Email is already registered.' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const userRole = role === 'seller' ? 'seller' : 'buyer';

        const [result] = await db.execute(
            `INSERT INTO users (name, email, password, role, business_cert, delivery_preference, pricing_preference, terms_accepted) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                name, 
                email, 
                hashedPassword, 
                userRole, 
                business_cert || null, 
                delivery_preference || 'self', 
                pricing_preference || 'keep', 
                userRole === 'seller' ? 1 : 0
            ]
        );

        res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Registration failed: ' + err.message });
    }
});

app.post(['/api/auth/login', '/api/login'], async (req, res) => {
    try {
        const { email, password } = req.body;
        const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        
        if (users.length === 0) return res.status(401).json({ error: 'Invalid credentials.' });

        const user = users[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).json({ error: 'Invalid credentials.' });

        const secret = process.env.JWT_SECRET || 'fallback_secret';
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, secret, { expiresIn: '24h' });

        res.json({
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed: ' + err.message });
    }
});

// PRODUCTS
app.get('/api/products', async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT p.id, p.seller_id, p.title, p.description, p.price, p.weight, p.images, p.created_at, u.name as seller_name 
            FROM products p 
            LEFT JOIN users u ON p.seller_id = u.id 
            ORDER BY p.id DESC
        `);

        const products = rows.map(p => {
            let parsedImages = [];
            try {
                if (p.images) {
                    if (Array.isArray(p.images)) {
                        parsedImages = p.images;
                    } else if (typeof p.images === 'string') {
                        const trimmed = p.images.trim();
                        if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
                            const temp = JSON.parse(trimmed);
                            parsedImages = Array.isArray(temp) ? temp : [temp];
                        } else {
                            parsedImages = [trimmed];
                        }
                    }
                }
            } catch (e) {
                parsedImages = p.images ? [String(p.images)] : [];
            }

            return { ...p, images: parsedImages };
        });

        res.json(products);
    } catch (err) {
        console.error('Fetch products error:', err);
        res.status(500).json({ error: 'Failed to retrieve products: ' + err.message });
    }
});


// ADD PRODUCT
app.post('/api/products', async (req, res) => {
    try {
        const { seller_id, title, description, price, weight, images } = req.body;
        
        // Convert images array to JSON string if it's an array
        const imagesString = Array.isArray(images) ? JSON.stringify(images) : images;

        const [result] = await db.execute(
            `INSERT INTO products (seller_id, title, description, price, weight, images) VALUES (?, ?, ?, ?, ?, ?)`,
            [seller_id || 1, title, description, price, weight || 0, imagesString]
        );

        res.status(201).json({ message: 'Product created successfully', productId: result.insertId });
    } catch (err) {
        console.error('Create product error:', err);
        res.status(500).json({ error: 'Failed to create product: ' + err.message });
    }
});
// CART
app.get('/api/cart', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT 
                c.id AS cart_id, 
                c.quantity, 
                p.id AS product_id, 
                p.title, 
                p.price, 
                p.images, 
                p.weight
            FROM cart c 
            INNER JOIN products p ON c.product_id = p.id 
            WHERE c.user_id = ?
        `, [req.user.id]);

        const cartItems = rows.map(item => ({ ...item, images: parseImages(item.images) }));
        res.json(cartItems);
    } catch (err) {
        console.error('Fetch cart error:', err);
        res.status(500).json({ error: 'Failed to load cart: ' + err.message });
    }
});

app.post('/api/cart', authenticateToken, async (req, res) => {
    try {
        const { product_id, productId } = req.body;
        const targetProductId = product_id || productId;

        if (!targetProductId) return res.status(400).json({ error: 'Product ID is required.' });

        const [existing] = await db.execute('SELECT id, quantity FROM cart WHERE user_id = ? AND product_id = ?', [req.user.id, targetProductId]);

        if (existing.length > 0) {
            await db.execute('UPDATE cart SET quantity = quantity + 1 WHERE id = ?', [existing[0].id]);
        } else {
            await db.execute('INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, 1)', [req.user.id, targetProductId]);
        }

        res.json({ message: 'Added to cart successfully' });
    } catch (err) {
        console.error('Add to cart error:', err);
        res.status(500).json({ error: 'Failed to add item to cart.' });
    }
});

app.delete('/api/cart/:id', authenticateToken, async (req, res) => {
    try {
        await db.execute('DELETE FROM cart WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
        res.json({ message: 'Cart item removed successfully' });
    } catch (err) {
        console.error('Remove cart item error:', err);
        res.status(500).json({ error: 'Failed to remove cart item.' });
    }
});

// PAY@ CHECKOUT & WEBHOOK
app.post(['/api/payat/checkout', '/api/checkout/payat'], authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const [cartItems] = await db.execute(`
            SELECT c.quantity, p.id AS product_id, p.price, p.weight 
            FROM cart c 
            INNER JOIN products p ON c.product_id = p.id 
            WHERE c.user_id = ?
        `, [userId]);

        if (cartItems.length === 0) return res.status(400).json({ error: 'Your cart is empty.' });

        let totalAmount = 0, totalWeight = 0;
        cartItems.forEach(item => {
            totalAmount += parseFloat(item.price) * item.quantity;
            totalWeight += (parseFloat(item.weight) || 0) * item.quantity;
        });

        const payatReference = 'PAYAT-' + Math.floor(1000000000 + Math.random() * 9000000000);

        const [orderResult] = await db.execute(
            `INSERT INTO orders (user_id, payat_reference, total_amount, total_weight, status, payment_status) 
             VALUES (?, ?, ?, ?, 'pending', 'unpaid')`,
            [userId, payatReference, totalAmount, totalWeight]
        );

        await db.execute('DELETE FROM cart WHERE user_id = ?', [userId]);

        res.status(201).json({
            message: 'Order created successfully',
            order_id: orderResult.insertId,
            payat_reference: payatReference,
            total_amount: totalAmount
        });
    } catch (err) {
        console.error('Checkout error:', err);
        res.status(500).json({ error: 'Checkout failed.' });
    }
});

app.post('/api/payat/notification', async (req, res) => {
    try {
        const { payat_reference, reference, status } = req.body;
        const targetRef = payat_reference || reference;

        if (!targetRef) return res.status(400).json({ error: 'Pay@ reference required.' });

        const isPaid = (status === 'SUCCESS' || status === 'PAID' || status === '00');
        await db.execute(
            `UPDATE orders SET payment_status = ?, status = ? WHERE payat_reference = ?`,
            [isPaid ? 'paid' : 'failed', isPaid ? 'processing' : 'pending', targetRef]
        );

        res.json({ status: 'ACCEPTED', payat_reference: targetRef });
    } catch (err) {
        console.error('Webhook error:', err);
        res.status(500).json({ error: 'Webhook processing failed.' });
    }
});

app.get('/api/payat/status/:reference', authenticateToken, async (req, res) => {
    try {
        const [orders] = await db.execute(
            `SELECT * FROM orders WHERE payat_reference = ? AND user_id = ?`,
            [req.params.reference, req.user.id]
        );

        if (orders.length === 0) return res.status(404).json({ error: 'Order not found.' });
        res.json(orders[0]);
    } catch (err) {
        console.error('Status check error:', err);
        res.status(500).json({ error: 'Status check failed.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`WeBuy API active on port ${PORT}`));