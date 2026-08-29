require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Increase payload limits to handle Base64 certificate and multi-image uploads
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());

// MySQL / TiDB Database Connection Pool
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 4000,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: {
        rejectUnauthorized: false
    }
});

// Test Database Connection
db.getConnection()
    .then(conn => {
        console.log('Successfully connected to TiDB/MySQL database');
        conn.release();
    })
    .catch(err => {
        console.error('Database connection error:', err.message);
    });

// Health Check
app.get('/api', (req, res) => {
    res.json({ message: 'WeBuy API is running smoothly' });
});

// ==========================================
// AUTHENTICATION MIDDLEWARE
// ==========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access token required' });

    try {
        const secret = process.env.JWT_SECRET || 'fallback_secret';
        const decoded = jwt.verify(token, secret);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

// ==========================================
// USER REGISTRATION (POST /api/register)
// ==========================================
app.post('/api/register', async (req, res) => {
    try {
        const { 
            name, 
            email, 
            password, 
            role, 
            business_cert, 
            delivery_preference, 
            pricing_preference 
        } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Name, email, and password are required.' });
        }

        const [existingUsers] = await db.execute(
            'SELECT id FROM users WHERE email = ?', 
            [email]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({ error: 'Email is already registered.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const userRole = role === 'seller' ? 'seller' : 'buyer';
        const isTermsAccepted = userRole === 'seller' ? 1 : 0;

        const [result] = await db.execute(
            `INSERT INTO users 
            (name, email, password, role, business_cert, delivery_preference, pricing_preference, terms_accepted) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                name,
                email,
                hashedPassword,
                userRole,
                business_cert || null,
                delivery_preference || 'self',
                pricing_preference || 'keep',
                isTermsAccepted
            ]
        );

        res.status(201).json({ 
            message: 'User registered successfully', 
            userId: result.insertId 
        });

    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ error: 'Internal server error during registration.' });
    }
});

// ==========================================
// USER LOGIN (POST /api/login)
// ==========================================
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const user = users[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const secret = process.env.JWT_SECRET || 'fallback_secret';
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role }, 
            secret, 
            { expiresIn: '7d' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Internal server error during login.' });
    }
});

// ==========================================
// PRODUCTS ENDPOINTS
// ==========================================

// Get all products
app.get('/api/products', async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT p.*, u.name as seller_name 
            FROM products p 
            LEFT JOIN users u ON p.seller_id = u.id 
            ORDER BY p.id DESC
        `);

        const products = rows.map(p => ({
            ...p,
            images: typeof p.images === 'string' ? JSON.parse(p.images) : p.images || []
        }));

        res.json(products);
    } catch (err) {
        console.error('Fetch products error:', err);
        res.status(500).json({ error: 'Failed to fetch products.' });
    }
});

// Get single product details
app.get('/api/products/:id', async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT p.*, u.name as seller_name 
            FROM products p 
            LEFT JOIN users u ON p.seller_id = u.id 
            WHERE p.id = ?
        `, [req.params.id]);

        if (rows.length === 0) return res.status(404).json({ error: 'Product not found' });

        const product = rows[0];
        product.images = typeof product.images === 'string' ? JSON.parse(product.images) : product.images || [];

        res.json(product);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch product.' });
    }
});

// Post a product (Seller only)
app.post('/api/products', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'seller') {
            return res.status(403).json({ error: 'Only registered sellers can post products.' });
        }

        const { title, description, price, weight, images } = req.body;
        const sellerId = req.user.id;

        // Auto-add R50 listing fee if seller opted to add fee on top during registration
        const [sellerInfo] = await db.execute('SELECT pricing_preference FROM users WHERE id = ?', [sellerId]);
        let finalPrice = parseFloat(price);

        if (sellerInfo.length > 0 && sellerInfo[0].pricing_preference === 'add') {
            finalPrice += 50;
        }

        const imagesJson = JSON.stringify(images || []);

        const [result] = await db.execute(
            `INSERT INTO products (seller_id, title, description, price, weight, images) VALUES (?, ?, ?, ?, ?, ?)`,
            [sellerId, title, description, finalPrice, weight || 0, imagesJson]
        );

        res.status(201).json({ message: 'Product listed successfully', productId: result.insertId });
    } catch (err) {
        console.error('Create product error:', err);
        res.status(500).json({ error: 'Failed to create product listing.' });
    }
});

// ==========================================
// CART ENDPOINTS
// ==========================================

// Get user cart items
app.get('/api/cart', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT c.id as cart_id, c.quantity, p.* 
            FROM cart c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.user_id = ?
        `, [req.user.id]);
        
        const cartItems = rows.map(item => ({
            ...item,
            images: typeof item.images === 'string' ? JSON.parse(item.images) : item.images || []
        }));

        res.json(cartItems);
    } catch (err) {
        res.status(500).json({ error: 'Failed to load cart.' });
    }
});

// Add product to cart
app.post('/api/cart', authenticateToken, async (req, res) => {
    try {
        const { product_id } = req.body;
        
        const [existing] = await db.execute('SELECT id, quantity FROM cart WHERE user_id = ? AND product_id = ?', [req.user.id, product_id]);

        if (existing.length > 0) {
            await db.execute('UPDATE cart SET quantity = quantity + 1 WHERE id = ?', [existing[0].id]);
        } else {
            await db.execute('INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, 1)', [req.user.id, product_id]);
        }

        res.json({ message: 'Added to cart' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to add item to cart.' });
    }
});

// Delete cart item
app.delete('/api/cart/:id', authenticateToken, async (req, res) => {
    try {
        await db.execute('DELETE FROM cart WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
        res.json({ message: 'Item removed' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to remove cart item.' });
    }
});

// ==========================================
// PAYAT CHECKOUT ENDPOINT
// ==========================================
app.post('/api/checkout/payat', authenticateToken, async (req, res) => {
    try {
        const { full_name, address, city, province, postal_code, phone, payment_option } = req.body;

        const payatReference = 'PAYAT-' + Math.floor(10000000 + Math.random() * 90000000);

        await db.execute('DELETE FROM cart WHERE user_id = ?', [req.user.id]);

        res.json({
            message: 'Order initiated',
            payat_reference: payatReference,
            payment_option
        });
    } catch (err) {
        res.status(500).json({ error: 'Checkout failed.' });
    }
});

// Start Express Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});