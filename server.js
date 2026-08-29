/**
 * WeBuy Marketplace - Complete Node.js & Express Backend Server
 * Supports: Authentication, Role-based Sellers, Product Catalog, Cart, and 30-min Pay@ Orders
 */
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'webuy_secure_secret_key_2026';

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' })); // Support large base64 image strings
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Database Connection Pool (TiDB / MySQL with SSL enabled)
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'webuy_db',
    port: process.env.DB_PORT || 4000,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: {
        rejectUnauthorized: true
    }
});
// Test DB Connection on Startup
db.getConnection()
    .then(connection => {
        console.log('Successfully connected to MySQL / TiDB Database');
        connection.release();
    })
    .catch(err => {
        console.error('Database connection failed:', err.message);
    });

// Middleware: Authenticate JWT Token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access token missing or unauthorized' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
}

// ==========================================
// 1. AUTHENTICATION ENDPOINTS
// ==========================================

// Register User (Buyer or Seller)
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, role, business_cert, delivery_preference, pricing_preference } = req.body;
        
        if (!name || !email || !password || !role) {
            return res.status(400).json({ error: 'Missing required registration fields' });
        }

        // Check if user already exists
        const [existing] = await db.execute('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email address is already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await db.execute(
            `INSERT INTO users (name, email, password, role, business_cert, delivery_preference, pricing_preference) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                name, 
                email, 
                hashedPassword, 
                role, 
                business_cert || null, 
                delivery_preference || 'self', 
                pricing_preference || 'keep'
            ]
        );

        res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ error: 'Server error during registration: ' + err.message });
    }
});

// Login User
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const tokenPayload = { id: user.id, email: user.email, role: user.role, name: user.name };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '7d' });

        res.status(200).json({
            message: 'Login successful',
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error during login: ' + err.message });
    }
});

// ==========================================
// 2. PRODUCT ENDPOINTS
// ==========================================

// Get All Products
app.get('/api/products', async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT p.*, u.name as seller_name 
            FROM products p 
            JOIN users u ON p.seller_id = u.id 
            ORDER BY p.id DESC
        `);

        // Parse images JSON string back into array for frontend use
        const products = rows.map(item => ({
            ...item,
            images: typeof item.images === 'string' ? JSON.parse(item.images || '[]') : item.images
        }));

        res.status(200).json(products);
    } catch (err) {
        console.error('Fetch products error:', err);
        res.status(500).json({ error: 'Failed to retrieve products' });
    }
});

// Post a New Product (Sellers Only)
app.post('/api/products', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'seller') {
            return res.status(403).json({ error: 'Unauthorized: Only verified sellers can post listings' });
        }

        const { title, description, price, weight, images } = req.body;
        if (!title || !price) {
            return res.status(400).json({ error: 'Product title and price are required' });
        }

        const imagesString = Array.isArray(images) ? JSON.stringify(images) : JSON.stringify([]);

        const [result] = await db.execute(
            `INSERT INTO products (seller_id, title, description, price, weight, images) VALUES (?, ?, ?, ?, ?, ?)`,
            [req.user.id, title, description || '', price, weight || 0.0, imagesString]
        );

        res.status(201).json({ message: 'Product created successfully', productId: result.insertId });
    } catch (err) {
        console.error('Create product error:', err);
        res.status(500).json({ error: 'Failed to create product: ' + err.message });
    }
});

// ==========================================
// 3. SHOPPING CART ENDPOINTS
// ==========================================

// Get User Cart
app.get('/api/cart', authenticateToken, async (req, res) => {
    try {
        const [items] = await db.execute(`
            SELECT c.id as cart_id, c.quantity, p.id as product_id, p.title, p.price, p.weight, p.images 
            FROM cart c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.user_id = ?
        `, [req.user.id]);

        const formattedCart = items.map(item => ({
            ...item,
            images: typeof item.images === 'string' ? JSON.parse(item.images || '[]') : item.images
        }));

        res.status(200).json(formattedCart);
    } catch (err) {
        console.error('Get cart error:', err);
        res.status(500).json({ error: 'Failed to retrieve cart items' });
    }
});

// Add Item to Cart
app.post('/api/cart', authenticateToken, async (req, res) => {
    try {
        const { product_id, quantity = 1 } = req.body;
        if (!product_id) return res.status(400).json({ error: 'Product ID is required' });

        // Check if item already exists in user's cart
        const [existing] = await db.execute(
            'SELECT id, quantity FROM cart WHERE user_id = ? AND product_id = ?', 
            [req.user.id, product_id]
        );

        if (existing.length > 0) {
            const newQty = existing[0].quantity + parseInt(quantity);
            await db.execute('UPDATE cart SET quantity = ? WHERE id = ?', [newQty, existing[0].id]);
        } else {
            await db.execute(
                'INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)', 
                [req.user.id, product_id, quantity]
            );
        }

        res.status(200).json({ message: 'Item added to cart successfully' });
    } catch (err) {
        console.error('Add to cart error:', err);
        res.status(500).json({ error: 'Failed to add item to cart' });
    }
});

// Remove Item from Cart
app.delete('/api/cart/:id', authenticateToken, async (req, res) => {
    try {
        await db.execute('DELETE FROM cart WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
        res.status(200).json({ message: 'Item removed from cart' });
    } catch (err) {
        console.error('Remove cart item error:', err);
        res.status(500).json({ error: 'Failed to remove item' });
    }
});

// ==========================================
// 4. CHECKOUT & PAY@ ENDPOINTS
// ==========================================

app.post('/api/payat/checkout', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        const [cartItems] = await db.execute(`
            SELECT c.id as cart_id, c.quantity, p.id as product_id, p.title, p.price, p.weight 
            FROM cart c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.user_id = ?
        `, [userId]);

        if (cartItems.length === 0) {
            return res.status(400).json({ error: 'Your cart is empty' });
        }

        const subtotal = cartItems.reduce((sum, item) => sum + (parseFloat(item.price) * item.quantity), 0);
        const totalWeight = cartItems.reduce((sum, item) => sum + ((parseFloat(item.weight) || 0) * item.quantity), 0);
        
        // Logistics fee formula: R400 per KG for managed deliveries
        const deliveryFee = totalWeight * 400; 
        const grandTotal = subtotal + deliveryFee;

        // Generate Pay@ reference code
        const payatReference = 'WB' + Math.floor(100000000 + Math.random() * 900000000);
        const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // 30 minutes expiry

        // Clear cart following order generation
        await db.execute('DELETE FROM cart WHERE user_id = ?', [userId]);

        res.status(200).json({
            message: 'Pay@ order generated successfully',
            payat_reference: payatReference,
            amount_due: grandTotal.toFixed(2),
            expires_at: expiresAt,
            supported_channels: [
                "Pick n Pay", "Shoprite", "Checkers", "Spar", "PEP", "Ackermans", 
                "Usave", "Boxer", "Rhino", "Cambridge Food", "Major SA Bank EFTs"
            ]
        });
    } catch (err) {
        console.error('Pay@ checkout error:', err);
        res.status(500).json({ error: 'Checkout processing failed: ' + err.message });
    }
});

// Root check
app.get('/', (req, res) => {
    res.send('WeBuy Marketplace Backend API is live and operational.');
});

app.listen(PORT, () => {
    console.log(`WeBuy server running live on port ${PORT}`);
});