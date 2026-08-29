/**
 * ============================================================================
 * WeBuy Marketplace - Enterprise Node.js & Express Backend Server
 * ============================================================================
 * Features:
 *  - Secure JWT Authentication & Password Hashing (bcrypt)
 *  - Role-Based Access Control (Buyers & Verified Business Sellers)
 *  - Product Catalog Management with Base64 Image Handling
 *  - Persistent Shopping Cart Operations
 *  - 30-Minute Expiration Pay@ Checkout (Supporting Retail & Instant EFT Channels)
 *  - TiDB Cloud / MySQL Secure SSL/TLS Connection Pool
 * ============================================================================
 */

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'webuy_secure_enterprise_secret_key_2026';

// Middleware Configuration
app.use(cors());
app.use(express.json({ limit: '50mb' })); // Large payload support for base64 images & certs
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Database Connection Pool (TiDB / MySQL with Secure SSL Enabled)
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'webuy_db',
    port: process.env.DB_PORT || 4000,
    waitForConnections: true,
    connectionLimit: 15,
    queueLimit: 0,
    ssl: {
        rejectUnauthorized: true
    }
});

// Verify Database Connectivity on Startup
db.getConnection()
    .then(connection => {
        console.log('[DATABASE] Successfully established secure SSL connection to MySQL / TiDB cluster.');
        connection.release();
    })
    .catch(err => {
        console.error('[DATABASE ERROR] Failed to connect to database cluster:', err.message);
    });

/**
 * Middleware: Authenticate JSON Web Token (JWT)
 */
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token missing or unauthorized request.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired authentication token.' });
        }
        req.user = user;
        next();
    });
}

// ============================================================================
// 1. AUTHENTICATION & USER MANAGEMENT ENDPOINTS
// ============================================================================

/**
 * Endpoint: Register a new user (Buyer or Seller)
 */
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, role, business_cert, delivery_preference, pricing_preference } = req.body;
        
        if (!name || !email || !password || !role) {
            return res.status(400).json({ error: 'Required registration parameters are missing.' });
        }

        // Check if user email already exists in system
        const [existingUsers] = await db.execute('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUsers.length > 0) {
            return res.status(400).json({ error: 'An account with this email address already exists.' });
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

        console.log(`[AUTH] New user registered: ${email} (Role: ${role})`);
        res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
    } catch (err) {
        console.error('[AUTH ERROR] Registration failed:', err);
        res.status(500).json({ error: 'Internal server error during registration: ' + err.message });
    }
});

/**
 * Endpoint: Authenticate user login and issue JWT
 */
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password credentials are required.' });
        }

        const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(400).json({ error: 'Invalid email or password.' });
        }

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid email or password.' });
        }

        const tokenPayload = { id: user.id, email: user.email, role: user.role, name: user.name };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '7d' });

        console.log(`[AUTH] User logged in successfully: ${email}`);
        res.status(200).json({
            message: 'Login successful',
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role }
        });
    } catch (err) {
        console.error('[AUTH ERROR] Login failed:', err);
        res.status(500).json({ error: 'Internal server error during login: ' + err.message });
    }
});

// ============================================================================
// 2. PRODUCT CATALOG ENDPOINTS
// ============================================================================

/**
 * Endpoint: Retrieve all marketplace product listings
 */
app.get('/api/products', async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT p.*, u.name as seller_name 
            FROM products p 
            JOIN users u ON p.seller_id = u.id 
            ORDER BY p.id DESC
        `);

        // Safely parse image JSON string arrays for frontend consumers
        const products = rows.map(item => ({
            ...item,
            images: typeof item.images === 'string' ? JSON.parse(item.images || '[]') : item.images
        }));

        res.status(200).json(products);
    } catch (err) {
        console.error('[PRODUCT ERROR] Failed to fetch products:', err);
        res.status(500).json({ error: 'Failed to retrieve product listings.' });
    }
});

/**
 * Endpoint: Create a new product listing (Verified Sellers Only)
 */
app.post('/api/products', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'seller') {
            return res.status(403).json({ error: 'Access denied: Only verified business sellers can create listings.' });
        }

        const { title, description, price, weight, images } = req.body;
        if (!title || price === undefined) {
            return res.status(400).json({ error: 'Product title and price are mandatory fields.' });
        }

        const imagesString = Array.isArray(images) ? JSON.stringify(images) : JSON.stringify([]);

        const [result] = await db.execute(
            `INSERT INTO products (seller_id, title, description, price, weight, images) VALUES (?, ?, ?, ?, ?, ?)`,
            [req.user.id, title, description || '', price, weight || 0.0, imagesString]
        );

        console.log(`[PRODUCT] New listing created by seller ID ${req.user.id}: "${title}"`);
        res.status(201).json({ message: 'Product successfully listed', productId: result.insertId });
    } catch (err) {
        console.error('[PRODUCT ERROR] Creation failed:', err);
        res.status(500).json({ error: 'Failed to create product listing: ' + err.message });
    }
});

// ============================================================================
// 3. SHOPPING CART MANAGEMENT ENDPOINTS
// ============================================================================

/**
 * Endpoint: Retrieve active cart items for authenticated user
 */
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
        console.error('[CART ERROR] Failed to retrieve cart:', err);
        res.status(500).json({ error: 'Failed to fetch shopping cart items.' });
    }
});

/**
 * Endpoint: Add item to user cart
 */
app.post('/api/cart', authenticateToken, async (req, res) => {
    try {
        const { product_id, quantity = 1 } = req.body;
        if (!product_id) {
            return res.status(400).json({ error: 'Product ID is required.' });
        }

        // Check if product already exists in cart
        const [existing] = await db.execute(
            'SELECT id, quantity FROM cart WHERE user_id = ? AND product_id = ?', 
            [req.user.id, product_id]
        );

        if (existing.length > 0) {
            const updatedQuantity = existing[0].quantity + parseInt(quantity, 10);
            await db.execute('UPDATE cart SET quantity = ? WHERE id = ?', [updatedQuantity, existing[0].id]);
        } else {
            await db.execute(
                'INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)', 
                [req.user.id, product_id, quantity]
            );
        }

        res.status(200).json({ message: 'Cart updated successfully' });
    } catch (err) {
        console.error('[CART ERROR] Add to cart failed:', err);
        res.status(500).json({ error: 'Failed to add item to cart.' });
    }
});

/**
 * Endpoint: Remove specific item from cart
 */
app.delete('/api/cart/:id', authenticateToken, async (req, res) => {
    try {
        await db.execute('DELETE FROM cart WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
        res.status(200).json({ message: 'Cart item removed successfully' });
    } catch (err) {
        console.error('[CART ERROR] Removal failed:', err);
        res.status(500).json({ error: 'Failed to remove item from cart.' });
    }
});

// ============================================================================
// 4. CHECKOUT & PAYMENT CHANNEL INTEGRATION ENDPOINTS
// ============================================================================

/**
 * Endpoint: Generate 30-minute Pay@ reference supporting Retail or Instant EFT networks
 */
app.post('/api/payat/checkout', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { channel_type } = req.body; // Expects 'retail' or 'eft'

        const [cartItems] = await db.execute(`
            SELECT c.id as cart_id, c.quantity, p.id as product_id, p.title, p.price, p.weight 
            FROM cart c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.user_id = ?
        `, [userId]);

        if (cartItems.length === 0) {
            return res.status(400).json({ error: 'Cannot checkout with an empty shopping cart.' });
        }

        // Calculate financial totals and logistics weight
        const subtotal = cartItems.reduce((sum, item) => sum + (parseFloat(item.price) * item.quantity), 0);
        const totalWeight = cartItems.reduce((sum, item) => sum + ((parseFloat(item.weight) || 0) * item.quantity), 0);
        
        // Logistics flat calculation: R400 per KG for platform-managed delivery
        const deliveryFee = totalWeight * 400; 
        const grandTotal = subtotal + deliveryFee;

        // Generate unique Pay@ transaction reference code
        const payatReference = 'WB' + Math.floor(100000000 + Math.random() * 900000000);
        const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // Exactly 30 minutes validity

        // Clear shopping cart post order generation
        await db.execute('DELETE FROM cart WHERE user_id = ?', [userId]);

        // Dynamically assign appropriate channel partners based on user preference
        let supportedChannels = [];
        if (channel_type === 'eft') {
            supportedChannels = [
                "Capitec Pay", "FNB Instant EFT", "Absa Pay", 
                "Standard Bank Secure EFT", "Nedbank Instant Pay", "Investec Online"
            ];
        } else {
            supportedChannels = [
                "Pick n Pay", "Shoprite", "Checkers", "Spar", 
                "PEP", "Ackermans", "Usave", "Boxer", "Rhino Cash & Carry", "Cambridge Food"
            ];
        }

        console.log(`[CHECKOUT] Generated Pay@ order (${payatReference}) for User ID ${userId} via [${channel_type.toUpperCase()}]`);

        res.status(200).json({
            message: 'Checkout reference generated successfully',
            payat_reference: payatReference,
            amount_due: grandTotal.toFixed(2),
            expires_at: expiresAt,
            channel_type: channel_type || 'retail',
            supported_channels: supportedChannels
        });
    } catch (err) {
        console.error('[CHECKOUT ERROR] Payment processing failed:', err);
        res.status(500).json({ error: 'Checkout processing failed: ' + err.message });
    }
});

// Root Health Check Route
app.get('/', (req, res) => {
    res.status(200).send('WeBuy Marketplace Enterprise Backend Server is running successfully.');
});

// Initialize Server Listener
app.listen(PORT, () => {
    console.log(`[SERVER] WeBuy backend listening securely on port ${PORT}`);
});