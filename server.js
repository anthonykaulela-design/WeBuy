require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Increase payload limits to handle up to 10 Base64 images per product listing
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

// Verify Database Connection on Boot
db.getConnection()
    .then(conn => {
        console.log('Successfully connected to TiDB/MySQL database');
        conn.release();
    })
    .catch(err => {
        console.error('Database connection error:', err.message);
    });

// ==========================================
// AUTHENTICATION MIDDLEWARE
// ==========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required. Please log in.' });
    }

    try {
        const secret = process.env.JWT_SECRET || 'fallback_secret';
        const decoded = jwt.verify(token, secret);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token. Please log in again.' });
    }
};

// Helper: Image parser safeguard
const parseImages = (imagesData) => {
    if (!imagesData) return [];
    if (Array.isArray(imagesData)) return imagesData;
    if (typeof imagesData === 'string') {
        try {
            return JSON.parse(imagesData);
        } catch (e) {
            return [imagesData];
        }
    }
    return [];
};

// ==========================================
// SYSTEM & HEALTH ROUTES
// ==========================================

// GET /api/health - Public: System status and operational health check
app.get('/api/health', async (req, res) => {
    try {
        const conn = await db.getConnection();
        conn.release();
        res.json({
            status: 'online',
            timestamp: new Date().toISOString(),
            database: 'connected',
            service: 'WeBuy API'
        });
    } catch (err) {
        res.status(500).json({
            status: 'degraded',
            timestamp: new Date().toISOString(),
            database: 'disconnected',
            error: err.message
        });
    }
});

// Root API Health fallback
app.get('/api', (req, res) => {
    res.json({ message: 'WeBuy API Engine is running' });
});

// ==========================================
// AUTHENTICATION ROUTES
// ==========================================

// POST /api/auth/register - Public: Register user
app.post('/api/auth/register', async (req, res) => {
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

        const [existingUsers] = await db.execute('SELECT id FROM users WHERE email = ?', [email]);
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
            message: 'User account created successfully', 
            userId: result.insertId 
        });

    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Registration failed.' });
    }
});

// Legacy route alias for frontend compatibility
app.post('/api/register', (req, res) => app._router.handle({ ...req, url: '/api/auth/register' }, res));

// POST /api/auth/login - Public: Authenticate and receive a 24-hour JWT token
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const user = users[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const secret = process.env.JWT_SECRET || 'fallback_secret';
        
        // Signed explicitly with 24-hour expiration
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role }, 
            secret, 
            { expiresIn: '24h' }
        );

        res.json({
            token,
            expiresIn: '24h',
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed.' });
    }
});

// Legacy route alias
app.post('/api/login', (req, res) => app._router.handle({ ...req, url: '/api/auth/login' }, res));

// ==========================================
// PRODUCT LISTING ROUTES
// ==========================================

// GET /api/products - Public: Fetch all available listings
app.get('/api/products', async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT p.*, u.name as seller_name 
            FROM products p 
            LEFT JOIN users u ON p.seller_id = u.id 
            ORDER BY p.id DESC
        `);

        const products = rows.map(product => ({
            ...product,
            images: parseImages(product.images)
        }));

        res.json(products);
    } catch (err) {
        console.error('Fetch products error:', err);
        res.status(500).json({ error: 'Failed to retrieve products.' });
    }
});

// POST /api/products - Token (Seller): Create product listing (up to 10 images)
app.post('/api/products', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'seller') {
            return res.status(403).json({ error: 'Access denied. Only sellers can list products.' });
        }

        const { title, name, description, price, weight, images } = req.body;
        const productTitle = title || name;

        if (!productTitle || price === undefined) {
            return res.status(400).json({ error: 'Product name/title and price are required.' });
        }

        const sellerId = req.user.id;

        // Apply R50 fee adjustment if seller selected pricing_preference = 'add'
        const [sellerInfo] = await db.execute('SELECT pricing_preference FROM users WHERE id = ?', [sellerId]);
        let finalPrice = parseFloat(price);

        if (sellerInfo.length > 0 && sellerInfo[0].pricing_preference === 'add') {
            finalPrice += 50;
        }

        // Limit to maximum 10 Base64 images
        let rawImages = parseImages(images);
        if (rawImages.length > 10) {
            rawImages = rawImages.slice(0, 10);
        }
        const imagesJson = JSON.stringify(rawImages);

        const [result] = await db.execute(
            `INSERT INTO products (seller_id, title, description, price, weight, images) VALUES (?, ?, ?, ?, ?, ?)`,
            [
                sellerId, 
                productTitle, 
                description || '', 
                finalPrice, 
                weight ? parseFloat(weight) : 0.00, 
                imagesJson
            ]
        );

        res.status(201).json({ 
            message: 'Product listed successfully', 
            productId: result.insertId,
            imageCount: rawImages.length
        });

    } catch (err) {
        console.error('Create product error:', err);
        res.status(500).json({ error: 'Failed to create product listing.' });
    }
});

// ==========================================
// CART MANAGEMENT ROUTES
// ==========================================

// GET /api/cart - Token: Retrieve all items in the logged-in user's cart
app.get('/api/cart', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT c.id as cart_id, c.quantity, p.id as product_id, p.title, p.price, p.images, p.weight
            FROM cart c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.user_id = ?
        `, [req.user.id]);

        const cartItems = rows.map(item => ({
            ...item,
            images: parseImages(item.images)
        }));

        res.json(cartItems);
    } catch (err) {
        console.error('Fetch cart error:', err);
        res.status(500).json({ error: 'Failed to load cart.' });
    }
});

// POST /api/cart - Token (Buyer): Add product to cart
app.post('/api/cart', authenticateToken, async (req, res) => {
    try {
        const { product_id, productId } = req.body;
        const targetProductId = product_id || productId;

        if (!targetProductId) {
            return res.status(400).json({ error: 'Product ID is required.' });
        }

        const [products] = await db.execute('SELECT id FROM products WHERE id = ?', [targetProductId]);
        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found.' });
        }

        const [existing] = await db.execute(
            'SELECT id, quantity FROM cart WHERE user_id = ? AND product_id = ?', 
            [req.user.id, targetProductId]
        );

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

// DELETE /api/cart/:id - Token: Remove cart item by cart_id
app.delete('/api/cart/:id', authenticateToken, async (req, res) => {
    try {
        const [result] = await db.execute(
            'DELETE FROM cart WHERE id = ? AND user_id = ?', 
            [req.params.id, req.user.id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Cart item not found or unauthorized.' });
        }

        res.json({ message: 'Cart item removed successfully' });
    } catch (err) {
        console.error('Remove cart item error:', err);
        res.status(500).json({ error: 'Failed to remove cart item.' });
    }
});

// ==========================================
// PAY@ PAYMENT & CHECKOUT ROUTES
// ==========================================

// POST /api/payat/checkout - Token (Buyer): Convert cart into order and generate Pay@ reference
app.post('/api/payat/checkout', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        // Fetch user's cart
        const [cartItems] = await db.execute(`
            SELECT c.quantity, p.id as product_id, p.price, p.weight 
            FROM cart c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.user_id = ?
        `, [userId]);

        if (cartItems.length === 0) {
            return res.status(400).json({ error: 'Your cart is empty.' });
        }

        let totalAmount = 0;
        let totalWeight = 0;

        cartItems.forEach(item => {
            totalAmount += parseFloat(item.price) * item.quantity;
            totalWeight += (parseFloat(item.weight) || 0) * item.quantity;
        });

        // Unique Pay@ Reference Generation
        const payatReference = 'PAYAT-' + Math.floor(1000000000 + Math.random() * 9000000000);

        // Store Order
        const [orderResult] = await db.execute(
            `INSERT INTO orders (user_id, payat_reference, total_amount, total_weight, status, payment_status) 
             VALUES (?, ?, ?, ?, 'pending', 'unpaid')`,
            [userId, payatReference, totalAmount, totalWeight]
        );

        // Clear user's cart
        await db.execute('DELETE FROM cart WHERE user_id = ?', [userId]);

        res.status(201).json({
            message: 'Order created successfully',
            order_id: orderResult.insertId,
            payat_reference: payatReference,
            total_amount: totalAmount,
            payment_status: 'unpaid'
        });

    } catch (err) {
        console.error('Checkout error:', err);
        res.status(500).json({ error: 'Pay@ checkout failed.' });
    }
});

// Legacy route alias
app.post('/api/checkout/payat', (req, res) => app._router.handle({ ...req, url: '/api/payat/checkout' }, res));

// POST /api/payat/notification - Public (Webhook): Webhook callback to mark orders as paid
app.post('/api/payat/notification', async (req, res) => {
    try {
        const { payat_reference, reference, status, amount_paid } = req.body;
        const targetRef = payat_reference || reference;

        if (!targetRef) {
            return res.status(400).json({ error: 'Pay@ reference is required.' });
        }

        // Search for matching order
        const [orders] = await db.execute('SELECT id FROM orders WHERE payat_reference = ?', [targetRef]);
        if (orders.length === 0) {
            return res.status(404).json({ error: 'Order reference not found.' });
        }

        const isPaid = (status === 'SUCCESS' || status === 'PAID' || status === '00');
        const newPaymentStatus = isPaid ? 'paid' : 'failed';
        const newOrderStatus = isPaid ? 'processing' : 'pending';

        await db.execute(
            `UPDATE orders SET payment_status = ?, status = ?, updated_at = NOW() WHERE payat_reference = ?`,
            [newPaymentStatus, newOrderStatus, targetRef]
        );

        res.json({ 
            status: 'ACCEPTED', 
            payat_reference: targetRef, 
            payment_status: newPaymentStatus 
        });

    } catch (err) {
        console.error('Pay@ webhook error:', err);
        res.status(500).json({ error: 'Failed to process Pay@ notification.' });
    }
});

// GET /api/payat/status/:reference - Token: Query payment and fulfillment status by Pay@ reference
app.get('/api/payat/status/:reference', authenticateToken, async (req, res) => {
    try {
        const payatRef = req.params.reference;

        const [orders] = await db.execute(
            `SELECT id, payat_reference, total_amount, total_weight, status, payment_status, created_at, updated_at 
             FROM orders 
             WHERE payat_reference = ? AND user_id = ?`,
            [payatRef, req.user.id]
        );

        if (orders.length === 0) {
            return res.status(404).json({ error: 'Order reference not found.' });
        }

        res.json(orders[0]);

    } catch (err) {
        console.error('Status query error:', err);
        res.status(500).json({ error: 'Failed to query order status.' });
    }
});

// ==========================================
// START EXPRESS SERVER
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`WeBuy backend server active on port ${PORT}`);
});