require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Set high body payload limits for base64 image strings (up to 10 images)
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

// Verify Database Connection
db.getConnection()
    .then(conn => {
        console.log('Database connected successfully');
        conn.release();
    })
    .catch(err => {
        console.error('Database connection failed:', err.message);
    });

// ==========================================
// AUTHENTICATION MIDDLEWARES
// ==========================================

// JWT Token Authentication
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

// Seller Guard
const isSeller = (req, res, next) => {
    if (req.user.role !== 'seller') {
        return res.status(403).json({ error: 'Access denied. Seller permissions required.' });
    }
    next();
};

// Buyer Guard
const isBuyer = (req, res, next) => {
    if (req.user.role !== 'buyer' && req.user.role !== 'seller') {
        return res.status(403).json({ error: 'Access denied. Buyer permissions required.' });
    }
    next();
};

// Helper for parsing JSON images safely
const parseImages = (imagesData) => {
    if (!imagesData) return [];
    if (Array.isArray(imagesData)) return imagesData;
    try {
        return typeof imagesData === 'string' ? JSON.parse(imagesData) : [];
    } catch (e) {
        return [imagesData];
    }
};

// ==========================================
// 1. HEALTH CHECK ENDPOINT
// ==========================================

// GET /api/health
app.get('/api/health', async (req, res) => {
    try {
        await db.query('SELECT 1');
        res.status(200).json({
            status: 'operational',
            database: 'connected',
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        res.status(500).json({
            status: 'degraded',
            database: 'disconnected',
            error: err.message
        });
    }
});

// ==========================================
// 2. AUTHENTICATION ENDPOINTS
// ==========================================

// POST /api/auth/register
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

        const [existing] = await db.execute('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
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
            message: 'User account registered successfully',
            userId: result.insertId
        });

    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ error: 'Failed to register account.' });
    }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required.' });
        }

        const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const user = users[0];
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const secret = process.env.JWT_SECRET || 'fallback_secret';
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            secret,
            { expiresIn: '24h' }
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
        res.status(500).json({ error: 'Login failed.' });
    }
});

// ==========================================
// 3. PRODUCT ENDPOINTS
// ==========================================

// GET /api/products
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
            images: parseImages(p.images)
        }));

        res.json(products);
    } catch (err) {
        console.error('Fetch products error:', err);
        res.status(500).json({ error: 'Failed to fetch products.' });
    }
});

// POST /api/products (Seller token required, max 10 images)
app.post('/api/products', authenticateToken, isSeller, async (req, res) => {
    try {
        const { title, name, description, price, weight, images } = req.body;
        const productTitle = title || name;

        if (!productTitle || price === undefined) {
            return res.status(400).json({ error: 'Product title/name and price are required.' });
        }

        let imageList = [];
        if (Array.isArray(images)) {
            imageList = images.slice(0, 10); // Enforce maximum 10 images
        } else if (typeof images === 'string' && images.trim() !== '') {
            imageList = [images];
        }

        const sellerId = req.user.id;
        const [sellerInfo] = await db.execute('SELECT pricing_preference FROM users WHERE id = ?', [sellerId]);
        let finalPrice = parseFloat(price);

        if (sellerInfo.length > 0 && sellerInfo[0].pricing_preference === 'add') {
            finalPrice += 50;
        }

        const [result] = await db.execute(
            `INSERT INTO products (seller_id, title, description, price, weight, images) VALUES (?, ?, ?, ?, ?, ?)`,
            [
                sellerId,
                productTitle,
                description || '',
                finalPrice,
                weight ? parseFloat(weight) : 0.00,
                JSON.stringify(imageList)
            ]
        );

        res.status(201).json({
            message: 'Product created successfully',
            productId: result.insertId
        });

    } catch (err) {
        console.error('Create product error:', err);
        res.status(500).json({ error: 'Failed to create product listing.' });
    }
});

// ==========================================
// 4. CART ENDPOINTS
// ==========================================

// GET /api/cart
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
        res.status(500).json({ error: 'Failed to retrieve cart items.' });
    }
});

// POST /api/cart (Buyer token required)
app.post('/api/cart', authenticateToken, isBuyer, async (req, res) => {
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
            await db.execute(
                'INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, 1)',
                [req.user.id, targetProductId]
            );
        }

        res.json({ message: 'Product added to cart successfully' });

    } catch (err) {
        console.error('Add to cart error:', err);
        res.status(500).json({ error: 'Failed to add product to cart.' });
    }
});

// DELETE /api/cart/:id
app.delete('/api/cart/:id', authenticateToken, async (req, res) => {
    try {
        const [result] = await db.execute(
            'DELETE FROM cart WHERE id = ? AND user_id = ?',
            [req.params.id, req.user.id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Cart item not found or unauthorized.' });
        }

        res.json({ message: 'Item removed from cart' });
    } catch (err) {
        console.error('Delete cart item error:', err);
        res.status(500).json({ error: 'Failed to remove cart item.' });
    }
});

// ==========================================
// 5. PAY@ CHECKOUT & WEBHOOK ENDPOINTS
// ==========================================

// POST /api/payat/checkout (Buyer token)
app.post('/api/payat/checkout', authenticateToken, isBuyer, async (req, res) => {
    try {
        const { full_name, address, city, province, postal_code, phone, payment_option } = req.body;

        // Fetch user's cart items
        const [cartItems] = await db.execute(`
            SELECT c.product_id, c.quantity, p.price 
            FROM cart c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.user_id = ?
        `, [req.user.id]);

        if (cartItems.length === 0) {
            return res.status(400).json({ error: 'Your cart is empty.' });
        }

        // Calculate total price
        let totalAmount = 0;
        cartItems.forEach(item => {
            totalAmount += parseFloat(item.price) * item.quantity;
        });

        // Generate 10-digit Pay@ Reference Number
        const payatReference = 'PAYAT' + Math.floor(10000000 + Math.random() * 90000000);
        const deliveryAddress = `${full_name}, ${address}, ${city}, ${province}, ${postal_code}, Tel: ${phone}`;

        // Store order in database
        const [orderResult] = await db.execute(
            `INSERT INTO orders (payat_reference, user_id, total_amount, status, payment_option, delivery_address) 
            VALUES (?, ?, ?, 'pending', ?, ?)`,
            [payatReference, req.user.id, totalAmount, payment_option || 'Standard Pay@', deliveryAddress]
        );

        const orderId = orderResult.insertId;

        // Insert items into order_items
        for (const item of cartItems) {
            await db.execute(
                `INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)`,
                [orderId, item.product_id, item.quantity, item.price]
            );
        }

        // Clear user's cart
        await db.execute('DELETE FROM cart WHERE user_id = ?', [req.user.id]);

        res.status(201).json({
            message: 'Order created successfully',
            payat_reference: payatReference,
            total_amount: totalAmount,
            status: 'pending'
        });

    } catch (err) {
        console.error('Checkout error:', err);
        res.status(500).json({ error: 'Failed to process checkout.' });
    }
});

// POST /api/payat/notification (Public Webhook)
app.post('/api/payat/notification', async (req, res) => {
    try {
        const { payat_reference, reference, status, transaction_id } = req.body;
        const targetRef = payat_reference || reference;

        if (!targetRef) {
            return res.status(400).json({ error: 'Missing Pay@ reference number.' });
        }

        const paymentStatus = (status && status.toLowerCase() === 'success') ? 'paid' : 'failed';

        const [result] = await db.execute(
            'UPDATE orders SET status = ?, updated_at = NOW() WHERE payat_reference = ?',
            [paymentStatus, targetRef]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Order reference not found.' });
        }

        res.status(200).json({
            status: 'received',
            payat_reference: targetRef,
            order_status: paymentStatus
        });

    } catch (err) {
        console.error('Pay@ Webhook error:', err);
        res.status(500).json({ error: 'Webhook processing error.' });
    }
});

// GET /api/payat/status/:reference
app.get('/api/payat/status/:reference', authenticateToken, async (req, res) => {
    try {
        const { reference } = req.params;

        const [orders] = await db.execute(`
            SELECT o.id, o.payat_reference, o.total_amount, o.status, o.payment_option, o.created_at, o.delivery_address 
            FROM orders o 
            WHERE o.payat_reference = ? AND o.user_id = ?
        `, [reference, req.user.id]);

        if (orders.length === 0) {
            return res.status(404).json({ error: 'Order reference not found.' });
        }

        const order = orders[0];

        const [items] = await db.execute(`
            SELECT oi.quantity, oi.price, p.title, p.images 
            FROM order_items oi 
            JOIN products p ON oi.product_id = p.id 
            WHERE oi.order_id = ?
        `, [order.id]);

        const formattedItems = items.map(item => ({
            ...item,
            images: parseImages(item.images)
        }));

        res.json({
            order: order,
            items: formattedItems
        }));

    } catch (err) {
        console.error('Fetch order status error:', err);
        res.status(500).json({ error: 'Failed to retrieve payment status.' });
    }
});

// Fallback Route Handler
app.use((req, res) => {
    res.status(404).json({ error: `Cannot ${req.method} ${req.url}` });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is active and listening on port ${PORT}`);
});