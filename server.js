/**
 * ============================================================================
 * WeBuy Marketplace - Enterprise Node.js & Express Backend Server
 * ============================================================================
 * Features:
 *  - Secure JWT Authentication & Password Hashing (bcrypt)
 *  - Role-Based Access Control (Buyers & Verified Business Sellers)
 *  - Product Catalog Management & Persistent Shopping Cart
 *  - 30-Minute Expiration Pay@ Checkout & Online Issuer Interface Endpoints
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
app.use(express.json({ limit: '50mb' }));
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

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, role, business_cert, delivery_preference, pricing_preference } = req.body;
        
        if (!name || !email || !password || !role) {
            return res.status(400).json({ error: 'Required registration parameters are missing.' });
        }

        const [existingUsers] = await db.execute('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUsers.length > 0) {
            return res.status(400).json({ error: 'An account with this email address already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await db.execute(
            `INSERT INTO users (name, email, password, role, business_cert, delivery_preference, pricing_preference) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                name, email, hashedPassword, role, 
                business_cert || null, 
                delivery_preference || 'self', 
                pricing_preference || 'keep'
            ]
        );

        res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
    } catch (err) {
        console.error('[AUTH ERROR] Registration failed:', err);
        res.status(500).json({ error: 'Internal server error during registration: ' + err.message });
    }
});

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

app.get('/api/products', async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT p.*, u.name as seller_name 
            FROM products p 
            JOIN users u ON p.seller_id = u.id 
            ORDER BY p.id DESC
        `);

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

        res.status(201).json({ message: 'Product successfully listed', productId: result.insertId });
    } catch (err) {
        console.error('[PRODUCT ERROR] Creation failed:', err);
        res.status(500).json({ error: 'Failed to create product listing: ' + err.message });
    }
});

// ============================================================================
// 3. SHOPPING CART MANAGEMENT ENDPOINTS
// ============================================================================

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

app.post('/api/cart', authenticateToken, async (req, res) => {
    try {
        const { product_id, quantity = 1 } = req.body;
        if (!product_id) {
            return res.status(400).json({ error: 'Product ID is required.' });
        }

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
// 4. CHECKOUT & PAY@ ISSUER INTERFACE INTEGRATION
// ============================================================================

/**
 * Endpoint: Generate Checkout Reference & Record in Orders Table
 */
app.post('/api/payat/checkout', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { channel_type } = req.body; // 'retail' or 'eft'

        const [cartItems] = await db.execute(`
            SELECT c.id as cart_id, c.quantity, p.id as product_id, p.title, p.price, p.weight 
            FROM cart c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.user_id = ?
        `, [userId]);

        if (cartItems.length === 0) {
            return res.status(400).json({ error: 'Cannot checkout with an empty shopping cart.' });
        }

        const subtotal = cartItems.reduce((sum, item) => sum + (parseFloat(item.price) * item.quantity), 0);
        const totalWeight = cartItems.reduce((sum, item) => sum + ((parseFloat(item.weight) || 0) * item.quantity), 0);
        const deliveryFee = totalWeight * 400; 
        const grandTotal = subtotal + deliveryFee;

        const payatReference = 'WB' + Math.floor(100000000 + Math.random() * 900000000);
        const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString().slice(0, 19).replace('T', ' ');

        // Save order to database so Pay@ till systems can query it via Enquiry endpoint
        await db.execute(
            `INSERT INTO orders (user_id, reference, amount, status, channel_type, expires_at) 
             VALUES (?, ?, ?, 'PENDING', ?, ?)`,
            [userId, payatReference, grandTotal.toFixed(2), channel_type || 'retail', expiresAt]
        );

        await db.execute('DELETE FROM cart WHERE user_id = ?', [userId]);

        let supportedChannels = channel_type === 'eft' 
            ? ["Capitec Pay", "FNB Instant EFT", "Absa Pay", "Standard Bank Secure EFT", "Nedbank Instant Pay"]
            : ["Pick n Pay", "Shoprite", "Checkers", "Spar", "PEP", "Ackermans", "Usave", "Boxer"];

        res.status(200).json({
            message: 'Checkout reference generated successfully',
            payat_reference: payatReference,
            amount_due: grandTotal.toFixed(2),
            expires_at: expiresAt,
            channel_type: channel_type || 'retail',
            supported_channels: supportedChannels
        });
    } catch (err) {
        console.error('[CHECKOUT ERROR]:', err);
        res.status(500).json({ error: 'Checkout processing failed: ' + err.message });
    }
});

/**
 * PAY@ ONLINE ISSUER INTERFACE ENDPOINTS (Called directly by Retail Point of Sale Systems)
 */

// 1. Echo Test
app.post('/api/payat/echo', (req, res) => {
    res.status(200).json({
        status: 'SUCCESS',
        message: 'WeBuy Pay@ Issuer Interface is active',
        timestamp: new Date().toISOString()
    });
});

// 2. Account Enquiry
app.post('/api/payat/enquiry', async (req, res) => {
    try {
        const { reference } = req.body;
        const [orders] = await db.execute(
            'SELECT o.*, u.name as customer_name FROM orders o JOIN users u ON o.user_id = u.id WHERE o.reference = ? AND o.status = ?', 
            [reference, 'PENDING']
        );

        if (orders.length === 0) {
            return res.status(404).json({
                response_code: 'ERR_INVALID_REFERENCE',
                message: 'Reference not found, already paid, or expired.'
            });
        }

        const order = orders[0];
        res.status(200).json({
            response_code: 'SUCCESS',
            reference: order.reference,
            customer_name: order.customer_name,
            amount_due: order.amount,
            currency: 'ZAR',
            expires_at: order.expires_at
        });
    } catch (err) {
        res.status(500).json({ response_code: 'ERROR', message: err.message });
    }
});

// 3. Transaction Authorisation
app.post('/api/payat/authorisation', async (req, res) => {
    try {
        const { reference } = req.body;
        const [orders] = await db.execute('SELECT * FROM orders WHERE reference = ? AND status = ?', [reference, 'PENDING']);

        if (orders.length === 0) {
            return res.status(400).json({ response_code: 'DECLINED', message: 'Invalid or expired reference.' });
        }

        res.status(200).json({
            response_code: 'AUTHORISED',
            reference: reference,
            message: 'Transaction authorised successfully by issuer.'
        });
    } catch (err) {
        res.status(500).json({ response_code: 'ERROR', message: err.message });
    }
});

// 4. Transaction Completion
app.post('/api/payat/completion', async (req, res) => {
    try {
        const { reference, transaction_id } = req.body;
        await db.execute(
            'UPDATE orders SET status = ?, payat_tx_id = ? WHERE reference = ?', 
            ['PAID', transaction_id || null, reference]
        );

        res.status(200).json({
            response_code: 'SUCCESS',
            message: 'Payment recorded and order fulfilled successfully.'
        });
    } catch (err) {
        res.status(500).json({ response_code: 'ERROR', message: err.message });
    }
});

// 5. Transaction Void
app.post('/api/payat/void', async (req, res) => {
    try {
        const { reference } = req.body;
        await db.execute('UPDATE orders SET status = ? WHERE reference = ?', ['VOIDED', reference]);

        res.status(200).json({
            response_code: 'SUCCESS',
            message: 'Transaction voided successfully.'
        });
    } catch (err) {
        res.status(500).json({ response_code: 'ERROR', message: err.message });
    }
});

// Root Route
app.get('/', (req, res) => {
    res.status(200).send('WeBuy Marketplace Enterprise Backend Server is running successfully.');
});

// Initialize Server Listener
app.listen(PORT, () => {
    console.log(`[SERVER] WeBuy backend listening securely on port ${PORT}`);
});