require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();

// Enable CORS for external frontend domains
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body payload limit set to 50MB for image and document uploads
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Database Connection Pool
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'webuy',
    port: process.env.DB_PORT || 4000,
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: false
    },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const JWT_SECRET = process.env.JWT_SECRET || 'webuy_secret_key_2026';
const PAYAT_SYSTEM_ID = process.env.PAYAT_SYSTEM_ID || 'WEBUY001';

// Email Transporter Configuration (SMTP)
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// Helper function to send email notification to seller
async function sendSellerPaymentNotification(payatReference) {
    try {
        const [rows] = await db.query(`
            SELECT 
                o.id AS order_id,
                o.payment_ref,
                o.total_amount,
                o.full_name AS buyer_name,
                o.company_name AS buyer_company,
                o.address AS buyer_address,
                o.city AS buyer_city,
                o.province AS buyer_province,
                o.postal_code AS buyer_postal,
                o.phone_number AS buyer_phone,
                oi.quantity,
                oi.price AS item_price,
                p.title AS product_title,
                u.email AS seller_email,
                u.name AS seller_name
            FROM orders o
            JOIN order_items oi ON o.id = oi.order_id
            JOIN products p ON oi.product_id = p.id
            JOIN users u ON p.seller_id = u.id
            WHERE o.payment_ref = ?
        `, [payatReference]);

        if (rows.length === 0) return;

        const sellerMap = {};
        for (let row of rows) {
            if (!sellerMap[row.seller_email]) {
                sellerMap[row.seller_email] = {
                    sellerName: row.seller_name,
                    buyerName: row.buyer_name,
                    buyerCompany: row.buyer_company,
                    buyerAddress: `${row.buyer_address}, ${row.buyer_city}, ${row.buyer_province}, ${row.buyer_postal}`,
                    buyerPhone: row.buyer_phone,
                    paymentRef: row.payment_ref,
                    items: []
                };
            }
            sellerMap[row.seller_email].items.push({
                title: row.product_title,
                quantity: row.quantity,
                price: parseFloat(row.item_price).toFixed(2)
            });
        }

        for (let sellerEmail in sellerMap) {
            const data = sellerMap[sellerEmail];
            
            let itemsHtml = data.items.map(item => 
                `<li><strong>${item.title}</strong> - Quantity: ${item.quantity} @ R ${item.price} each</li>`
            ).join('');

            const mailOptions = {
                from: `"WeBuy Marketplace" <${process.env.SMTP_USER || 'no-reply@webuy.co.za'}>`,
                to: sellerEmail,
                subject: `Order Confirmed & Paid - Pay@ Ref: ${data.paymentRef}`,
                html: `
                    <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                        <h2 style="color: #0b55b2;">Good news, ${data.sellerName}!</h2>
                        <p>Your item(s) listed on <strong>WeBuy</strong> have been ordered and payment has been confirmed.</p>
                        
                        <div style="background: #eef7e8; border: 1px solid #68b819; padding: 15px; border-radius: 6px; margin: 15px 0;">
                            <h3 style="margin-top: 0; color: #68b819;">Payment Information</h3>
                            <p><strong>Pay@ Reference:</strong> <span style="font-size: 1.2em; color: #0b55b2;">${data.paymentRef}</span></p>
                            <p><strong>Payment Status:</strong> Paid / Confirmed</p>
                        </div>

                        <h3>Ordered Items</h3>
                        <ul>${itemsHtml}</ul>

                        <h3>Delivery Details</h3>
                        <p><strong>Recipient:</strong> ${data.buyerName} ${data.buyerCompany ? `(${data.buyerCompany})` : ''}</p>
                        <p><strong>Address:</strong> ${data.buyerAddress}</p>
                        <p><strong>Contact Phone:</strong> ${data.buyerPhone}</p>

                        <hr style="border: none; border-top: 1px solid #ccc; margin: 20px 0;">
                        <p style="font-size: 0.85em; color: #777;">Please prepare the package for delivery. Thank you for selling on WeBuy!</p>
                    </div>
                `
            };

            await transporter.sendMail(mailOptions);
            console.log(`Notification email sent to seller: ${sellerEmail}`);
        }
    } catch (err) {
        console.error('FAILED TO SEND SELLER EMAIL:', err.message);
    }
}

// Automatically create and migrate database tables
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
                business_cert LONGTEXT,
                needs_platform_delivery BOOLEAN DEFAULT FALSE,
                tc_accepted BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Migration safety for legacy user tables
        const userMigrations = [
            'ALTER TABLE users ADD COLUMN business_cert LONGTEXT;',
            'ALTER TABLE users ADD COLUMN needs_platform_delivery BOOLEAN DEFAULT FALSE;',
            'ALTER TABLE users ADD COLUMN tc_accepted BOOLEAN DEFAULT FALSE;'
        ];
        for (let query of userMigrations) {
            try { await conn.query(query); } catch (e) {}
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

        try {
            await conn.query(`ALTER TABLE product_images MODIFY image_url LONGTEXT;`);
        } catch (e) {}

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

        const deliveryColumns = [
            'ALTER TABLE orders ADD COLUMN full_name VARCHAR(255);',
            'ALTER TABLE orders ADD COLUMN company_name VARCHAR(255);',
            'ALTER TABLE orders ADD COLUMN address TEXT;',
            'ALTER TABLE orders ADD COLUMN city VARCHAR(100);',
            'ALTER TABLE orders ADD COLUMN province VARCHAR(100);',
            'ALTER TABLE orders ADD COLUMN postal_code VARCHAR(20);',
            'ALTER TABLE orders ADD COLUMN phone_number VARCHAR(50);'
        ];

        for (let colQuery of deliveryColumns) {
            try { await conn.query(colQuery); } catch (e) {}
        }

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
        console.log('Database tables and schema verified.');
    } catch (err) {
        console.error('DATABASE INIT ERROR:', err.message);
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

// --- AUTHENTICATION ENDPOINTS ---

app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'WeBuy API operational.' });
});

// Platform Terms & Pricing Info
app.get('/api/terms', (req, res) => {
    res.json({
        deliveryFeePerKg: 400.00,
        adFeePerProductSold: 50.00,
        termsText: "All sellers agree to a platform advertising fee of R50 per product sold. If platform-handled delivery is requested, a rate of R400 per KG applies."
    });
});

app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role, business_cert, needs_platform_delivery, tc_accepted } = req.body;

    if (!name || !email || !password || !role) {
        return res.status(400).json({ error: 'All primary fields are required.' });
    }

    const normalizedRole = role.toLowerCase();

    if (normalizedRole === 'seller') {
        if (!business_cert) {
            return res.status(400).json({ error: 'Business registration certificate is required for sellers.' });
        }
        if (!tc_accepted) {
            return res.status(400).json({ error: 'Sellers must accept the Terms and Conditions (R50 ad fee per product sold & delivery terms).' });
        }
    }

    try {
        const [existing] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email already registered.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const deliveryPref = needs_platform_delivery ? true : false;
        const acceptedTC = tc_accepted ? true : false;
        const certData = normalizedRole === 'seller' ? business_cert : null;

        const [result] = await db.query(
            'INSERT INTO users (name, email, password, role, business_cert, needs_platform_delivery, tc_accepted) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [name, email, hashedPassword, normalizedRole, certData, deliveryPref, acceptedTC]
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
            return res.status(400).json({ error: 'Invalid credentials.' });
        }

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid credentials.' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, name: user.name },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: { 
                id: user.id, 
                name: user.name, 
                email: user.email, 
                role: user.role,
                needs_platform_delivery: Boolean(user.needs_platform_delivery)
            }
        });
    } catch (err) {
        console.error('LOGIN ERROR:', err);
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

// --- MARKETPLACE & PRODUCT ENDPOINTS ---

// Fetch products with optional search query filter (?q=keyword)
app.get('/api/products', async (req, res) => {
    const searchQuery = req.query.q;
    try {
        let queryStr = `
            SELECT p.id, p.title, p.description, p.price, p.created_at, u.name AS seller_name, u.needs_platform_delivery
            FROM products p 
            JOIN users u ON p.seller_id = u.id 
        `;
        let params = [];

        if (searchQuery && searchQuery.trim() !== '') {
            queryStr += ` WHERE p.title LIKE ? OR p.description LIKE ?`;
            const term = `%${searchQuery.trim()}%`;
            params.push(term, term);
        }

        queryStr += ` ORDER BY p.created_at DESC`;

        const [products] = await db.query(queryStr, params);

        for (let p of products) {
            const [imgs] = await db.query('SELECT image_url FROM product_images WHERE product_id = ?', [p.id]);
            p.images = imgs.map(i => i.image_url);
            if (p.images.length === 0) p.images = ['logo.jpg'];
        }

        res.json(products);
    } catch (err) {
        console.error('PRODUCTS FETCH ERROR:', err);
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        const [products] = await db.query(`
            SELECT p.id, p.title, p.description, p.price, p.created_at, u.name AS seller_name, u.needs_platform_delivery
            FROM products p 
            JOIN users u ON p.seller_id = u.id 
            WHERE p.id = ?
        `, [req.params.id]);

        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found.' });
        }

        const product = products[0];
        const [imgs] = await db.query('SELECT image_url FROM product_images WHERE product_id = ?', [product.id]);
        product.images = imgs.map(i => i.image_url);
        if (product.images.length === 0) product.images = ['logo.jpg'];

        res.json(product);
    } catch (err) {
        console.error('FETCH SINGLE PRODUCT ERROR:', err);
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

app.post('/api/products', authenticateToken, async (req, res) => {
    if (req.user.role !== 'seller') {
        return res.status(403).json({ error: 'Only sellers can list products.' });
    }

    const { title, description, price, images } = req.body;

    if (!title || !price) {
        return res.status(400).json({ error: 'Title and price are required.' });
    }

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
        console.error('CREATE PRODUCT ERROR:', err);
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
        console.error('FETCH CART ERROR:', err);
        res.status(500).json({ error: 'Cart fetch error', details: err.message });
    }
});

app.post('/api/cart', authenticateToken, async (req, res) => {
    if (req.user.role !== 'buyer') {
        return res.status(403).json({ error: 'Only buyers can add items to cart.' });
    }

    const { product_id } = req.body;

    try {
        const [existing] = await db.query(
            'SELECT id, quantity FROM cart_items WHERE buyer_id = ? AND product_id = ?',
            [req.user.id, product_id]
        );

        if (existing.length > 0) {
            await db.query('UPDATE cart_items SET quantity = quantity + 1 WHERE id = ?', [existing[0].id]);
        } else {
            await db.query('INSERT INTO cart_items (buyer_id, product_id, quantity) VALUES (?, ?, 1)', [req.user.id, product_id]);
        }

        res.json({ message: 'Item added to cart' });
    } catch (err) {
        console.error('ADD CART ERROR:', err);
        res.status(500).json({ error: 'Cart operation error', details: err.message });
    }
});

app.delete('/api/cart/:id', authenticateToken, async (req, res) => {
    try {
        await db.query('DELETE FROM cart_items WHERE id = ? AND buyer_id = ?', [req.params.id, req.user.id]);
        res.json({ message: 'Item removed from cart' });
    } catch (err) {
        console.error('REMOVE CART ERROR:', err);
        res.status(500).json({ error: 'Remove error', details: err.message });
    }
});

// --- CHECKOUT & PAY@ PAYMENT ENDPOINTS ---

app.post('/api/payat/checkout', authenticateToken, async (req, res) => {
    if (req.user.role !== 'buyer') {
        return res.status(403).json({ error: 'Only buyers can perform checkout.' });
    }

    const { payment_method, full_name, company_name, address, city, province, postal_code, phone_number } = req.body;

    if (!full_name || !address || !city || !province || !postal_code || !phone_number) {
        return res.status(400).json({ error: 'Please provide all required delivery details.' });
    }

    try {
        const [cartItems] = await db.query(`
            SELECT c.product_id, c.quantity, p.price 
            FROM cart_items c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.buyer_id = ?
        `, [req.user.id]);

        if (cartItems.length === 0) {
            return res.status(400).json({ error: 'Your cart is empty.' });
        }

        let totalAmount = cartItems.reduce((sum, item) => sum + (parseFloat(item.price) * item.quantity), 0);
        const payatRef = `10101${Date.now().toString().slice(-6)}${Math.floor(10 + Math.random() * 90)}`;

        const [orderRes] = await db.query(
            `INSERT INTO orders 
            (buyer_id, total_amount, status, payment_ref, payment_status, payment_method, full_name, company_name, address, city, province, postal_code, phone_number) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                req.user.id,
                totalAmount,
                'pending',
                payatRef,
                'unpaid',
                payment_method || 'retail_store',
                full_name,
                company_name || null,
                address,
                city,
                province,
                postal_code,
                phone_number
            ]
        );
        const orderId = orderRes.insertId;

        for (let item of cartItems) {
            await db.query(
                'INSERT INTO order_items (order_id, product_id, price, quantity) VALUES (?, ?, ?, ?)',
                [orderId, item.product_id, item.price, item.quantity]
            );
        }

        await db.query('DELETE FROM cart_items WHERE buyer_id = ?', [req.user.id]);

        res.status(201).json({
            message: 'Order and Pay@ Payment reference generated successfully',
            orderId,
            payatReference: payatRef,
            totalAmount: totalAmount.toFixed(2),
            paymentUrl: `https://payat.io/pay/${payatRef}?amount=${totalAmount.toFixed(2)}&sys=${PAYAT_SYSTEM_ID}`
        });
    } catch (err) {
        console.error('CHECKOUT ERROR:', err);
        res.status(500).json({ error: 'Checkout failed', details: err.message });
    }
});

// Pay@ Webhook Notification Endpoint (Triggers Seller Email)
app.post('/api/payat/notification', async (req, res) => {
    const { payat_reference, status } = req.body;

    try {
        if (status === 'PAID' || status === 'SUCCESS') {
            await db.query(
                'UPDATE orders SET status = ?, payment_status = ? WHERE payment_ref = ?',
                ['completed', 'paid', payat_reference]
            );
            console.log(`Pay@ Payment confirmed for reference: ${payat_reference}`);

            await sendSellerPaymentNotification(payat_reference);
        }

        res.status(200).json({ response: 'OK', reference: payat_reference });
    } catch (err) {
        console.error('PAYAT NOTIFICATION ERROR:', err);
        res.status(500).json({ error: 'Webhook processing error' });
    }
});

app.get('/api/payat/status/:reference', authenticateToken, async (req, res) => {
    try {
        const [orders] = await db.query(
            'SELECT id, total_amount, status, payment_status, payment_ref, full_name, city FROM orders WHERE payment_ref = ?',
            [req.params.reference]
        );

        if (orders.length === 0) return res.status(404).json({ error: 'Order reference not found' });

        res.json(orders[0]);
    } catch (err) {
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

// --- RETURN POLICY ENDPOINT ---

app.get('/api/return-policy', (req, res) => {
    res.json({
        title: "WeBuy Return & Refund Policy",
        effectiveDate: "2026-01-01",
        policy: [
            "1. Standard Return Window: Buyers may request a return within 7 calendar days of receipt of the item.",
            "2. Condition Requirements: Items must be returned in their original condition, unused, and with all original packaging.",
            "3. Delivery Costs for Returns: If an item is defective or incorrect, WeBuy will handle return shipping fees. For change-of-mind returns, the buyer is responsible for return transport costs.",
            "4. Platform & Ad Fees: Seller advertising charges (R50 per item sold) are non-refundable once an order is processed.",
            "5. Processing Time: Refunds will be issued back via original payment methods or EFT within 3-5 business days of item inspection."
        ]
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`WeBuy API running on port ${PORT}`));