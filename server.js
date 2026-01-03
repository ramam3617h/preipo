// ============================================
// ENHANCED SERVER.JS with Security & Validation
// ============================================
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const { body, validationResult } = require('express-validator');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const nodemailer = require('nodemailer');
const twilio = require('twilio');
require('dotenv').config();

const app = express();

// ============================================
// MIDDLEWARE & SECURITY
// ============================================

// Security headers
app.use(helmet());

// CORS
//app.use(cors({
 // origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  //credentials: true
// }));

//const allowedOrigins = ['https://market.vrksatechnology.com','https://eshushop.com','https://www.eshushop.com','localhost:3000>
// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  //  orgin: allowedOrigins || '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE','OPTION'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));



// Body parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // limit each IP to 5 login attempts per 15 minutes
  message: 'Too many login attempts, please try again later.'
});

app.use('/api/', limiter);
app.use('/api/auth/login', authLimiter);

// ============================================
// DATABASE POOL
// ============================================
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'preipo_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
});

// ============================================
// RAZORPAY CONFIGURATION
// ============================================
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// ============================================
// EMAIL TRANSPORTER
// ============================================
const emailTransporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// ============================================
// TWILIO CLIENT
// ============================================
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// ============================================
// VALIDATION MIDDLEWARE
// ============================================
const validate = (validations) => {
  return async (req, res, next) => {
    await Promise.all(validations.map(validation => validation.run(req)));

    const errors = validationResult(req);
    if (errors.isEmpty()) {
      return next();
    }

    res.status(400).json({ 
      success: false,
      errors: errors.array().map(err => ({
        field: err.param,
        message: err.msg
      }))
    });
  };
};

// ============================================
// AUTH MIDDLEWARE
// ============================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }
  next();
};

// ============================================
// NOTIFICATION SERVICES
// ============================================
const sendEmail = async (to, subject, html) => {
  try {
    const info = await emailTransporter.sendMail({
      from: process.env.SMTP_FROM,
      to,
      subject,
      html
    });
    console.log('Email sent:', info.messageId);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('Email error:', error);
    return { success: false, error: error.message };
  }
};

const sendSMS = async (to, message) => {
  try {
    const result = await twilioClient.messages.create({
      from: process.env.TWILIO_PHONE_NUMBER,
      to,
      body: message
    });
    console.log('SMS sent:', result.sid);
    return { success: true, sid: result.sid };
  } catch (error) {
    console.error('SMS error:', error);
    return { success: false, error: error.message };
  }
};

const sendWhatsApp = async (to, message) => {
  try {
    const result = await twilioClient.messages.create({
      from: `whatsapp:${process.env.TWILIO_WHATSAPP_NUMBER}`,
      to: `whatsapp:${to}`,
      body: message
    });
    console.log('WhatsApp sent:', result.sid);
    return { success: true, sid: result.sid };
  } catch (error) {
    console.error('WhatsApp error:', error);
    return { success: false, error: error.message };
  }
};

// ============================================
// COMPREHENSIVE NOTIFICATION FUNCTION
// ============================================
const sendBookingNotifications = async (user, booking, share) => {
  const notifications = [];

  // Email notification
  const emailHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .details { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .detail-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }
        .detail-label { font-weight: bold; color: #667eea; }
        .footer { text-align: center; color: #999; padding: 20px; font-size: 12px; }
        .button { display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🎉 Booking Confirmed!</h1>
        </div>
        <div class="content">
          <p>Dear ${user.name},</p>
          <p>Congratulations! Your booking has been confirmed successfully.</p>
          
          <div class="details">
            <h3>Booking Details:</h3>
            <div class="detail-row">
              <span class="detail-label">Booking ID:</span>
              <span>#${booking.id}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Company:</span>
              <span>${share.company}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Sector:</span>
              <span>${share.sector}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Number of Shares:</span>
              <span>${booking.quantity}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Price per Share:</span>
              <span>$${share.price}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Total Amount:</span>
              <span><strong>$${booking.total_amount}</strong></span>
            </div>
          </div>
          
          <p>Your investment is secure and will be processed according to our terms.</p>
          
          <center>
            <a href="${process.env.FRONTEND_URL}/bookings" class="button">View My Bookings</a>
          </center>
        </div>
        <div class="footer">
          <p>© 2026 PreIPO Market. All rights reserved.</p>
          <p>This is an automated email. Please do not reply.</p>
        </div>
      </div>
    </body>
    </html>
  `;

  notifications.push(
    sendEmail(user.email, 'Booking Confirmation - PreIPO Market', emailHtml)
  );

  // SMS notification
  if (user.phone) {
    const smsMessage = `PreIPO Market: Booking confirmed! ${share.company} - ${booking.quantity} shares for $${booking.total_amount}. Booking ID: #${booking.id}`;
    notifications.push(sendSMS(user.phone, smsMessage));
  }

  // WhatsApp notification
  if (user.phone) {
    const whatsappMessage = `🎉 *Booking Confirmed!*\n\n*Company:* ${share.company}\n*Shares:* ${booking.quantity}\n*Price per Share:* $${share.price}\n*Total Amount:* $${booking.total_amount}\n\n*Booking ID:* #${booking.id}\n\nThank you for choosing PreIPO Market!\n\nView details: ${process.env.FRONTEND_URL}/bookings`;
    notifications.push(sendWhatsApp(user.phone, whatsappMessage));
  }

  const results = await Promise.allSettled(notifications);
  return results;
};

// ============================================
// AUTH ROUTES
// ============================================

// Register
app.post('/api/auth/register', 
  validate([
    body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
    body('email').isEmail().normalizeEmail().withMessage('Invalid email address'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('phone').optional().isMobilePhone().withMessage('Invalid phone number')
  ]),
  async (req, res) => {
    try {
      const { name, email, password, phone } = req.body;

      // Check if user exists
      const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
      if (existing.length > 0) {
        return res.status(400).json({ success: false, error: 'Email already registered' });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert user
      const [result] = await pool.query(
        'INSERT INTO users (name, email, password, phone, role) VALUES (?, ?, ?, ?, ?)',
        [name, email, hashedPassword, phone || null, 'customer']
      );

      // Generate token
      const token = jwt.sign(
        { id: result.insertId, email, role: 'customer' },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      // Send welcome email (non-blocking)
      sendEmail(
        email,
        'Welcome to PreIPO Market',
        `<h2>Welcome ${name}!</h2><p>Your account has been created successfully. Start exploring pre-IPO investment opportunities today!</p>`
      ).catch(err => console.error('Welcome email failed:', err));

      res.status(201).json({
        success: true,
        token,
        user: { 
          id: result.insertId, 
          name, 
          email, 
          phone: phone || null,
          role: 'customer' 
        }
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ success: false, error: 'Registration failed. Please try again.' });
    }
  }
);

// Login
app.post('/api/auth/login',
  validate([
    body('email').isEmail().normalizeEmail().withMessage('Invalid email address'),
    body('password').notEmpty().withMessage('Password is required')
  ]),
  async (req, res) => {
    try {
      const { email, password } = req.body;

      const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
      if (users.length === 0) {
        return res.status(401).json({ success: false, error: 'Invalid email or password' });
      }

      const user = users[0];
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        return res.status(401).json({ success: false, error: 'Invalid email or password' });
      }

      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        success: true,
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          phone: user.phone,
          role: user.role
        }
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ success: false, error: 'Login failed. Please try again.' });
    }
  }
);

// ============================================
// SHARES ROUTES
// ============================================

// Get all shares with filters
app.get('/api/shares', async (req, res) => {
  try {
    const { sector, search, status = 'available', limit = 50, offset = 0 } = req.query;
    
    let query = 'SELECT * FROM shares WHERE 1=1';
    const params = [];

    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }

    if (sector && sector !== 'all') {
      query += ' AND sector = ?';
      params.push(sector);
    }

    if (search) {
      query += ' AND company LIKE ?';
      params.push(`%${search}%`);
    }

    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    const [shares] = await pool.query(query, params);
    
    // Get total count
    const [countResult] = await pool.query('SELECT COUNT(*) as total FROM shares WHERE status = ?', [status]);
    
    res.json({
      success: true,
      data: shares,
      total: countResult[0].total,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
  } catch (error) {
    console.error('Fetch shares error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch shares' });
  }
});

// Get single share
app.get('/api/shares/:id', async (req, res) => {
  try {
    const [shares] = await pool.query('SELECT * FROM shares WHERE id = ?', [req.params.id]);
    if (shares.length === 0) {
      return res.status(404).json({ success: false, error: 'Share not found' });
    }
    res.json({ success: true, data: shares[0] });
  } catch (error) {
    console.error('Fetch share error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch share details' });
  }
});

// Add new share (Admin only)
app.post('/api/shares',
  authenticateToken,
  isAdmin,
  validate([
    body('company').trim().isLength({ min: 2 }).withMessage('Company name is required'),
    body('sector').trim().notEmpty().withMessage('Sector is required'),
    body('price').isFloat({ min: 0.01 }).withMessage('Valid price is required'),
    body('available_quantity').isInt({ min: 1 }).withMessage('Valid quantity is required'),
    body('min_order').isInt({ min: 1 }).withMessage('Valid minimum order is required')
  ]),
  async (req, res) => {
    try {
      const { company, sector, price, available_quantity, min_order, valuation, founded, description } = req.body;

      const [result] = await pool.query(
        `INSERT INTO shares (company, sector, price, available_quantity, min_order, valuation, founded, description, status) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'available')`,
        [company, sector, price, available_quantity, min_order, valuation || null, founded || null, description || null]
      );

      res.status(201).json({ success: true, id: result.insertId, message: 'Share added successfully' });
    } catch (error) {
      console.error('Add share error:', error);
      res.status(500).json({ success: false, error: 'Failed to add share' });
    }
  }
);

// Update share (Admin only)
app.put('/api/shares/:id',
  authenticateToken,
  isAdmin,
  validate([
    body('company').optional().trim().isLength({ min: 2 }),
    body('price').optional().isFloat({ min: 0.01 }),
    body('available_quantity').optional().isInt({ min: 0 }),
    body('status').optional().isIn(['available', 'limited', 'closed'])
  ]),
  async (req, res) => {
    try {
      const updates = req.body;
      const fields = Object.keys(updates).map(key => `${key} = ?`).join(', ');
      const values = [...Object.values(updates), req.params.id];

      await pool.query(`UPDATE shares SET ${fields} WHERE id = ?`, values);

      res.json({ success: true, message: 'Share updated successfully' });
    } catch (error) {
      console.error('Update share error:', error);
      res.status(500).json({ success: false, error: 'Failed to update share' });
    }
  }
);

// ============================================
// PAYMENT ROUTES (Razorpay)
// ============================================

// Create Razorpay order
app.post('/api/payment/create-order',
  authenticateToken,
  validate([
    body('amount').isFloat({ min: 1 }).withMessage('Valid amount required'),
    body('bookingId').isInt().withMessage('Valid booking ID required')
  ]),
  async (req, res) => {
    try {
      const { amount, bookingId } = req.body;

      // Verify booking belongs to user
      const [bookings] = await pool.query(
        'SELECT * FROM bookings WHERE id = ? AND user_id = ?',
        [bookingId, req.user.id]
      );

      if (bookings.length === 0) {
        return res.status(404).json({ success: false, error: 'Booking not found' });
      }

      const options = {
        amount: Math.round(amount * 100), // Convert to paise
        currency: 'INR',
        receipt: `booking_${bookingId}_${Date.now()}`,
        notes: {
          bookingId,
          userId: req.user.id
        }
      };

      const order = await razorpay.orders.create(options);
      
      // Save transaction
      await pool.query(
        'INSERT INTO transactions (booking_id, order_id, amount, currency, status) VALUES (?, ?, ?, ?, ?)',
        [bookingId, order.id, amount, 'INR', 'created']
      );

      res.json({ success: true, order });
    } catch (error) {
      console.error('Create order error:', error);
      res.status(500).json({ success: false, error: 'Failed to create payment order' });
    }
  }
);

// Verify Razorpay payment
app.post('/api/payment/verify',
  authenticateToken,
  validate([
    body('razorpay_order_id').notEmpty(),
    body('razorpay_payment_id').notEmpty(),
    body('razorpay_signature').notEmpty(),
    body('bookingId').isInt()
  ]),
  async (req, res) => {
    try {
      const crypto = require('crypto');
      const { razorpay_order_id, razorpay_payment_id, razorpay_signature, bookingId } = req.body;

      // Verify signature
      const sign = razorpay_order_id + '|' + razorpay_payment_id;
      const expectedSign = crypto
        .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
        .update(sign.toString())
        .digest('hex');

      if (razorpay_signature !== expectedSign) {
        return res.status(400).json({ success: false, error: 'Invalid payment signature' });
      }

      // Update booking
      await pool.query(
        'UPDATE bookings SET payment_status = ?, payment_id = ?, status = ? WHERE id = ?',
        ['paid', razorpay_payment_id, 'confirmed', bookingId]
      );

      // Update transaction
      await pool.query(
        'UPDATE transactions SET payment_id = ?, status = ? WHERE order_id = ?',
        [razorpay_payment_id, 'success', razorpay_order_id]
      );

      // Get details for notifications
      const [bookingDetails] = await pool.query(
        `SELECT b.*, s.company, s.sector, s.price, u.name, u.email, u.phone 
         FROM bookings b 
         JOIN shares s ON b.share_id = s.id 
         JOIN users u ON b.user_id = u.id 
         WHERE b.id = ?`,
        [bookingId]
      );

      if (bookingDetails.length > 0) {
        const booking = bookingDetails[0];
        
        // Send notifications (non-blocking)
        sendBookingNotifications(
          { name: booking.name, email: booking.email, phone: booking.phone },
          { id: booking.id, quantity: booking.quantity, total_amount: booking.total_amount },
          { company: booking.company, sector: booking.sector, price: booking.price }
        ).catch(err => console.error('Notification error:', err));
      }

      res.json({ success: true, message: 'Payment verified successfully' });
    } catch (error) {
      console.error('Payment verification error:', error);
      res.status(500).json({ success: false, error: 'Payment verification failed' });
    }
  }
);

// ============================================
// BOOKINGS ROUTES
// ============================================

// Create booking
app.post('/api/bookings',
  authenticateToken,
  validate([
    body('shareId').isInt().withMessage('Valid share ID required'),
    body('quantity').isInt({ min: 1 }).withMessage('Valid quantity required')
  ]),
  async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
      await connection.beginTransaction();

      const { shareId, quantity } = req.body;
      const userId = req.user.id;

      // Get share with lock
      const [shares] = await connection.query(
        'SELECT * FROM shares WHERE id = ? FOR UPDATE',
        [shareId]
      );

      if (shares.length === 0) {
        throw new Error('Share not found');
      }

      const share = shares[0];

      // Validate
      if (quantity < share.min_order) {
        throw new Error(`Minimum order is ${share.min_order} shares`);
      }

      if (quantity > share.available_quantity) {
        throw new Error('Insufficient shares available');
      }

      if (share.status !== 'available' && share.status !== 'limited') {
        throw new Error('This share is no longer available for booking');
      }

      const totalAmount = share.price * quantity;

      // Create booking
      const [result] = await connection.query(
        `INSERT INTO bookings (user_id, share_id, quantity, price_per_share, total_amount, status, payment_status) 
         VALUES (?, ?, ?, ?, ?, 'pending', 'unpaid')`,
        [userId, shareId, quantity, share.price, totalAmount]
      );

      // Update available quantity
      await connection.query(
        'UPDATE shares SET available_quantity = available_quantity - ? WHERE id = ?',
        [quantity, shareId]
      );

      await connection.commit();

      res.status(201).json({ 
        success: true, 
        bookingId: result.insertId,
        totalAmount,
        message: 'Booking created successfully. Please complete payment.' 
      });
    } catch (error) {
      await connection.rollback();
      console.error('Booking error:', error);
      res.status(400).json({ success: false, error: error.message || 'Booking failed' });
    } finally {
      connection.release();
    }
  }
);

// Get user bookings
app.get('/api/bookings/user', authenticateToken, async (req, res) => {
  try {
    const { status, limit = 50, offset = 0 } = req.query;
    
    let query = `
      SELECT b.*, s.company, s.sector 
      FROM bookings b 
      JOIN shares s ON b.share_id = s.id 
      WHERE b.user_id = ?
    `;
    const params = [req.user.id];

    if (status) {
      query += ' AND b.status = ?';
      params.push(status);
    }

    query += ' ORDER BY b.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    const [bookings] = await pool.query(query, params);
    
    res.json({ success: true, data: bookings });
  } catch (error) {
    console.error('Fetch bookings error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch bookings' });
  }
});

// Get all bookings (Admin)
app.get('/api/bookings', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status, limit = 100, offset = 0 } = req.query;
    
    let query = `
      SELECT b.*, s.company, s.sector, u.name as user_name, u.email as user_email 
      FROM bookings b 
      JOIN shares s ON b.share_id = s.id 
      JOIN users u ON b.user_id = u.id 
      WHERE 1=1
    `;
    const params = [];

    if (status) {
      query += ' AND b.status = ?';
      params.push(status);
    }

    query += ' ORDER BY b.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    const [bookings] = await pool.query(query, params);
    
    res.json({ success: true, data: bookings });
  } catch (error) {
    console.error('Fetch bookings error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch bookings' });
  }
});

// Update booking status (Admin)
app.put('/api/bookings/:id',
  authenticateToken,
  isAdmin,
  validate([
    body('status').isIn(['pending', 'confirmed', 'cancelled']).withMessage('Invalid status')
  ]),
  async (req, res) => {
    try {
      const { status } = req.body;
      
      await pool.query('UPDATE bookings SET status = ? WHERE id = ?', [status, req.params.id]);
      
      res.json({ success: true, message: 'Booking updated successfully' });
    } catch (error) {
      console.error('Update booking error:', error);
      res.status(500).json({ success: false, error: 'Failed to update booking' });
    }
  }
);

// ============================================
// ADMIN ROUTES
// ============================================

// Dashboard statistics
app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [stats] = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM shares) as total_shares,
        (SELECT COUNT(*) FROM bookings) as total_bookings,
        (SELECT COUNT(*) FROM bookings WHERE status = 'confirmed') as confirmed_bookings,
        (SELECT COALESCE(SUM(total_amount), 0) FROM bookings WHERE payment_status = 'paid') as total_revenue,
        (SELECT COUNT(*) FROM users WHERE role = 'customer') as total_users
    `);

    res.json({ success: true, data: stats[0] });
  } catch (error) {
    console.error('Fetch stats error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch statistics' });
  }
});

// Get all users (Admin)
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT id, name, email, phone, role, created_at FROM users ORDER BY created_at DESC'
    );
    res.json({ success: true, data: users });
  } catch (error) {
    console.error('Fetch users error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch users' });
  }
});

// ============================================
// ERROR HANDLING
// ============================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Route not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    success: false, 
    error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error' 
  });
});

// ============================================
// GRACEFUL SHUTDOWN
// ============================================
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully...');
  await pool.end();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully...');
  await pool.end();
  process.exit(0);
});

// ============================================
// START SERVER
// ============================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`
    🚀 Server running on port ${PORT}
    📝 Environment: ${process.env.NODE_ENV || 'development'}
    🔗 API URL: http://localhost:${PORT}
  `);
});
