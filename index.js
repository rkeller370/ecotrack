//const functions = require("@google-cloud/functions-framework");
const express = require("express");
const app = express();
require('dotenv').config();
const bodyParser = require("body-parser");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { OAuth2Client } = require("google-auth-library");
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion } = require("mongodb");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 50,
  message: "Too many requests, please try again later.",
  headers: true,
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many requests, please try again later.",
  headers: true,
});
const mongoSanitize = require("express-mongo-sanitize");
const enforce = require("express-enforces-ssl");
//const xss = require("xss-clean")
const crypto = require("node:crypto");
const bcrypt = require("bcrypt");
const csrf = require("csurf");
const axios = require("axios");
const { OpenAI } = require("openai");
const csrfProtection = csrf({
  cookie: {
    key: "XSRF-TOKEN",
    httpOnly: true,
    secure: true,
    partitioned: true,
    sameSite: "None",
  },
});

const port = process.env.PORT || 3000;

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

const url = 'https://creative-horse-1afc49.netlify.app'

const isISO8601 = (date) => {
  const isoDateRegex =
    /^\d{4}-\d{2}-\d{2}([Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|([+-]\d{2}:\d{2})))?$/;
  return isoDateRegex.test(date) && !isNaN(new Date(date).getTime());
};

const whitelist = [
  url,
  "http://127.0.0.1:5500",
];

app.set("trust proxy", 1);
app.use(bodyParser.json());
app.use(limiter)
app.use(enforce());
app.use(
  helmet({
    // Content Security Policy (CSP)
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'", ...whitelist], // Allow resources from self and whitelist
        scriptSrc: ["'self'", ...whitelist], // Allow scripts from self and whitelist
        styleSrc: ["'self'", ...whitelist, "'unsafe-inline'"], // Allow styles from self, whitelist, and inline
        imgSrc: ["'self'", "data:", ...whitelist], // Allow images from self, data URIs, and whitelist
        fontSrc: ["'self'", ...whitelist], // Allow fonts from self and whitelist
        connectSrc: ["'self'", ...whitelist], // Allow API calls to self and whitelist
        frameSrc: ["'none'"], // Disallow embedding in frames
        objectSrc: ["'none'"], // Disallow plugins like Flash
        baseUri: ["'self'"], // Restrict base URLs to the same origin
        formAction: ["'self'", ...whitelist], // Allow form submissions to self and whitelist
        frameAncestors: ["'none'"], // Disallow embedding in iframes
        upgradeInsecureRequests: [], // Upgrade HTTP requests to HTTPS
      },
    },
    // HTTP Strict Transport Security (HSTS) - Keep one instance
    hsts: {
      maxAge: 31536000, // Enforce HTTPS for 1 year
      includeSubDomains: true, // Apply to all subdomains
      preload: true, // Allow preloading in browsers
    },
    // Cross-Origin Embedder Policy (COEP)
    crossOriginEmbedderPolicy: { policy: "require-corp" }, // Require cross-origin isolation
    // Cross-Origin Resource Policy (CORP)
    crossOriginResourcePolicy: { policy: "same-site" }, // Restrict cross-origin resource loading
    // Cross-Origin Opener Policy (COOP)
    crossOriginOpenerPolicy: { policy: "same-origin" }, // Prevent cross-origin window access
    // Referrer Policy
    referrerPolicy: { policy: "no-referrer" }, // Prevent referrer leakage
    // X-Content-Type-Options
    xContentTypeOptions: true, // Prevent MIME type sniffing
    // X-Frame-Options
    xFrameOptions: { action: "deny" }, // Prevent embedding in iframes
    // X-XSS-Protection
    xXssProtection: true, // Enable XSS protection in older browsers
    // Expect-CT
    expectCt: {
      enforce: true, // Enforce Certificate Transparency
      maxAge: 86400, // Cache for 1 day
    },
    // Permissions Policy
    permissionsPolicy: {
      features: {
        camera: ["'none'"], // Disallow camera access
        microphone: ["'none'"], // Disallow microphone access
        geolocation: ["'none'"], // Disallow geolocation access
        fullscreen: ["'self'"], // Allow fullscreen only for the same origin
      },
    },
  })
);

app.use(mongoSanitize());
app.use(cookieParser());
const corsOptions = {
  origin: function (origin, callback) {
    if (whitelist.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE"], // Allowed HTTP methods
  credentials: true, // Allow credentials (cookies, authorization headers)
};

app.use(cors(corsOptions));
//app.use(csrfProtection);
/*app.use((req, res, next) => {
  res.cookie("XSRF-TOKEN", req.csrfToken(), { httpOnly: true, secure: true, sameSite: 'None', partitioned: true });
  next();
});*/
app.use((req, res, next) => {
  const timestamp = req.headers['x-request-timestamp'];
  if (Date.now() - parseInt(timestamp) > 2000) {
    return res.status(403).json({ message: 'Expired request' });
  }
  next();
});

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: 'donotreply.mshstutoring@gmail.com',
    pass: process.env.GMAIL_PASS, 
  },
});

// Environment Variables
const SECRET_KEY = process.env.JWT_SECRET;
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID
const MONGO_URI = process.env.MONGO_URI;

const mongoClient = new MongoClient(MONGO_URI, {
  ssl: true,
  tlsAllowInvalidCertificates: false,
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db;

// Add retry logic to MongoDB connection
const initializeMongo = async (retries = 5, delay = 5000) => {
  for (let i = 0; i < retries; i++) {
    try {
      const client = await mongoClient.connect();
      db = await client.db("Development");
      console.log("Connected to MongoDB");
      return;
    } catch (err) {
      console.error(`Failed to connect to MongoDB (attempt ${i + 1}):`, err);
      if (i === retries - 1) throw err;
      await new Promise(res => setTimeout(res, delay));
    }
  }
};

initializeMongo();

const client = new OAuth2Client(CLIENT_ID);

/*
const algorithm = "aes-256-cbc"; // Encryption algorithm (AES-256-CBC)
const secretKey = Buffer.from(process.env.ENCRYPTION_KEY, "hex"); // Load from environment
const iv = crypto.randomBytes(16); // Initialization vector for encryption (random)

function encryptUserId(userId) {
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(secretKey), iv);
  let encrypted = cipher.update(userId.toString(), "utf-8", "hex");
  encrypted += cipher.final("hex");
  return { encryptedUserId: encrypted, iv: iv.toString("hex") };
}

function decryptUserId(encryptedUserId, iv) {
  const decipher = crypto.createDecipheriv(
    algorithm,
    Buffer.from(secretKey),
    Buffer.from(iv, "hex")
  );
  let decrypted = decipher.update(encryptedUserId, "hex", "utf-8");
  decrypted += decipher.final("utf-8");
  return decrypted;
}*/

const generateAccessToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "20m",
    algorithm: "HS256",
  });
};

const generateRefreshToken = (userId) => {
  return jwt.sign({ userId }, process.env.REFRESH_SECRET, {
    expiresIn: "7d",
    algorithm: "HS256",
  });
};

const validateEmail = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
};

// Password validation helper
const validatePassword = (password, email, previousPasswords = []) => {
  const minLength = 10; // Increased minimum length
  const hasUpperCase = /[A-Z]/;
  const hasLowerCase = /[a-z]/;
  const hasNumbers = /\d/;
  const hasSpecialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/;

  // Basic checks
  if (password.length < minLength) {
    return {
      valid: false,
      message: `Password must be at least ${minLength} characters long`,
    };
  }

  if (!hasUpperCase.test(password)) {
    return {
      valid: false,
      message: "Password must contain at least one uppercase letter",
    };
  }

  if (!hasLowerCase.test(password)) {
    return {
      valid: false,
      message: "Password must contain at least one lowercase letter",
    };
  }

  if (!hasNumbers.test(password)) {
    return {
      valid: false,
      message: "Password must contain at least one number",
    };
  }

  if (!hasSpecialChars.test(password)) {
    return {
      valid: false,
      message: "Password must contain at least one special character",
    };
  }

  // Check for common weak passwords
  const commonPasswords = [
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "123123",
    "baseball",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "shadow",
    "master",
    "666666",
    "qwertyuiop",
    "123321",
    "mustang",
    "1234567890",
    "michael",
    "654321",
    "superman",
    "1qaz2wsx",
    "7777777",
    "qazwsx",
    "password1",
    "qwerty123",
    "welcome",
    "iloveyou",
    "adobe123",
    "admin",
    "login",
    "passw0rd",
    "starwars",
    "zaq1zaq1",
    "zaq12wsx",
    "123qwe",
    "access",
    "flower",
    "cheese",
    "computer",
    "freedom",
    "whatever",
    "princess",
    "q1w2e3r4",
    "secret",
    "charlie",
    "hottie",
    "loveme",
    "sunshine",
    "ashley",
    "bailey",
    "jordan",
    "mercedes",
    "austin",
    "harley",
    "maggie",
    "buster",
    "jennifer",
    "nicole",
    "justin",
    "tigger",
    "soccer",
    "ginger",
    "cookie",
    "pepper",
    "cameron",
    "scooter",
    "joshua",
    "lovely",
    "matthew",
    "killer",
    "jasmine",
    "samantha",
    "donald",
    "iloveu",
    "snoopy",
    "sweet",
    "eagle",
    "samsung",
    "qwert",
    "11111111",
    "12345678910",
    "000000",
    "987654321",
    "888888",
    "999999",
    "101010",
    "121212",
    "131313",
    "159753",
    "159357",
    "123654",
    "777777",
    "147258",
    "852963",
    "456456",
    "00000000",
    "999999999"
  ];  
  if (commonPasswords.includes(password.toLowerCase())) {
    return {
      valid: false,
      message: "Password is too common and easily guessable",
    };
  }

  // Check for email or username in password
  const emailParts = email.split("@")[0].split(/[.\-_]/); // Split email local part
  if (
    emailParts.some((part) => password.toLowerCase().includes(part.toLowerCase()))
  ) {
    return {
      valid: false,
      message: "Password should not contain your email or username",
    };
  }

  // Check for password reuse
  if (previousPasswords.length > 0) {
    const isReused = previousPasswords.some((prevPassword) =>
      bcrypt.compareSync(password, prevPassword)
    );
    if (isReused) {
      return {
        valid: false,
        message: "Password has been used before. Please choose a new one.",
      };
    }
  }

  // Check for sequential or repeated characters
  if (/(.)\1{2,}/.test(password)) {
    return {
      valid: false,
      message: "Password contains repeated characters",
    };
  }

  if (/123|234|345|456|567|678|789|890/.test(password)) {
    return {
      valid: false,
      message: "Password contains sequential characters",
    };
  }

  return { valid: true, message: "Password is valid" };
};

// Improved JWT authentication middleware
const authenticateJWT = (req, res, next) => {
  const token = req.cookies.accessToken || req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: "Authorization token required" 
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ 
        success: false, 
        message: "Invalid or expired token" 
      });
    }
    req.user = decoded.userId;
    next();
  });
};

const sendVerifEmail = async (email, subject, html, token) => {
  const verifyLink = `${url}/verifyemail?token=${token}`;
  const mailOptions = {
    from: "donotreply.mshstutoring@gmail.com",
    to: email,
    subject,
    html,
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (err) {
    console.error("Error sending email:", err);
  }
};

const sendLockoutEmail = async (email, ip, lockDuration) => {
  const mailOptions = {
    from: "donotreply.mshstutoring@gmail.com",
    to: email,
    subject: 'Account Locked - Security Alert',
    html: `
      <!DOCTYPE html>
      <html>
        <head>
          <style>
            body {
              font-family: 'Inter', sans-serif;
              background-color: #f5f5f5;
              color: #333333;
              margin: 0;
              padding: 0;
            }
            .email-container {
              max-width: 600px;
              margin: 0 auto;
              background-color: white;
              border-radius: 8px;
              overflow: hidden;
              box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            }
            .email-header {
              background-color: #4caf50;
              color: white;
              padding: 20px;
              text-align: center;
              font-size: 1.5rem;
              font-weight: bold;
            }
            .email-body {
              padding: 30px;
              text-align: center;
            }
            .email-body p {
              font-size: 1rem;
              margin-bottom: 30px;
              line-height: 1.5;
              color: #666;
            }
            .email-footer {
              background-color: #212121;
              color: white;
              padding: 20px;
              text-align: center;
              font-size: 0.9rem;
            }
            .email-footer a {
              color: #4caf50;
              text-decoration: none;
              font-weight: bold;
            }
            .email-footer a:hover {
              color: #3e8e41;
            }
          </style>
        </head>
        <body>
          <div class="email-container">
            <div class="email-header">
              Security Alert
            </div>
            <div class="email-body">
              <p>Your account has been temporarily locked due to 3 failed login attempts.</p>
              <p><strong>Details:</strong></p>
              <ul>
                <li>Time: ${new Date().toLocaleString()}</li>
                <li>IP Address: ${ip}</li>
                <li>Lock Duration: ${lockDuration / 60000} minutes</li>
              </ul>
              <p>If this was you, please wait until the lock expires to try again.</p>
              <p>If this wasn't you, please contact our security team immediately.</p>
              <p><a href="">Review Account Security</a></p>
            </div>
            <div class="email-footer">
              © AdmitVault 2024. All rights reserved. <br />
              <a href="${url}">Visit our website</a> | <a href="${url}/privacy" >Privacy Policy</a> | <a href="${url}/terms" >Terms of Service</a>
            </div>
          </div>
        </body>
      </html>
    `
  };

  await transporter.sendMail(mailOptions);
};

const handleFailedLogin = async (email, ip) => {
  const user = await db.collection('users').findOne({ email });
  
  // Increment failed attempts
  await db.collection('users').updateOne(
    { email },
    { 
      $inc: { failedLoginAttempts: 1 },
      $set: { lastFailedLogin: new Date() }
    }
  );

  // Check if account should be locked
  if (user.failedLoginAttempts + 1 >= 3) {
    const lockDuration = 15 * 60 * 1000; // 15 minutes
    await db.collection('users').updateOne(
      { email },
      {
        $set: {
          accountLockedUntil: new Date(Date.now() + lockDuration),
          failedLoginAttempts: 0 // Reset counter
        },
        $push: {
          securityAlerts: {
            message: `Account locked due to 3 failed login attempts`,
            date: new Date()
          }
        }
      }
    );

    // Send lockout email
    await sendLockoutEmail(email, ip, lockDuration);
  }
};

app.post("/api/auth/register", loginLimiter, async (req, res) => {
  const { email, name, password, authType, token } = req.body;
  if(!email || !validateEmail(email)) {
    return res
    .status(400)
    .json({ success: false, message: "Please enter a valid email" });
  }

  if(!name || !String(name) || !authType || !String(authType)) {
    return res
    .status(400)
    .json({ success: false, message: "Please enter a valid name and authType" });
  }

  if(!password || !validatePassword(password,email)) {
    return res
    .status(400)
    .json({ success: false, message: "Please enter a valid password" });
  }

  let user = await db.collection("users").findOne({ email: email });
  if (user) {
    return res
      .status(400)
      .json({ success: false, message: "Account already exists" });
  }
  if (authType == "pass") {
    const hashedPassword = await bcrypt.hash(password, 10);
    const chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let userId = "";
    let length = 10;
    for (let i = 0; i < length; i++) {
      userId += chars[Math.floor(Math.random() * chars.length)];
    }

    const emailVerificationToken = jwt.sign({ userId: userId }, SECRET_KEY, {
      expiresIn: "15m",
      algorithm: "HS256",
    });

    sendVerifEmail(
      email,
      "Email Verification",
      `<!DOCTYPE html>
    <html>
      <head>
        <style>
          body {
            font-family: 'Inter', sans-serif;
            background-color: #f5f5f5;
            color: #333333;
            margin: 0;
            padding: 0;
          }
    
          .email-container {
            max-width: 600px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
          }
    
          .email-header {
            background-color: #4caf50;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 1.5rem;
            font-weight: bold;
          }
    
          .email-body {
            padding: 30px;
            text-align: center;
          }
    
          .email-body h1 {
            font-size: 1.8rem;
            margin-bottom: 20px;
          }
    
          .email-body p {
            font-size: 1rem;
            margin-bottom: 30px;
            line-height: 1.5;
            color: #666;
          }
    
          .email-body .verify-button {
            display: inline-block;
            padding: 15px 25px;
            font-size: 1rem;
            font-weight: bold;
            color: white;
            background-color: #4caf50;
            border-radius: 5px;
            text-decoration: none;
            transition: background-color 0.3s ease;
          }
    
          .email-body .verify-button:hover {
            background-color: #3e8e41;
          }
    
          .email-footer {
            background-color: #212121;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9rem;
          }
    
          .email-footer a {
            color: #4caf50;
            text-decoration: none;
            font-weight: bold;
          }
    
          .email-footer a:hover {
            color: #3e8e41;
          }
        </style>
      </head>
      <body>
        <div class="email-container">
          <div class="email-header">
            Verify Your Email
          </div>
          <div class="email-body">
            <h1>Hello, ${name}!</h1>
            <p>Thank you for signing up. Please click the button below to verify your email address and activate your account.</p>
            <a href="${url}/verifyemail.html?token=${emailVerificationToken}" class="verify-button">Verify Email</a>
            <p>If you did not sign up, please ignore this email and contact our support team.</p>
          </div>
          <div class="email-footer">
          © AdmitVault 2024. All rights reserved. <br />
          <a href="${url}">Visit our website</a> | <a href="${url}/privacy" >Privacy Policy</a> | <a href="${url}/terms" >Terms of Service</a>
        </div>
        </div>
      </body>
    </html>`,
      emailVerificationToken
    );

    db.collection("users").insertOne({
      email: email,
      userId: userId,
      name: name,
      password: hashedPassword,
      auth: "pass",
      verified: false,
      verificationCode: emailVerificationToken,
    });

    res.status(201).json({ success: true, message: "User created" });
  } else if (authType == "google") {
    if (!token) {
      return res
        .status(400)
        .json({ success: false, message: "No token provided" });
    }
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: CLIENT_ID,
    });

    if (!ticket || !ticket.getPayload()) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid token" });
    }

    const payload = ticket.getPayload();
    const email = payload.email;
    const name = payload.name;

    let user = await db.collection("users").findOne({ email: email });
    if (user) {
      return res
        .status(400)
        .json({ success: false, message: "Account already exists" });
    }

    const chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let userId = "";
    let length = 10;
    for (let i = 0; i < length; i++) {
      userId += chars[Math.floor(Math.random() * chars.length)];
    }

    db.collection("users").insertOne({
      email: email,
      userId: userId,
      name: name,
      password: null,
      auth: "google",
      verified: true,
      verificationCode: null,
    });

    const accessToken = generateAccessToken(userId);
    const refreshToken = generateRefreshToken(userId);

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 20 * 60 * 1000,
      partitioned: true,
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      partitioned: true,
    });

    res.status(201).json({ success: true, message: "User created" });
  } else {
    res
      .status(400)
      .json({ success: false, message: "Invalid authentication type" });
  }
});

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    if (!db) {
      await initializeMongo();
    }

    const { email, password, authType, token } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    if (authType !== "pass" && authType !== "google") {
      return res
        .status(400)
        .json({ success: false, message: "Invalid authentication type" });
    }

    if (authType === "pass") {
      const user = await db.collection("users").findOne({ email: email });

      if (!user || !user.password) {
        return res
          .status(401)
          .json({ success: false, message: "Invalid email or password" });
      }

      if (user?.accountLockedUntil && new Date(user.accountLockedUntil) > new Date()) {
        return res.status(403).json({
          success: false,
          message: `Account locked until ${user.accountLockedUntil.toLocaleString()}`
        });
      }

      if (user.verified == false) {
        return res
          .status(404)
          .json({ success: false, message: "Email not verified" });
      }

      if(user.auth === "google") {
        return res
          .status(404)
          .json({ success: false, message: "Auth type not supported for this account" });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        await handleFailedLogin(email, ip);
        return res
          .status(401)
          .json({ success: false, message: "Invalid email or password" });
      }

      const accessToken = generateAccessToken(user.userId);
      const refreshToken = generateRefreshToken(user.userId);

      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 20 * 60 * 1000,
        partitioned: true,
      });

      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 7 * 24 * 60 * 60 * 1000,
        partitioned: true,
      });

      await db.collection('users').updateOne(
        { email },
        { $set: { failedLoginAttempts: 0, accountLockedUntil: null } }
      );

      res.status(200).json({ success: true, message: "Login successful" });
    } else if (authType === "google") {
      if (!token) {
        return res
          .status(400)
          .json({ success: false, message: "No token provided" });
      }
      const ticket = await client.verifyIdToken({
        idToken: token,
        audience: CLIENT_ID,
      });

      if (!ticket || !ticket.getPayload()) {
        return res
          .status(400)
          .json({ success: false, message: "Invalid token" });
      }

      const payload = ticket.getPayload();

      if (!payload || !payload.email) {
        return res
          .status(401)
          .json({ success: false, message: "Invalid email or password" });
      }

      const email = payload.email;
      const user = await db.collection("users").findOne({ email: email });

      if (!user) {
        return res
          .status(401)
          .json({ success: false, message: "Invalid email or password" });
      }

            
      if (user?.accountLockedUntil && new Date(user.accountLockedUntil) > new Date()) {
        return res.status(403).json({
          success: false,
          message: `Account locked until ${user.accountLockedUntil.toLocaleString()}`
        });
      }

      if(user.auth === "pass") {
        return res
          .status(404)
          .json({ success: false, message: "Auth type not supported for this account" });
      }

      const accessToken = generateAccessToken(user.userId);
      const refreshToken = generateRefreshToken(user.userId);

      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 20 * 60 * 1000,
        partitioned: true,
      });

      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 7 * 24 * 60 * 60 * 1000,
        partitioned: true,
      });

      await db.collection('users').updateOne(
        { email },
        { $set: { failedLoginAttempts: 0, accountLockedUntil: null } }
      );

      res.status(200).json({ success: true, message: "Login successful" });
    } else {
      res.status(400).send("Invalid auth type");
    }
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/api/auth/verify", authenticateJWT, limiter, async (req, res) => {
  try {
    if (!db) {
      await initializeMongo();
    }

    if (!req.user) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const user = await db.collection("users").findOne({ userId: req.user });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    const { password, auth, _id, email, verificationCode, failedLoginAttempts, accountLockedUntil, securityAlerts, lastFailedLogin, ...safeUser } = user;

    res.status(200).json({ success: true, user: safeUser });
  } catch (error) {
    console.error("Error verifying token:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Update verification process to clear token
app.get("/api/auth/verifyemail", limiter, async (req, res) => {
  try {
    const token = req.query.token;
    if(!token) {
      return res.status(400).json({
        success: false,
        message: "No token provided"
      });
    }
    const decoded = jwt.verify(token, SECRET_KEY);
    const user = await db.collection("users").findOneAndUpdate(
      { verificationCode: token },
      { $set: { verified: true }, $unset: { verificationCode: 1 } },
      { returnDocument: 'after' }
    );
    
    if (!user.value) {
      return res.status(404).json({ 
        success: false, 
        message: "Invalid verification token" 
      });
    }
    
    res.status(200).json({ 
      success: true, 
      message: "Email verified successfully" 
    });
  } catch (err) {
    res.status(400).json({ 
      success: false, 
      message: "Invalid or expired verification link" 
    });
  }
});

app.get("/api/v1/universities", authenticateJWT, limiter, async (req, res) => {
  try {
    const { college } = req.query;

    if (!college || !String(college) || college.trim() === "") {
      return res.status(400).json({
        success: false,
        message: "No college provided"
      });
    }

    const govApiKey = process.env.GOV_API_KEY; // Replace with your actual API key
    const response = await axios.get(
      `https://api.data.gov/ed/collegescorecard/v1/schools.json`, {
        params: {
          api_key: govApiKey,
          'school.name': college,  // Make sure this is the correct query parameter
          per_page: 10
        }
      });

    // Process the results from the response
    const universities = response.data.results.map((uni) => ({
      name: uni.school.name,
      city: uni.school.city,
      state: uni.school.state,
    }));

    // Send the results back in the response
    return res.json({
      success: true,
      results: universities,
    });
  } catch (error) {
    // Handle error if something goes wrong
    console.error(error);
    return res.status(500).json({
      success: false,
      message: "An error occurred while fetching university data"
    });
  }
});


app.post("/api/v1/eval", authenticateJWT, limiter, async (req, res) => {
  try {
      const studentData = req.body;
      let user = await db.collection("users").findOne({ userId: req.user });

      if(!studentData) {
        return res.status(400).json({
          success: false,
          message: "No student data provided"
        });
      }

      if(!user) {
        return res.status(404).json({
          success: false,
          message: "User not found"
        });
      }

      if(user.recommended) {
        return res.status(400).json({
          success: false,
          message: "User already recommended"
        });
      }

      const prompt = `You are an elite AI-powered college admissions consultant, specializing in meticulously analyzing high school student applications. Your mission is to deliver an extraordinarily detailed evaluation, packed with precise, high-value recommendations that dramatically increase the student’s admission chances at their target colleges.

      You must:
      - **Tailor all feedback** to the student’s data and the unique priorities of their target colleges (based on Common Data Set (CDS), mission statements, and admissions trends).
      - **Be hyper-specific** by comparing the student's profile against competitive benchmarks (e.g., middle 50% ranges for GPA, SAT/ACT, course rigor, extracurricular expectations).
      - **Provide a vast number of insights**—not just 3-4, but **multiple, highly detailed, strategic** recommendations per section.
      - **Prioritize actionable strategies**—every recommendation must be measurable, concrete, and immediately implementable.
      
      ---
      
      ### **Structured Input:**
      \`\`\`json
      ${JSON.stringify(studentData, null, 2)}
      \`\`\`
      
      ---
      
      ### **Deliverables:**
      You must generate a JSON object that contains **four comprehensive sections**:  
      
      #### **1. Holistic Portfolio Assessment**
      - Assign an overall **portfolio rating** ('Exceptional', 'Very Strong', 'Strong', 'Good', 'Fair', 'Needs Improvement') based on the student’s profile.
      - Justify this rating by analyzing the student’s strengths, weaknesses, and alignment with their college goals.
      - **Summarize unique strengths** that set the student apart, connecting them to the priorities of their target colleges.
      
      #### **2. In-Depth Analysis of Key Areas**
      For **each** category below, provide **at least 6-8 highly detailed** recommendations tailored to the student's strengths, weaknesses, and target colleges.
      
      - **Academics:**
        - Evaluate **GPA, course rigor, trends, and standardized test scores** compared to CDS data.
        - **Identify inconsistencies or areas for improvement.**
        - Provide **specific, multi-step recommendations** for academic enhancement.
        - **Examples of strong recommendations:**
          - “Enroll in AP Chemistry and AP Calculus BC next year, as [Target College] reports 92% of admitted students taking both.”
          - “Increase SAT Math score from 710 to 770 to meet [Target College’s] middle 50% range (750-790).”
      
      - **Extracurriculars:**
        - Assess **leadership, impact, depth of involvement, and initiative.**
        - **Recommend at least 6-8 strategic moves** to enhance extracurricular strength.
        - **Examples of strong recommendations:**
          - “Launch a self-led research project on AI in healthcare and submit findings to the Regeneron Science Talent Search.”
          - “Expand [volunteering initiative] by partnering with [organization] to reach 500+ people annually.”
          - “Compete in the USA Biology Olympiad to gain national-level recognition.”
      
      - **Awards & Recognition:**
        - **Analyze the competitiveness** of current awards.
        - Suggest **at least 5-6 new high-profile awards or competitions.**
        - **Examples of strong recommendations:**
          - “Apply for the Davidson Fellows Scholarship ($50,000) for your work in [field].”
          - “Compete in the Conrad Challenge to gain entrepreneurial recognition.”
      
      - **Scholarships:**
        - Identify **specific, high-value scholarships** based on the student’s profile.
        - Provide **at least 5-6 opportunities with clear justification**.
        - **Examples of strong recommendations:**
          - “Apply for the Coca-Cola Scholars Program ($20,000) given your leadership in [activity].”
          - “Submit your STEM research to the Intel Science and Engineering Fair for scholarship opportunities.”
      
      #### **3. Targeted Improvement Recommendations**
      For **each** of the following, provide **at least 6-8 concrete, strategic recommendations** tailored to the student’s situation:
      
      - **Academics**
      - **Extracurriculars**
      - **Essays**
      - **Time Management**
      - **College List Optimization**
      
      Each recommendation must be **highly detailed and actionable**, such as:
      - “Reduce extracurricular overload by prioritizing [top 3 activities] and cutting [least impactful one].”
      - “Structure personal statement around a ‘challenge-growth-impact’ framework to enhance narrative flow.”
      
      #### **4. College List Evaluation & Expansion**
      - **Assess the competitiveness** of the student’s college list.
      - Provide **at least 4-5 additional schools** tailored to the student's profile.
      - Justify each new school based on **program strength, financial aid, admissions probability, and alignment with the student’s goals.**
      - **Example recommendations:**
        - “Consider applying to [Highly Competitive College] because of its [specialized program], where [X%] of students pursue [intended major].”
        - “Add [Safety School] to your list, as it offers strong merit aid and has a [X%] admissions rate.”
      
      ---
      
      ### **Output Format**
      Return a **pure JSON response** (NO code blocks, NO formatting, NO extra text). The JSON must be **deeply structured** for seamless integration into a frontend UI.
      
      \`\`\`json
      {
        "portfolioRating": "Exceptional",
        "summary": "This student presents a compelling profile...",
        "areas": {
          "academics": {
            "analysis": "The student has a strong GPA...",
            "recommendations": [
              "Take AP Calculus BC to align with [Target College’s] rigorous academic expectations.",
              "Raise SAT Math score to 770 to meet [Target College’s] middle 50% range (750-790).",
              "Conduct independent research in [intended major] and submit findings to a peer-reviewed journal.",
              "Enroll in a dual-enrollment program at a local university to showcase college-level coursework."
            ]
          },
          "extracurriculars": {
            "analysis": "The student has deep involvement in...",
            "recommendations": [
              "Expand leadership role in [activity] by founding a new initiative.",
              "Compete in [national competition] to gain recognition in [field].",
              "Quantify impact by tracking growth metrics (e.g., 'raised $10,000 for X cause').",
              "Secure an internship in [field] to strengthen real-world experience."
            ]
          },
          "awards": {
            "analysis": "The student has received notable awards in...",
            "recommendations": [
              "Apply for the Regeneron STS competition.",
              "Submit work to the MIT Think Scholars program.",
              "Compete in the Conrad Challenge for recognition in innovation."
            ]
          },
          "scholarships": {
            "analysis": "The student is eligible for several competitive scholarships...",
            "recommendations": [
              "Apply for the Coca-Cola Scholars Program ($20,000).",
              "Submit application for the Davidson Fellows Scholarship ($50,000).",
              "Consider the Jack Kent Cooke Foundation scholarship for high-achieving students with financial need."
            ]
          }
        },
        "collegeListEvaluation": {
          "analysis": "The student’s college list is well-balanced...",
          "recommendations": [
            "Add [Reach College] for its strong [program].",
            "Remove [Target College] as its median GPA is significantly higher than the student’s.",
            "Explore [Safety School] due to strong merit aid opportunities."
          ]
        }
      }
      \`\`\`
      
      ---
      
      ### **Critical Guidelines**
      - **Every section must contain at least 6-8 recommendations.**
      - **Justify all suggestions with specific benchmarks, data points, or strategic reasoning.**
      - **Be as detailed, insightful, and data-driven as possible.**
      - **Return only JSON. No explanations, no formatting, no extra text.**`;
            
      // Call OpenAI API
      const response = await openai.chat.completions.create(
        {
            model: "gpt-4o-mini",
            messages: [
                { role: "system", content: "You are an expert college admissions advisor." },
                { role: "user", content: prompt }
            ],
            temperature: 0.7,
        },
    );

      if (!response.choices || response.choices.length === 0) {
          return res.status(500).json({ error: "OpenAI API returned no response." });
      }

      // set db with returned values
      await db.collection('users').updateOne(
        { userId: req.user },
        { $set: { recommended: response.choices[0].message.content } }
      );

      const aiResponse = response.choices[0].message.content;
      return res.json({ evaluation: aiResponse });
  } catch (error) {
      console.error("Error:", error);
      return res.status(500).json({ error: "An error occurred while processing the request." });
  }
});

app.post("/api/auth/refresh", limiter, async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ success: false, message: "No refresh token provided" });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
    if(!decoded) {
      return res.status(401).json({ success: false, message: "Invalid refresh token" });
    }
    const user = await db.collection("users").findOne({ userId: decoded.userId });

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Generate a new access token
    const accessToken = generateAccessToken(user.userId);

    // Set the new access token in a cookie
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 20 * 60 * 1000, // 20 minutes
      partitioned: true,
    });

    res.status(200).json({ success: true, message: "Token refreshed" });
  } catch (err) {
    res.status(403).json({ success: false, message: "Invalid or expired refresh token" });
  }
});

// Logout endpoint
app.post("/api/auth/logout", authenticateJWT, limiter, async (req, res) => {
  const userId = req.user;

  try {
    // Clear cookies
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    res.status(200).json({ success: true, message: "Logged out successfully" });
  } catch (err) {
    console.error("Error logging out:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/api/v1/analysis", authenticateJWT, limiter, async (req, res) => {
  try {
    const user = await db.collection("users").findOne({ userId: req.user });
    if(!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }
    return res.json({ recommended: user.recommended });
  } catch (error) {
    console.error("Error:", error);
    return res.status(500).json({ error: "An error occurred while processing the request." });
  }
})

app.post("/api/v1/essay-review", authenticateJWT, limiter, async (req, res) => {
  try {
    const { essay, prompt: userPrompt } = req.body;
    const userId = req.user;

    // Validate essay input
    if (!essay || typeof essay !== "string" || essay.trim().length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: "Valid essay text is required" 
      });
    }

    // Check essay length
    if (essay.length > 10000) {
      return res.status(400).json({
        success: false,
        message: "Essay exceeds maximum length of 10,000 characters",
      });
    }

    // Get user and check review limits
    const user = await db.collection("users").findOne({ userId });
    const now = new Date();
    const currentMonthStart = new Date(now.getFullYear(), now.getMonth(), 1);

    const monthlyReviews = user.essayReviews
      ? user.essayReviews.filter((date) => new Date(date) >= currentMonthStart)
      : [];

    if (monthlyReviews.length >= 3) {
      return res.status(429).json({
        success: false,
        message: "Monthly limit of 3 essay reviews exceeded",
      });
    }

    // Create analysis prompt
    const defaultPrompt = `Act as a elite college essay specialist. Provide EXTREMELY DETAILED, line-by-line feedback focused on actionables. Analyze:

    **Core Elements**
    1. Grammar/Syntax (highlight specific errors)
    2. Tone (formal/informal balance)
    3. Word Choice (precise vs vague language)
    4. Diction (academic vs conversational) 
    5. Sentence Structure (variety/complexity)
    6. Narrative Flow (transitions/pacing)
    7. Hook Effectiveness (opening impact)
    8. Unique Voice (authenticity markers)
    9. Concrete Examples (specificity level)
    10. Admissions Fit (alignment with college values)
    
    **Response Requirements**
    - For EACH category: 3-5 SPECIFIC examples FROM THE ESSAY
    - Provide a minimum of 7 (recommended more) suggested improvements
    - Direct quotes from text with line numbers
    - Concrete revision suggestions
    - Percentage ratings reflecting skill level
    
    **JSON Template**
    \`\`\`json
    {
      "ratings": {
        "grammar": <1-100>, 
        "tone": <1-100>,
        "word_choice": <1-100>,
        "diction": <1-100>,
        "sentence_structure": <1-100>,
        "narrative_flow": <1-100>,
        "hook": <1-100>,
        "uniqueness": <1-100>,
        "examples": <1-100>,
        "admissions_fit": <1-100>
      },
      "strengths": [
        {
          "category": "Word Choice",
          "example": "\"The laboratory's sterile environment\" (line 12)",
          "analysis": "Excellent precise terminology showing scientific awareness"
        }
      ],
      "improvements": [
        {
          "category": "Tone",
          "excerpt": "\"I kinda stumbled into research\" (line 8)",
          "issue": "Overly casual for academic context",
          "fix": "\"My research journey began unexpectedly\"",
          "rationale": "Maintains authenticity while using more formal academic register"
        }
      ],
      "overall_impression": {
        "summary": "Strong foundation needing polish in...",
        "top_3_priorities": [
          "Revise informal phrases in lines 8,15,22",
          "Vary sentence starters in paragraphs 3-4", 
          "Add 2-3 discipline-specific terms in methods section"
        ]
      }
    }
    \`\`\`
    
    **Rules**
    1. Minimum 15 specific examples TOTAL
    2. Every improvement MUST include:
       - Exact text excerpt 
       - Line number reference
       - Suggested revision
       - Brief technical rationale
    3. Never use vague statements - ALWAYS anchor in text
    4. Prioritize changes with biggest admissions impact

    ** RETURN ONLY A JSON FILE, DO NOT PROVIDE TEXT RESPONSES, DO NOT WRAP IT IN A CODE BLOCK. JSON MUST BE FULLY FUNCTIONAL AND CONTAIN NO ERRORS **
    
    Essay: ${essay.substring(0, 7500)}`;
    

    const analysisPrompt = userPrompt || defaultPrompt;

    // Get OpenAI feedback
    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { 
          role: "system", 
          content: "You are a college admissions essay expert. Provide thorough, professional feedback." 
        },
        { 
          role: "user", 
          content: analysisPrompt 
        }
      ],
      temperature: 0.4,
      max_tokens: 1500,
    });

    const feedback = response.choices[0].message.content;

    // Update review count
    await db.collection("users").updateOne(
      { userId },
      { $push: { essayReviews: new Date().toISOString() } }
    );

    res.status(200).json({ 
      success: true, 
      feedback: feedback,
      reviewsRemaining: 3 - (monthlyReviews.length + 1)
    });

  } catch (error) {
    console.error("Essay review error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Error processing essay review" 
    });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

//functions.http("helloHttp", app);