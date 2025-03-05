const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const { db } = require("../../config/db");
const { sendVerifEmail, sendLockoutEmail } = require("../../utils/emailUtils");
const { validateEmail, validatePassword } = require("../../utils/validationUtils");
const { generateAccessToken, generateRefreshToken } = require("../../utils/jwtUtils");

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Register a new user
exports.register = async (req, res) => {
  const { email, name, password, authType, token } = req.body;

  if (!email || !validateEmail(email)) {
    return res.status(400).json({ success: false, message: "Please enter a valid email" });
  }

  if (!name || !String(name) || !authType || !String(authType)) {
    return res.status(400).json({ success: false, message: "Please enter a valid name and authType" });
  }

  if (!password || !validatePassword(password, email).valid) {
    return res.status(400).json({ success: false, message: "Please enter a valid password" });
  }

  let user = await db.collection("users").findOne({ email: email });
  if (user) {
    return res.status(400).json({ success: false, message: "Account already exists" });
  }

  if (authType === "pass") {
    const hashedPassword = await bcrypt.hash(password, 10);
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let userId = "";
    let length = 10;
    for (let i = 0; i < length; i++) {
      userId += chars[Math.floor(Math.random() * chars.length)];
    }

    const emailVerificationToken = jwt.sign({ userId: userId }, process.env.JWT_SECRET, {
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
              <a href="${process.env.FRONTEND_URL}/verifyemail.html?token=${emailVerificationToken}" class="verify-button">Verify Email</a>
              <p>If you did not sign up, please ignore this email and contact our support team.</p>
            </div>
            <div class="email-footer">
              © AdmitVault 2024. All rights reserved. <br />
              <a href="${process.env.FRONTEND_URL}">Visit our website</a> | <a href="${process.env.FRONTEND_URL}/privacy">Privacy Policy</a> | <a href="${process.env.FRONTEND_URL}/terms">Terms of Service</a>
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
  } else if (authType === "google") {
    if (!token) {
      return res.status(400).json({ success: false, message: "No token provided" });
    }
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    if (!ticket || !ticket.getPayload()) {
      return res.status(400).json({ success: false, message: "Invalid token" });
    }

    const payload = ticket.getPayload();
    const email = payload.email;
    const name = payload.name;

    let user = await db.collection("users").findOne({ email: email });
    if (user) {
      return res.status(400).json({ success: false, message: "Account already exists" });
    }

    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
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
    res.status(400).json({ success: false, message: "Invalid authentication type" });
  }
};

// Login a user
exports.login = async (req, res) => {
  try {
    const { email, password, authType, token } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    if (authType !== "pass" && authType !== "google") {
      return res.status(400).json({ success: false, message: "Invalid authentication type" });
    }

    if (authType === "pass") {
      const user = await db.collection("users").findOne({ email: email });

      if (!user || !user.password) {
        return res.status(401).json({ success: false, message: "Invalid email or password" });
      }

      if (user?.accountLockedUntil && new Date(user.accountLockedUntil) > new Date()) {
        return res.status(403).json({
          success: false,
          message: `Account locked until ${user.accountLockedUntil.toLocaleString()}`,
        });
      }

      if (user.verified === false) {
        return res.status(404).json({ success: false, message: "Email not verified" });
      }

      if (user.auth === "google") {
        return res.status(404).json({ success: false, message: "Auth type not supported for this account" });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        await handleFailedLogin(email, ip);
        return res.status(401).json({ success: false, message: "Invalid email or password" });
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

      await db.collection("users").updateOne(
        { email },
        { $set: { failedLoginAttempts: 0, accountLockedUntil: null } }
      );

      res.status(200).json({ success: true, message: "Login successful" });
    } else if (authType === "google") {
      if (!token) {
        return res.status(400).json({ success: false, message: "No token provided" });
      }
      const ticket = await client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID,
      });

      if (!ticket || !ticket.getPayload()) {
        return res.status(400).json({ success: false, message: "Invalid token" });
      }

      const payload = ticket.getPayload();
      const email = payload.email;
      const user = await db.collection("users").findOne({ email: email });

      if (!user) {
        return res.status(401).json({ success: false, message: "Invalid email or password" });
      }

      if (user?.accountLockedUntil && new Date(user.accountLockedUntil) > new Date()) {
        return res.status(403).json({
          success: false,
          message: `Account locked until ${user.accountLockedUntil.toLocaleString()}`,
        });
      }

      if (user.auth === "pass") {
        return res.status(404).json({ success: false, message: "Auth type not supported for this account" });
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

      await db.collection("users").updateOne(
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
};

// Logout a user
exports.logout = async (req, res) => {
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  res.status(200).json({ success: true, message: "Logged out successfully" });
};

// Refresh access token
exports.refreshToken = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ success: false, message: "No refresh token provided" });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
    const user = await db.collection("users").findOne({ userId: decoded.userId });

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const accessToken = generateAccessToken(user.userId);

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 20 * 60 * 1000,
      partitioned: true,
    });

    res.status(200).json({ success: true, message: "Token refreshed" });
  } catch (err) {
    res.status(403).json({ success: false, message: "Invalid or expired refresh token" });
  }
};

// Verify user token
exports.verify = async (req, res) => {
  try {
    const user = await db.collection("users").findOne({ userId: req.user });

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const { password, auth, _id, email, verificationCode, failedLoginAttempts, accountLockedUntil, securityAlerts, lastFailedLogin, ...safeUser } = user;

    res.status(200).json({ success: true, user: safeUser });
  } catch (error) {
    console.error("Error verifying token:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// Verify email
exports.verifyEmail = async (req, res) => {
  try {
    const token = req.query.token;
    if (!token) {
      return res.status(400).json({ success: false, message: "No token provided" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await db.collection("users").findOneAndUpdate(
      { verificationCode: token },
      { $set: { verified: true }, $unset: { verificationCode: 1 } },
      { returnDocument: 'after' }
    );

    if (!user.value) {
      return res.status(404).json({ success: false, message: "Invalid verification token" });
    }

    res.status(200).json({ success: true, message: "Email verified successfully" });
  } catch (err) {
    res.status(400).json({ success: false, message: "Invalid or expired verification link" });
  }
};

// Handle failed login attempts
const handleFailedLogin = async (email, ip) => {
  const user = await db.collection('users').findOne({ email });

  await db.collection('users').updateOne(
    { email },
    { 
      $inc: { failedLoginAttempts: 1 },
      $set: { lastFailedLogin: new Date() }
    }
  );

  if (user.failedLoginAttempts + 1 >= 3) {
    const lockDuration = 15 * 60 * 1000; // 15 minutes
    await db.collection('users').updateOne(
      { email },
      {
        $set: {
          accountLockedUntil: new Date(Date.now() + lockDuration),
          failedLoginAttempts: 0
        },
        $push: {
          securityAlerts: {
            message: `Account locked due to 3 failed login attempts`,
            date: new Date()
          }
        }
      }
    );

    await sendLockoutEmail(email, ip, lockDuration);
  }
};