const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
let { getDb, initializeMongo } = require("../../config/db");
//const { sendVerifEmail, sendLockoutEmail } = require("../../utils/emailUtils");
const { getClientIp } = require("../../utils/getIP");
const {
  validateEmail,
  validatePassword,
} = require("../../utils/validationUtils");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../../utils/jwtUtils");

const initializeDatabase = async () => {
  db = await getDb();
};

initializeDatabase();

const url = "https://creative-horse-1afc49.netlify.app";

exports.register = async (req, res) => {
  if (!db) {
    db = getDb();
  }
  const { email, name, password } = req.body;

  if (!email || !validateEmail(email)) {
    return res
      .status(400)
      .json({ success: false, message: "Please enter a valid email" });
  }

  if (!name || !String(name)) {
    return res.status(400).json({
      success: false,
      message: "Please enter a valid name and authType",
    });
  }

  if (!password || !validatePassword(password, email).valid) {
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

  const hashedPassword = await bcrypt.hash(password, 12);
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let userId = "";
  let length = 8;
  for (let i = 0; i < length; i++) {
    userId += chars[Math.floor(Math.random() * chars.length)];
  }

  db.collection("users").insertOne({
    email: email,
    userId: userId,
    name: name,
    activities: [],
    badges: [],
    settings: [],
    password: hashedPassword,
    auth: "pass",
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
};

exports.login = async (req, res) => {
  try {
    if (!db) {
      db = getDb();
    }
    const { email, password, token } = req.body;
    const ip = getClientIp(req);

    const user = await db.collection("users").findOne({ email: email });

    if (!user || !user.password) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid email or password" });
    }

    if (
      user?.accountLockedUntil &&
      new Date(user.accountLockedUntil) > new Date()
    ) {
      return res.status(403).json({
        success: false,
        message: `Account locked until ${user.accountLockedUntil.toLocaleString()}`,
      });
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

    await db
      .collection("users")
      .updateOne(
        { email },
        { $set: { failedLoginAttempts: 0, accountLockedUntil: null } }
      );

    res.status(200).json({ success: true, message: "Login successful" });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

exports.logout = async (req, res) => {
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  res.status(200).json({ success: true, message: "Logged out successfully" });
};

exports.refreshToken = async (req, res) => {
  if (!db) {
    db = getDb();
  }

  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res
      .status(401)
      .json({ success: false, message: "No refresh token provided" });
  }

  jwt.verify(refreshToken, process.env.REFRESH_SECRET, async (err, decoded) => {
    if (err) {
      console.error("Error refreshing token:", err);
      return res
        .status(403)
        .json({ success: false, message: "Invalid or expired refresh token" });
    }

    const user = await db
      .collection("users")
      .findOne({ userId: decoded.userId });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
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
  });
};

exports.verify = async (req, res) => {
  if (!db) {
    db = getDb();
  }
  try {
    const user = await db.collection("users").findOne({ userId: req.user });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    const {
      password,
      auth,
      _id,
      email,
      verificationCode,
      failedLoginAttempts,
      accountLockedUntil,
      securityAlerts,
      lastFailedLogin,
      ...safeUser
    } = user;

    res.status(200).json({ success: true, user: safeUser });
  } catch (error) {
    console.error("Error verifying token:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

exports.verifyEmail = async (req, res) => {
  if (!db) {
    db = getDb();
  }
  try {
    const token = req.query.token;
    if (!token) {
      return res
        .status(400)
        .json({ success: false, message: "No token provided" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await db
      .collection("users")
      .findOneAndUpdate(
        { verificationCode: token },
        { $set: { verified: true }, $unset: { verificationCode: 1 } },
        { returnDocument: "after" }
      );

    if (!user.value) {
      return res
        .status(404)
        .json({ success: false, message: "Invalid verification token" });
    }

    res
      .status(200)
      .json({ success: true, message: "Email verified successfully" });
  } catch (err) {
    res.status(400).json({
      success: false,
      message: "Invalid or expired verification link",
    });
  }
};

const handleFailedLogin = async (email, ip) => {
  if (!db) {
    db = getDb();
  }
  const user = await db.collection("users").findOne({ email });

  await db.collection("users").updateOne(
    { email },
    {
      $inc: { failedLoginAttempts: 1 },
      $set: { lastFailedLogin: new Date() },
    }
  );

  if (user.failedLoginAttempts + 1 >= 3) {
    const lockDuration = 15 * 60 * 1000; // 15 minutes
    await db.collection("users").updateOne(
      { email },
      {
        $set: {
          accountLockedUntil: new Date(Date.now() + lockDuration),
          failedLoginAttempts: 0,
        },
        $push: {
          securityAlerts: {
            message: `Account locked due to 3 failed login attempts`,
            date: new Date(),
          },
        },
      }
    );

    await sendLockoutEmail(email, ip, lockDuration);
  }
};
