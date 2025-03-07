const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const mongoSanitize = require("express-mongo-sanitize");
const csrf = require("csurf");
const crypto = require("node:crypto");
const hpp = require("hpp");

const app = express();

const ENVIRONMENT = process.env.NODE_ENV || "development";
const SECRET = process.env.TIMESTAMP_SECRET_KEY;
const FRONTEND_URL = "https://creative-horse-1afc49.netlify.app";
const whitelist = ENVIRONMENT === "production" 
  ? [FRONTEND_URL]
  : [FRONTEND_URL, "http://127.0.0.1:5500", "http://localhost:3000"];

app.set("trust proxy", 1);

app.use((req, res, next) => {
  if (req.headers["x-forwarded-proto"] !== "https") {
    return res.redirect(308, `https://${req.headers.host}${req.url}`);
  }
  next();
});

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", ...whitelist],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        fontSrc: ["'self'"],
        connectSrc: ["'self'", ...whitelist],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: ENVIRONMENT === "production" ? [] : null,
      },
    },
    hsts: { 
      maxAge: 31536000, 
      includeSubDomains: true, 
      preload: ENVIRONMENT === "production"
    },
    crossOriginEmbedderPolicy: ENVIRONMENT === "production",
    crossOriginResourcePolicy: { policy: "same-site" },
    crossOriginOpenerPolicy: { policy: "same-origin" },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  })
);

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true }));

app.use(mongoSanitize());
app.use(hpp());
app.use(cookieParser());

const corsOptions = {
  origin: (origin, callback) => {
    if (ENVIRONMENT === "development" && !origin) return callback(null, true);
    if (origin && whitelist.some(whitelisted => {
      try {
        const url = new URL(whitelisted);
        const originUrl = new URL(origin);
        return originUrl.origin === url.origin;
      } catch {
        return false;
      }
    })) {
      return callback(null, true);
    }
    callback(new Error("Not allowed by CORS"));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Request-Timestamp", "X-Signature","x-pingother","x-forwarded-proto","x-forwaded-for"]
};
app.use(cors(corsOptions));

const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: ENVIRONMENT === "production",
    sameSite: "None",
    partitioned: true,
    maxAge: 86400
  }
});
app.use((req, res, next) => {
  if (req.method === "GET" || req.path.startsWith("/api/")) {
    return next();
  }
  csrfProtection(req, res, next);
});

app.use((req, res, next) => {
  res.cookie("XSRF-TOKEN", req.csrfToken(), { 
    secure: true,
    sameSite: "None",
    httpOnly: true,
    partitioned: true 
  });
  next();
});

app.use((req, res, next) => {
  const timestamp = req.headers["x-request-timestamp"];
  const signature = req.headers["x-signature"];

  if (!timestamp || !signature) {
    return res.status(403).json({ message: "Missing security headers" });
  }

  if (!/^\d+$/.test(timestamp)) {
    return res.status(400).json({ message: "Invalid timestamp format" });
  }

  const timestampNumber = parseInt(timestamp, 10);
  const timeDifference = Date.now() - timestampNumber;

  if (timeDifference < 0 || timeDifference > 5000) {
    return res.status(403).json({ message: "Expired request" });
  }

  const expectedSignature = crypto
    .createHmac("sha256", SECRET)
    .update(timestamp)
    .digest("hex");

  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
    return res.status(403).json({ message: "Invalid signature" });
  }

  next();
});

app.use("/api/auth", require("./routes/auth/authRoutes"));
app.use("/api/v1", require("./routes/api/apiRoutes"));

app.use((err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] Error: ${err.message}`);
  
  const statusCode = err.status || 500;
  const message = statusCode === 500 ? "Internal Server Error" : err.message;
  
  res.status(statusCode).json({
    status: "error",
    message,
    ...(ENVIRONMENT === "development" && { stack: err.stack })
  });
});

module.exports = app;