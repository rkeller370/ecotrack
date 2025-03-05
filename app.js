const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const enforce = require("express-enforces-ssl");
const mongoSanitize = require("express-mongo-sanitize");

const app = express();

const url = "https://creative-horse-1afc49.netlify.app"
const whitelist = [url, "http://127.0.0.1:5500"];

// Middleware
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

// Routes
app.use("/api/auth", require("./routes/auth/authRoutes"));
app.use("/api/v1", require("./routes/api/apiRoutes"));

module.exports = app;