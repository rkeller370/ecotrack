const express = require("express");
const router = express.Router();
const authController = require("./authController");
const { authenticateJWT } = require("../../middleware/authMiddleware");
const limiter = require("../../middleware/rateLimiter");

router.post("/register", limiter.loginLimiter, authController.register);
router.post("/login", limiter.loginLimiter, authController.login);
router.post("/logout", authenticateJWT, limiter.limiter, authController.logout);
router.post("/refresh", limiter.limiter, authController.refreshToken);
router.get("/verify", authenticateJWT, limiter.limiter, authController.verify);
router.get("/verifyemail", limiter.limiter, authController.verifyEmail);

module.exports = router;