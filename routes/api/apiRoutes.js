const express = require("express");
const router = express.Router();
const apiController = require("./apiController");
const { authenticateJWT } = require("../../middleware/authMiddleware");
const limiter = require("../../middleware/rateLimiter");

router.get("/universities", authenticateJWT, limiter.limiter, apiController.getUniversities);
router.post("/eval", authenticateJWT, limiter.limiter, apiController.evaluateStudent);
router.get("/analysis", authenticateJWT, limiter.limiter, apiController.getAnalysis);
router.get("/settings", authenticateJWT, limiter.limiter, apiController.getSettings);
router.post("/essay-review", authenticateJWT, limiter.limiter, apiController.reviewEssay);
router.post("/submitPreferences", authenticateJWT, limiter.limiter, apiController.submitCollegePreferences)

module.exports = router;
