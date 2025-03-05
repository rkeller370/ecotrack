const express = require("express");
const router = express.Router();
const apiController = require("./apiController");
const { authenticateJWT } = require("../../middleware/authMiddleware");
const limiter = require("../../middleware/rateLimiter");

router.get("/universities", authenticateJWT, limiter.limiter, apiController.getUniversities);
router.post("/eval", authenticateJWT, limiter.limiter, apiController.evaluateStudent);
router.get("/analysis", authenticateJWT, limiter.limiter, apiController.getAnalysis);
router.post("/essay-review", authenticateJWT, limiter.limiter, apiController.reviewEssay);

module.exports = router;
