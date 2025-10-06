const express = require("express");
const router = express.Router();
const apiController = require("./apiController");
const { authenticateJWT } = require("../../middleware/authMiddleware");
const limiter = require("../../middleware/rateLimiter");

router.post("/addLog",authenticateJWT,limiter.limiter)
router.get("/universities", authenticateJWT, limiter.limiter, apiController.getUniversities);
router.post("/eval", authenticateJWT, limiter.limiter, apiController.evaluateStudent);
router.get("/analysis", authenticateJWT, limiter.limiter, apiController.getAnalysis);
router.get("/settings", authenticateJWT, limiter.limiter, apiController.getSettings);
router.get("/preferences", authenticateJWT, limiter.limiter, apiController.getCollegePreferences);
router.post("/essay-review", authenticateJWT, limiter.limiter, apiController.reviewEssay);
router.post("/submitPreferences", authenticateJWT, limiter.limiter, apiController.submitCollegePreferences)
router.post("/changeSettings", authenticateJWT, limiter.limiter, apiController.changeSettings)

module.exports = router;
