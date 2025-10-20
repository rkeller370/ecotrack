const express = require("express");
const router = express.Router();
const apiController = require("./apiController");
const { authenticateJWT } = require("../../middleware/authMiddleware");
const limiter = require("../../middleware/rateLimiter");

router.post("/addLog",authenticateJWT,limiter.limiter, apiController.addLog)
router.post("/registerEvent",authenticateJWT,limiter.limiter, apiController.registerEvent)
router.post("/unregisterEvent",authenticateJWT,limiter.limiter, apiController.unregisterEvent)
router.post("/createEvent",authenticateJWT,limiter.limiter, apiController.createEvent)
router.get("/ecoRecommendations",authenticateJWT,limiter.ailimiter,apiController.ecoSuggestions)
router.get("/volunteerEvents",authenticateJWT,limiter.limiter,apiController.getVolunteerEvents)

module.exports = router;
