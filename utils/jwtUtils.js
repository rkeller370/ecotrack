const jwt = require("jsonwebtoken");

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

module.exports = { generateAccessToken, generateRefreshToken };