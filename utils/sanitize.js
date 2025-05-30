const sanitizeHtml = require("sanitize-html");

const sanitizeInput = (
  input,
  maxLength = 1000,
  allowedChars = /[^\p{L}\p{N}\s.,!?\-]/gu
) => {
  if (typeof input !== "string" || !input) return "";

  input = sanitizeHtml(input, {
    allowedTags: [],
    allowedAttributes: {},
  });

  return input
    .trim()
    .replace(allowedChars, "")
    .replace(/\s+/g, " ")
    .slice(0, maxLength);
};

const sanitizeEssayInput = (input, maxLength = 5000) => {
  if (typeof input !== "string" || !input) return "";

  input = sanitizeHtml(input, {
    allowedTags: [],
    allowedAttributes: {},
  });

  input = input.replace(/<[^>]*>/g, ""); 

  input = input.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, "[REDACTED EMAIL]");
  input = input.replace(/\b\d{3}[-. ]?\d{3}[-. ]?\d{4}\b/g, "[REDACTED PHONE]");
  input = input.replace(/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, "[REDACTED CARD]");

  input = input.replace(/[^\p{L}\p{N}\s.,!?;:'"()\[\]{}\-–—]/gu, "");

  input = input.replace(/\s+/g, " ").trim();

  return input.slice(0, maxLength);
};

module.exports = { sanitizeInput, sanitizeEssayInput };