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

module.exports = { sanitizeInput };