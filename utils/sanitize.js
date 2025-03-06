const sanitizeInput = (
  input,
  maxLength = 255,
  allowedChars = /[^\p{L}\p{N}\s.,!?\-]/gu
) => {
  if (typeof input !== "string" || !input) return "";

  return input
    .trim()
    .replace(allowedChars, "")
    .replace(/\s+/g, " ")
    .slice(0, maxLength);
};

module.exports = { sanitizeInput };