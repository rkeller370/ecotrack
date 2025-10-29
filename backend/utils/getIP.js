const getClientIp = (req) => {
  const xForwardedFor = req.headers["x-forwarded-for"];

  if (xForwardedFor) {
    const ips = xForwardedFor.split(",");
    return ips[0].trim();
  }

  return req.connection.remoteAddress;
};

module.exports = { getClientIp };