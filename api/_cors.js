const CANONICAL_ORIGIN = "https://portal.maidenrescuesquad.org";
const ALLOWED_ORIGINS = new Set([
  CANONICAL_ORIGIN,
  "https://www.maidenrescuesquad.org",
  ...(process.env.PORTAL_ALLOWED_ORIGINS || "")
    .split(",")
    .map(origin => origin.trim())
    .filter(Boolean)
]);

function setCorsHeaders(req, res, methods) {
  const origin = req.headers.origin;
  const allowed = !origin || ALLOWED_ORIGINS.has(origin);

  res.setHeader(
    "Access-Control-Allow-Origin",
    origin && allowed ? origin : CANONICAL_ORIGIN
  );
  res.setHeader("Access-Control-Allow-Methods", methods);
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Vary", "Origin");

  return allowed;
}

module.exports = { setCorsHeaders };
