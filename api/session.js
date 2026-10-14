
const { MongoClient, ObjectId } = require("mongodb");
const crypto = require("crypto");

const SESSION_COOKIE = "mrs_session";

let cachedClient = global.portalSessionMongoClient;

async function getDatabase() {
  if (!process.env.MONGODB_URI) {
    throw new Error("Database configuration is missing.");
  }

  if (!cachedClient) {
    cachedClient = new MongoClient(process.env.MONGODB_URI);
    await cachedClient.connect();
    global.portalSessionMongoClient = cachedClient;
  }

  return cachedClient.db(
    process.env.PORTAL_DB_NAME || "MRSStaffPortal"
  );
}

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie || "";

  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");

    if (separator === -1) continue;

    const key = part.slice(0, separator).trim();

    if (key === name) {
      return part.slice(separator + 1).trim();
    }
  }

  return null;
}

function verifySession(token) {
  const secret = process.env.SESSION_SECRET;

  if (!secret || Buffer.byteLength(secret) < 32 || !token) {
    return null;
  }

  const parts = token.split(".");

  if (parts.length !== 2) return null;

  const [encoded, signature] = parts;

  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(encoded)
    .digest();

  let suppliedSignature;

  try {
    suppliedSignature = Buffer.from(signature, "base64url");
  } catch {
    return null;
  }

  if (
    suppliedSignature.length !== expectedSignature.length ||
    !crypto.timingSafeEqual(
      suppliedSignature,
      expectedSignature
    )
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(encoded, "base64url").toString("utf8")
    );

    if (
      typeof payload.uid !== "string" ||
      !/^[a-f\d]{24}$/i.test(payload.uid) ||
      !Number.isSafeInteger(payload.exp) ||
      payload.exp <= Date.now()
    ) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

module.exports = async function handler(req, res) {
  const allowedOrigin = "https://portal.maidenrescuesquad.org";

  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Vary", "Origin");
  res.setHeader("Cache-Control", "no-store");

  if (req.headers.origin && req.headers.origin !== allowedOrigin) {
    return res.status(403).json({
      ok: false,
      message: "Origin not allowed."
    });
  }

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET, OPTIONS");
    return res.status(405).json({
      ok: false,
      message: "Method not allowed."
    });
  }

  try {
    const token = getCookie(req, SESSION_COOKIE);
    const payload = verifySession(token);

    if (!payload) {
      return res.status(401).json({
        ok: false,
        authenticated: false,
        message: "Please sign in."
      });
    }

    const db = await getDatabase();

    const user = await db.collection("users").findOne(
      { _id: new ObjectId(payload.uid) },
      {
        projection: {
          name: 1,
          username: 1,
          role: 1,
          active: 1,
          approved: 1
        }
      }
    );

    if (
      !user ||
      user.active !== true ||
      user.approved !== true
    ) {
      res.setHeader(
        "Set-Cookie",
        `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
      );

      return res.status(401).json({
        ok: false,
        authenticated: false,
        message: "Your session is no longer valid."
      });
    }

    return res.status(200).json({
      ok: true,
      authenticated: true,
      user: {
        id: String(user._id),
        name: user.name || "",
        username: user.username,
        role: user.role || "STAFF"
      }
    });
  } catch (error) {
    console.error("Session verification failed:", error.message);

    return res.status(500).json({
      ok: false,
      message: "Unable to verify your session right now."
    });
  }
};
