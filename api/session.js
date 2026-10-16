
const { MongoClient, ObjectId } = require("mongodb");
const crypto = require("crypto");
const { setCorsHeaders } = require("./_cors");

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
  for (const part of (req.headers.cookie || "").split(";")) {
    const separator = part.indexOf("=");

    if (separator < 0) continue;

    if (part.slice(0, separator).trim() === name) {
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

  const expected = crypto
    .createHmac("sha256", secret)
    .update(encoded)
    .digest();

  const supplied = Buffer.from(signature, "base64url");

  if (
    supplied.length !== expected.length ||
    !crypto.timingSafeEqual(supplied, expected)
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

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
  );
}

module.exports = async function handler(req, res) {
  const originAllowed = setCorsHeaders(
    req,
    res,
    "GET, POST, OPTIONS"
  );
  res.setHeader("Cache-Control", "no-store");

  if (!originAllowed) {
    return res.status(403).json({
      ok: false,
      message: "Origin not allowed."
    });
  }

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (!["GET", "POST"].includes(req.method)) {
    res.setHeader("Allow", "GET, POST, OPTIONS");
    return res.status(405).json({
      ok: false,
      message: "Method not allowed."
    });
  }

  // Logout does not require a valid session.
  if (req.method === "POST" && req.body?.action === "logout") {
    clearSessionCookie(res);

    return res.status(200).json({
      ok: true,
      message: "Signed out successfully."
    });
  }

  try {
    const payload = verifySession(
      getCookie(req, SESSION_COOKIE)
    );

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
      clearSessionCookie(res);

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
