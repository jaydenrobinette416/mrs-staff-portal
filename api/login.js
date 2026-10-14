
const { MongoClient } = require("mongodb");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
const SESSION_COOKIE = "mrs_session";
const SESSION_DURATION = 8 * 60 * 60 * 1000;

let cachedClient = global.portalMongoClient;

async function getDatabase() {
  if (!process.env.MONGODB_URI) {
    throw new Error("Database configuration is missing.");
  }

  if (!cachedClient) {
    cachedClient = new MongoClient(process.env.MONGODB_URI);
    await cachedClient.connect();
    global.portalMongoClient = cachedClient;
  }

  return cachedClient.db(
    process.env.PORTAL_DB_NAME || "MRSStaffPortal"
  );
}

function signSession(payload) {
  const secret = process.env.SESSION_SECRET;

  if (!secret || Buffer.byteLength(secret) < 32) {
    throw new Error("Session configuration is missing or too short.");
  }

  const encoded = Buffer.from(JSON.stringify(payload)).toString(
    "base64url"
  );

  const signature = crypto
    .createHmac("sha256", secret)
    .update(encoded)
    .digest("base64url");

  return `${encoded}.${signature}`;
}

module.exports = async function handler(req, res) {
  const allowedOrigin = "https://mrs-staff-portal.vercel.app";

  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
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

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, OPTIONS");
    return res.status(405).json({
      ok: false,
      message: "Method not allowed."
    });
  }

  try {
    const username = String(req.body?.username || "")
      .trim()
      .toLowerCase();
    const password = String(req.body?.password || "");

    if (!username || !password) {
      return res.status(400).json({
        ok: false,
        message: "Enter your username and password."
      });
    }

    const db = await getDatabase();
    const user = await db.collection("users").findOne({
      username,
      active: true
    });

    if (!user || !user.passwordSalt || !user.passwordHash) {
      return res.status(401).json({
        ok: false,
        message: "Invalid username or password."
      });
    }

    const actualHash = await scrypt(
      password,
      user.passwordSalt,
      64
    );

    const expectedHash = Buffer.from(user.passwordHash, "hex");

    if (
      expectedHash.length !== actualHash.length ||
      !crypto.timingSafeEqual(actualHash, expectedHash)
    ) {
      return res.status(401).json({
        ok: false,
        message: "Invalid username or password."
      });
    }

    if (user.approved !== true) {
      return res.status(403).json({
        ok: false,
        message: "Your account is waiting for approval."
      });
    }

    const now = Date.now();

    const token = signSession({
      uid: String(user._id),
      exp: now + SESSION_DURATION
    });

    res.setHeader(
      "Set-Cookie",
      `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_DURATION / 1000)}`
    );

    return res.status(200).json({
      ok: true,
      message: "Signed in successfully.",
      user: {
        id: String(user._id),
        name: user.name || "",
        username: user.username,
        role: user.role || "STAFF"
      }
    });
  } catch (error) {
    console.error("Portal login failed:", error.message);

    return res.status(500).json({
      ok: false,
      message: "Unable to sign in right now."
    });
  }
};
