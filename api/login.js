
const { MongoClient } = require("mongodb");
const crypto = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(crypto.scrypt);
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

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "https://mrs-staff-portal.vercel.app");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Vary", "Origin");

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
    const username = String(req.body?.username || "").trim();
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

    if (!user) {
      return res.status(401).json({
        ok: false,
        message: "Invalid username or password."
      });
    }

    // Portal accounts store a salt and scrypt password hash.
    if (!user.passwordSalt || !user.passwordHash) {
      return res.status(401).json({
        ok: false,
        message: "This account is not configured for secure login."
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

    return res.status(200).json({
      ok: true,
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
