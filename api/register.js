
const { MongoClient } = require("mongodb");
const crypto = require("crypto");
const { promisify } = require("util");
const { setCorsHeaders } = require("./_cors");

const scrypt = promisify(crypto.scrypt);
let cachedClient = global.portalRegisterClient;

async function getDatabase() {
  if (!process.env.MONGODB_URI) {
    throw new Error("Database configuration is missing.");
  }

  if (!cachedClient) {
    cachedClient = new MongoClient(process.env.MONGODB_URI);
    await cachedClient.connect();
    global.portalRegisterClient = cachedClient;
  }

  return cachedClient.db(
    process.env.PORTAL_DB_NAME || "MRSStaffPortal"
  );
}

module.exports = async function handler(req, res) {
  const originAllowed = setCorsHeaders(req, res, "POST, OPTIONS");
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

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, OPTIONS");
    return res.status(405).json({
      ok: false,
      message: "Method not allowed."
    });
  }

  try {
    const name = String(req.body?.name || "").trim();
    const username = String(req.body?.username || "")
      .trim()
      .toLowerCase();
    const password = String(req.body?.password || "");
    const confirmPassword = String(req.body?.confirmPassword || "");

    if (!name || !username || !password || !confirmPassword) {
      return res.status(400).json({
        ok: false,
        message: "Complete all fields."
      });
    }

    if (name.length > 100) {
      return res.status(400).json({
        ok: false,
        message: "Name must be 100 characters or fewer."
      });
    }

    if (!/^[a-z0-9._-]{3,50}$/.test(username)) {
      return res.status(400).json({
        ok: false,
        message:
          "Username must be 3–50 characters using letters, numbers, dots, underscores, or hyphens."
      });
    }

    if (password.length < 12 || password.length > 128) {
      return res.status(400).json({
        ok: false,
        message: "Password must be 12–128 characters long."
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        ok: false,
        message: "Passwords do not match."
      });
    }

    const db = await getDatabase();
    const users = db.collection("users");

    const passwordSalt = crypto.randomBytes(16).toString("hex");
    const passwordHash = (
      await scrypt(password, passwordSalt, 64)
    ).toString("hex");

    await users.insertOne({
      name,
      username,
      passwordSalt,
      passwordHash,
      role: "STAFF",
      approved: false,
      active: true,
      createdAt: new Date(),
      updatedAt: new Date()
    });

    return res.status(201).json({
      ok: true,
      message:
        "Registration submitted. An administrator must approve your account before you can sign in."
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        ok: false,
        message: "That username is already taken."
      });
    }

    console.error("Registration failed:", error.message);

    return res.status(500).json({
      ok: false,
      message: "Unable to register right now. Please try again later."
    });
  }
};
