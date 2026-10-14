
const { MongoClient } = require("mongodb");
const crypto = require("crypto");
const { promisify } = require("util");

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
  res.setHeader(
    "Access-Control-Allow-Origin",
    "https://mrs-staff-portal.vercel.app"
  );
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
    const name = String(req.body?.name || "").trim();
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    const confirmPassword = String(
      req.body?.confirmPassword || ""
    );

    if (!name || !username || !password || !confirmPassword) {
      return res.status(400).json({
        ok: false,
        message: "Complete all fields."
      });
    }

    if (name.length > 100 || username.length > 50) {
      return res.status(400).json({
        ok: false,
        message: "Name or username is too long."
      });
    }

    if (!/^[a-zA-Z0-9._-]{3,50}$/.test(username)) {
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

    const existing = await users.findOne({
      username: { $regex: "^" + username.replace(
        /[.*+?^${}()|[\]\\]/g, "\\$&"
      ) + "$", $options: "i" }
    });

    if (existing) {
      return res.status(409).json({
        ok: false,
        message: "That username is already taken."
      });
    }

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
    console.error("Registration failed:", error.message);

    return res.status(500).json({
      ok: false,
      message: "Unable to register right now. Please try again later."
    });
  }
};
