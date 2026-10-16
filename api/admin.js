
const { MongoClient, ObjectId } = require("mongodb");
const crypto = require("crypto");
const { setCorsHeaders } = require("./_cors");

const SESSION_COOKIE = "mrs_session";

let cachedClient = global.portalAdminMongoClient;

async function getDatabase() {
  if (!process.env.MONGODB_URI) {
    throw new Error("Database configuration is missing.");
  }

  if (!cachedClient) {
    cachedClient = new MongoClient(process.env.MONGODB_URI);
    await cachedClient.connect();
    global.portalAdminMongoClient = cachedClient;
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

  try {
    const payload = verifySession(
      getCookie(req, SESSION_COOKIE)
    );

    if (!payload) {
      return res.status(401).json({
        ok: false,
        message: "Please sign in."
      });
    }

    const db = await getDatabase();
    const users = db.collection("users");

    const admin = await users.findOne(
      { _id: new ObjectId(payload.uid) },
      { projection: { role: 1, active: 1, approved: 1 } }
    );

    if (
      !admin ||
      admin.active !== true ||
      admin.approved !== true
    ) {
      return res.status(401).json({
        ok: false,
        message: "Your account is no longer authorized."
      });
    }

    if (admin.role !== "ADMIN") {
      return res.status(403).json({
        ok: false,
        message: "Administrator access required."
      });
    }

    if (req.method === "GET") {
      const pending = await users.find(
        {
          approved: false,
          active: true,
          role: { $ne: "ADMIN" }
        },
        {
          projection: { name: 1, username: 1, createdAt: 1 }
        }
      )
        .sort({ createdAt: 1 })
        .limit(100)
        .toArray();

      return res.status(200).json({
        ok: true,
        users: pending.map(user => ({
          id: String(user._id),
          name: user.name || "",
          username: user.username || "",
          createdAt: user.createdAt || null
        }))
      });
    }

    const action = String(req.body?.action || "");
    const userId = String(req.body?.userId || "");

    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({
        ok: false,
        message: "Invalid action."
      });
    }

    if (!/^[a-f\d]{24}$/i.test(userId)) {
      return res.status(400).json({
        ok: false,
        message: "Invalid account ID."
      });
    }

    const targetId = new ObjectId(userId);

    if (targetId.equals(new ObjectId(payload.uid))) {
      return res.status(400).json({
        ok: false,
        message: "You cannot change your own account here."
      });
    }

    const targetFilter = {
      _id: targetId,
      role: { $ne: "ADMIN" },
      approved: false,
      active: true
    };

    const update = action === "approve"
      ? {
          $set: {
            approved: true,
            updatedAt: new Date()
          }
        }
      : {
          $set: {
            active: false,
            rejectedAt: new Date(),
            updatedAt: new Date()
          }
        };

    const result = await users.updateOne(targetFilter, update);

    if (result.matchedCount !== 1) {
      return res.status(404).json({
        ok: false,
        message: "Pending account not found."
      });
    }

    return res.status(200).json({
      ok: true,
      message: action === "approve"
        ? "Account approved."
        : "Account rejected and deactivated."
    });
  } catch (error) {
    console.error("Admin API failed:", error.message);

    return res.status(500).json({
      ok: false,
      message: "Unable to complete the administrator request."
    });
  }
};
