const { MongoClient, ObjectId } = require("mongodb");
const crypto = require("crypto");
const { setCorsHeaders } = require("./_cors");

const SESSION_COOKIE = "mrs_session";
let cachedClient = global.portalAnnouncementsMongoClient;

async function getDatabase() {
  if (!process.env.MONGODB_URI) {
    throw new Error("Database configuration is missing.");
  }

  if (!cachedClient) {
    cachedClient = new MongoClient(process.env.MONGODB_URI);
    await cachedClient.connect();
    global.portalAnnouncementsMongoClient = cachedClient;
  }

  return cachedClient.db(process.env.PORTAL_DB_NAME || "MRSStaffPortal");
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
  if (!secret || Buffer.byteLength(secret) < 32 || !token) return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [encoded, signature] = parts;
  const expected = crypto
    .createHmac("sha256", secret)
    .update(encoded)
    .digest();
  let supplied;
  try {
    supplied = Buffer.from(signature, "base64url");
  } catch {
    return null;
  }
  if (
    supplied.length !== expected.length ||
    !crypto.timingSafeEqual(supplied, expected)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
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

async function getApprovedUser(req, db) {
  const payload = verifySession(getCookie(req, SESSION_COOKIE));
  if (!payload) return null;

  return db.collection("users").findOne(
    {
      _id: new ObjectId(payload.uid),
      active: true,
      approved: true
    },
    { projection: { name: 1, username: 1, role: 1 } }
  );
}

function isAdmin(user) {
  return String(user.role || "").toUpperCase() === "ADMIN";
}

function getBody(req) {
  return req.body && typeof req.body === "object" ? req.body : {};
}

function validText(value, maximum, required = false) {
  return typeof value === "string" &&
    value.trim().length <= maximum &&
    (!required || value.trim().length > 0);
}

module.exports = async function handler(req, res) {
  const originAllowed = setCorsHeaders(req, res, "GET, POST, OPTIONS");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (!originAllowed) {
    return res.status(403).json({ ok: false, error: "Origin not allowed." });
  }
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }
  if (!["GET", "POST"].includes(req.method)) {
    res.setHeader("Allow", "GET, POST, OPTIONS");
    return res.status(405).json({ ok: false, error: "Method not allowed." });
  }

  try {
    const db = await getDatabase();
    const user = await getApprovedUser(req, db);
    if (!user) {
      return res.status(401).json({
        ok: false,
        authenticated: false,
        error: "Please sign in with an approved account."
      });
    }

    const announcements = db.collection("announcements");
    if (req.method === "GET") {
      const storedAnnouncements = await announcements.find({})
        .sort({ createdAt: -1, _id: -1 })
        .limit(100)
        .toArray();
      return res.status(200).json({
        ok: true,
        announcements: storedAnnouncements.map(announcement => ({
          id: announcement._id.toString(),
          title: announcement.title,
          message: announcement.message,
          postedBy: announcement.postedBy,
          createdAt: announcement.createdAt
        }))
      });
    }

    if (!isAdmin(user)) {
      return res.status(403).json({
        ok: false,
        error: "Administrator permission is required."
      });
    }

    const body = getBody(req);
    if (body.action === "createAnnouncement") {
      if (
        !validText(body.title, 120, true) ||
        !validText(body.message, 5000, true)
      ) {
        return res.status(400).json({
          ok: false,
          error: "Enter a title (up to 120 characters) and announcement (up to 5000 characters)."
        });
      }

      await announcements.insertOne({
        title: body.title.trim(),
        message: body.message.trim(),
        postedBy: user.name || user.username || "Administrator",
        createdBy: user._id.toString(),
        createdAt: new Date()
      });
      return res.status(201).json({
        ok: true,
        message: "Announcement posted."
      });
    }

    if (body.action === "deleteAnnouncement") {
      if (
        typeof body.announcementId !== "string" ||
        !/^[a-f\d]{24}$/i.test(body.announcementId)
      ) {
        return res.status(400).json({
          ok: false,
          error: "Invalid announcement ID."
        });
      }

      const result = await announcements.deleteOne({
        _id: new ObjectId(body.announcementId)
      });
      if (!result.deletedCount) {
        return res.status(404).json({
          ok: false,
          error: "Announcement not found."
        });
      }
      return res.status(200).json({
        ok: true,
        message: "Announcement deleted."
      });
    }

    return res.status(400).json({
      ok: false,
      error: "Unknown announcement action."
    });
  } catch (error) {
    console.error("Announcements API error:", error.message);
    return res.status(500).json({
      ok: false,
      error: "Unable to process the announcements request."
    });
  }
};
