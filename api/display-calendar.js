const { MongoClient } = require("mongodb");
const { ObjectId } = require("mongodb");
const crypto = require("crypto");
const { setCorsHeaders } = require("./_cors");

const SESSION_COOKIE = "mrs_session";
let cachedClient = global.portalDisplayCalendarMongoClient;

async function getDatabase() {
  if (!process.env.MONGODB_URI) {
    throw new Error("Database configuration is missing.");
  }

  if (!cachedClient) {
    cachedClient = new MongoClient(process.env.MONGODB_URI);
    await cachedClient.connect();
    global.portalDisplayCalendarMongoClient = cachedClient;
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
  const expected = crypto.createHmac("sha256", secret).update(encoded).digest();
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

module.exports = async function handler(req, res) {
  const originAllowed = setCorsHeaders(req, res, "GET, OPTIONS");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (!originAllowed) {
    return res.status(403).json({ ok: false, error: "Origin not allowed." });
  }
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET, OPTIONS");
    return res.status(405).json({ ok: false, error: "Method not allowed." });
  }

  try {
    const db = await getDatabase();
    const session = verifySession(getCookie(req, SESSION_COOKIE));
    const user = session
      ? await db.collection("users").findOne(
        {
          _id: new ObjectId(session.uid),
          active: true,
          approved: true
        },
        { projection: { _id: 1, name: 1, username: 1 } }
      )
      : null;
    const events = await db.collection("calendarEvents")
      .find({})
      .sort({ dateKey: 1, startTime: 1 })
      .limit(500)
      .project({
        _id: 0,
        id: 1,
        title: 1,
        dateKey: 1,
        description: 1,
        allDay: 1,
        startTime: 1,
        endTime: 1
      })
      .toArray();

    const eventIds = events.map(event => event.id);
    const [settings, registrations] = user && eventIds.length
      ? await Promise.all([
        db.collection("eventSettings")
          .find({ eventId: { $in: eventIds } })
          .project({ eventId: 1, paidStaffCount: 1 })
          .toArray(),
        db.collection("registrations")
          .find({ eventId: { $in: eventIds } })
          .sort({ eventId: 1, createdAt: 1, _id: 1 })
          .project({ eventId: 1, userId: 1, name: 1, username: 1, createdAt: 1 })
          .toArray()
      ])
      : [[], []];
    const paidSlotsByEventId = new Map(
      settings.map(setting => [setting.eventId, setting.paidStaffCount || 0])
    );
    const registrationsByEventId = new Map();
    for (const registration of registrations) {
      if (!registrationsByEventId.has(registration.eventId)) {
        registrationsByEventId.set(registration.eventId, []);
      }
      registrationsByEventId.get(registration.eventId).push(registration);
    }

    return res.status(200).json({
      ok: true,
      authenticated: Boolean(user),
      user: user ? { name: user.name || "", username: user.username } : null,
      events: events.map(event => ({
        id: event.id,
        title: event.title || "Untitled event",
        dateKey: event.dateKey,
        description: event.description || "",
        allDay: event.allDay === true,
        startTime: event.startTime || "",
        endTime: event.endTime || "",
        ...(user ? {
          paidStaffCount: paidSlotsByEventId.get(event.id) || 0,
          registrations: (registrationsByEventId.get(event.id) || [])
            .map((registration, index) => ({
              name: registration.name || registration.username || "Staff member",
              staffType: index < (paidSlotsByEventId.get(event.id) || 0)
                ? "paid"
                : "volunteer"
            }))
        } : {})
      }))
    });
  } catch (error) {
    console.error("Display calendar API error:", error.message);
    return res.status(500).json({
      ok: false,
      error: "Unable to load the display calendar."
    });
  }
};
