
const { MongoClient, ObjectId } = require("mongodb");
const crypto = require("crypto");

const SESSION_COOKIE = "mrs_session";
const ALLOWED_ORIGIN = "https://portal.maidenrescuesquad.org";

let cachedClient = global.portalCalendarMongoClient;

async function getDatabase() {
  if (!process.env.MONGODB_URI) {
    throw new Error("Database configuration is missing.");
  }

  if (!cachedClient) {
    cachedClient = new MongoClient(process.env.MONGODB_URI);
    await cachedClient.connect();
    global.portalCalendarMongoClient = cachedClient;
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

async function getApprovedUser(req, db) {
  const payload = verifySession(getCookie(req, SESSION_COOKIE));

  if (!payload) return null;

  return db.collection("users").findOne(
    {
      _id: new ObjectId(payload.uid),
      active: true,
      approved: true
    },
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
}

function isAdmin(user) {
  return String(user.role || "").toUpperCase() === "ADMIN";
}

function getBody(req) {
  if (req.body && typeof req.body === "object") {
    return req.body;
  }

  return {};
}

function validEventId(value) {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= 500;
}

async function ensureIndexes(db) {
  await db.collection("registrations").createIndex(
    { eventId: 1, userId: 1 },
    { unique: true, name: "one_registration_per_user_event" }
  );

  await db.collection("registrations").createIndex(
    { eventId: 1, createdAt: 1 }
  );

  await db.collection("eventSettings").createIndex(
    { eventId: 1 },
    { unique: true, name: "one_settings_document_per_event" }
  );
}

async function ensureEventSettings(db, eventId) {
  await db.collection("eventSettings").updateOne(
    { eventId },
    {
      $setOnInsert: {
        eventId,
        capacity: null,
        registeredCount: 0,
        updatedAt: new Date()
      }
    },
    { upsert: true }
  );
}

async function registerUser(db, eventId, targetUser, addedByAdmin = false) {
  const registrations = db.collection("registrations");
  const settings = db.collection("eventSettings");

  await ensureEventSettings(db, eventId);

  const session = db.client.startSession();
  let outcome = "error";

  try {
    await session.withTransaction(async () => {
      const existing = await registrations.findOne(
        { eventId, userId: targetUser._id.toString() },
        { session }
      );

      if (existing) {
        outcome = "duplicate";
        return;
      }

      const capacityUpdate = await settings.updateOne(
        {
          eventId,
          $expr: {
            $or: [
              { $eq: [{ $ifNull: ["$capacity", null] }, null] },
              {
                $lt: [
                  { $ifNull: ["$registeredCount", 0] },
                  "$capacity"
                ]
              }
            ]
          }
        },
        {
          $inc: { registeredCount: 1 },
          $set: { updatedAt: new Date() }
        },
        { session }
      );

      if (capacityUpdate.modifiedCount !== 1) {
        outcome = "full";
        return;
      }

      await registrations.insertOne(
        {
          eventId,
          userId: targetUser._id.toString(),
          name: targetUser.name || targetUser.username,
          username: targetUser.username,
          createdAt: new Date(),
          addedByAdmin
        },
        { session }
      );

      outcome = "registered";
    });

    return outcome;
  } finally {
    await session.endSession();
  }
}

async function withdrawUser(db, eventId, userId) {
  const session = db.client.startSession();
  let removed = false;

  try {
    await session.withTransaction(async () => {
      const result = await db.collection("registrations").deleteOne(
        { eventId, userId },
        { session }
      );

      if (result.deletedCount === 1) {
        await db.collection("eventSettings").updateOne(
          {
            eventId,
            registeredCount: { $gt: 0 }
          },
          {
            $inc: { registeredCount: -1 },
            $set: { updatedAt: new Date() }
          },
          { session }
        );

        removed = true;
      }
    });

    return removed;
  } finally {
    await session.endSession();
  }
}

async function getEventRoster(db, eventId) {
  const [settings, registrations] = await Promise.all([
    db.collection("eventSettings").findOne({ eventId }),
    db.collection("registrations")
      .find({ eventId })
      .sort({ createdAt: 1 })
      .project({
        userId: 1,
        name: 1,
        username: 1,
        createdAt: 1,
        addedByAdmin: 1
      })
      .toArray()
  ]);

  return {
    eventId,
    capacity: settings?.capacity ?? null,
    registeredCount: registrations.length,
    spotsRemaining: settings?.capacity == null
      ? null
      : Math.max(0, settings.capacity - registrations.length),
    registrations: registrations.map(registration => ({
      id: registration._id.toString(),
      userId: registration.userId,
      name: registration.name,
      username: registration.username,
      createdAt: registration.createdAt,
      addedByAdmin: registration.addedByAdmin === true
    }))
  };
}

async function getCalendarEvents(db) {
  const bridgeUrl = process.env.GOOGLE_CALENDAR_BRIDGE_URL;
  const bridgeSecret = process.env.PORTAL_API_SECRET;

  if (!bridgeUrl || !bridgeSecret) {
    throw new Error("Calendar integration is not configured.");
  }

  const url = new URL(bridgeUrl);
  url.searchParams.set("action", "events");
  url.searchParams.set("secret", bridgeSecret);

  const response = await fetch(url.toString(), {
    method: "GET",
    redirect: "follow"
  });

  if (!response.ok) {
    throw new Error(`Calendar bridge returned HTTP ${response.status}`);
  }

  const data = await response.json();

  if (!data.ok || !Array.isArray(data.events)) {
    throw new Error("Calendar bridge returned an invalid response.");
  }

  const events = [];

  for (const event of data.events) {
    if (!event.id) continue;

    const roster = await getEventRoster(db, event.id);

    events.push({
      ...event,
      registration: {
        capacity: roster.capacity,
        registeredCount: roster.registeredCount,
        spotsRemaining: roster.spotsRemaining,
        registrations: roster.registrations,
        signedUp: false
      }
    });
  }

  return events;
}

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Vary", "Origin");
  res.setHeader("Cache-Control", "no-store");

  if (req.headers.origin && req.headers.origin !== ALLOWED_ORIGIN) {
    return res.status(403).json({
      ok: false,
      error: "Origin not allowed."
    });
  }

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (!["GET", "POST"].includes(req.method)) {
    res.setHeader("Allow", "GET, POST, OPTIONS");
    return res.status(405).json({
      ok: false,
      error: "Method not allowed."
    });
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

    await ensureIndexes(db);

    if (req.method === "GET") {
      const events = await getCalendarEvents(db);

      const myRegistrations = await db.collection("registrations")
        .find({ userId: user._id.toString() })
        .project({ eventId: 1 })
        .toArray();

      const signedUpIds = new Set(
        myRegistrations.map(item => item.eventId)
      );

      return res.status(200).json({
        ok: true,
        events: events.map(event => ({
          ...event,
          registration: {
            ...event.registration,
            signedUp: signedUpIds.has(event.id)
          }
        }))
      });
    }

    const body = getBody(req);
    const action = body.action;
    const eventId = body.eventId;

    if (!validEventId(eventId)) {
      return res.status(400).json({
        ok: false,
        error: "A valid event ID is required."
      });
    }

    if (action === "signup") {
      const result = await registerUser(db, eventId, user);

      if (result === "full") {
        return res.status(409).json({
          ok: false,
          error: "This event has reached its registration limit."
        });
      }

      if (result === "duplicate") {
        return res.status(409).json({
          ok: false,
          error: "You are already registered for this event."
        });
      }

      return res.status(200).json({
        ok: true,
        message: "You have signed up for this event.",
        registration: await getEventRoster(db, eventId)
      });
    }

    if (action === "withdraw") {
      const removed = await withdrawUser(
        db,
        eventId,
        user._id.toString()
      );

      return res.status(200).json({
        ok: true,
        message: removed
          ? "You have withdrawn from this event."
          : "You were not registered for this event.",
        registration: await getEventRoster(db, eventId)
      });
    }

    if (action === "roster") {
      return res.status(200).json({
        ok: true,
        registration: await getEventRoster(db, eventId)
      });
    }

    if (!isAdmin(user)) {
      return res.status(403).json({
        ok: false,
        error: "Administrator permission is required."
      });
    }

    if (action === "setCapacity") {
      const capacity = body.capacity;

      if (
        capacity !== null &&
        (!Number.isSafeInteger(capacity) || capacity < 0 || capacity > 10000)
      ) {
        return res.status(400).json({
          ok: false,
          error: "Capacity must be a whole number from 0 to 10000, or null for unlimited."
        });
      }

      await ensureEventSettings(db, eventId);

      const current = await db.collection("eventSettings").findOne({ eventId });

      if (
        capacity !== null &&
        capacity < (current.registeredCount || 0)
      ) {
        return res.status(409).json({
          ok: false,
          error: "Capacity cannot be lower than the current number of registrations."
        });
      }

      await db.collection("eventSettings").updateOne(
        { eventId },
        {
          $set: {
            capacity,
            updatedAt: new Date(),
            updatedBy: user._id.toString()
          }
        }
      );

      return res.status(200).json({
        ok: true,
        registration: await getEventRoster(db, eventId)
      });
    }

    if (action === "addAttendee") {
      if (
        typeof body.userId !== "string" ||
        !/^[a-f\d]{24}$/i.test(body.userId)
      ) {
        return res.status(400).json({
          ok: false,
          error: "A valid staff user ID is required."
        });
      }

      const targetUser = await db.collection("users").findOne({
        _id: new ObjectId(body.userId),
        active: true,
        approved: true
      });

      if (!targetUser) {
        return res.status(404).json({
          ok: false,
          error: "Approved staff account not found."
        });
      }

      const result = await registerUser(db, eventId, targetUser, true);

      if (result === "full") {
        return res.status(409).json({
          ok: false,
          error: "This event has reached its registration limit."
        });
      }

      if (result === "duplicate") {
        return res.status(409).json({
          ok: false,
          error: "This staff member is already registered."
        });
      }

      return res.status(200).json({
        ok: true,
        registration: await getEventRoster(db, eventId)
      });
    }

    if (action === "removeAttendee") {
      if (
        typeof body.userId !== "string" ||
        !/^[a-f\d]{24}$/i.test(body.userId)
      ) {
        return res.status(400).json({
          ok: false,
          error: "A valid staff user ID is required."
        });
      }

      const removed = await withdrawUser(db, eventId, body.userId);

      return res.status(200).json({
        ok: true,
        removed,
        registration: await getEventRoster(db, eventId)
      });
    }

    return res.status(400).json({
      ok: false,
      error: "Unknown calendar action."
    });
  } catch (error) {
    console.error("Calendar API error:", error.message);

    return res.status(500).json({
      ok: false,
      error: "Unable to process the calendar request."
    });
  }
};
