
const { MongoClient, ObjectId } = require("mongodb");
const crypto = require("crypto");
const { setCorsHeaders } = require("./_cors");

const SESSION_COOKIE = "mrs_session";

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
  const payload = verifySession(
    getCookie(req, SESSION_COOKIE)
  );

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
  return (
    typeof value === "string" &&
    /^[a-f\d]{24}$/i.test(value)
  );
}

function validateEvent(body) {
  const title = typeof body.title === "string" ? body.title.trim() : "";
  const dateKey = typeof body.dateKey === "string" ? body.dateKey : "";
  const location = typeof body.location === "string" ? body.location.trim() : "";
  const description = typeof body.description === "string" ? body.description.trim() : "";
  const allDay = body.allDay === true;
  const startTime = typeof body.startTime === "string" ? body.startTime : "";
  const endTime = typeof body.endTime === "string" ? body.endTime : "";

  if (!title || title.length > 120) {
    return { error: "Event title is required and must be 120 characters or fewer." };
  }

  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateKey)) {
    return { error: "Enter a valid event date." };
  }

  const [year, month, day] = dateKey.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    return { error: "Enter a valid event date." };
  }

  if (location.length > 200 || description.length > 2000) {
    return { error: "Location must be 200 characters or fewer and description 2000 characters or fewer." };
  }

  if (
    typeof body.allDay !== "boolean" ||
    (!allDay && (
      !/^([01]\d|2[0-3]):[0-5]\d$/.test(startTime) ||
      !/^([01]\d|2[0-3]):[0-5]\d$/.test(endTime) ||
      startTime >= endTime
    ))
  ) {
    return { error: "Choose a valid start and end time, or mark the event as all day." };
  }

  return {
    event: {
      title,
      dateKey,
      location,
      description,
      allDay,
      startTime: allDay ? "" : startTime,
      endTime: allDay ? "" : endTime
    }
  };
}

function validCapacity(capacity) {
  return capacity === null || (
    Number.isSafeInteger(capacity) &&
    capacity >= 0 &&
    capacity <= 10000
  );
}

function validPaidStaffCount(count) {
  return Number.isSafeInteger(count) && count >= 0 && count <= 10000;
}

async function ensureIndexes(db) {
  await db.collection("registrations").createIndex(
    { eventId: 1, userId: 1 },
    {
      unique: true,
      name: "one_registration_per_user_event"
    }
  );

  await db.collection("registrations").createIndex(
    { eventId: 1, createdAt: 1 }
  );

  await db.collection("eventSettings").createIndex(
    { eventId: 1 },
    {
      unique: true,
      name: "one_settings_document_per_event"
    }
  );

  await db.collection("calendarEvents").createIndex(
    { id: 1 },
    {
      unique: true,
      name: "one_calendar_event_id"
    }
  );

  await db.collection("calendarEvents").createIndex({ dateKey: 1 });
}

async function ensureEventSettings(db, eventId) {
  await db.collection("eventSettings").updateOne(
    { eventId },
    {
      $setOnInsert: {
        eventId,
        capacity: null,
        paidStaffCount: 0,
        registeredCount: 0,
        updatedAt: new Date()
      }
    },
    { upsert: true }
  );
}

async function registerUser(
  db,
  eventId,
  targetUser,
  addedByAdmin = false
) {
  const registrations = db.collection("registrations");
  const settings = db.collection("eventSettings");

  await ensureEventSettings(db, eventId);

  const session = db.client.startSession();
  let outcome = "error";

  try {
    await session.withTransaction(async () => {
      const event = await db.collection("calendarEvents").findOne(
        { id: eventId },
        { session, projection: { _id: 1 } }
      );

      if (!event) {
        outcome = "not-found";
        return;
      }

      const existing = await registrations.findOne(
        {
          eventId,
          userId: targetUser._id.toString()
        },
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
              {
                $eq: [
                  { $ifNull: ["$capacity", null] },
                  null
                ]
              },
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

function formatEventRoster(eventId, settings, registrations) {
  const capacity = settings?.capacity ?? null;
  const paidStaffCount = settings?.paidStaffCount ?? 0;
  const paidCount = Math.min(paidStaffCount, registrations.length);

  return {
    eventId,
    capacity,
    registeredCount: registrations.length,
    paidStaffCount,
    paidCount,
    volunteerCount: registrations.length - paidCount,

    spotsRemaining: capacity === null
      ? null
      : Math.max(0, capacity - registrations.length),

    registrations: registrations.map((registration, index) => ({
      id: registration._id.toString(),
      userId: registration.userId,
      name: registration.name,
      username: registration.username,
      createdAt: registration.createdAt,
      addedByAdmin: registration.addedByAdmin === true,
      staffType: index < paidStaffCount ? "paid" : "volunteer"
    }))
  };
}

async function getEventRoster(db, eventId) {
  const [settings, registrations] = await Promise.all([
    db.collection("eventSettings").findOne({ eventId }),

    db.collection("registrations")
      .find({ eventId })
      .sort({ createdAt: 1, _id: 1 })
      .project({
        userId: 1,
        name: 1,
        username: 1,
        createdAt: 1,
        addedByAdmin: 1
      })
      .toArray()
  ]);

  return formatEventRoster(eventId, settings, registrations);
}

async function getCalendarEvents(db) {
  const storedEvents = await db.collection("calendarEvents")
    .find({})
    .sort({ dateKey: 1, startTime: 1 })
    .limit(500)
    .toArray();

  const eventIds = storedEvents.map(event => event.id);
  const [settings, registrations] = await Promise.all([
    db.collection("eventSettings")
      .find({ eventId: { $in: eventIds } })
      .toArray(),
    db.collection("registrations")
      .find({ eventId: { $in: eventIds } })
      .sort({ eventId: 1, createdAt: 1, _id: 1 })
      .project({
        eventId: 1,
        userId: 1,
        name: 1,
        username: 1,
        createdAt: 1,
        addedByAdmin: 1
      })
      .toArray()
  ]);

  const settingsByEventId = new Map(
    settings.map(item => [item.eventId, item])
  );
  const registrationsByEventId = new Map();
  for (const registration of registrations) {
    if (!registrationsByEventId.has(registration.eventId)) {
      registrationsByEventId.set(registration.eventId, []);
    }
    registrationsByEventId.get(registration.eventId).push(registration);
  }

  return storedEvents.map(event => {
    const roster = formatEventRoster(
      event.id,
      settingsByEventId.get(event.id),
      registrationsByEventId.get(event.id) || []
    );

    return {
      id: event.id,
      title: event.title,
      dateKey: event.dateKey,
      location: event.location,
      description: event.description,
      allDay: event.allDay,
      startTime: event.startTime,
      endTime: event.endTime,
      registration: {
        capacity: roster.capacity,
        registeredCount: roster.registeredCount,
        spotsRemaining: roster.spotsRemaining,
        registrations: roster.registrations,
        signedUp: false
      }
    };
  });
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

    const adminActions = [
      "createEvent",
      "updateEvent",
      "deleteEvent",
      "setCapacity",
      "setPaidStaffCount",
      "addAttendee",
      "removeAttendee"
    ];

    if (adminActions.includes(action) && !isAdmin(user)) {
      return res.status(403).json({
        ok: false,
        error: "Administrator permission is required."
      });
    }

    const events = db.collection("calendarEvents");

    if (action === "createEvent") {
      const validated = validateEvent(body);
      if (validated.error) {
        return res.status(400).json({ ok: false, error: validated.error });
      }

      const capacity = body.capacity;
      if (!validCapacity(capacity)) {
        return res.status(400).json({
          ok: false,
          error: "Capacity must be a whole number from 0 to 10000, or null for unlimited."
        });
      }
      const paidStaffCount = body.paidStaffCount ?? 0;
      if (!validPaidStaffCount(paidStaffCount)) {
        return res.status(400).json({
          ok: false,
          error: "Paid staff slots must be a whole number from 0 to 10000."
        });
      }

      const id = new ObjectId().toString();
      const now = new Date();
      await events.insertOne({
        id,
        ...validated.event,
        createdAt: now,
        updatedAt: now,
        updatedBy: user._id.toString()
      });
      await ensureEventSettings(db, id);
      await db.collection("eventSettings").updateOne(
        { eventId: id },
        {
          $set: {
            capacity,
            paidStaffCount,
            updatedAt: now,
            updatedBy: user._id.toString()
          }
        }
      );

      return res.status(201).json({
        ok: true,
        message: "Event created.",
        eventId: id
      });
    }

    if (action === "updateEvent") {
      if (!validEventId(eventId)) {
        return res.status(400).json({
          ok: false,
          error: "A valid event ID is required."
        });
      }

      const validated = validateEvent(body);
      if (validated.error) {
        return res.status(400).json({ ok: false, error: validated.error });
      }

      const update = {
        $set: {
          ...validated.event,
          updatedAt: new Date(),
          updatedBy: user._id.toString()
        }
      };

      if (Object.prototype.hasOwnProperty.call(body, "capacity")) {
        if (!validCapacity(body.capacity)) {
          return res.status(400).json({
            ok: false,
            error: "Capacity must be a whole number from 0 to 10000, or null for unlimited."
          });
        }
      }

      if (
        Object.prototype.hasOwnProperty.call(body, "paidStaffCount") &&
        !validPaidStaffCount(body.paidStaffCount)
      ) {
        return res.status(400).json({
          ok: false,
          error: "Paid staff slots must be a whole number from 0 to 10000."
        });
      }

      if (
        Object.prototype.hasOwnProperty.call(body, "capacity") ||
        Object.prototype.hasOwnProperty.call(body, "paidStaffCount")
      ) {
        await ensureEventSettings(db, eventId);
      }

      if (Object.prototype.hasOwnProperty.call(body, "capacity")) {
        const current = await db.collection("eventSettings")
          .findOne({ eventId });
        if (
          body.capacity !== null &&
          body.capacity < (current.registeredCount || 0)
        ) {
          return res.status(409).json({
            ok: false,
            error: "Capacity cannot be lower than the current number of registrations."
          });
        }
      }

      const result = await events.updateOne({ id: eventId }, update);
      if (result.matchedCount !== 1) {
        return res.status(404).json({
          ok: false,
          error: "That event could not be found on the calendar."
        });
      }

      const settingsUpdate = {};
      if (Object.prototype.hasOwnProperty.call(body, "capacity")) {
        settingsUpdate.capacity = body.capacity;
      }
      if (Object.prototype.hasOwnProperty.call(body, "paidStaffCount")) {
        settingsUpdate.paidStaffCount = body.paidStaffCount;
      }
      if (Object.keys(settingsUpdate).length) {
        await db.collection("eventSettings").updateOne(
          { eventId },
          {
            $set: {
              ...settingsUpdate,
              updatedAt: new Date(),
              updatedBy: user._id.toString()
            }
          }
        );
      }

      return res.status(200).json({
        ok: true,
        message: "Event updated."
      });
    }

    if (action === "deleteEvent") {
      if (!validEventId(eventId)) {
        return res.status(400).json({
          ok: false,
          error: "A valid event ID is required."
        });
      }

      const session = db.client.startSession();
      let deleted = false;
      try {
        await session.withTransaction(async () => {
          const result = await events.deleteOne({ id: eventId }, { session });
          if (result.deletedCount !== 1) return;

          await db.collection("registrations").deleteMany(
            { eventId },
            { session }
          );
          await db.collection("eventSettings").deleteOne(
            { eventId },
            { session }
          );
          deleted = true;
        });
      } finally {
        await session.endSession();
      }

      if (!deleted) {
        return res.status(404).json({
          ok: false,
          error: "That event could not be found on the calendar."
        });
      }

      return res.status(200).json({
        ok: true,
        message: "Event and its registrations deleted."
      });
    }

    if (!validEventId(eventId)) {
      return res.status(400).json({
        ok: false,
        error: "A valid event ID is required."
      });
    }

    const exists = await events.findOne({ id: eventId }, { projection: { _id: 1 } });
    if (!exists) {
      return res.status(404).json({
        ok: false,
        error: "That event could not be found on the calendar."
      });
    }

    if (action === "signup") {
      const result = await registerUser(db, eventId, user);

      if (result === "not-found") {
        return res.status(404).json({
          ok: false,
          error: "That event could not be found on the calendar."
        });
      }

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

    if (action === "setCapacity") {
      const capacity = body.capacity;

      if (!validCapacity(capacity)) {
        return res.status(400).json({
          ok: false,
          error: "Capacity must be a whole number from 0 to 10000, or null for unlimited."
        });
      }

      await ensureEventSettings(db, eventId);

      const current = await db.collection("eventSettings")
        .findOne({ eventId });

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

    if (action === "setPaidStaffCount") {
      const paidStaffCount = body.paidStaffCount;
      if (!validPaidStaffCount(paidStaffCount)) {
        return res.status(400).json({
          ok: false,
          error: "Paid staff slots must be a whole number from 0 to 10000."
        });
      }

      await ensureEventSettings(db, eventId);
      await db.collection("eventSettings").updateOne(
        { eventId },
        {
          $set: {
            paidStaffCount,
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

      const result = await registerUser(
        db,
        eventId,
        targetUser,
        true
      );

      if (result === "not-found") {
        return res.status(404).json({
          ok: false,
          error: "That event could not be found on the calendar."
        });
      }

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

      const removed = await withdrawUser(
        db,
        eventId,
        body.userId
      );

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
