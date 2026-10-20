const { MongoClient } = require("mongodb");
const { setCorsHeaders } = require("./_cors");

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

    return res.status(200).json({
      ok: true,
      events: events.map(event => ({
        id: event.id,
        title: event.title || "Untitled event",
        dateKey: event.dateKey,
        description: event.description || "",
        allDay: event.allDay === true,
        startTime: event.startTime || "",
        endTime: event.endTime || ""
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
