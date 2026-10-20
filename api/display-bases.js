const { MongoClient, ObjectId } = require("mongodb");
const crypto = require("crypto");
const { setCorsHeaders } = require("./_cors");

const SESSION_COOKIE = "mrs_session";
let cachedClient = global.portalDisplayBasesMongoClient;

async function getMongoClient() {
  if (!process.env.MONGODB_URI) {
    throw new Error("Database configuration is missing.");
  }

  if (!cachedClient) {
    cachedClient = new MongoClient(process.env.MONGODB_URI);
    await cachedClient.connect();
    global.portalDisplayBasesMongoClient = cachedClient;
  }

  return cachedClient;
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

function text(value, fallback = "") {
  return typeof value === "string" || typeof value === "number"
    ? String(value).trim()
    : fallback;
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

  const month = typeof req.query?.month === "string" ? req.query.month : "";
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(month)) {
    return res.status(400).json({ ok: false, error: "A valid month in YYYY-MM format is required." });
  }

  try {
    const client = await getMongoClient();
    const portalDb = client.db(process.env.PORTAL_DB_NAME || "MRSStaffPortal");
    const scheduleDb = client.db("ApparatusCheck");
    const session = verifySession(getCookie(req, SESSION_COOKIE));
    const user = session
      ? await portalDb.collection("users").findOne(
        {
          _id: new ObjectId(session.uid),
          active: true,
          approved: true
        },
        { projection: { _id: 1 } }
      )
      : null;

    const monthStart = `${month}-01`;
    const [year, monthNumber] = month.split("-").map(Number);
    const nextMonth = new Date(Date.UTC(year, monthNumber, 1));
    const monthEnd = `${nextMonth.getUTCFullYear()}-${String(nextMonth.getUTCMonth() + 1).padStart(2, "0")}-01`;
    const shifts = await scheduleDb.collection("schedules")
      .find({ date: { $gte: monthStart, $lt: monthEnd } })
      .sort({ date: 1, shift: 1, time: 1 })
      .limit(1000)
      .project({
        _id: 0,
        date: 1,
        shift: 1,
        time: 1,
        base: 1,
        station: 1,
        location: 1,
        employee: 1,
        unassigned: 1
      })
      .toArray();

    return res.status(200).json({
      ok: true,
      authenticated: Boolean(user),
      month,
      shifts: shifts.map(shift => ({
        date: text(shift.date),
        shift: text(shift.shift),
        time: text(shift.time),
        base: text(shift.base || shift.station || shift.location, "Base"),
        employee: user ? text(shift.employee, shift.unassigned ? "Unassigned" : "") : "",
        unassigned: shift.unassigned === true || shift.employee === "(Unassigned)"
      }))
    });
  } catch (error) {
    console.error("Base schedule display API error:", error.message);
    return res.status(500).json({
      ok: false,
      error: "Unable to load the base schedule."
    });
  }
};
