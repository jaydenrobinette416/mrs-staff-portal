
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

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
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

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET, OPTIONS");
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

    const bridgeUrl = process.env.GOOGLE_CALENDAR_BRIDGE_URL;
    const bridgeSecret = process.env.PORTAL_API_SECRET;

    if (!bridgeUrl || !bridgeSecret) {
      return res.status(500).json({
        ok: false,
        error: "Calendar integration is not configured."
      });
    }

    const url = new URL(bridgeUrl);
    url.searchParams.set("action", "events");
    url.searchParams.set("secret", bridgeSecret);

    const response = await fetch(url.toString(), {
      method: "GET",
      redirect: "follow"
    });

    if (!response.ok) {
      console.error("Calendar bridge returned HTTP", response.status);
      return res.status(502).json({
        ok: false,
        error: "Unable to retrieve calendar events."
      });
    }

    const data = await response.json();

    if (!data.ok || !Array.isArray(data.events)) {
      console.error("Calendar bridge returned an invalid response.");
      return res.status(502).json({
        ok: false,
        error: "Calendar bridge returned an invalid response."
      });
    }

    return res.status(200).json({
      ok: true,
      events: data.events
    });
  } catch (error) {
    console.error("Calendar API error:", error.message);

    return res.status(500).json({
      ok: false,
      error: "Unable to retrieve calendar events."
    });
  }
};
