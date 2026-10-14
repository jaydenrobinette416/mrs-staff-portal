
const ALLOWED_ORIGIN = "https://portal.maidenrescuesquad.org";

function setCors(req, res) {
  const origin = req.headers.origin;

  if (origin === ALLOWED_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }

  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Vary", "Origin");
}

module.exports = async function handler(req, res) {
  setCors(req, res);

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "GET") {
    return res.status(405).json({
      ok: false,
      error: "Method not allowed"
    });
  }

  try {
    const bridgeUrl = process.env.GOOGLE_CALENDAR_BRIDGE_URL;
    const secret = process.env.PORTAL_API_SECRET;

    if (!bridgeUrl || !secret) {
      return res.status(500).json({
        ok: false,
        error: "Calendar integration is not configured"
      });
    }

    const url = new URL(bridgeUrl);
    url.searchParams.set("action", "events");
    url.searchParams.set("secret", secret);

    const response = await fetch(url.toString(), {
      method: "GET",
      redirect: "follow"
    });

    if (!response.ok) {
      return res.status(502).json({
        ok: false,
        error: "Calendar bridge request failed"
      });
    }

    const data = await response.json();

    if (!data.ok || !Array.isArray(data.events)) {
      return res.status(502).json({
        ok: false,
        error: "Calendar bridge returned an invalid response"
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
      error: "Unable to retrieve calendar events"
    });
  }
};
