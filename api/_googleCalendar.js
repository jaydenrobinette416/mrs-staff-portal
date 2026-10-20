async function sendGoogleCalendarRequest(payload) {
  const bridgeUrl = process.env.GOOGLE_CALENDAR_BRIDGE_URL;
  const bridgeSecret = process.env.GOOGLE_CALENDAR_BRIDGE_SECRET;
  if (!bridgeUrl || !bridgeSecret) {
    return { configured: false, synced: false };
  }

  let url;
  try {
    url = new URL(bridgeUrl);
  } catch {
    throw new Error("Google Calendar bridge URL is invalid.");
  }
  if (url.protocol !== "https:") {
    throw new Error("Google Calendar bridge URL must use HTTPS.");
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...payload, secret: bridgeSecret }),
      signal: controller.signal
    });
    const text = await response.text();
    let result;
    try {
      result = JSON.parse(text);
    } catch {
      throw new Error("Google Calendar bridge returned an unexpected response.");
    }
    if (!response.ok || !result.ok) {
      throw new Error(result.error || "Google Calendar bridge rejected the update.");
    }
    return { configured: true, synced: true };
  } finally {
    clearTimeout(timeout);
  }
}

module.exports = { sendGoogleCalendarRequest };
