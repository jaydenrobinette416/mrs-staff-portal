const CALENDAR_ID = "c_76d544ac64718001f1f50d49c4f3ff55810ded6d4b4c8b44094446c7a0501c5a@group.calendar.google.com";
const EVENT_TAG = "portalEventId";

function authorizeCalendarAccess() {
  const calendar = CalendarApp.getCalendarById(CALENDAR_ID);
  if (!calendar) {
    throw new Error("Google Calendar was not found or this account cannot edit it.");
  }
  return calendar.getName();
}

function doPost(e) {
  try {
    const request = JSON.parse(e.postData.contents);
    const configuredSecret = PropertiesService.getScriptProperties()
      .getProperty("BRIDGE_SECRET");
    if (!configuredSecret || request.secret !== configuredSecret) {
      return jsonResponse({ ok: false, error: "Unauthorized." });
    }

    const calendar = CalendarApp.getCalendarById(CALENDAR_ID);
    if (!calendar) {
      return jsonResponse({ ok: false, error: "Google Calendar was not found or is not accessible." });
    }
    if (typeof request.eventId !== "string" || !/^[a-f\d]{24}$/i.test(request.eventId)) {
      return jsonResponse({ ok: false, error: "Invalid portal event ID." });
    }

    const properties = PropertiesService.getScriptProperties();
    const mappingKey = "event_" + request.eventId;
    const googleEventId = properties.getProperty(mappingKey);

    if (request.action === "delete") {
      if (googleEventId) {
        const existing = calendar.getEventById(googleEventId);
        if (existing) existing.deleteEvent();
        properties.deleteProperty(mappingKey);
      }
      return jsonResponse({ ok: true });
    }

    if (request.action !== "upsert" || !request.event) {
      return jsonResponse({ ok: false, error: "Unknown calendar action." });
    }

    const details = request.event;
    if (
      typeof details.title !== "string" ||
      typeof details.dateKey !== "string" ||
      !/^\d{4}-\d{2}-\d{2}$/.test(details.dateKey)
    ) {
      return jsonResponse({ ok: false, error: "Invalid event details." });
    }

    const dateParts = details.dateKey.split("-").map(Number);
    const date = new Date(dateParts[0], dateParts[1] - 1, dateParts[2]);
    let googleEvent = googleEventId ? calendar.getEventById(googleEventId) : null;
    const description = formatDescription(details);

    if (details.allDay) {
      if (!googleEvent) {
        googleEvent = calendar.createAllDayEvent(details.title, date);
      } else {
        googleEvent.setAllDayDate(date);
        googleEvent.setTitle(details.title);
      }
    } else {
      if (
        typeof details.startTime !== "string" ||
        typeof details.endTime !== "string" ||
        !/^([01]\d|2[0-3]):[0-5]\d$/.test(details.startTime) ||
        !/^([01]\d|2[0-3]):[0-5]\d$/.test(details.endTime)
      ) {
        return jsonResponse({ ok: false, error: "Invalid event times." });
      }
      const start = dateAtTime(date, details.startTime);
      const end = dateAtTime(date, details.endTime);
      if (end <= start) {
        return jsonResponse({ ok: false, error: "Event end time must follow its start time." });
      }
      if (!googleEvent) {
        googleEvent = calendar.createEvent(details.title, start, end);
      } else {
        googleEvent.setTime(start, end);
        googleEvent.setTitle(details.title);
      }
    }

    googleEvent.setLocation(details.location || "");
    googleEvent.setDescription(description);
    googleEvent.setTag(EVENT_TAG, request.eventId);
    properties.setProperty(mappingKey, googleEvent.getId());
    return jsonResponse({ ok: true });
  } catch (error) {
    console.error("Google Calendar bridge error: " + error.message);
    return jsonResponse({
      ok: false,
      error: String(error.message || "Unable to update Google Calendar.").slice(0, 300)
    });
  }
}

function dateAtTime(date, time) {
  const [hours, minutes] = time.split(":").map(Number);
  const result = new Date(date.getTime());
  result.setHours(hours, minutes, 0, 0);
  return result;
}

function formatDescription(event) {
  const sections = [];
  if (event.description) sections.push(event.description);

  const registration = event.registration || {};
  const attendees = Array.isArray(registration.registrations)
    ? registration.registrations
    : [];
  const paid = attendees.filter(person => person.staffType === "paid");
  const volunteers = attendees.filter(person => person.staffType === "volunteer");

  sections.push(
    "Paid staff (" + paid.length + "/" + (registration.paidStaffCount || 0) + "):\n" +
      (paid.length ? paid.map(person => "- " + person.name).join("\n") : "- None")
  );
  sections.push(
    "Volunteers (" + volunteers.length + "):\n" +
      (volunteers.length ? volunteers.map(person => "- " + person.name).join("\n") : "- None")
  );
  return sections.join("\n\n");
}

function jsonResponse(data) {
  return ContentService
    .createTextOutput(JSON.stringify(data))
    .setMimeType(ContentService.MimeType.JSON);
}
