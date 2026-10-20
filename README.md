# Maiden Rescue Squad Staff Portal

- `index.html` — staff portal, login, and standalone event calendar
- `api/` — Vercel serverless endpoints for accounts, sessions, calendar registrations, resources, and announcements

## Favicon

Both the staff portal and admin page use `favicon.png` from the project root.
Add your PNG image there using that filename; a square image at 32 × 32 pixels
or larger is recommended.

## Calendar

Calendar events are stored in the portal's MongoDB database in the `calendarEvents`
collection. Approved administrators can create, edit, and delete events from the
calendar; approved staff can sign up, withdraw, and view attendee lists. Signup
capacity and registrations are stored in the `eventSettings` and `registrations`
collections. Event paid staff slots are filled by signup order; additional
registrations are labeled as volunteers. The overall registration limit remains
an independent cap.

### Google Calendar sync

Portal events are mirrored to the Google Calendar configured in
`google-calendar-bridge.gs`. Event edits, signups, withdrawals, paid-slot
changes, admin attendee changes, and event deletions are synchronized. The
Google Calendar event title shows paid and volunteer names in its preview; the
event description also includes the full separate name lists. Anyone who can
view the Google Calendar events can see the roster.

To enable syncing:

1. Create a Google Apps Script project and copy in `google-calendar-bridge.gs`.
2. In **Project Settings → Script Properties**, add `BRIDGE_SECRET` with a
   unique random secret. Use the same secret as the
   `GOOGLE_CALENDAR_BRIDGE_SECRET` Vercel environment variable; do not commit it.
3. Set the Apps Script project time zone to `America/New_York`.
4. Select and run `authorizeCalendarAccess` once in the Apps Script editor, and
   authorize Calendar access. Make sure the Google account running the script
   can edit the target calendar.
5. Deploy as a **Web app**, executing as your account. Set access to **Anyone**
   so the portal API can call it; the shared secret protects the endpoint.
6. Add the deployed `/exec` URL to Vercel as `GOOGLE_CALENDAR_BRIDGE_URL`, and
   add `GOOGLE_CALENDAR_BRIDGE_SECRET` with the same secret. Redeploy the API.

The bridge is set to the calendar ID supplied for this portal. Sync failures
are queued and retried on later calendar API requests; the portal reports when
an update is pending. Existing portal events are also queued for an initial
sync after the bridge is configured.

If the portal reports **Unauthorized**, the bridge URL is reachable but the
shared secret was rejected. Confirm the Apps Script property name is exactly
`BRIDGE_SECRET`, compare its value with Vercel's
`GOOGLE_CALENDAR_BRIDGE_SECRET` (without quotes), save both, and redeploy the
Apps Script web app using a new version and redeploy the Vercel API. Do not
share either secret.

## Staff resources

Approved staff can browse shared web links and download uploaded files.
Administrators can add links, upload files, and delete resources from the Staff
Resources section. Link addresses can be entered as a domain (for example,
`emrs.catawbacountync.gov`) or a full `http://`/`https://` address; `https://`
is added automatically when omitted. Uploaded files are stored in MongoDB GridFS in the
`resourceFiles` bucket; resource details are stored in the `resources`
collection. Uploads are limited to 3 MB and supported PDF, Office, text, CSV,
JPEG, PNG, and WebP files.

## Announcements

Approved staff can view the 100 most recent announcements. Administrators can
post announcements with a title and message, and delete announcements. Records
are stored in the `announcements` collection in the portal MongoDB database.

Events and signup rosters previously supplied by Google Calendar are not
imported automatically. Re-create events that should remain on the portal;
staff will need to sign up for those new events.

## GitHub Pages
1. Open repository **Settings → Pages**.
2. Under **Build and deployment**, choose **Deploy from a branch**.
3. Choose branch `main` and folder `/(root)`, then save.

## Vercel
1. Import this same repository into Vercel.
2. Keep the project root at the repository root.
3. Deploy. Vercel should detect `api/health.js` as `/api/health`.
4. Open `https://YOUR-VERCEL-PROJECT.vercel.app/api/health` to test it.

Never put database credentials or secrets in this repository. Configure
`MONGODB_URI` and `SESSION_SECRET` in the API deployment's environment variables;
the calendar uses the same MongoDB database as staff accounts.
