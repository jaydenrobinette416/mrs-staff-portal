# Maiden Rescue Squad Staff Portal

- `index.html` — staff portal, login, and standalone event calendar
- `api/` — Vercel serverless endpoints for accounts, sessions, and calendar registrations

## Calendar

Calendar events are stored in the portal's MongoDB database in the `calendarEvents`
collection. Approved administrators can create, edit, and delete events from the
calendar; approved staff can sign up, withdraw, and view attendee lists. Signup
capacity and registrations are stored in the `eventSettings` and `registrations`
collections. Event paid staff slots are filled by signup order; additional
registrations are labeled as volunteers. The overall registration limit remains
an independent cap. No Google Calendar connection is used.

## Staff resources

Approved staff can browse shared web links and download uploaded files.
Administrators can add links, upload files, and delete resources from the Staff
Resources section. Uploaded files are stored in MongoDB GridFS in the
`resourceFiles` bucket; resource details are stored in the `resources`
collection. Uploads are limited to 3 MB and supported PDF, Office, text, CSV,
JPEG, PNG, and WebP files.

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
