# Maiden Rescue Squad Staff Portal

Starter repository for the staff portal.

- `index.html` — static website for GitHub Pages
- `api/health.js` — first Vercel serverless API endpoint

## GitHub Pages
1. Open repository **Settings → Pages**.
2. Under **Build and deployment**, choose **Deploy from a branch**.
3. Choose branch `main` and folder `/(root)`, then save.

## Vercel
1. Import this same repository into Vercel.
2. Keep the project root at the repository root.
3. Deploy. Vercel should detect `api/health.js` as `/api/health`.
4. Open `https://YOUR-VERCEL-PROJECT.vercel.app/api/health` to test it.

Never put database credentials or secrets in this repository. MongoDB will be connected later using Vercel Environment Variables.
