# Chinese Character Writer

Hosted web app for learning Chinese characters with real user accounts. Lists sync across phone, desktop, and any other device.

## Features
- Register / login (accounts stored on the server)
- Create, edit, save, and delete personal vocabulary lists
- Stroke-order animation with numbered strokes (Learn mode)
- Writing practice quizzes
- Automatic pinyin with tone marks
- Dictation, quiz, and learn modes
- **Progress tracking**: records every successful practice (character, times practiced, success rate, last practiced date)

## Run locally

```bash
cd chinese-writer-app
npm install
npm start
```

Open http://localhost:3000

## Deploy on Render.com (one-click friendly)

1. Push this folder to a GitHub repository.
2. On [Render](https://render.com) → New → Blueprint → connect the repo (it will detect `render.yaml`).
3. Or manually: New → Web Service → connect repo.
   - Build: `npm install`
   - Start: `npm start`
   - Add environment variable `SESSION_SECRET` (long random string).
4. Deploy. You get a public URL.

## Login options
- Username + password (or email + password)
- **Google** login (set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`)
- Students can reset their own password via email (configure SMTP for production emails; in development the reset link is returned in the response)

Apple Sign In requires an Apple Developer account and is not included yet. Google covers most cases.

## Deploy on Railway (recommended free alternative)

1. Push the project to GitHub (make sure `railway.toml` is included).
2. Go to [railway.app](https://railway.app) and sign in with GitHub.
3. New Project → Deploy from GitHub repo → select this repository.
4. Railway will detect the Node app.
5. (Optional but recommended) Add a Volume so the database persists:
   - Service → Volumes → Add volume
   - Mount path: `/app`
6. Add variables if you want:
   - `SESSION_SECRET` = any long random string
   - `NODE_ENV` = production
7. Deploy. You get a public URL.

First person to register becomes the parent/teacher.

## Local run

```bash
cd chinese-writer-app
npm install
npm start
```

Open http://localhost:3000

## Features
- Multi-user accounts with saved logins
- Personal vocab lists
- Stroke-order practice with numbered strokes
- Progress tracking per user
- Admin panel (first user is admin): view users and reset passwords
- Automatic pinyin with tone marks

