TELEGRAM CONTROL CENTER

A mobile-first Telegram messaging and automation dashboard.

SETUP
1. Create Telegram API credentials at my.telegram.org -> API development tools.
2. Copy .env.example to .env.
3. Set API_ID and API_HASH.
4. Set a strong PANEL_PASSWORD when the dashboard is exposed beyond localhost.
5. Run:
     npm install
     npm start
6. Open http://localhost:3000 and connect Telegram with the QR code.

FEATURES
- Individual message sender with rich text formatting.
- Recipient search and chat-type filters.
- Persistent automation jobs with start time, interval, gap and max rounds.
- Pause, resume, stop and delete jobs.
- Templates stored in telegram-data.json.
- Persistent sending history with retry for failed messages.
- Dashboard statistics and recent activity.
- Telegram FloodWait / Slowmode aware sending.
- Mobile-first responsive interface.

IMPORTANT SECURITY
- Never share .env or session.txt.
- session.txt is a live Telegram login session and should be treated like a password.
- telegram-data.json contains local job/template/history data and should not be committed if it contains sensitive message content.
- The project ZIP should never include node_modules, .env or session.txt.
