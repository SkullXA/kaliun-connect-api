# Kaliun Connect API

Backend API for Kaliun device registration, claiming, and OAuth2 authentication.

## Features

- **Device Registration & Claiming**: KaliunBox devices register and get claimed by users
- **OAuth2 Device Code Flow**: Home Assistant integration authentication
- **Health Reporting**: Device health metrics collection
- **User Authentication**: Magic link (email) authentication
- **Web UI**: Login, claim devices, view installations

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Or start production server
npm start
```

Server runs at `http://localhost:7331`

## API Endpoints

### Device APIs (for KaliunBox)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/installations/register` | Register new device |
| GET | `/api/v1/installations/:id/config` | Get device config (poll for claim) |
| DELETE | `/api/v1/installations/:id/config` | Confirm config received |
| POST | `/api/v1/installations/token/refresh` | Refresh tokens |
| POST | `/api/v1/installations/:id/health` | Submit health report |

### OAuth2 (for Home Assistant)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/oauth/device/code` | Request device code |
| POST | `/oauth/token` | Exchange code for token |
| GET | `/oauth/userinfo` | Get user info |

### Web UI

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/login` | Login page |
| GET | `/claim/:code` | Claim device page |
| GET | `/installations` | View installations |
| GET | `/link` | OAuth device code authorization |
| GET | `/settings` | Account settings |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `7331` | Server port |
| `BASE_URL` | `http://localhost:7331` | Public URL |
| `JWT_SECRET` | (dev default) | JWT signing secret |
| `DATABASE_PATH` | `./kaliun.db` | SQLite database path |

## Device Flow

1. **Device boots** → Generates `install_id` (UUID)
2. **Device registers** → `POST /api/v1/installations/register` → Gets `claim_code`
3. **Device displays** → QR code + claim code on console
4. **User scans/enters code** → Goes to `/claim/:code`
5. **User claims** → Fills in details, submits form
6. **Device polls** → `GET /api/v1/installations/:id/config`
7. **Device gets config** → Full config with tokens
8. **Device confirms** → `DELETE /api/v1/installations/:id/config`
9. **Device starts** → Normal operation with health reporting

## OAuth2 Device Code Flow (RFC 8628)

Used by Home Assistant integration:

1. **HA requests code** → `POST /oauth/device/code`
2. **HA shows code** → User sees "XXXX-XXXX" and URL
3. **User authorizes** → Goes to `/link?code=XXXX-XXXX`, logs in, authorizes
4. **HA polls** → `POST /oauth/token` until authorized
5. **HA gets token** → Uses for API calls

## Development

```bash
# Watch mode with auto-reload
npm run dev
```

Magic link emails are printed to console in dev mode.

## Deployment (Railway)

1. Create new project in Railway
2. Connect GitHub repo
3. Add environment variables:
   - `PORT` (Railway sets this automatically)
   - `BASE_URL=https://connect.kaliun.com`
   - `JWT_SECRET=your-production-secret`
4. Deploy!

## License

MIT












