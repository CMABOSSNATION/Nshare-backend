# NetShare VPS — WireGuard Edition

**No mobile app required.** Users download the official WireGuard app and import a config file.

---

## Architecture

```
Admin (you)           VPS (this backend)           Users
──────────           ───────────────────           ─────
Browser admin  ───►  Node.js API (port 4000)
panel                WireGuard (port 51820)  ◄───  Official WireGuard app
                     iptables NAT                  (Android/iOS/Windows/Mac)
```

## Files

```
netshare-relay/
├── server.js           ← Main API + WireGuard peer manager
├── package.json
├── ecosystem.config.cjs  ← PM2 config (set your IP + password here)
├── setup.sh            ← Run once on fresh VPS
├── admin/
│   └── index.html      ← Admin panel (served at /admin)
└── download.html       ← User-facing download page (served at / and /download)
```

---

## Deployment

### Step 1 — Run setup on your VPS

```bash
ssh root@YOUR_VPS_IP
# Upload setup.sh then:
chmod +x setup.sh
VPS_ENDPOINT="YOUR_IP:51820" ADMIN_KEY="yourpassword" ./setup.sh
```

### Step 2 — Upload files

Upload these files to `/opt/netshare-relay/` on your VPS:
- `server.js`
- `package.json`
- `ecosystem.config.cjs`
- `download.html`
- `admin/index.html`  (in the `admin/` subfolder)

### Step 3 — Edit ecosystem.config.cjs

```js
VPS_ENDPOINT: '1.2.3.4:51820',   // your real VPS public IP
ADMIN_KEY:    'yourpassword',     // admin panel password
```

### Step 4 — Start the server

```bash
cd /opt/netshare-relay
npm install
pm2 start ecosystem.config.cjs
pm2 save
```

---

## Using the Admin Panel

Open `http://YOUR_VPS_IP:4000/admin` in any browser.

### Create a Host Code
1. Click **+ New Host Code**
2. Add a label (e.g. "Raphael's phone")
3. Click **Create Code(s)**
4. Copy the download link → share with host user

### Create Client Codes
1. Host must connect first (so a session exists)
2. Click **+ Client Codes**
3. Select the host session from the dropdown
4. Set count (e.g. 5 codes for 5 users)
5. Share the download links with each client

### Admin tasks
- **Sessions tab** — see who's connected, kick clients, end sessions
- **Codes tab** — see all codes, delete unused/compromised codes
- **Server tab** — view server pubkey, restart WireGuard

---

## User Flow

1. User receives link: `http://YOUR_IP:4000/download?code=CXXXX-XXXX`
2. Opens it in any browser on their phone
3. Taps **Download WireGuard Config** → gets a `.conf` file
4. Opens WireGuard app → `+` → **Import from file** → select file
5. Toggles tunnel ON → connected!

### WireGuard app download links for users
- Android: https://play.google.com/store/apps/details?id=com.wireguard.android
- iOS:     https://apps.apple.com/app/wireguard/id1441195209
- Windows: https://www.wireguard.com/install/

---

## API Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | — | Server status |
| GET | `/config?code=XXXX` | — | Download WireGuard .conf |
| GET | `/config/info?code=XXXX` | — | Check code validity |
| GET | `/download` | — | User download page |
| GET | `/admin` | — | Admin panel UI |
| POST | `/admin/codes/create` | Admin | Create access codes |
| GET | `/admin/codes` | Admin | List all codes |
| DELETE | `/admin/codes/:code` | Admin | Delete a code |
| GET | `/admin/sessions` | Admin | List active sessions |
| DELETE | `/admin/sessions/:id` | Admin | End a session |
| DELETE | `/admin/sessions/:id/clients/:cid` | Admin | Kick one client |
| GET | `/admin/stats` | Admin | Dashboard numbers |
| POST | `/admin/wg/restart` | Admin | Restart WireGuard |

Admin auth: `x-admin-key: YOUR_ADMIN_KEY` header

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `4000` | API port |
| `ADMIN_KEY` | `change-me-NOW` | Admin password |
| `WG_IFACE` | `wg0` | WireGuard interface name |
| `VPS_ENDPOINT` | *(required)* | Your VPS `IP:51820` |
| `MAX_CLIENTS` | `10` | Max clients per host session |
| `DATA_FILE` | `/opt/netshare-relay/data.json` | State persistence file |

---

## Firewall (UFW)

The setup script opens these ports:
- `22/tcp` — SSH
- `51820/udp` — WireGuard
- `4000/tcp` — API + Admin panel

To restrict admin panel to your IP only (recommended):
```bash
ufw delete allow 4000/tcp
ufw allow from YOUR_HOME_IP to any port 4000
```

---

## Optional: Nginx reverse proxy + HTTPS

```nginx
server {
    listen 443 ssl;
    server_name netshare.yourdomain.com;
    ssl_certificate     /etc/letsencrypt/live/.../fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/.../privkey.pem;

    location / {
        proxy_pass http://localhost:4000;
        proxy_set_header Host $host;
    }
}
```

Then `certbot --nginx -d netshare.yourdomain.com` for free HTTPS.
