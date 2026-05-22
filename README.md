# NetShare — WireGuard + VPS Edition

A full-stack internet-sharing app. A **host** device shares its internet connection; **clients** connect via a WireGuard tunnel routed through your VPS.

## Why WireGuard instead of Cloudflare?

| | Old (Cloudflare) | New (WireGuard + VPS) |
|---|---|---|
| Protocol | WebSocket over HTTPS | WireGuard UDP |
| Latency | High (CF hop + WS overhead) | ~3× lower |
| Throughput | Limited by CF Workers | Limited only by VPS NIC |
| Cost | Cloudflare plan | ~$5/mo VPS |
| Privacy | CF sees all traffic | Only your VPS sees it |
| Reliability | CF quota limits | No quotas |

---

## Architecture

```
[Client Device]                    [Host Device]
  Selected apps                      All outbound
     │                                    │
  WireGuard TUN                    WireGuard TUN
     │                                    │
  UDP:51820                          UDP:51820
     └──────────────┐  ┌─────────────────┘
                    ▼  ▼
              ┌──────────────┐
              │  Your VPS    │
              │  wg0 iface   │◄── Relay API :4000
              │  NAT masq    │    (session mgmt)
              └──────┬───────┘
                     │
                  Internet
```

### Split-tunnel (no background drain)

The Android VPN builder uses `addAllowedApplication()` instead of routing *all* device traffic. Only the apps the user selects enter the tunnel:

```
System / Email / Maps → real network (no VPN)
TikTok / YouTube     → WireGuard tunnel → VPS → Host internet
```

This is the fix for *"doesn't consume client internet in the background"*.

---

## VPS Setup

### 1. Provision a VPS

Any Ubuntu 22.04 VPS works. Recommended:
- **DigitalOcean / Vultr / Hetzner** — $4–6/mo, 1 vCPU, 1 GB RAM
- Port **51820/UDP** open (WireGuard)
- Port **4000/TCP** open (relay API)

### 2. Run the setup script

```bash
scp vps/setup.sh root@YOUR_VPS_IP:/root/
ssh root@YOUR_VPS_IP "chmod +x setup.sh && ./setup.sh"
```

This installs WireGuard, Node.js 20, PM2, configures `wg0`, and enables NAT masquerade.

### 3. Deploy the relay server

```bash
scp backend/server.js root@YOUR_VPS_IP:/opt/netshare-relay/
ssh root@YOUR_VPS_IP
cd /opt/netshare-relay
cp .env.example .env
nano .env   # set VPS_ENDPOINT=YOUR_VPS_IP:51820
pm2 start server.js --name netshare-relay
pm2 save
```

### 4. Verify

```bash
# WireGuard
wg show wg0

# Relay API
curl http://localhost:4000/health
# → {"ok":true,"sessions":0}
```

---

## App Setup

### 1. Configure the relay URL

Edit `app/src/services/WireGuardService.js`:

```js
export const RELAY_URL = 'https://YOUR_VPS_IP_OR_DOMAIN:4000';
```

For HTTPS (recommended), put Nginx in front with a Let's Encrypt cert:

```nginx
server {
    listen 443 ssl;
    server_name vpn.yourdomain.com;
    ssl_certificate     /etc/letsencrypt/live/vpn.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vpn.yourdomain.com/privkey.pem;
    location / { proxy_pass http://localhost:4000; proxy_http_version 1.1;
                 proxy_set_header Upgrade $http_upgrade;
                 proxy_set_header Connection "upgrade"; }
}
```

### 2. Install dependencies

```bash
cd app
npm install

# Android only — add Bouncy Castle for Android < 13 X25519 support
# In android/app/build.gradle, inside dependencies {}:
#   implementation 'org.bouncycastle:bcprov-jdk15on:1.70'
```

### 3. Merge AndroidManifest entries

Copy the entries from `android/app/src/main/AndroidManifest.additions.xml`
into your `AndroidManifest.xml`.

### 4. Register the native module

In `android/app/src/main/java/com/netshare/MainApplication.java`:

```java
// Inside getPackages():
packages.add(new VpnPackage());
```

Create `VpnPackage.java`:

```java
package com.netshare;
import com.facebook.react.ReactPackage;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.uimanager.ViewManager;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class VpnPackage implements ReactPackage {
    @Override
    public List<NativeModule> createNativeModules(ReactApplicationContext ctx) {
        return Arrays.asList(new VpnModule(ctx));
    }
    @Override
    public List<ViewManager> createViewManagers(ReactApplicationContext ctx) {
        return Collections.emptyList();
    }
}
```

In `MainActivity.java`, add:

```java
private VpnModule vpnModule;

@Override
protected void onActivityResult(int req, int res, Intent data) {
    super.onActivityResult(req, res, data);
    if (vpnModule == null) {
        vpnModule = (VpnModule) getReactNativeHost()
            .getReactInstanceManager()
            .getCurrentReactContext()
            .getNativeModule(VpnModule.class);
    }
    if (vpnModule != null) vpnModule.onActivityResult(req, res, data);
}
```

### 5. Build & run

```bash
npx react-native run-android
```

---

## File Map

```
netshare-wg/
├── vps/
│   └── setup.sh                  ← Run once on VPS to configure WireGuard + Node
│
├── backend/
│   ├── server.js                 ← Relay API (peer management, session codes, stats)
│   ├── package.json
│   └── .env.example
│
└── app/
    ├── App.jsx                   ← Root component
    ├── package.json
    ├── src/
    │   ├── services/
    │   │   └── WireGuardService.js   ← All VPS API calls + VPN start/stop
    │   ├── store/
    │   │   └── index.js              ← Redux state + async thunks + event bridge
    │   └── screens/
    │       └── HomeScreen.jsx        ← Full UI: idle / connect / connected
    └── android/app/src/main/
        ├── AndroidManifest.additions.xml
        └── java/com/netshare/
            ├── NetShareVpnService.java   ← WireGuard TUN + I/O loops + keepalive
            └── VpnModule.java            ← React Native bridge (keygen, start, stop, stats)
```

---

## How sessions work

```
HOST                          VPS RELAY                      CLIENT
 │                                │                              │
 │── POST /host/register ────────►│                              │
 │◄─ { sessionCode, wgConfig } ───│                              │
 │                                │                              │
 │── WG handshake (UDP 51820) ───►│                              │
 │◄─ handshake response ──────────│                              │
 │   [tunnel established]         │                              │
 │                                │◄── POST /client/join ────────│
 │                                │─── { wgConfig } ────────────►│
 │◄── WS: clientConnected ────────│                              │
 │                                │◄── WG handshake (UDP 51820)──│
 │                                │─── handshake response ───────►│
 │                                │   [tunnel established]        │
 │                                │                              │
 │   [client traffic flows]       │                              │
 │   Client → VPS → Host → Internet                             │
```

The VPS performs **NAT masquerade**: all client traffic appears to originate from the VPS's public IP, which WireGuard routes to the host peer, which then exits through the host's internet connection.

---

## Rate limiting / Fair bandwidth

The relay server applies `fq_codel` (Fair Queue Controlled Delay) on the `wg0` interface via `tc`. This gives each client a fair share of the available bandwidth and prevents any one client from saturating the host's uplink. No fixed cap is set — the queue adapts to actual throughput.

To set a hard cap per client (optional), add to `setup.sh`:

```bash
tc qdisc add dev wg0 root handle 1: htb default 10
tc class add dev wg0 parent 1: classid 1:10 htb rate 5mbit ceil 10mbit
```

---

## Security notes

- WireGuard private keys are generated on-device and never leave the device.
- The relay server only stores public keys and allocated IPs.
- Session codes expire when the host disconnects (60-second grace period).
- Set a strong `ADMIN_KEY` in `.env` before deploying.
- For production: put the relay API behind HTTPS (Nginx + Let's Encrypt).
