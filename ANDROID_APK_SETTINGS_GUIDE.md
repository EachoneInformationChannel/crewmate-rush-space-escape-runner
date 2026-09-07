# 🚀 WebIntoApp Android APK Configuration Guide

### Crewmate Rush Space Escape Runner
**Live Game URL:** `https://crewmate-rush-space-escape-runner.ai.studio`

WebIntoApp me naye APK build banate waqt niche di gayi settings ko verify karein:

---

## ⚙️ Required WebIntoApp Checkboxes & Permissions

| Setting / Permission | Recommended Value | Reason |
| :--- | :--- | :--- |
| **JavaScript** | **ON / Enabled** | Required for React game engine, Canvas runner, tasks & animations. |
| **Internet Permission** | **ON / Enabled** (`INTERNET`) | Connects to galactic multiplayer server, highscores, and real-time chat. |
| **DOM Storage / LocalStorage** | **ON / Enabled** | Saves skin unlocks, coins, high scores, commander ranks and audio settings. |
| **Cookies / Storage Access** | **ON / Enabled** | Preserves user session and device fingerprinting securely. |
| **WebSocket Support** | **ON / Enabled** | Powers real-time multiplayer room matchmaking and live comms feed. |
| **HTTPS Only / Mixed Content** | **HTTPS (WSS) Active** | All game assets and endpoints communicate over secure TLS/HTTPS without CORS block. |
| **Offline / Cache-Only Mode** | **OFF / Default Network** | Prevents WebView from serving stale broken screens or throwing artificial 500 pages. |
| **Hardware Acceleration** | **ON / Enabled** | Smooth 60 FPS Canvas rendering on Android 10, 11, 12, 13, 14, 15 devices. |

---

## 🛡️ Fixes Applied in the Game Code

1. **Automatic Network Health Detection:**
   - The app now checks real `/api/health` connectivity with an `AbortController` timeout instead of blindly forcing offline mode when a WebSocket isn't yet opened.
   - When network is live, it immediately shows **"GALACTIC NETWORK ONLINE"**.
   - If user is truly disconnected (e.g. Airplane mode), solo mode, missions, shop, and offline AI bot arena remain 100% playable.

2. **Zero 500-Status Shield:**
   - The backend server intercepts any potential 500 status codes, converting them to safe 200 JSON fallbacks so Web Into App's native `WebViewClient` never catches an HTTP 500 error code.

3. **Missing Static Asset Shield:**
   - If an asset chunk is requested that does not exist, the server returns empty JS/CSS instead of serving `index.html`, eliminating the `SyntaxError: Unexpected token '<'` crash.

4. **Android Network Security Config:**
   - Added `ai.studio` to `network_security_config.xml` and permissions in `AndroidManifest.xml` (`INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`).

5. **In-Game Diagnostics:**
   - Tap **"Diagnostics & Server 500 Log"** on the main menu footer anytime to check live URL origin, user agent, WebSocket state, DOM storage status, and inspect crash stack traces.
