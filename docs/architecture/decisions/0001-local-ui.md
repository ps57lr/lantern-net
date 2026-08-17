# ADR 0001: Local UI transport

Status: accepted for development

Lantern Local uses bundled HTML, CSS, and JavaScript served by a short-lived Python HTTP server bound to an operating-system-assigned port on `127.0.0.1`. It opens the system browser after a one-use launch-secret exchange. Assets are offline and allowlisted; the server provides no filesystem mapping, CORS, remote binding, or command endpoint.

This keeps the runtime small, reuses the responsive technician interface, and avoids an Electron-class dependency. Loopback is not treated as a privilege boundary: future elevated work must use a separately reviewed typed helper.

Lantern LAN is a distinct server policy and cannot be enabled by changing this server's bind address.
