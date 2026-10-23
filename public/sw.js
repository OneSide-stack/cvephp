/* Offline application shell only. Guest images are SHA-256 verified and stored
 * by src/lib/assets.ts; this worker never supplies fallback guest execution. */
const CACHE = "enterprise-cyber-range-shell-v1";
const SHELL = ["./", "./index.html", "./favicon.svg", "./manifest.webmanifest"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((key) => key.startsWith("enterprise-cyber-range-shell-") && key !== CACHE).map((key) => caches.delete(key)))).then(() => self.clients.claim()));
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  if (request.mode === "navigate") {
    event.respondWith(fetch(request).then((response) => {
      if (response.ok) {
        const copy = response.clone();
        void caches.open(CACHE).then((cache) => cache.put("./index.html", copy));
      }
      return response;
    }).catch(() => caches.match("./index.html").then((response) => response || caches.match("./"))));
    return;
  }

  // Hashed Vite assets and small public shell files are safe to cache. Do not
  // intercept manifests, guest ISOs, VM state, or emulator buffers here.
  if (!url.pathname.includes("/assets/") && !url.pathname.endsWith("/favicon.svg") && !url.pathname.endsWith("/manifest.webmanifest")) return;
  event.respondWith(caches.match(request).then((cached) => cached || fetch(request).then((response) => {
    if (response.ok) {
      const copy = response.clone();
      event.waitUntil(caches.open(CACHE).then((cache) => cache.put(request, copy)));
    }
    return response;
  })));
});
