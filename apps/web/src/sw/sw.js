/* urkey service worker (R-SEC-12, R-ACC-4).
 * Pins the installed release: every file of this release is precached and served cache-first, so
 * a changed bundle on the server is not used until the user approves the update. API requests
 * (other origin) are never touched. Template: the build replaces the two placeholders.
 */
const RELEASE = "__RELEASE_HASH__";
const FILES = __FILES__;
const CACHE = `urkey-${RELEASE}`;

self.addEventListener("install", (event) => {
  // No skipWaiting(): a new release waits until the user chooses to activate it.
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(FILES)));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith("urkey-") && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("message", (event) => {
  if (event.data === "activate-update") self.skipWaiting();
  if (event.data === "release" && event.source) event.source.postMessage({ release: RELEASE });
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.origin !== self.location.origin) return;
  if (url.pathname === "/release.json" || url.pathname === "/sw.js") return; // always fresh
  const key = event.request.mode === "navigate" ? "/" : event.request;
  // ignoreVary: cached responses carry Vary headers; the cache only holds this release's files.
  event.respondWith(caches.open(CACHE).then(async (cache) => (await cache.match(key, { ignoreVary: true })) ?? fetch(event.request)));
});
