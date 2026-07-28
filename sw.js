// Self-destruct: unregister all old service workers so the latest version always loads
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', () => {
  self.registration.unregister();
  clients.claim();
});
