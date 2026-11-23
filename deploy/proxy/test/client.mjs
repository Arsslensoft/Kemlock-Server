// Opens a WebSocket through a proxy and expects the stub's "sync now". Node 22 or later.
const url = process.argv[2];
if (!url) {
  console.error('usage: node client.mjs ws://proxy/kem/v1/live');
  process.exit(2);
}
const socket = new WebSocket(url);
const timer = setTimeout(() => {
  console.error(`${url}: no message within 10 s`);
  process.exit(1);
}, 10_000);
socket.addEventListener('message', (event) => {
  clearTimeout(timer);
  if (event.data === 'sync now') {
    console.log(`${url}: ok`);
    process.exit(0);
  }
  console.error(`${url}: unexpected message ${event.data}`);
  process.exit(1);
});
socket.addEventListener('error', () => {
  console.error(`${url}: connection failed`);
  process.exit(1);
});
