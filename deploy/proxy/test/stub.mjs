// A stand-in for Kemlock's WebSocket routes, for testing proxies: it answers an upgrade on
// /kem/v1/live and /notifications/hub with one text frame, "sync now", and the plain GET /alive
// with 200. Node only, no packages.
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const server = createServer((req, res) => {
  if (req.url === '/alive') {
    res.writeHead(200);
    res.end('ok');
    return;
  }
  res.writeHead(404);
  res.end();
});
server.on('upgrade', (req, socket) => {
  if (!['/kem/v1/live', '/notifications/hub'].includes(req.url)) {
    socket.destroy();
    return;
  }
  const accept = createHash('sha1')
    .update(req.headers['sec-websocket-key'] + GUID)
    .digest('base64');
  socket.write(
    [
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${accept}`,
      '',
      '',
    ].join('\r\n'),
  );
  const payload = Buffer.from('sync now');
  socket.write(Buffer.concat([Buffer.from([0x81, payload.length]), payload]));
  socket.on('error', () => {});
});
server.listen(8080, '0.0.0.0', () => console.log('stub listening on 8080'));
