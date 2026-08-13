const net = require('net');
const fs = require('fs');

const SOCKET_PATH = '/umids';

if (fs.existsSync(SOCKET_PATH)) {
  fs.unlinkSync(SOCKET_PATH);
}

net.createServer(client => {
  client.on('data', data => {
    console.log(data.toString());
  });
  client.on('error', () => {});
}).listen(SOCKET_PATH, () => {
  console.log('Listening on ' + SOCKET_PATH);
});