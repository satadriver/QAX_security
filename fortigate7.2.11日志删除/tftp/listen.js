const net = require('net');

// Create TCP server
const server = net.createServer((socket) => {
  const clientIP = socket.remoteAddress;
  const clientPort = socket.remotePort;
  console.log(`New connection from ${clientIP}:${clientPort}`);

  // Send greeting message
  const greeting = `hello ${clientIP} ${clientPort}\n`;
  socket.write(greeting, (err) => {
    if (err) {
      console.error(`Failed to send greeting: ${err.message}`);
    } else {
      console.log(`Sent: ${greeting.trim()}`);
    }
  });

  // Listen for data events – this will keep receiving and printing
  socket.on('data', (data) => {
    console.log(`Received: ${data.toString()}`);
  });

  // Handle client disconnection
  socket.on('end', () => {
    console.log('Client disconnected');
  });

  // Handle socket errors
  socket.on('error', (err) => {
    console.error(`Socket error: ${err.message}`);
  });
});

// Start listening on port 54321
server.listen(80, '0.0.0.0',() => {
  console.log('TCP server started, listening on port 54321');
});

// Handle server errors
server.on('error', (err) => {
  console.error(`Server error: ${err.message}`);
});