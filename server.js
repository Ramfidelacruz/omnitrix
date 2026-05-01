/**
 * PHANTOM Chat — Signaling Server
 * 
 * This server does TWO things:
 * 1. Serves static files from /public
 * 2. Manages WebSocket rooms for message relay
 * 
 * IMPORTANT: The server NEVER sees message content.
 * All payloads are encrypted client-side with AES-256-GCM.
 * The server only knows room IDs and user connection metadata.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

// ───────────────────────────────────────────────
// Static file server (no Express needed)
// ───────────────────────────────────────────────

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

const PUBLIC_DIR = path.join(__dirname, 'public');

const server = http.createServer((req, res) => {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');

  // Parse the URL pathname (ignore query strings)
  const urlPath = new URL(req.url, `http://${req.headers.host}`).pathname;

  // Determine which file to serve
  const requestedFile = (urlPath === '/' || urlPath === '') ? 'index.html' : urlPath;

  // Resolve and sanitize the full path
  const filePath = path.resolve(PUBLIC_DIR, '.' + path.sep + requestedFile.replace(/^\/+/, ''));

  // Prevent directory traversal
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      console.error(`[404] ${req.url} -> ${filePath}`);
      res.writeHead(404);
      res.end('Not Found');
      return;
    }
    res.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-store', // Never cache (privacy)
    });
    res.end(content);
  });
});

// ───────────────────────────────────────────────
// WebSocket signaling server
// ───────────────────────────────────────────────

const wss = new WebSocketServer({ server });

// Room management: Map<roomId, Map<userId, WebSocket>>
const rooms = new Map();

// Room auto-destroy timeout: Map<roomId, timeoutId>
const roomTimers = new Map();

const MAX_USERS_PER_ROOM = 25;

function broadcast(roomId, message, excludeUserId = null) {
  const room = rooms.get(roomId);
  if (!room) return;
  const raw = JSON.stringify(message);
  for (const [uid, ws] of room) {
    if (uid !== excludeUserId && ws.readyState === 1) {
      ws.send(raw);
    }
  }
}

function removeUserFromRoom(userId, roomId) {
  const room = rooms.get(roomId);
  if (!room) return;

  room.delete(userId);

  if (room.size === 0) {
    rooms.delete(roomId);
    // Clear any existing timer
    if (roomTimers.has(roomId)) {
      clearTimeout(roomTimers.get(roomId));
      roomTimers.delete(roomId);
    }
  } else {
    broadcast(roomId, {
      type: 'user-left',
      userCount: room.size,
    });
  }
}

wss.on('connection', (ws) => {
  let userId = crypto.randomUUID();
  let currentRoom = null;

  // Send the assigned user ID
  ws.send(JSON.stringify({ type: 'welcome', userId }));

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw.toString());

      switch (msg.type) {
        case 'join': {
          const roomId = String(msg.room || '').trim().slice(0, 50);
          if (!roomId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Room code required' }));
            return;
          }

          // Leave current room if in one
          if (currentRoom) {
            removeUserFromRoom(userId, currentRoom);
          }

          // Create room if it doesn't exist
          if (!rooms.has(roomId)) {
            rooms.set(roomId, new Map());
          }

          const room = rooms.get(roomId);

          if (room.size >= MAX_USERS_PER_ROOM) {
            ws.send(JSON.stringify({ type: 'error', message: 'Room is full' }));
            return;
          }

          room.set(userId, ws);
          currentRoom = roomId;

          // Clear room auto-destroy timer if any
          if (roomTimers.has(roomId)) {
            clearTimeout(roomTimers.get(roomId));
            roomTimers.delete(roomId);
          }

          // Confirm join
          ws.send(JSON.stringify({
            type: 'joined',
            userId,
            userCount: room.size,
            room: roomId,
          }));

          // Notify others
          broadcast(roomId, {
            type: 'user-joined',
            userCount: room.size,
          }, userId);

          break;
        }

        case 'message': {
          if (!currentRoom) return;
          if (!msg.payload || typeof msg.payload !== 'string') return;
          if (msg.payload.length > 10000) return; // Sanity limit

          const messageId = crypto.randomUUID();

          // Relay encrypted payload — server has NO idea what's inside
          broadcast(currentRoom, {
            type: 'message',
            id: messageId,
            payload: msg.payload,
            from: userId,
            timestamp: Date.now(),
          });

          break;
        }

        case 'typing': {
          if (!currentRoom) return;
          broadcast(currentRoom, {
            type: 'typing',
            from: userId,
          }, userId);
          break;
        }

        default:
          break;
      }
    } catch (e) {
      // Malformed message, ignore silently
    }
  });

  ws.on('close', () => {
    if (currentRoom) {
      removeUserFromRoom(userId, currentRoom);
    }
  });

  ws.on('error', () => {
    if (currentRoom) {
      removeUserFromRoom(userId, currentRoom);
    }
  });
});

// ───────────────────────────────────────────────
// Start server
// ───────────────────────────────────────────────

function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

const PORT = process.env.PORT || 4002
server.listen(PORT, '0.0.0.0', () => {
  const localIP = getLocalIP();
  console.log('');
  console.log('  ╔══════════════════════════════════════════╗');
  console.log('  ║          👻 PHANTOM CHAT SERVER          ║');
  console.log('  ╠══════════════════════════════════════════╣');
  console.log(`  ║  Local:   http://localhost:${PORT}          ║`);
  console.log(`  ║  Network: http://${localIP}:${PORT}     ║`);
  console.log('  ║                                          ║');
  console.log('  ║  Share the Network URL with your team    ║');
  console.log('  ║  🔒 All messages are E2E encrypted      ║');
  console.log('  ║  🗑️  Messages self-destruct in 10 min    ║');
  console.log('  ╚══════════════════════════════════════════╝');
  console.log('');
});
