/**
 * PHANTOM Chat — Client Application
 *
 * Architecture:
 *   Crypto  → AES-256-GCM encryption via Web Crypto API
 *   WS      → WebSocket connection for signaling relay
 *   Messages→ Message lifecycle (create, render, auto-destroy)
 *   UI      → Screen management, event handlers, privacy controls
 *   App     → Orchestrates all modules
 *
 * Security model:
 *   - Passphrase → PBKDF2 (100k iterations, SHA-256) → AES-256-GCM key
 *   - Room code used as PBKDF2 salt (same pass + different room = different key)
 *   - Each message encrypted with unique 12-byte IV prepended to ciphertext
 *   - Server NEVER sees plaintext — only relays opaque base64 blobs
 */
(() => {
  'use strict';

  // ═══════════ CONFIG ═══════════
  const CONFIG = {
    MESSAGE_TTL: 10 * 60 * 1000, // 10 minutes in ms
    CLEANUP_INTERVAL: 1000,       // Expiry check interval
    MAX_MSG_LENGTH: 500,
    TYPING_TIMEOUT: 2500,
    RECONNECT_DELAY: 2000,
    MAX_RECONNECTS: 5,
  };

  // ═══════════ CRYPTO MODULE ═══════════
  const Crypto = {
    /**
     * Derive an AES-256-GCM key from a passphrase + room salt
     */
    async deriveKey(passphrase, roomSalt) {
      const encoder = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(passphrase),
        'PBKDF2',
        false,
        ['deriveKey']
      );
      return crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: encoder.encode(`phantom:${roomSalt}`),
          iterations: 100000,
          hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    },

    /**
     * Encrypt plaintext → base64 string (IV prepended)
     */
    async encrypt(plaintext, key) {
      const encoder = new TextEncoder();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        encoder.encode(plaintext)
      );
      // Prepend IV to ciphertext
      const combined = new Uint8Array(iv.length + ciphertext.byteLength);
      combined.set(iv);
      combined.set(new Uint8Array(ciphertext), iv.length);
      return btoa(String.fromCharCode(...combined));
    },

    /**
     * Decrypt base64 string → plaintext
     */
    async decrypt(base64, key) {
      try {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }
        const iv = bytes.slice(0, 12);
        const ciphertext = bytes.slice(12);
        const decrypted = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv },
          key,
          ciphertext
        );
        return new TextDecoder().decode(decrypted);
      } catch {
        return null; // Decryption failed (wrong key)
      }
    },
  };

  // ═══════════ STATE ═══════════
  const state = {
    ws: null,
    key: null,
    nickname: '',
    room: '',
    userId: null,
    connected: false,
    reconnects: 0,
    typingTimeout: null,
    lastTypingSent: 0,
    cleanupInterval: null,
    windowFocused: true,
    messages: new Map(), // id → { timestamp, timeout }
  };

  // ═══════════ DOM HELPERS ═══════════
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  // ═══════════ UTILS ═══════════
  function generateRoomCode() {
    const adjectives = ['shadow', 'phantom', 'ghost', 'cipher', 'stealth', 'covert', 'silent', 'dark', 'void', 'spectre'];
    const nouns = ['wolf', 'hawk', 'fox', 'raven', 'viper', 'cobra', 'lynx', 'eagle', 'panther', 'falcon'];
    const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
    const noun = nouns[Math.floor(Math.random() * nouns.length)];
    const num = Math.floor(Math.random() * 900) + 100;
    return `${adj}-${noun}-${num}`;
  }

  function nicknameColor(name) {
    let hash = 0;
    for (let i = 0; i < name.length; i++) {
      hash = name.charCodeAt(i) + ((hash << 5) - hash);
    }
    const hue = Math.abs(hash % 360);
    return `hsl(${hue}, 65%, 62%)`;
  }

  function formatTime(ts) {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  /**
   * Format cipher data to look like a realistic hex dump
   * e.g. "4a7f c2b1 9d3e 08a5 f1c6 ..."
   */
  function formatCipherData(base64) {
    const HEX = '0123456789abcdef';
    let hash = 0;
    for (let i = 0; i < base64.length; i++) {
      hash = base64.charCodeAt(i) + ((hash << 5) - hash);
    }
    // Generate deterministic hex blocks from the base64 input
    const blocks = [];
    const numBlocks = Math.max(8, Math.min(24, Math.floor(base64.length / 3)));
    for (let i = 0; i < numBlocks; i++) {
      let block = '';
      for (let j = 0; j < 4; j++) {
        const seed = (hash * (i * 4 + j + 1) + base64.charCodeAt(i % base64.length)) & 0xffff;
        block += HEX[seed & 0xf];
      }
      blocks.push(block);
    }
    return blocks.join(' ');
  }

  /**
   * Generate cipher text for the input field (live hashing effect)
   */
  const CIPHER_CHARS = '0123456789abcdef';
  function generateInputCipher(length) {
    if (length === 0) return '';
    // Each real char = ~3 cipher chars for "expansion" effect
    const cipherLen = length * 3;
    let result = '';
    for (let i = 0; i < cipherLen; i++) {
      if (i > 0 && i % 4 === 0) result += ' ';
      result += CIPHER_CHARS[Math.floor(Math.random() * 16)];
    }
    return result;
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // ═══════════ WEBSOCKET MODULE ═══════════
  const WS = {
    connect() {
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${location.host}`;

      state.ws = new WebSocket(wsUrl);

      state.ws.onopen = () => {
        state.reconnects = 0;
        // Join will happen after receiving 'welcome'
      };

      state.ws.onmessage = async (event) => {
        try {
          const msg = JSON.parse(event.data);
          await WS.handleMessage(msg);
        } catch (e) {
          console.error('[WS] Parse error:', e);
        }
      };

      state.ws.onclose = () => {
        if (state.connected && state.reconnects < CONFIG.MAX_RECONNECTS) {
          state.reconnects++;
          setTimeout(() => WS.connect(), CONFIG.RECONNECT_DELAY);
        } else if (state.connected) {
          UI.showError('Connection lost. Please reconnect.');
          App.disconnect();
        }
      };

      state.ws.onerror = () => {
        // onclose will fire after this
      };
    },

    send(type, data = {}) {
      if (state.ws?.readyState === WebSocket.OPEN) {
        state.ws.send(JSON.stringify({ type, ...data }));
      }
    },

    async handleMessage(msg) {
      switch (msg.type) {
        case 'welcome':
          state.userId = msg.userId;
          // Now join the room
          WS.send('join', { room: state.room });
          break;

        case 'joined':
          state.connected = true;
          state.userId = msg.userId;
          UI.showChat();
          UI.updateUserCount(msg.userCount);
          Messages.addSystem('🔒 Encrypted connection established');
          break;

        case 'user-joined':
          UI.updateUserCount(msg.userCount);
          Messages.addSystem('A new agent has joined');
          break;

        case 'user-left':
          UI.updateUserCount(msg.userCount);
          Messages.addSystem('An agent has left');
          break;

        case 'message':
          await Messages.receive(msg);
          break;

        case 'typing':
          if (msg.from !== state.userId) {
            UI.showTyping();
          }
          break;

        case 'error':
          UI.showError(msg.message);
          break;
      }
    },
  };

  // ═══════════ MESSAGES MODULE ═══════════
  const Messages = {
    async send(text) {
      if (!text.trim() || !state.key) return;

      const payload = JSON.stringify({
        text: text.trim(),
        nickname: state.nickname,
        color: nicknameColor(state.nickname),
      });

      const encrypted = await Crypto.encrypt(payload, state.key);
      WS.send('message', { payload: encrypted });
    },

    async receive(msg) {
      const decrypted = await Crypto.decrypt(msg.payload, state.key);
      const isOwn = msg.from === state.userId;

      if (decrypted) {
        try {
          const data = JSON.parse(decrypted);
          Messages.render({
            id: msg.id,
            text: data.text,
            nickname: data.nickname || 'Unknown',
            color: data.color || '#888',
            timestamp: msg.timestamp,
            cipher: msg.payload,
            own: isOwn,
          });
        } catch {
          Messages.render({
            id: msg.id,
            text: '[Corrupted message]',
            nickname: 'Unknown',
            color: '#888',
            timestamp: msg.timestamp,
            cipher: msg.payload,
            own: isOwn,
          });
        }
      } else {
        // Can't decrypt — wrong key
        Messages.render({
          id: msg.id,
          text: '🔐 Cannot decrypt (wrong passphrase?)',
          nickname: '???',
          color: '#ff1744',
          timestamp: msg.timestamp,
          cipher: msg.payload,
          own: false,
          error: true,
        });
      }
    },

    render(data) {
      const container = $('#messages');
      const emptyState = $('#messages-empty');
      if (emptyState) emptyState.classList.add('hidden');

      const el = document.createElement('div');
      el.className = `message${data.own ? ' own' : ''}${data.error ? ' error' : ''}`;
      el.dataset.id = data.id;
      el.dataset.expires = data.timestamp + CONFIG.MESSAGE_TTL;

      const elapsed = Date.now() - data.timestamp;
      const remaining = CONFIG.MESSAGE_TTL - elapsed;

      if (remaining <= 0) return; // Already expired

      el.innerHTML = `
        <div class="msg-header">
          <span class="msg-dot" style="background: ${data.color}"></span>
          <span class="msg-alias">${escapeHtml(data.nickname)}</span>
          <span class="msg-time">${formatTime(data.timestamp)}</span>
        </div>
        <div class="msg-body">
          <div class="msg-cipher">${formatCipherData(data.cipher)}</div>
          <div class="msg-text">${escapeHtml(data.text)}</div>
        </div>
        <div class="msg-timer">
          <div class="msg-timer-bar"
               style="--timer-duration: ${CONFIG.MESSAGE_TTL}ms; --timer-delay: -${elapsed}ms">
          </div>
        </div>
      `;

      container.appendChild(el);
      container.scrollTop = container.scrollHeight;

      // Schedule removal
      const timeout = setTimeout(() => {
        el.classList.add('expiring');
        setTimeout(() => {
          el.remove();
          state.messages.delete(data.id);
          // Show empty state if no messages left
          const remaining = container.querySelectorAll('.message:not(.system-msg)');
          if (remaining.length === 0 && emptyState) {
            emptyState.classList.remove('hidden');
          }
        }, 400);
      }, remaining);

      state.messages.set(data.id, { timestamp: data.timestamp, timeout });
    },

    addSystem(text) {
      const container = $('#messages');
      const el = document.createElement('div');
      el.className = 'message system-msg';

      el.innerHTML = `
        <div class="msg-body">
          <div class="msg-text">${escapeHtml(text)}</div>
        </div>
      `;

      container.appendChild(el);
      container.scrollTop = container.scrollHeight;

      // System messages also expire in 2 minutes
      setTimeout(() => {
        el.classList.add('expiring');
        setTimeout(() => el.remove(), 400);
      }, 2 * 60 * 1000);
    },

    clearAll() {
      for (const [, data] of state.messages) {
        clearTimeout(data.timeout);
      }
      state.messages.clear();
      const container = $('#messages');
      container.innerHTML = `
        <div class="messages-empty" id="messages-empty">
          <div class="empty-icon">👻</div>
          <p>No messages yet</p>
          <small>Messages will self-destruct in 10 minutes</small>
        </div>
      `;
    },
  };

  // ═══════════ UI MODULE ═══════════
  const UI = {
    init() {
      // Login form
      $('#login-form').addEventListener('submit', (e) => {
        e.preventDefault();
        App.connect();
      });

      // Generate room code
      $('#gen-room-btn').addEventListener('click', () => {
        $('#room-input').value = generateRoomCode();
        $('#room-input').focus();
      });

      // Toggle password visibility
      $('#toggle-pass-btn').addEventListener('click', () => {
        const input = $('#passphrase-input');
        const isPass = input.type === 'password';
        input.type = isPass ? 'text' : 'password';
        $('#toggle-pass-btn').classList.toggle('active', !isPass);
      });

      // Send message
      const cipherDisplay = $('#cipher-display');
      const msgInput = $('#message-input');

      $('#send-btn').addEventListener('click', () => {
        if (msgInput.value.trim()) {
          Messages.send(msgInput.value);
          msgInput.value = '';
          cipherDisplay.textContent = '';
          msgInput.focus();
        }
      });

      msgInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          $('#send-btn').click();
        }
      });

      // ── Cipher input display: hash text while typing ──
      let cipherRefreshInterval = null;

      msgInput.addEventListener('input', () => {
        const len = msgInput.value.length;

        // Update cipher display
        if (len > 0) {
          cipherDisplay.textContent = generateInputCipher(len);
          // Start periodic scramble for "live encryption" feel
          if (!cipherRefreshInterval) {
            cipherRefreshInterval = setInterval(() => {
              if (msgInput.value.length > 0) {
                // Only scramble last few chars for subtle "computing" effect
                const current = cipherDisplay.textContent;
                const keepLen = Math.max(0, current.length - 8);
                const kept = current.slice(0, keepLen);
                let tail = '';
                for (let i = 0; i < current.length - keepLen; i++) {
                  if (current[keepLen + i] === ' ') { tail += ' '; continue; }
                  tail += CIPHER_CHARS[Math.floor(Math.random() * 16)];
                }
                cipherDisplay.textContent = kept + tail;
              } else {
                clearInterval(cipherRefreshInterval);
                cipherRefreshInterval = null;
              }
            }, 150);
          }
        } else {
          cipherDisplay.textContent = '';
          if (cipherRefreshInterval) {
            clearInterval(cipherRefreshInterval);
            cipherRefreshInterval = null;
          }
        }

        // Typing indicator
        const now = Date.now();
        if (now - state.lastTypingSent > CONFIG.TYPING_TIMEOUT) {
          state.lastTypingSent = now;
          WS.send('typing');
        }
      });

      // Panic button
      $('#panic-btn').addEventListener('click', () => App.panic());

      // ── All security (Esc, shortcuts, etc.) handled by Security module ──
    },

    showChat() {
      $('#login-screen').classList.remove('active');
      $('#chat-screen').classList.add('active');
      $('#room-name').textContent = state.room;
      $('#message-input').focus();

      // Remove loading state
      $('#connect-btn')?.classList.remove('loading');
    },

    showLogin() {
      $('#chat-screen').classList.remove('active');
      $('#login-screen').classList.add('active');
      $('#connect-btn')?.classList.remove('loading');
    },

    updateUserCount(count) {
      $('#user-count').textContent = count;
    },

    showTyping() {
      const indicator = $('#typing-indicator');
      indicator.classList.remove('hidden');
      clearTimeout(state.typingTimeout);
      state.typingTimeout = setTimeout(() => {
        indicator.classList.add('hidden');
      }, CONFIG.TYPING_TIMEOUT);
    },

    showError(msg) {
      const el = $('#login-error');
      el.textContent = msg;
      el.classList.add('visible');
      $('#connect-btn')?.classList.remove('loading');
      setTimeout(() => el.classList.remove('visible'), 5000);
    },
  };

  // ═══════════ SECURITY MODULE (Military-Grade) ═══════════
  const Security = {
    devToolsOpen: false,
    devToolsCheckInterval: null,

    init() {
      this.blockKeyboardShortcuts();
      this.blockCopyPaste();
      this.blockSelection();
      this.blockContextMenu();
      this.blockDragDrop();
      this.detectPrintScreen();
      this.detectDevTools();
      this.monitorFocus();
    },

    /**
     * Block ALL dangerous keyboard shortcuts
     * Uses capture phase (3rd arg = true) so it fires BEFORE any other handler
     */
    blockKeyboardShortcuts() {
      document.addEventListener('keydown', (e) => {
        // === ALWAYS BLOCKED ===

        // Block DevTools
        if (e.key === 'F12') { e.preventDefault(); e.stopPropagation(); return; }
        if (e.ctrlKey && e.shiftKey && ['I','J','C'].includes(e.key.toUpperCase())) {
          e.preventDefault(); e.stopPropagation(); return;
        }

        // Block View Source
        if (e.ctrlKey && e.key.toLowerCase() === 'u') { e.preventDefault(); return; }

        // Block Save Page
        if (e.ctrlKey && e.key.toLowerCase() === 's') { e.preventDefault(); return; }

        // Block Print
        if (e.ctrlKey && e.key.toLowerCase() === 'p') { e.preventDefault(); return; }

        // === BLOCKED ONLY IN CHAT SCREEN ===
        if (!$('#chat-screen')?.classList.contains('active')) return;

        // Block Select All
        if (e.ctrlKey && e.key.toLowerCase() === 'a') {
          e.preventDefault(); e.stopPropagation(); return;
        }

        // Block Copy / Cut — poison clipboard with cipher data
        if (e.ctrlKey && ['c', 'x'].includes(e.key.toLowerCase())) {
          e.preventDefault(); e.stopPropagation();
          this.writePoison();
          return;
        }

        // Escape = Panic
        if (e.key === 'Escape' && state.connected) {
          App.panic();
          return;
        }
      }, true); // CAPTURE PHASE
    },

    /**
     * Intercept copy/cut events and replace clipboard with cipher garbage
     */
    blockCopyPaste() {
      document.addEventListener('copy', (e) => {
        if ($('#chat-screen')?.classList.contains('active')) {
          e.preventDefault();
          const poison = generateInputCipher(32);
          e.clipboardData?.setData('text/plain', poison);
          e.clipboardData?.setData('text/html', `<pre>${poison}</pre>`);
        }
      }, true);

      document.addEventListener('cut', (e) => {
        if ($('#chat-screen')?.classList.contains('active')) {
          e.preventDefault();
          const poison = generateInputCipher(32);
          e.clipboardData?.setData('text/plain', poison);
        }
      }, true);

      // Allow paste ONLY in message-input, block everywhere else in chat
      document.addEventListener('paste', (e) => {
        if (e.target.closest('#chat-screen') && e.target.id !== 'message-input') {
          e.preventDefault();
        }
      }, true);
    },

    /**
     * Block ALL text selection in chat area
     */
    blockSelection() {
      document.addEventListener('selectstart', (e) => {
        if (e.target.closest('#chat-screen') && e.target.id !== 'message-input') {
          e.preventDefault();
        }
      });
    },

    /**
     * Block right-click everywhere in chat
     */
    blockContextMenu() {
      document.addEventListener('contextmenu', (e) => {
        if (e.target.closest('#chat-screen')) {
          e.preventDefault();
        }
      }, true);
    },

    /**
     * Block ALL drag operations in chat
     */
    blockDragDrop() {
      document.addEventListener('dragstart', (e) => {
        if (e.target.closest('#chat-screen')) { e.preventDefault(); }
      }, true);
      document.addEventListener('drop', (e) => {
        if (e.target.closest('#chat-screen')) { e.preventDefault(); }
      }, true);
    },

    /**
     * Detect PrintScreen / Win+Shift+S and immediately hide content
     */
    detectPrintScreen() {
      document.addEventListener('keyup', (e) => {
        if (e.key === 'PrintScreen') {
          this.flashProtection();
          this.writePoison();
        }
      }, true);

      document.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.key === 'Meta') && e.shiftKey && e.key.toLowerCase() === 's') {
          e.preventDefault();
          this.flashProtection();
        }
      }, true);
    },

    /**
     * Detect DevTools via window size difference — auto-panic
     */
    detectDevTools() {
      this.devToolsCheckInterval = setInterval(() => {
        if (!$('#chat-screen')?.classList.contains('active')) return;

        const widthDiff = window.outerWidth - window.innerWidth > 200;
        const heightDiff = window.outerHeight - window.innerHeight > 200;

        if ((widthDiff || heightDiff) && !this.devToolsOpen) {
          this.devToolsOpen = true;
          console.clear();
          App.panic();
        } else if (!widthDiff && !heightDiff) {
          this.devToolsOpen = false;
        }
      }, 1500);
    },

    /**
     * Monitor window focus and visibility
     */
    monitorFocus() {
      const hide = () => {
        state.windowFocused = false;
        $('#blur-overlay')?.classList.add('active');
      };
      const show = () => {
        state.windowFocused = true;
        if (!this.devToolsOpen) {
          $('#blur-overlay')?.classList.remove('active');
        }
      };

      window.addEventListener('blur', hide);
      window.addEventListener('focus', show);
      document.addEventListener('visibilitychange', () => {
        if (document.hidden) hide(); else show();
      });
    },

    /**
     * Flash protection overlay for 3 seconds
     */
    flashProtection() {
      const overlay = $('#blur-overlay');
      overlay?.classList.add('active');
      setTimeout(() => {
        if (document.hasFocus() && !this.devToolsOpen) {
          overlay?.classList.remove('active');
        }
      }, 3000);
    },

    /**
     * Write cipher garbage to clipboard
     */
    async writePoison() {
      try {
        await navigator.clipboard.writeText(generateInputCipher(48));
      } catch { /* Clipboard API might not be available */ }
    },
  };

  // ═══════════ APP (Orchestrator) ═══════════
  const App = {
    async connect() {
      const room = $('#room-input').value.trim();
      const passphrase = $('#passphrase-input').value;
      const nickname = $('#nickname-input').value.trim() || 'Ghost-' + Math.floor(Math.random() * 9000 + 1000);

      if (!room) {
        UI.showError('Room code is required');
        return;
      }
      if (!passphrase || passphrase.length < 4) {
        UI.showError('Passphrase must be at least 4 characters');
        return;
      }

      $('#connect-btn').classList.add('loading');

      try {
        state.key = await Crypto.deriveKey(passphrase, room);
        state.room = room;
        state.nickname = nickname;
        state.reconnects = 0;
        WS.connect();
      } catch (err) {
        UI.showError('Failed to initialize encryption');
      }
    },

    disconnect() {
      state.connected = false;
      state.key = null;
      state.room = '';
      state.nickname = '';

      if (state.ws) {
        state.ws.onclose = null;
        state.ws.close();
        state.ws = null;
      }

      Messages.clearAll();
      UI.showLogin();
    },

    panic() {
      document.body.classList.add('panic-active');
      setTimeout(() => document.body.classList.remove('panic-active'), 600);

      Messages.clearAll();
      App.disconnect();

      // Clear ALL traces
      $('#passphrase-input').value = '';
      $('#message-input').value = '';
      $('#cipher-display').textContent = '';
      Security.writePoison();
      console.clear();
    },
  };

  // ═══════════ BOOT ═══════════
  document.addEventListener('DOMContentLoaded', () => {
    UI.init();
    Security.init();

    // Pre-fill room code with a generated one
    if (!$('#room-input').value) {
      $('#room-input').value = generateRoomCode();
    }
  });
})();
