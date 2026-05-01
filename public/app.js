/**
 * PHANTOM Chat — Client Application
 *
 * Módulos:
 *   Crypto      → AES-256-GCM via Web Crypto API
 *   WS          → WebSocket connection + relay
 *   Messages    → Ciclo de vida, render, reacciones, TTL
 *   Invite      → Modal, QR code, URL hash
 *   BossKey     → Camuflaje como Google Sheets
 *   Notifications → Sonidos Web Audio API
 *   UI          → Pantallas, botones, eventos
 *   Security    → Protección militar de contenido
 *   App         → Orquestador
 */
(() => {
  'use strict';

  // ═══════════ CONFIG ═══════════
  const CONFIG = {
    CLEANUP_INTERVAL: 1000,
    MAX_MSG_LENGTH: 500,
    TYPING_TIMEOUT: 2500,
    RECONNECT_DELAY: 2000,
    MAX_RECONNECTS: 5,
    REACTION_EMOJIS: ['👍', '❤️', '😂', '🎯', '🔒'],
  };

  // ═══════════ CRYPTO MODULE ═══════════
  const Crypto = {
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

    async encrypt(plaintext, key) {
      const encoder = new TextEncoder();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        encoder.encode(plaintext)
      );
      const combined = new Uint8Array(iv.length + ciphertext.byteLength);
      combined.set(iv);
      combined.set(new Uint8Array(ciphertext), iv.length);
      return btoa(String.fromCharCode(...combined));
    },

    async decrypt(base64, key) {
      try {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        const iv = bytes.slice(0, 12);
        const ciphertext = bytes.slice(12);
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
        return new TextDecoder().decode(decrypted);
      } catch {
        return null;
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
    windowFocused: true,
    messageTTL: 600000,            // 10 min por defecto
    readMode: false,
    soundEnabled: true,
    messages: new Map(),           // id → { timestamp, timeout, reactions }
    knownUsers: new Map(),         // userId → { nickname, color, initials }
    reactions: new Map(),          // messageId → Map(emoji → Set(userId))
  };

  // ═══════════ DOM HELPERS ═══════════
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  // ═══════════ UTILS ═══════════
  const generateRoomCode = () => {
    const adj  = ['shadow','phantom','ghost','cipher','stealth','covert','silent','dark','void','spectre'];
    const noun = ['wolf','hawk','fox','raven','viper','cobra','lynx','eagle','panther','falcon'];
    const a = adj[Math.floor(Math.random() * adj.length)];
    const n = noun[Math.floor(Math.random() * noun.length)];
    const num = Math.floor(Math.random() * 900) + 100;
    return `${a}-${n}-${num}`;
  };

  const nicknameColor = (name) => {
    let hash = 0;
    for (let i = 0; i < name.length; i++) {
      hash = name.charCodeAt(i) + ((hash << 5) - hash);
    }
    const hue = Math.abs(hash % 360);
    return `hsl(${hue}, 65%, 62%)`;
  };

  const nicknameInitials = (name) => {
    const parts = name.replace(/^Ghost-/i, 'G ').split(/[\s-_]+/);
    return parts.slice(0, 2).map(p => p[0]?.toUpperCase() || '').join('') || '?';
  };

  const formatTime = (ts) => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  const escapeHtml = (text) => {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  };

  const CIPHER_CHARS = '0123456789abcdef';

  const formatCipherData = (base64) => {
    let hash = 0;
    for (let i = 0; i < base64.length; i++) {
      hash = base64.charCodeAt(i) + ((hash << 5) - hash);
    }
    const blocks = [];
    const numBlocks = Math.max(8, Math.min(20, Math.floor(base64.length / 3)));
    for (let i = 0; i < numBlocks; i++) {
      let block = '';
      for (let j = 0; j < 4; j++) {
        const seed = (hash * (i * 4 + j + 1) + base64.charCodeAt(i % base64.length)) & 0xffff;
        block += CIPHER_CHARS[seed & 0xf];
      }
      blocks.push(block);
    }
    return blocks.join(' ');
  };

  const generateInputCipher = (length) => {
    if (length === 0) return '';
    const cipherLen = length * 3;
    let result = '';
    for (let i = 0; i < cipherLen; i++) {
      if (i > 0 && i % 4 === 0) result += ' ';
      result += CIPHER_CHARS[Math.floor(Math.random() * 16)];
    }
    return result;
  };

  // ═══════════ WEBSOCKET MODULE ═══════════
  const WS = {
    connect() {
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      state.ws = new WebSocket(`${protocol}//${location.host}`);

      state.ws.onopen = () => { state.reconnects = 0; };

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

      state.ws.onerror = () => { /* onclose fires next */ };
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
          WS.send('join', { room: state.room });
          break;

        case 'joined':
          state.connected = true;
          state.userId = msg.userId;
          UI.showChat();
          UI.updateUserCount(msg.userCount);
          Messages.addSystem('🔒 Encrypted connection established');
          if (msg.isNewRoom) {
            Messages.addSystem('🏠 You created this room — share the code to invite others');
          }
          // Enviar presencia para que otros sepan el alias
          setTimeout(() => Messages.sendPresence('joined'), 200);
          break;

        case 'user-joined':
          UI.updateUserCount(msg.userCount);
          // La presencia llegará en el siguiente mensaje cifrado
          break;

        case 'user-left':
          UI.updateUserCount(msg.userCount);
          if (msg.leftId && state.knownUsers.has(msg.leftId)) {
            const u = state.knownUsers.get(msg.leftId);
            Messages.addSystem(`👋 ${u.nickname} has left`);
            state.knownUsers.delete(msg.leftId);
            UI.renderUserAvatars();
          } else {
            Messages.addSystem('An agent has left');
          }
          break;

        case 'message':
          await Messages.receive(msg);
          break;

        case 'typing':
          if (msg.from !== state.userId) UI.showTyping();
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
        msgType: 'chat',
        text: text.trim(),
        nickname: state.nickname,
        color: nicknameColor(state.nickname),
      });

      const encrypted = await Crypto.encrypt(payload, state.key);
      WS.send('message', { payload: encrypted });
    },

    async sendPresence(action) {
      if (!state.key) return;
      const payload = JSON.stringify({
        msgType: 'presence',
        action,
        nickname: state.nickname,
        color: nicknameColor(state.nickname),
      });
      const encrypted = await Crypto.encrypt(payload, state.key);
      WS.send('message', { payload: encrypted });
    },

    async sendReaction(messageId, emoji) {
      if (!state.key) return;
      const payload = JSON.stringify({
        msgType: 'reaction',
        messageId,
        emoji,
        nickname: state.nickname,
        color: nicknameColor(state.nickname),
      });
      const encrypted = await Crypto.encrypt(payload, state.key);
      WS.send('message', { payload: encrypted });
    },

    async receive(msg) {
      const decrypted = await Crypto.decrypt(msg.payload, state.key);
      const isOwn = msg.from === state.userId;

      if (!decrypted) {
        // No se puede descifrar — clave incorrecta
        Messages.render({
          id: msg.id,
          msgType: 'chat',
          text: '🔐 Cannot decrypt — wrong passphrase?',
          nickname: '???',
          color: '#ff1744',
          timestamp: msg.timestamp,
          cipher: msg.payload,
          own: false,
          error: true,
        });
        return;
      }

      try {
        const data = JSON.parse(decrypted);

        if (data.msgType === 'presence') {
          // Registrar usuario conocido
          if (!isOwn && data.action === 'joined') {
            state.knownUsers.set(msg.from, {
              nickname: data.nickname || 'Unknown',
              color: data.color || '#888',
              initials: nicknameInitials(data.nickname || 'Unknown'),
            });
            UI.renderUserAvatars();
            Messages.addSystem(`👤 ${escapeHtml(data.nickname)} has joined`);
          }
          return;
        }

        if (data.msgType === 'reaction') {
          Messages.handleReaction(msg.from, data);
          return;
        }

        // Mensaje normal de chat
        if (data.nickname && !isOwn) {
          state.knownUsers.set(msg.from, {
            nickname: data.nickname,
            color: data.color || '#888',
            initials: nicknameInitials(data.nickname),
          });
          UI.renderUserAvatars();
        }

        Messages.render({
          id: msg.id,
          msgType: 'chat',
          text: data.text,
          nickname: data.nickname || 'Unknown',
          color: data.color || '#888',
          timestamp: msg.timestamp,
          cipher: msg.payload,
          own: isOwn,
          senderId: msg.from,
        });

        // Notificación de sonido si no es propio y la ventana no tiene foco
        if (!isOwn) Notifications.ping();

      } catch {
        Messages.render({
          id: msg.id,
          msgType: 'chat',
          text: '[Corrupted message]',
          nickname: 'Unknown',
          color: '#888',
          timestamp: msg.timestamp,
          cipher: msg.payload,
          own: isOwn,
          error: true,
        });
      }
    },

    handleReaction(fromUserId, data) {
      const { messageId, emoji } = data;
      if (!messageId || !emoji) return;

      if (!state.reactions.has(messageId)) {
        state.reactions.set(messageId, new Map());
      }
      const reactionMap = state.reactions.get(messageId);

      if (!reactionMap.has(emoji)) {
        reactionMap.set(emoji, new Set());
      }
      reactionMap.get(emoji).add(fromUserId);

      // Actualizar UI del mensaje si existe
      const msgEl = $(`[data-id="${messageId}"]`);
      if (msgEl) {
        Messages.renderReactions(msgEl, messageId);
      }
    },

    renderReactions(msgEl, messageId) {
      let reactionsEl = msgEl.querySelector('.msg-reactions');
      if (!reactionsEl) {
        reactionsEl = document.createElement('div');
        reactionsEl.className = 'msg-reactions';
        const timerEl = msgEl.querySelector('.msg-timer');
        if (timerEl) msgEl.insertBefore(reactionsEl, timerEl);
        else msgEl.appendChild(reactionsEl);
      }

      reactionsEl.innerHTML = '';
      const reactionMap = state.reactions.get(messageId);
      if (!reactionMap) return;

      for (const [emoji, users] of reactionMap) {
        if (users.size === 0) continue;
        const pill = document.createElement('div');
        pill.className = 'reaction-pill';
        pill.title = `${users.size} reaction${users.size > 1 ? 's' : ''}`;
        pill.innerHTML = `<span class="r-emoji">${emoji}</span><span class="r-count">${users.size}</span>`;
        reactionsEl.appendChild(pill);
      }
    },

    render(data) {
      const container = $('#messages');
      const emptyState = $('#messages-empty');
      if (emptyState) emptyState.classList.add('hidden');

      const el = document.createElement('div');
      el.className = [
        'message',
        data.own    ? 'own'       : '',
        data.error  ? 'error-msg' : '',
      ].filter(Boolean).join(' ');
      el.dataset.id = data.id;
      el.dataset.expires = data.timestamp + state.messageTTL;

      const elapsed = Date.now() - data.timestamp;
      const remaining = state.messageTTL - elapsed;
      if (remaining <= 0) return;

      // Construir picker de reacciones
      const pickerHtml = CONFIG.REACTION_EMOJIS.map(
        (e) => `<button class="reaction-opt" data-emoji="${e}" aria-label="React ${e}">${e}</button>`
      ).join('');

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
        <div class="msg-reactions"></div>
        <div class="msg-reaction-picker" aria-hidden="true">${pickerHtml}</div>
        <div class="msg-timer">
          <div class="msg-timer-bar"
               style="--timer-duration: ${state.messageTTL}ms; --timer-delay: -${elapsed}ms">
          </div>
        </div>
      `;

      // Event listeners de reacciones
      el.querySelectorAll('.reaction-opt').forEach((btn) => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          Messages.sendReaction(data.id, btn.dataset.emoji);
          // Reacción optimista local
          Messages.handleReaction(state.userId, {
            messageId: data.id,
            emoji: btn.dataset.emoji,
          });
        });
      });

      container.appendChild(el);
      container.scrollTop = container.scrollHeight;

      // Programar eliminación
      const timeout = setTimeout(() => {
        el.classList.add('expiring');
        setTimeout(() => {
          el.remove();
          state.messages.delete(data.id);
          state.reactions.delete(data.id);
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
      el.innerHTML = `<div class="msg-body"><div class="msg-text">${text}</div></div>`;
      container.appendChild(el);
      container.scrollTop = container.scrollHeight;

      setTimeout(() => {
        el.classList.add('expiring');
        setTimeout(() => el.remove(), 400);
      }, 2 * 60 * 1000);
    },

    clearAll() {
      for (const [, data] of state.messages) clearTimeout(data.timeout);
      state.messages.clear();
      state.reactions.clear();
      const container = $('#messages');
      container.innerHTML = `
        <div class="messages-empty" id="messages-empty">
          <div class="empty-icon">👻</div>
          <p>No messages yet</p>
          <small>Messages self-destruct based on TTL</small>
        </div>
      `;
    },
  };

  // ═══════════ INVITE MODULE ═══════════
  const Invite = {
    open() {
      const modal = $('#invite-modal');
      if (!modal || !state.room) return;

      const url = `${location.protocol}//${location.host}/#r=${encodeURIComponent(state.room)}`;

      $('#invite-room-display').textContent = state.room;
      $('#invite-url-display').textContent = url;

      // Generar QR code
      const canvas = $('#invite-qr');
      if (canvas && window.QRCode) {
        QRCode.toCanvas(canvas, url, {
          width: 180,
          margin: 1,
          color: { dark: '#00e5ff', light: '#ffffff' },
        }, (err) => {
          if (err) console.error('[QR]', err);
        });
      }

      modal.classList.remove('hidden');
      $('#invite-close').focus();
    },

    close() {
      $('#invite-modal')?.classList.add('hidden');
    },

    copyRoom() {
      const btn = $('#copy-room-btn');
      navigator.clipboard.writeText(state.room).then(() => {
        Invite.flashCopied(btn);
        UI.toast('Room code copied!', 'success');
      }).catch(() => {});
    },

    copyUrl() {
      const btn = $('#copy-url-btn');
      const url = `${location.protocol}//${location.host}/#r=${encodeURIComponent(state.room)}`;
      navigator.clipboard.writeText(url).then(() => {
        Invite.flashCopied(btn);
        UI.toast('URL copied!', 'success');
      }).catch(() => {});
    },

    flashCopied(btn) {
      if (!btn) return;
      btn.classList.add('copied');
      setTimeout(() => btn.classList.remove('copied'), 1800);
    },

    readHashRoom() {
      const hash = location.hash;
      if (!hash) return null;
      const match = hash.match(/[#&]r=([^&]+)/);
      return match ? decodeURIComponent(match[1]) : null;
    },
  };

  // ═══════════ BOSS KEY MODULE ═══════════
  const BossKey = {
    active: false,
    originalTitle: document.title,

    // Datos de la hoja de cálculo falsa
    DATA: [
      ['Q2 Budget Planning 2026 — Marketing Division', '', '', '', '', '', '', '', '', ''],
      ['', '', '', '', '', '', '', '', '', ''],
      ['Department', 'January', 'February', 'March', 'Q1 Total', 'Q2 Budget', 'Q2 Forecast', 'Delta', '', 'Status'],
      ['Marketing',        '15,230', '14,780', '15,220', '45,230', '52,000', '49,800', '(2,200)', '', '✓'],
      ['Sales',            '22,100', '21,450', '23,670', '67,220', '75,000', '71,500', '(3,500)', '', '✓'],
      ['Operations',       '8,900',  '9,120',  '8,750',  '26,770', '28,000', '27,800', '(200)',   '', '✓'],
      ['Human Resources',  '5,600',  '5,450',  '5,780',  '16,830', '18,500', '18,200', '(300)',   '', '✓'],
      ['Information Tech', '12,340', '11,890', '13,100', '37,330', '42,000', '40,500', '(1,500)', '', '✓'],
      ['Finance & Legal',  '4,200',  '4,100',  '4,350',  '12,650', '14,000', '13,500', '(500)',   '', '✓'],
      ['Product Dev.',     '18,900', '17,650', '19,200', '55,750', '62,000', '59,000', '(3,000)', '', '✓'],
      ['Customer Success', '6,780',  '6,500',  '7,100',  '20,380', '23,000', '22,000', '(1,000)', '', '✓'],
      ['', '', '', '', '', '', '', '', '', ''],
      ['TOTAL', '94,050', '90,940', '97,170', '282,160', '314,500', '302,300', '(12,200)', '', ''],
      ['', '', '', '', '', '', '', '', '', ''],
      ['Notes:', '', '', '', '', '', '', '', '', ''],
      ['• All amounts in USD ($)', '', '', '', '', '', '', '', '', ''],
      ['• Q2 Forecast last updated: 04/28/2026', '', '', '', '', '', '', '', '', ''],
      ['• Delta = Q2 Forecast − Q2 Budget', '', '', '', '', '', '', '', '', ''],
      ['• Pending CFO approval by 05/05/2026', '', '', '', '', '', '', '', '', ''],
      ['', '', '', '', '', '', '', '', '', ''],
      ['Prepared by:', 'J. Martinez', '', 'Reviewed by:', 'A. Chen', '', 'Date:', '04/30/2026', '', ''],
    ],

    COLS: ['', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J'],
    COL_WIDTHS: [46, 160, 80, 80, 80, 90, 90, 100, 90, 20, 70],

    init() {
      BossKey.buildGrid();
    },

    buildGrid() {
      const colHeadersEl = $('#boss-col-headers');
      const gridEl = $('#boss-grid');
      if (!colHeadersEl || !gridEl) return;

      // Cabeceras de columnas
      colHeadersEl.innerHTML = '';
      BossKey.COLS.forEach((col, i) => {
        const el = document.createElement('div');
        el.className = i === 0 ? 'boss-col-h-corner' : 'boss-col-h';
        el.style.width = (BossKey.COL_WIDTHS[i] || 90) + 'px';
        el.style.minWidth = (BossKey.COL_WIDTHS[i] || 90) + 'px';
        el.textContent = col;
        colHeadersEl.appendChild(el);
      });

      // Filas de datos
      gridEl.innerHTML = '';
      BossKey.DATA.forEach((row, rowIdx) => {
        const rowEl = document.createElement('div');
        rowEl.className = 'boss-row';
        rowEl.dataset.row = rowIdx + 1;

        // Número de fila
        const numCell = document.createElement('div');
        numCell.className = 'boss-row-num';
        numCell.textContent = rowIdx + 1;
        rowEl.appendChild(numCell);

        // Celdas de datos
        row.forEach((cellVal, colIdx) => {
          const cell = document.createElement('div');
          cell.className = 'boss-cell';
          cell.style.width = (BossKey.COL_WIDTHS[colIdx + 1] || 90) + 'px';
          cell.style.minWidth = (BossKey.COL_WIDTHS[colIdx + 1] || 90) + 'px';
          cell.textContent = cellVal;
          cell.dataset.col = BossKey.COLS[colIdx + 1] || '';
          cell.dataset.row = rowIdx + 1;

          // Estilos especiales por fila/columna
          if (rowIdx === 0) cell.classList.add('title-cell');
          else if (rowIdx === 2) cell.classList.add('header-cell');
          else if (rowIdx === 12) cell.classList.add('total-cell');
          else if (rowIdx >= 14 && rowIdx <= 18) cell.classList.add('note-cell');

          if (cellVal.startsWith('(') && cellVal.endsWith(')')) cell.classList.add('negative');
          if (cellVal === '✓') cell.classList.add('check-cell');
          if (colIdx >= 1 && colIdx <= 7 && rowIdx >= 3 && rowIdx <= 11) cell.classList.add('number-cell');

          // Click para seleccionar celda
          cell.addEventListener('click', () => BossKey.selectCell(cell, colIdx, rowIdx));
          rowEl.appendChild(cell);
        });

        gridEl.appendChild(rowEl);
      });

      // Seleccionar celda por defecto (A3 = "Department")
      setTimeout(() => {
        const defaultCell = gridEl.querySelector('[data-row="3"][data-col="A"]');
        if (defaultCell) BossKey.selectCell(defaultCell, 0, 2);
      }, 50);
    },

    selectCell(cell, colIdx, rowIdx) {
      $$('.boss-cell.selected').forEach(c => c.classList.remove('selected'));
      cell.classList.add('selected');

      const colLabel = BossKey.COLS[colIdx + 1] || 'A';
      const rowLabel = rowIdx + 1;
      const ref = `${colLabel}${rowLabel}`;

      const nameBox = $('#boss-name-box');
      const formulaContent = $('#boss-formula-content');
      const statusCenter = $('#boss-status-center');

      if (nameBox) nameBox.textContent = ref;
      if (formulaContent) formulaContent.textContent = cell.textContent || '';

      // Status bar con stats de la selección
      if (statusCenter && cell.textContent) {
        const num = parseFloat(cell.textContent.replace(/[,$()]/g, '').replace(/\((.+)\)/, '-$1'));
        if (!isNaN(num)) {
          statusCenter.textContent = `Sum: ${cell.textContent}`;
        } else {
          statusCenter.textContent = '';
        }
      }
    },

    show() {
      BossKey.active = true;
      const overlay = $('#boss-overlay');
      if (!overlay) return;
      overlay.classList.remove('hidden');
      document.title = 'Q2 Budget Planning 2026 - Google Sheets';
      // Silenciar sonidos mientras está activo
    },

    hide() {
      BossKey.active = false;
      const overlay = $('#boss-overlay');
      if (!overlay) return;
      overlay.classList.add('hidden');
      document.title = BossKey.originalTitle;
    },

    toggle() {
      if (BossKey.active) BossKey.hide();
      else BossKey.show();
    },
  };

  // ═══════════ NOTIFICATIONS MODULE ═══════════
  const Notifications = {
    audioCtx: null,

    getCtx() {
      if (!Notifications.audioCtx) {
        Notifications.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      }
      return Notifications.audioCtx;
    },

    ping() {
      if (!state.soundEnabled) return;
      // No suena si boss key está activo (evitar alertar al jefe)
      if (BossKey.active) return;

      try {
        const ctx = Notifications.getCtx();
        const oscillator = ctx.createOscillator();
        const gainNode = ctx.createGain();

        oscillator.connect(gainNode);
        gainNode.connect(ctx.destination);

        oscillator.type = 'sine';
        oscillator.frequency.setValueAtTime(880, ctx.currentTime);
        oscillator.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.15);

        gainNode.gain.setValueAtTime(0.08, ctx.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4);

        oscillator.start(ctx.currentTime);
        oscillator.stop(ctx.currentTime + 0.4);
      } catch { /* Audio API no disponible */ }
    },
  };

  // ═══════════ UI MODULE ═══════════
  const UI = {
    init() {
      // Login form
      $('#login-form').addEventListener('submit', (e) => { e.preventDefault(); App.connect(); });

      $('#gen-room-btn').addEventListener('click', () => {
        $('#room-input').value = generateRoomCode();
        $('#room-input').focus();
      });

      $('#toggle-pass-btn').addEventListener('click', () => {
        const input = $('#passphrase-input');
        const isPass = input.type === 'password';
        input.type = isPass ? 'text' : 'password';
        $('#toggle-pass-btn').classList.toggle('active', !isPass);
      });

      // Send message
      const cipherDisplay = $('#cipher-display');
      const msgInput = $('#message-input');
      const charCount = $('#char-count');

      const handleSend = () => {
        if (msgInput.value.trim()) {
          Messages.send(msgInput.value);
          msgInput.value = '';
          cipherDisplay.textContent = '';
          if (charCount) charCount.textContent = '0 / 500';
          if (charCount) { charCount.classList.remove('warn', 'limit'); }
          msgInput.focus();
        }
      };

      $('#send-btn').addEventListener('click', handleSend);

      msgInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(); }
      });

      // Contador de caracteres + cipher display
      let cipherRefreshInterval = null;

      msgInput.addEventListener('input', () => {
        const len = msgInput.value.length;

        // Char count
        if (charCount) {
          charCount.textContent = `${len} / 500`;
          charCount.classList.toggle('warn', len > 400);
          charCount.classList.toggle('limit', len >= 500);
        }

        // Cipher display
        if (len > 0) {
          cipherDisplay.textContent = generateInputCipher(len);
          if (!cipherRefreshInterval) {
            cipherRefreshInterval = setInterval(() => {
              if (msgInput.value.length > 0) {
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
          if (cipherRefreshInterval) { clearInterval(cipherRefreshInterval); cipherRefreshInterval = null; }
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

      // Invite
      $('#invite-btn')?.addEventListener('click', () => Invite.open());
      $('#invite-close')?.addEventListener('click', () => Invite.close());
      $('#copy-room-btn')?.addEventListener('click', () => Invite.copyRoom());
      $('#copy-url-btn')?.addEventListener('click', () => Invite.copyUrl());

      // Cerrar modal al hacer click fuera
      $('#invite-modal')?.addEventListener('click', (e) => {
        if (e.target === $('#invite-modal')) Invite.close();
      });

      // Boss Key
      $('#boss-btn')?.addEventListener('click', () => BossKey.toggle());

      // Toggle sonido
      $('#notif-btn')?.addEventListener('click', () => {
        state.soundEnabled = !state.soundEnabled;
        const btn = $('#notif-btn');
        if (btn) {
          btn.classList.toggle('notif-on', state.soundEnabled);
          btn.setAttribute('aria-pressed', String(state.soundEnabled));
        }
      });

      // Toggle read mode
      $('#read-mode-btn')?.addEventListener('click', () => UI.toggleReadMode());

      // TTL selector
      $('#ttl-select')?.addEventListener('change', (e) => {
        state.messageTTL = parseInt(e.target.value, 10);
        UI.toast(`TTL set to ${e.target.options[e.target.selectedIndex].text}`, 'success');
      });

      // Copy room code desde el header
      $('#copy-room-header-btn')?.addEventListener('click', () => {
        navigator.clipboard.writeText(state.room).then(() => {
          UI.toast('Room code copied!', 'success');
        }).catch(() => {});
      });
    },

    toggleReadMode() {
      state.readMode = !state.readMode;
      document.body.classList.toggle('read-mode', state.readMode);
      const btn = $('#read-mode-btn');
      if (btn) {
        btn.classList.toggle('active', state.readMode);
        btn.setAttribute('aria-pressed', String(state.readMode));
        btn.title = state.readMode
          ? 'Read Mode ON — Alt+R to toggle'
          : 'Read Mode OFF — Alt+R to toggle';
      }
    },

    showChat() {
      $('#login-screen').classList.remove('active');
      $('#chat-screen').classList.add('active');
      $('#room-name').textContent = state.room;
      $('#message-input').focus();
      $('#connect-btn')?.classList.remove('loading');

      // Limpiar hash de URL si viene de un invite link
      if (location.hash) history.replaceState(null, '', location.pathname);
    },

    showLogin() {
      $('#chat-screen').classList.remove('active');
      $('#login-screen').classList.add('active');
      $('#connect-btn')?.classList.remove('loading');
      state.knownUsers.clear();
      UI.renderUserAvatars();
      Invite.close();
      if (BossKey.active) BossKey.hide();
    },

    updateUserCount(count) {
      $('#user-count').textContent = count;
    },

    renderUserAvatars() {
      const container = $('#user-avatars');
      if (!container) return;
      container.innerHTML = '';

      const MAX_AVATARS = 5;
      const users = [...state.knownUsers.values()].slice(0, MAX_AVATARS);

      users.forEach((user) => {
        const avatar = document.createElement('div');
        avatar.className = 'user-avatar';
        avatar.style.background = user.color;
        avatar.textContent = user.initials;
        avatar.setAttribute('data-name', user.nickname);
        avatar.setAttribute('title', user.nickname);
        container.appendChild(avatar);
      });

      if (state.knownUsers.size > MAX_AVATARS) {
        const more = document.createElement('div');
        more.className = 'user-avatar';
        more.style.background = 'rgba(255,255,255,0.1)';
        more.style.color = 'var(--text-secondary)';
        more.style.fontSize = '0.55rem';
        more.textContent = `+${state.knownUsers.size - MAX_AVATARS}`;
        container.appendChild(more);
      }
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

    toast(message, type = 'success') {
      const container = $('#toast-container');
      if (!container) return;

      const toast = document.createElement('div');
      toast.className = `toast ${type}`;

      const icon = type === 'success'
        ? '<svg class="toast-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>'
        : '<svg class="toast-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';

      toast.innerHTML = `${icon}<span>${escapeHtml(message)}</span>`;
      container.appendChild(toast);

      setTimeout(() => {
        toast.classList.add('removing');
        setTimeout(() => toast.remove(), 280);
      }, 2200);
    },
  };

  // ═══════════ SECURITY MODULE ═══════════
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

    blockKeyboardShortcuts() {
      document.addEventListener('keydown', (e) => {
        // DevTools
        if (e.key === 'F12') { e.preventDefault(); e.stopPropagation(); return; }
        if (e.ctrlKey && e.shiftKey && ['I','J','C'].includes(e.key.toUpperCase())) {
          e.preventDefault(); e.stopPropagation(); return;
        }

        // Ver fuente / guardar / imprimir
        if (e.ctrlKey && ['u','s','p'].includes(e.key.toLowerCase())) { e.preventDefault(); return; }

        // ── Solo en chat screen ──
        if (!$('#chat-screen')?.classList.contains('active')) return;

        // Boss Key: Alt+B
        if (e.altKey && e.key.toLowerCase() === 'b') {
          e.preventDefault();
          BossKey.toggle();
          return;
        }

        // Read Mode: Alt+R
        if (e.altKey && e.key.toLowerCase() === 'r') {
          e.preventDefault();
          UI.toggleReadMode();
          return;
        }

        // Invite: Alt+I
        if (e.altKey && e.key.toLowerCase() === 'i') {
          e.preventDefault();
          Invite.open();
          return;
        }

        // Si boss key está activo, bloquear Escape para evitar que active el panic
        if (BossKey.active && e.key === 'Escape') {
          e.preventDefault();
          BossKey.hide();
          return;
        }

        // Si invite modal abierto, Escape lo cierra
        if (!$('#invite-modal')?.classList.contains('hidden') && e.key === 'Escape') {
          e.preventDefault();
          Invite.close();
          return;
        }

        // Escape = PANIC (solo si conectado y sin modales)
        if (e.key === 'Escape' && state.connected) {
          App.panic();
          return;
        }

        // Seleccionar todo — bloqueado en chat
        if (e.ctrlKey && e.key.toLowerCase() === 'a') { e.preventDefault(); e.stopPropagation(); return; }

        // Copiar/cortar — envenenar clipboard
        if (e.ctrlKey && ['c','x'].includes(e.key.toLowerCase())) {
          e.preventDefault(); e.stopPropagation();
          Security.writePoison();
          return;
        }
      }, true);
    },

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

      document.addEventListener('paste', (e) => {
        if (e.target.closest('#chat-screen') && e.target.id !== 'message-input') {
          e.preventDefault();
        }
      }, true);
    },

    blockSelection() {
      document.addEventListener('selectstart', (e) => {
        const inChat = e.target.closest('#chat-screen');
        const isInput = e.target.id === 'message-input';
        const isReaction = e.target.classList.contains('reaction-opt');
        if (inChat && !isInput && !isReaction) e.preventDefault();
      });
    },

    blockContextMenu() {
      document.addEventListener('contextmenu', (e) => {
        if (e.target.closest('#chat-screen')) e.preventDefault();
      }, true);
    },

    blockDragDrop() {
      document.addEventListener('dragstart', (e) => {
        if (e.target.closest('#chat-screen')) e.preventDefault();
      }, true);
      document.addEventListener('drop', (e) => {
        if (e.target.closest('#chat-screen')) e.preventDefault();
      }, true);
    },

    detectPrintScreen() {
      document.addEventListener('keyup', (e) => {
        if (e.key === 'PrintScreen') {
          Security.flashProtection();
          Security.writePoison();
        }
      }, true);

      document.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.key === 'Meta') && e.shiftKey && e.key.toLowerCase() === 's') {
          e.preventDefault();
          Security.flashProtection();
        }
      }, true);
    },

    detectDevTools() {
      Security.devToolsCheckInterval = setInterval(() => {
        if (!$('#chat-screen')?.classList.contains('active')) return;

        const widthDiff  = window.outerWidth  - window.innerWidth  > 200;
        const heightDiff = window.outerHeight - window.innerHeight > 200;

        if ((widthDiff || heightDiff) && !Security.devToolsOpen) {
          Security.devToolsOpen = true;
          console.clear();
          App.panic();
        } else if (!widthDiff && !heightDiff) {
          Security.devToolsOpen = false;
        }
      }, 1500);
    },

    monitorFocus() {
      const hide = () => {
        state.windowFocused = false;
        if (!BossKey.active) {
          $('#blur-overlay')?.classList.add('active');
        }
      };
      const show = () => {
        state.windowFocused = true;
        if (!Security.devToolsOpen) {
          $('#blur-overlay')?.classList.remove('active');
        }
      };

      window.addEventListener('blur', hide);
      window.addEventListener('focus', show);
      document.addEventListener('visibilitychange', () => {
        if (document.hidden) hide(); else show();
      });
    },

    flashProtection() {
      const overlay = $('#blur-overlay');
      overlay?.classList.add('active');
      setTimeout(() => {
        if (document.hasFocus() && !Security.devToolsOpen) {
          overlay?.classList.remove('active');
        }
      }, 3000);
    },

    async writePoison() {
      try {
        await navigator.clipboard.writeText(generateInputCipher(48));
      } catch { /* Clipboard API no disponible */ }
    },
  };

  // ═══════════ APP (Orchestrator) ═══════════
  const App = {
    async connect() {
      const room       = $('#room-input').value.trim();
      const passphrase = $('#passphrase-input').value;
      const nickname   = $('#nickname-input').value.trim()
        || 'Ghost-' + Math.floor(Math.random() * 9000 + 1000);

      if (!room) { UI.showError('Room code is required'); return; }
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
      } catch {
        UI.showError('Failed to initialize encryption');
        $('#connect-btn').classList.remove('loading');
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

      // Ocultar todo inmediatamente
      $('#blur-overlay')?.classList.add('active');

      Messages.clearAll();
      App.disconnect();

      // Borrar rastros
      $('#passphrase-input').value = '';
      $('#message-input').value = '';
      $('#cipher-display').textContent = '';
      Security.writePoison();
      console.clear();

      setTimeout(() => {
        $('#blur-overlay')?.classList.remove('active');
      }, 800);
    },
  };

  // ═══════════ BOOT ═══════════
  document.addEventListener('DOMContentLoaded', () => {
    UI.init();
    Security.init();
    BossKey.init();

    // Pre-rellenar room code desde URL hash (invite link)
    const hashRoom = Invite.readHashRoom();
    if (hashRoom) {
      $('#room-input').value = hashRoom;
      // Enfocar el campo de passphrase directamente
      setTimeout(() => $('#passphrase-input')?.focus(), 100);
    } else if (!$('#room-input').value) {
      $('#room-input').value = generateRoomCode();
    }
  });
})();
