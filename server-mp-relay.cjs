// server-mp-relay.cjs —— 微信小游戏原生 WebSocket 实时联机中继
// 由 server.cjs 在 socket.io / rooms / roomChats 初始化之后 require，
// 复用其房间数据与 io 广播，使管理后台的房间监管对小程序同样生效。
// 用 WebSocket.Server({noServer}) 挂在已有 http server 上，不依赖 PeerJS/WebRTC/web-view。

module.exports = function mountMpRelay({ app, server, io, rooms, roomChats, players, onlinePlayers,
                                         globalFunctions, userBans, clientIp, isIPBanned,
                                         generateRoomId, getRandomColor, getAllRoomsList,
                                         broadcastRoomList, WebSocket }) {
    const mpRelayClients = new Map(); // ws -> {clientId, roomId, playerId}
    const mpRelayRooms = new Map();   // roomId -> Set<WebSocket>

    function mpRelaySend(ws, msg) {
        try { if (ws && ws.readyState === 1) ws.send(JSON.stringify(msg)); } catch (e) {}
    }
    function mpRelayBroadcast(roomId, msg, exceptWs) {
        const set = mpRelayRooms.get(roomId);
        if (!set) return;
        for (const ws of set) if (ws !== exceptWs) mpRelaySend(ws, msg);
    }
    function mpRelaySnapshot(room) {
        return {
            roomId: room.id,
            name: room.name || '',
            status: room.status,
            maxPlayers: room.maxPlayers,
            private: !!room.private,
            hostName: room.hostName || '',
            chatDisabled: !!room.chatDisabled,
            maze: room.maze || null,
            players: Array.from(room.players.values()).map(p => ({
                id: p.id, name: p.name, color: p.color || '#ffffff',
                x: (typeof p.x === 'number') ? p.x : null,
                y: (typeof p.y === 'number') ? p.y : null,
                isHost: !!p.isHost, clientId: p.clientId || null,
                reachedExit: !!p.reachedExit
            }))
        };
    }

    // 与 socket.io 事件互通：网页端走 io 房间，小游戏走原生 ws，两边都能收到对方动作
    for (const ev of ['player-joined','player-left','game-started','maze-updated','player-kicked-by-admin',
                      'promoted-to-host','room-kicked','room-cleared-by-admin','admin-teleport',
                      'admin-transfer-host','room-max-players-changed','admin-chat-message','admin-chat-delete',
                      'admin-room-chat-disabled']) {
        io.on(ev, (data) => {
            const roomId = data && (data.roomId || data.id);
            if (roomId) mpRelayBroadcast(String(roomId), Object.assign({ t: 'socket-event', event: ev }, data));
        });
    }

    function mpRelayLeave(ws) {
        const c = mpRelayClients.get(ws);
        if (!c || !c.roomId) return;
        const room = rooms.get(c.roomId);
        const set = mpRelayRooms.get(c.roomId);
        if (set) { set.delete(ws); if (!set.size) mpRelayRooms.delete(c.roomId); }
        mpRelayClients.set(ws, Object.assign({}, c, { roomId: null }));
        if (!room) return;
        room.players.delete(c.playerId);
        room.lastActivity = Date.now();
        io.to(room.id).emit('player-left', { playerId: c.playerId, playerName: c.name });
        mpRelayBroadcast(room.id, { t: 'player-left', playerId: c.playerId, name: c.name });
        if (c.isHost && room.players.size > 0) {
            const newHost = room.players.values().next().value;
            newHost.isHost = true;
            room.actualHost = newHost.socketId || room.actualHost;
            room.hostName = newHost.name;
            io.to(room.id).emit('promoted-to-host', { roomId: room.id, message: '你已成为新任房主。' });
            mpRelayBroadcast(room.id, { t: 'host-changed', hostId: newHost.id, hostName: newHost.name });
        }
        if (onlinePlayers.get(c.clientId) && onlinePlayers.get(c.clientId).socketId === 'mp') {
            onlinePlayers.get(c.clientId).roomId = null;
        }
        broadcastRoomList();
    }

    function mpRelayHandle(ws, raw) {
        let m;
        try { m = JSON.parse(String(raw)); } catch (e) { return; }
        if (!m || !m.t) return;
        const c = mpRelayClients.get(ws) || {};
        const cid = c.clientId;
        const hall = !!globalFunctions.multiplayer;
        const chatOn = !!globalFunctions.multiplayerChat;
        const ban = (cid && userBans.get(String(cid))) || { multiplayer:false, chat:false, reasons:{} };
        const ipBanned = !!c.ip && isIPBanned(c.ip);
        const reply = (obj) => mpRelaySend(ws, Object.assign({ rid: m.rid }, obj));

        if (m.t === 'ping') { reply({ t: 'pong', at: Date.now() }); return; }

        if (m.t === 'hello') {
            c.clientId = String(m.clientId || cid || '').slice(0, 64) || ('wx_' + Date.now());
            c.name = String(m.name || '玩家').slice(0, 20);
            c.ip = String(m.ip || '').slice(0, 64) || null;
            mpRelayClients.set(ws, c);
            reply({ t: 'welcome', clientId: c.clientId, name: c.name, features: { multiplayer: hall, chat: chatOn } });
            return;
        }

        if (m.t === 'list') {
            if (cid && ban.multiplayer) return reply({ t: 'error', message: ban.reasons.multiplayer || '多人游戏已被封禁' });
            return reply({ t: 'rooms', rooms: getAllRoomsList().filter(r => !r.private) });
        }

        if (m.t === 'detail') {
            const room = rooms.get(String(m.roomId || ''));
            if (!room) return reply({ t: 'error', message: '房间不存在' });
            return reply(Object.assign({ t: 'detail' }, mpRelaySnapshot(room)));
        }

        if ((m.t === 'create' || m.t === 'join') && (ipBanned || ban.multiplayer || !hall)) {
            return reply({ t: 'error', message: ipBanned ? 'IP 已被封禁' : (ban.multiplayer ? (ban.reasons.multiplayer || '多人游戏已被封禁') : '多人联机功能已被管理员关闭') });
        }

        if (m.t === 'create') {
            if (c.roomId) mpRelayLeave(ws);
            const roomCode = String(m.roomCode || '').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 24);
            const roomId = roomCode && !rooms.has(roomCode) ? roomCode : generateRoomId();
            const isPrivate = !!m.isPrivate, password = String(m.password || '');
            if (password && !/^[0-9a-f]{64}$/i.test(password))
                return reply({ t: 'error', message: '房间密码格式不正确' });
            if (c.name.length > 20) return reply({ t: 'error', message: '昵称不能超过20个字' });
            const playerId = 'mp_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
            const color = getRandomColor();
            const room = {
                id: roomId, name: String(m.name || (c.name + '的房间')).slice(0, 30),
                host: playerId, actualHost: null, waitingSocket: false,
                players: new Map([[playerId, { id: playerId, name: c.name, color, isHost: true,
                    clientId: c.clientId, x: null, y: null, socketId: null, joinedAt: Date.now(), reachedExit: false }]]),
                maxPlayers: Math.max(1, Math.min(12, parseInt(m.maxPlayers, 10) || 4)),
                status: 'waiting', hostName: c.name, private: isPrivate, password: password || undefined,
                inviteCode: Math.random().toString(36).slice(2, 10).toUpperCase(),
                createdAt: Date.now(), lastActivity: Date.now(), maze: null, chatDisabled: false
            };
            rooms.set(roomId, room);
            let set = mpRelayRooms.get(roomId); if (!set) mpRelayRooms.set(roomId, set = new Set());
            set.add(ws);
            Object.assign(c, { roomId, playerId, isHost: true });
            mpRelayClients.set(ws, c);
            onlinePlayers.set(c.clientId, { id: c.clientId, name: c.name, color, socketId: 'mp', roomId, joinedAt: Date.now() });
            broadcastRoomList();
            reply(Object.assign({ t: 'joined', playerId, color, isHost: true, inviteCode: room.inviteCode }, mpRelaySnapshot(room)));
            console.log(`[MP-RELAY] 玩家 ${c.name} 创建房间 ${roomId}`);
            return;
        }

        if (m.t === 'join') {
            const roomId = String(m.roomId || '').trim();
            const room = rooms.get(roomId);
            if (!room) return reply({ t: 'error', message: '房间不存在' });
            if (room.status !== 'waiting') return reply({ t: 'error', message: '游戏已开始' });
            if (room.private && String(m.password || '') !== (room.password || ''))
                return reply({ t: 'error', message: '房间密码错误' });
            if (room.players.size >= room.maxPlayers) return reply({ t: 'error', message: '房间已满' });
            if (!hall || ipBanned) return reply({ t: 'error', message: '无法加入房间' });
            if (c.roomId) mpRelayLeave(ws);
            const playerId = 'mp_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
            const color = getRandomColor();
            const p = { id: playerId, name: c.name, color, isHost: false, clientId: c.clientId,
                x: null, y: null, socketId: null, joinedAt: Date.now(), reachedExit: false };
            room.players.set(playerId, p);
            room.lastActivity = Date.now();
            let set = mpRelayRooms.get(roomId); if (!set) mpRelayRooms.set(roomId, set = new Set());
            set.add(ws);
            Object.assign(c, { roomId, playerId, isHost: false });
            mpRelayClients.set(ws, c);
            onlinePlayers.set(c.clientId, { id: c.clientId, name: c.name, color, socketId: 'mp', roomId, joinedAt: Date.now() });
            const snap = mpRelaySnapshot(room);
            mpRelayBroadcast(roomId, { t: 'player-joined', player: p, snapshot: snap }, ws);
            io.to(roomId).emit('player-joined', { player: p, players: Array.from(room.players.values()) });
            broadcastRoomList();
            reply(Object.assign({ t: 'joined', playerId, color, isHost: false, inviteCode: room.inviteCode }, snap));
            console.log(`[MP-RELAY] 玩家 ${c.name} 加入房间 ${roomId}`);
            return;
        }

        if (m.t === 'leave') { mpRelayLeave(ws); reply({ t: 'left' }); return; }

        if (!c.roomId) return reply({ t: 'error', message: '尚未加入房间' });
        const room = rooms.get(c.roomId);
        if (!room) { c.roomId = null; return reply({ t: 'error', message: '房间已关闭' }); }
        room.lastActivity = Date.now();

        switch (m.t) {
            case 'maze': {
                if (!c.isHost) return reply({ t: 'error', message: '只有房主可以更换地图' });
                const maze = m.maze;
                if (!Array.isArray(maze) || !maze.length || !Array.isArray(maze[0]) || maze.length > 64 || maze[0].length > 64) return;
                room.maze = maze;
                mpRelayBroadcast(c.roomId, { t: 'maze-updated', maze }, ws);
                io.to(c.roomId).emit('maze-updated', { maze });
                break;
            }
            case 'start': {
                if (!c.isHost) return reply({ t: 'error', message: '只有房主可以开始游戏' });
                room.status = 'playing';
                mpRelayBroadcast(c.roomId, { t: 'game-started' });
                io.to(c.roomId).emit('game-started', { roomId: c.roomId, status: 'playing' });
                broadcastRoomList();
                break;
            }
            case 'move': {
                const p = room.players.get(c.playerId);
                if (!p) return;
                const x = Number(m.x), y = Number(m.y);
                if (!Number.isFinite(x) || !Number.isFinite(y) || x < 0 || y < 0 || x > 64 || y > 64) return;
                p.x = x; p.y = y;
                mpRelayBroadcast(c.roomId, { t: 'player-move', playerId: c.playerId, x, y }, ws);
                io.to(c.roomId).emit('mp-player-move', { roomId: c.roomId, playerId: c.playerId, x, y });
                break;
            }
            case 'exit': {
                const p = room.players.get(c.playerId);
                if (!p) return;
                p.reachedExit = true;
                mpRelayBroadcast(c.roomId, { t: 'player-reached-exit', playerId: c.playerId }, ws);
                break;
            }
            case 'chat': {
                const text = String(m.text || '').slice(0, 500);
                if (!text.trim()) return;
                if (!chatOn || ban.chat || room.chatDisabled) return reply({ t: 'error', message: '聊天功能已被关闭' });
                const msgId = String(m.messageId || ('mp_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6))).slice(0, 80);
                const payload = { t: 'chat', messageId: msgId, from: c.playerId, sender: c.name, color: c.color || '#ffffff', text };
                mpRelayBroadcast(c.roomId, payload, ws);
                reply(payload);
                let list = roomChats.get(c.roomId); if (!list) roomChats.set(c.roomId, list = []);
                if (!list.some(x => x.messageId === msgId)) list.push({
                    messageId: msgId, sender: c.name, clientId: c.clientId, message: text, image: null, isAdmin: false, time: Date.now()
                });
                if (list.length > 200) list.shift();
                break;
            }
            case 'pm': {
                const to = String(m.to || '');
                const text = String(m.text || '').slice(0, 500);
                if (!to || !text.trim()) return;
                if (!chatOn || ban.chat || room.chatDisabled) return reply({ t: 'error', message: '聊天功能已被关闭' });
                const payload = { t: 'pm', from: c.playerId, to, sender: c.name, text, messageId: String(m.messageId || '') };
                mpRelaySend(ws, payload);
                for (const [rw, rc] of mpRelayClients) {
                    if (rc.playerId === to && rc.roomId === c.roomId) mpRelaySend(rw, payload);
                }
                break;
            }
            case 'image': {
                const data = String(m.image || '').slice(0, 500000);
                if (!data) return;
                if (!chatOn || ban.chat || room.chatDisabled) return reply({ t: 'error', message: '聊天功能已被关闭' });
                const msgId = String(m.messageId || ('mp_' + Date.now()));
                const payload = { t: 'image', messageId: msgId, from: c.playerId, sender: c.name, image: data };
                mpRelayBroadcast(c.roomId, payload, ws);
                reply(payload);
                // 监管镜像（与文字聊天一致，admin 可查看/删除图片）
                let imgList = roomChats.get(c.roomId); if (!imgList) roomChats.set(c.roomId, imgList = []);
                if (!imgList.some(x => x.messageId === msgId)) imgList.push({
                    messageId: msgId, sender: c.name, clientId: c.clientId, message: null, image: data, isAdmin: false, time: Date.now()
                });
                if (imgList.length > 200) imgList.shift();
                break;
            }
            case 'voice': {
                const data = String(m.voice || '').slice(0, 500000);
                const duration = Math.max(1, Math.min(60, parseInt(m.duration, 10) || 3));
                if (!data) return;
                const vId = String(m.messageId || ('mpv_' + Date.now()));
                const payload = { t: 'voice', from: c.playerId, sender: c.name, voice: data, duration, messageId: vId };
                mpRelayBroadcast(c.roomId, payload, ws);
                reply(payload);
                // 语音消息同样镜像（不解码，仅留存 base64 与时长）
                let vList = roomChats.get(c.roomId); if (!vList) roomChats.set(c.roomId, vList = []);
                if (!vList.some(x => x.messageId === vId)) vList.push({
                    messageId: vId, sender: c.name, clientId: c.clientId, message: '[语音 ' + duration + '″]', image: data, isAdmin: false, time: Date.now()
                });
                if (vList.length > 200) vList.shift();
                break;
            }
            case 'recall': {
                const msgId = String(m.messageId || '');
                if (!msgId) return;
                mpRelayBroadcast(c.roomId, { t: 'recalled', messageId: msgId });
                const list = roomChats.get(c.roomId) || [];
                const idx = list.findIndex(x => x.messageId === msgId);
                if (idx >= 0) list.splice(idx, 1);
                break;
            }
            case 'kick': {
                if (!c.isHost) return reply({ t: 'error', message: '只有房主可以踢人' });
                const target = String(m.playerId || '');
                if (!target || target === c.playerId) return;
                if (!room.players.has(target)) return;
                room.players.delete(target);
                for (const [rw, rc] of Array.from(mpRelayClients)) {
                    if (rc.playerId === target && rc.roomId === c.roomId) {
                        mpRelaySend(rw, { t: 'kicked', message: '你已被房主移出房间' });
                        try { rw.close(); } catch (e) {} mpRelayLeave(rw);
                    }
                }
                mpRelayBroadcast(c.roomId, { t: 'player-left', playerId: target });
                io.to(c.roomId).emit('player-kicked-by-admin', { playerName: target });
                break;
            }
            case 'promote': {
                if (!c.isHost) return reply({ t: 'error', message: '只有房主可以转让' });
                const target = room.players.get(String(m.playerId || ''));
                if (!target) return;
                for (const p of room.players.values()) p.isHost = false;
                target.isHost = true;
                c.isHost = false;
                room.actualHost = target.socketId || room.actualHost;
                room.hostName = target.name;
                mpRelayBroadcast(c.roomId, { t: 'host-changed', hostId: target.id, hostName: target.name });
                io.to(c.roomId).emit('admin-transfer-host', { roomId: room.id, newHostId: target.id, newHostName: target.name });
                break;
            }
        }
    }

    const mpRelayWss = new WebSocket.Server({ noServer: true, maxPayload: 1024 * 1024 });
    server.on('upgrade', (req, socket, head) => {
        let pathname = '';
        try { pathname = new URL(req.url, 'http://localhost').pathname; } catch (e) { return; }
        if (pathname !== '/mp-relay') return; // 非本中继路径交给 socket.io 的 engine.io 处理
        mpRelayWss.handleUpgrade(req, socket, head, (ws) => mpRelayWss.emit('connection', ws, req));
    });
    mpRelayWss.on('connection', (ws, req) => {
        mpRelayClients.set(ws, { clientId: '', roomId: null, playerId: null, name: '玩家', ip: null });
        // 取真实 IP（X-Forwarded-For 优先，onrender 等反代场景）
        try {
            const c = mpRelayClients.get(ws);
            const xff = req.headers && req.headers['x-forwarded-for'];
            c.ip = (xff && String(xff).split(',')[0].trim()) || (req.socket && req.socket.remoteAddress) || null;
        } catch (e) {}
        ws.on('message', (data) => {
            try { mpRelayHandle(ws, data); } catch (e) { console.error('[MP-RELAY] 处理消息失败:', e); }
        });
        ws.on('close', () => { try { mpRelayLeave(ws); } catch (e) {} mpRelayClients.delete(ws); });
        ws.on('error', () => {});
    });
    console.log('[MP-RELAY] 微信小游戏原生 WebSocket 联机中继已挂载: /mp-relay');
    return { mpRelayWss, mpRelayClients, mpRelayRooms };
};
