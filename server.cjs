const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// 定义服务器的版本号
const SERVER_VERSION = "1.8.3";

// JWT 配置
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// 全局房间数据存储
const rooms = new Map(); // 存储所有房间信息 {roomId: roomData}
const players = new Map(); // 存储所有玩家信息 {socketId: playerData}
const pendingRooms = new Map(); // 存储等待连接的房间
const adminTokens = new Map(); // 存储管理员令牌

// 辅助函数
function generateRoomId() {
    return Math.random().toString(36).substring(2, 8).toUpperCase();
}

function getRandomColor() {
    const colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD', '#98D8C8', '#F7DC6F'];
    return colors[Math.floor(Math.random() * colors.length)];
}

// 初始化管理员密码
function initializeAdminPassword() {
    const adminPasswordPath = path.join(__dirname, 'admin-password.txt');
    if (!fs.existsSync(adminPasswordPath)) {
        const defaultPassword = 'admin123';
        console.log('🔑 正在初始化管理员密码...');
        
        // 生成密码哈希
        const hashedPassword = bcrypt.hashSync(defaultPassword, 10);
        fs.writeFileSync(adminPasswordPath, hashedPassword);
        
        console.log(`✅ 管理员密码已初始化: ${defaultPassword}`);
        console.log(`📝 密码文件已创建: ${adminPasswordPath}`);
        console.log(`🔐 请妥善保管管理员密码文件`);
    }
}

// 验证管理员令牌
function verifyAdminToken(token) {
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return adminTokens.has(decoded.tokenId);
    } catch (err) {
        return false;
    }
}

// 生成管理员令牌
function generateAdminToken() {
    const tokenId = 'admin_' + Date.now();
    const token = jwt.sign({ tokenId }, JWT_SECRET, { expiresIn: '24h' });
    adminTokens.set(tokenId, true);
    return token;
}

// 检查管理员权限中间件
function requireAdminAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: '需要管理员身份验证' });
    }
    
    const token = authHeader.substring(7);
    if (!verifyAdminToken(token)) {
        return res.status(403).json({ success: false, message: '无效的管理员令牌' });
    }
    
    next();
}

// 获取所有房间的信息（包括私密房间）
function getAllRoomsList() {
    const roomList = [];
    for (const [roomId, room] of rooms.entries()) {
        // 使用 Map.get() 方法从 playerID-based Map 获取玩家数量
        const playerCount = room.players ? room.players.size : 0;
        
        roomList.push({
            id: room.id,
            name: room.name,
            players: playerCount, // 修复: 使用实际的玩家数量
            maxPlayers: room.maxPlayers,
            status: room.status,
            hostName: room.hostName,
            private: room.private || false,
            created: room.createdAt,
            hasPassword: room.password !== undefined
            // 如果需要，可以在这里添加更多字段
        });
    }
    // 按创建时间倒序排列
    return roomList.sort((a, b) => b.created - a.created);
}


// API: 服务器状态检查
app.get('/api/server-status', (req, res) => {
    res.json({ 
        status: 'ok',
        message: '服务器运行正常',
        timestamp: Date.now(),
        version: SERVER_VERSION,
        uptime: process.uptime()
    });
});

app.get('/api/rooms', (req, res) => {
    console.log(`收到获取公开房间列表请求，当前有 ${rooms.size} 个房间。`);
    const publicRooms = getAllRoomsList().filter(room => !room.private);
    res.json({ success: true, rooms: publicRooms });
});

// API: 获取所有房间的信息 (管理员专用) - 更新以显示玩家数量
app.get('/api/admin/rooms', requireAdminAuth, (req, res) => {
    try {
        console.log(`管理员请求获取所有房间列表，当前有 ${rooms.size} 个房间。`);
        
        // 1. 先获取所有房间对象（这些对象中的 players 是 Map）
        const allRoomObjects = Array.from(rooms.values());
        
        // 2. 创建一个新的房间列表数组，其中每个房间的 players 都被转换成了数组
        // 同时添加玩家数量
        const formattedRoomsForAdmin = allRoomObjects.map(room => {
            // 将 Map 转换成 Array of Objects 的形式
            const playersArray = Array.from(room.players ? room.players.values() : []);
            return {
                id: room.id,
                name: room.name,
                hostName: room.hostName,
                created: room.createdAt,
                private: room.private || false,
                maxPlayers: room.maxPlayers,
                status: room.status,
                players: playersArray, // <-- 关键修改：这里提供的是数组
                playersCount: playersArray.length, // 新增：提供总数
                totalPlayers: room.players ? room.players.size : 0
            };
        });
        
        // 3. 发送格式化后的房间列表
        res.json({ 
            success: true, 
            rooms: formattedRoomsForAdmin, 
            totalRooms: formattedRoomsForAdmin.length 
        });
    } catch (error) {
        console.error('[API] 获取房间列表失败:', error);
        res.status(500).json({ success: false, message: '获取房间列表失败' });
    }
});



// // API: 管理员登录
// app.post('/api/admin/login', async (req, res) => {
//     try {
//         const { password } = req.body;
        
//         if (!password) {
//             return res.status(400).json({ success: false, message: '密码不能为空' });
//         }
        
//         const adminPasswordPath = path.join(__dirname, 'admin-password.txt');
        
//         // 检查密码文件是否存在
//         if (!fs.existsSync(adminPasswordPath)) {
//             console.error('⚠️ 管理员密码文件不存在:', adminPasswordPath);
//             return res.status(500).json({ success: false, message: '管理员密码文件未初始化' });
//         }
        
//         const hashedPassword = fs.readFileSync(adminPasswordPath, 'utf8');
        
//         const isValid = await bcrypt.compare(password, hashedPassword);
        
//         if (isValid) {
//             const token = generateAdminToken();
//             res.json({ 
//                 success: true, 
//                 message: '登录成功',
//                 token: token
//             });
//         } else {
//             res.status(401).json({ success: false, message: '密码错误' });
//         }
//     } catch (error) {
//         console.error('[Admin] 登录失败:', error);
//         res.status(500).json({ success: false, message: '登录失败' });
//     }
// });
// 在 server.cjs 中找到登录API，临时修改为：
app.post('/api/admin/login', async (req, res) => {
    try {
        const { password } = req.body;
        
        console.log('收到管理员登录请求');
        
        if (!password) {
            return res.status(400).json({ success: false, message: '密码不能为空' });
        }
        
        // 临时：明文比较（仅用于调试）
        const adminPassword = 'admin123';
        
        // 临时：使用明文比较
        if (password === 'admin123') {
            const token = generateAdminToken();
            console.log('管理员登录成功');
            return res.json({ 
                success: true, 
                message: '登录成功',
                token: token
            });
        } else {
            console.log('管理员密码验证失败');
            return res.status(401).json({ success: false, message: '密码错误' });
        }
        
    } catch (error) {
        console.error('[Admin] 登录失败:', error);
        res.status(500).json({ success: false, message: '登录失败' });
    }
});
// API:版本更新


// API: 获取服务器统计信息（管理员专用）
app.get('/api/admin/stats', requireAdminAuth, (req, res) => {
    try {
        const allRooms = getAllRoomsList();
        const totalPlayers = Array.from(rooms.values()).reduce((sum, room) => sum + room.players.size, 0);
        const waitingRooms = allRooms.filter(room => room.status === 'waiting').length;
        const playingRooms = allRooms.filter(room => room.status === 'playing').length;
        const fullRooms = allRooms.filter(room => room.players >= room.maxPlayers).length;
        
        res.json({
            success: true,
            stats: {
                totalRooms: allRooms.length,
                totalPlayers: totalPlayers,
                waitingRooms: waitingRooms,
                playingRooms: playingRooms,
                fullRooms: fullRooms,
                privateRooms: allRooms.filter(room => room.private).length,
                memoryUsage: process.memoryUsage(),
                uptime: process.uptime()
            },
            rooms: allRooms
        });
    } catch (error) {
        console.error('[API] 获取统计信息失败:', error);
        res.status(500).json({ success: false, message: '获取统计信息失败' });
    }
});

// API: 删除房间（管理员专用）
app.delete('/api/admin/rooms/:roomId', requireAdminAuth, (req, res) => {
    try {
        const roomId = req.params.roomId;
        const room = rooms.get(roomId);
        
        if (!room) {
            return res.status(404).json({ success: false, message: '房间不存在' });
        }
        
        // 通知房间内所有玩家
        io.to(roomId).emit('room-kicked', {
            message: '房间已被管理员删除'
        });
        
        // 强制断开所有玩家的连接
        for (const [playerId, player] of room.players.entries()) {
            const socket = io.sockets.sockets.get(player.socketId);
            if (socket) {
                socket.disconnect(true);
            }
        }
        
        // 删除房间
        rooms.delete(roomId);
        
        console.log(`[Admin] 房间 ${roomId} 已被管理员删除`);
        
        res.json({ success: true, message: '房间删除成功' });
    } catch (error) {
        console.error('[API] 删除房间失败:', error);
        res.status(500).json({ success: false, message: '删除房间失败' });
    }
});

// API: 踢出房间所有玩家（管理员专用）
app.post('/api/admin/rooms/:roomId/kick-all', requireAdminAuth, (req, res) => {
    try {
        const roomId = req.params.roomId;
        const room = rooms.get(roomId);
        
        if (!room) {
            return res.status(404).json({ success: false, message: '房间不存在' });
        }
        
        // 记录被踢出的玩家数量
        const kickedPlayersCount = room.players.size;
        
        // 通知房间内所有玩家
        io.to(roomId).emit('room-kicked', {
            message: '您已被管理员请出房间'
        });
        
        // 强制断开所有玩家的连接
        for (const [playerId, player] of room.players.entries()) {
            const socket = io.sockets.sockets.get(player.socketId);
            if (socket) {
                socket.disconnect(true);
            }
        }
        
        // 清空房间玩家
        room.players.clear();
        
        // 将房间状态重置为等待
        room.status = 'waiting';
        
        console.log(`[Admin] 房间 ${roomId} 的所有玩家已被请出，共 ${kickedPlayersCount} 人`);
        
        res.json({ success: false, success: true, message: `已请出 ${kickedPlayersCount} 名玩家` });
    } catch (error) {
        console.error('[API] 踢出玩家失败:', error);
        res.status(500).json({ success: false, message: '踢出玩家失败' });
    }
});

// API: 切换房间私密状态（管理员专用）
app.patch('/api/admin/rooms/:roomId/privacy', requireAdminAuth, (req, res) => {
    try {
        const roomId = req.params.roomId;
        const { isPrivate } = req.body;
        const room = rooms.get(roomId);
        
        if (!room) {
            return res.status(404).json({ success: false, message: '房间不存在' });
        }
        
        // 禁止将游戏中或已满的房间设为私密
        if (isPrivate && (room.status === 'playing' || room.players.size >= room.maxPlayers)) {
            return res.status(400).json({ success: false, message: '只能将等待中且未满的房间设为私密' });
        }
        
        room.private = isPrivate;
        
        console.log(`[Admin] 房间 ${roomId} 私密状态已切换为: ${isPrivate}`);
        
        res.json({ 
            success: true, 
            message: `房间已${isPrivate ? '设为私密' : '设为公开'}`,
            room: {
                id: room.id,
                name: room.name,
                private: room.private
            }
        });
    } catch (error) {
        console.error('[API] 切换房间私密状态失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// API: 快速创建房间（通过REST API）
app.post('/api/create-room', express.json(), (req, res) => {
    
        const { playerName, maxPlayers = 4, roomName, isPrivate = false, password } = req.body;
        
        if (!playerName || !roomName) {
            return res.status(400).json({ 
                success: false, 
                message: '玩家名和房间名不能为空',
                code: 'INVALID_PARAMS'
            });
        }

        if (playerName.length > 20) {
            return res.status(400).json({ 
                success: false, 
                message: '玩家名不能超过20个字符',
                code: 'PLAYER_NAME_TOO_LONG'
            });
        }

        if (roomName.length > 30) {
            return res.status(400).json({ 
                success: false, 
                message: '房间名不能超过30个字符',
                code: 'ROOM_NAME_TOO_LONG'
            });
        }

        // 如果是私密房间，需要密码
        if (isPrivate && !password) {
            return res.status(400).json({ 
                success: false, 
                message: '私密房间需要设置密码',
                code: 'PASSWORD_REQUIRED'
            });
        }

        const roomId = generateRoomId();
        const playerColor = getRandomColor();
        
        const hostPlayer = {
            id: `player_api_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
            name: playerName,
            socketId: null, // 等待Socket连接
            roomId: roomId,
            color: playerColor,
            isHost: false, // Socket连接后设为true
            isReady: false,
            joinedAt: Date.now()
        };

        const newRoom = {
            id: roomId,
            name: roomName,
            host: hostPlayer.id,
            players: new Map([[hostPlayer.id, hostPlayer]]),
            maxPlayers,
            status: 'waiting',
            hostName: playerName,
            private: isPrivate,
            password: password, // 存储房间密码
            createdAt: Date.now(),
            actualHost: null, // 存储实际的Socket ID
            waitingSocket: false, // 等待房主连接
        };

        rooms.set(roomId, newRoom);
        pendingRooms.set(roomId, hostPlayer.id);

        console.log(`[REST API] 房间 "${roomName}" (ID: ${roomId}) 已创建` +
                   `, 等待房主连接...`);

    res.json({ success: true, roomId, playerId: hostPlayer.id, color: hostPlayer.color, isHost: true });

});
// ===== 新增：版本检查 API =====
// 这个端点用于客户端检查服务器状态和版本
app.get('/api/version-check', (req, res) => {
    console.log('收到版本检查请求');
    
    // ===== 修改点：从请求头中获取客户端版本号 =====
    const clientVersion = req.headers['client-version'];

    console.log(`服务器版本: ${SERVER_VERSION}, 客户端版本: ${clientVersion}`);

    let responseData = {};

    if (clientVersion === SERVER_VERSION) {
        // 情况1: 版本匹配
        console.log(`[版本检查] 成功: 客户端版本 ${clientVersion} 与服务器版本 ${SERVER_VERSION} 匹配。`);
        responseData = {
            status: 'ok',
            version: SERVER_VERSION,
        message: '服务器在线，版本匹配'
        };
    } else {
        // 情况2: 版本不匹配
        console.log(`[版本检查] 失败: 客户端版本 ${clientVersion} 与服务器版本 ${SERVER_VERSION} 不匹配。`);
        responseData = {
            status: 'outdated',
            clientVersion: clientVersion,
            serverVersion: SERVER_VERSION,
            message: '检测到版本不匹配，请更新客户端或刷新页面。'
        };
    }

    // 将处理好的数据以 JSON 格式返回给客户端
    res.json(responseData);
});

// 1. 首先，创建一个 HTTP 服务器
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

io.on('connection', (socket) => {
    console.log(`用户连接: ${socket.id}`);

    // 检查是否有待验证的房间
    for (const [roomId, playerId] of pendingRooms.entries()) {
        const room = rooms.get(roomId);
        if (room && room.players.get(playerId)) {
            const player = room.players.get(playerId);
            if (!player.socketId) {
                player.socketId = socket.id;
                player.isHost = true;
                room.actualHost = socket.id;
                room.waitingSocket = false;
                
                console.log(`[Socket] 房主 ${player.name} (Socket ID: ${socket.id}) 已连接，验证房间 ${roomId}`);
                socket.join(roomId);
                
                // 通知前端验证成功
                socket.emit('host-verified', {
                    success: true,
                    roomId: roomId,
                    playerId: player.id,
                    room: getRoomInfo(room)
                });
                
                pendingRooms.delete(roomId);
                break;
            }
        }
    }

    socket.on('createRoom', (data, callback) => {
        try {
            const { playerName, maxPlayers = 4, roomName, isPrivate = false, password } = data;
            const roomId = generateRoomId();
            
            const hostPlayer = {
                id: `player_${Date.now()}`,
                name: playerName,
                socketId: socket.id,
                roomId,
                color: getRandomColor(),
                isHost: true,
                isReady: false,
                joinedAt: Date.now()
            };
            
            // 生成邀请码
        const inviteCode = Math.random().toString(36).substring(2, 10).toUpperCase();
        
        const newRoom = {
                id: roomId,
                name: roomName,
                host: socket.id,
                actualHost: socket.id,
                players: new Map([[hostPlayer.id, hostPlayer]]),
                maxPlayers,
                status: 'waiting',
                hostName: playerName,
                private: isPrivate,
                password: password,
                inviteCode: inviteCode,
                createdAt: Date.now()
            };
            
            rooms.set(roomId, newRoom);
            socket.join(roomId);
            players.set(socket.id, hostPlayer);

            callback({ success: true, roomId, playerId: hostPlayer.id, color: hostPlayer.color, isHost: true, inviteCode: newRoom.inviteCode });
            broadcastRoomList();

        } catch (err) {
            callback({ success: false, message: err.message });
        }
    });

    socket.on('joinRoom', (data, callback) => {
        const { roomId, playerName, password, inviteCode } = data;
        const realSocketId = socket.id;
        const playerId = `socket_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`;
        const room = rooms.get(roomId);
        
        if (!room) {
            console.log(`玩家 ${playerName} 尝试加入不存在的房间 ${roomId}`);
            return callback({ success: false, message: '房间不存在' });
        }
        
        // 检查房间密码
        if (room.private && room.password !== password) {
            console.log(`玩家 ${playerName} 尝试加入私密房间 ${roomId}，密码错误`);
            return callback({ success: false, message: '房间密码错误' });
        }
        
        // 检查邀请码
        if (inviteCode && room.inviteCode !== inviteCode) {
            console.log(`玩家 ${playerName} 尝试加入房间 ${roomId}，邀请码错误`);
            return callback({ success: false, message: '邀请码错误' });
        }
        
        if (room.status !== 'waiting') {
            console.log(`玩家 ${playerName} 尝试加入已开始游戏的房间 ${roomId}`);
            return callback({ success: false, message: '游戏已开始' });
        }
        if (room.players.size >= room.maxPlayers) {
            console.log(`房间 ${roomId} 已满，玩家 ${playerName} 加入失败`);
            return callback({ success: false, message: '房间已满' });
        }
        
        const newPlayer = {
            id: playerId,
            name: playerName,
            socketId: realSocketId,
            color: getRandomColor(),
            isHost: false,
            isReady: false,
            joinedAt: Date.now()
        };
        
        room.players.set(playerId, newPlayer);
        players.set(realSocketId, newPlayer);
        socket.join(roomId);
        console.log(`玩家 ${newPlayer.name} (ID: ${playerId}) 成功加入房间 ${roomId}`);
        
        io.on('player-join', (data, callback) => {
            try {
                console.log('收到加入请求:', data);
                const { playerName, roomId } = data;
                
                // 【关键】获取更精确的房间信息
                const room = rooms.get(roomId); // 从 serverside room data fetch
                if (!room) {
                    console.log(`房间 ${roomId} 不存在`);
                    if (callback) callback({ success: false, message: '房间不存在' });
                    return;
                }

                const realSocketId = socket.id;
                const playerId = `socket_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`;
                
                // 双重检查：看是否已连接防止重复加入
                if(room.players.has(realSocketId)) {
                    console.log(`玩家 ${playerName} 已在此房间中`);
                    if(callback) callback({ success: false, message: '你已在此房间中' });
                    return;
                }

                // 检查房间是否真的已满
                if (room.players.size >= room.maxPlayers) {
                    console.log(`房间 ${roomId} 已满，拒绝玩家加入`); // Directly use room data
                    if (callback) callback({ success: false, message: '房间已满' });
                    return;
                }

                // 剩余逻辑不变...
                const conn = socket.join(roomId);
                players.set(realSocketId, { id: playerId, name: playerName, roomId, socketId: realSocketId });
                room.players.set(playerId, { id: playerId, name: playerName, socketId: realSocketId }); // Add to actual room player count

                const newPlayer = { id: playerId, name: playerName, color: getRandomColor() };
                
                console.log(`玩家 ${newPlayer.name} 正在加入房间 ${roomId}`);
                
                // 【修复核心】广播更新后的玩家列表给新加入玩家和房主
                // 计算加入后的真实玩家数量
                const updatedPlayersCount = room.players.size;

                // 这个更新后的列表应该包含新加入的玩家
                const allPlayersAfterJoin = Array.from(room.players.values())
                .map(p => ({ id: p.id, name: p.name, color: newPlayer.color })); // Assign new player's color

                // 发送给房间内所有成员（包括新加入自己）
                io.to(roomId).emit('player-joined', {
                    type: 'player-list-update',
                    newPlayer: newPlayer,
                    players: allPlayersAfterJoin,
                    currentPlayerCount: updatedPlayersCount, // 【修复】发送修正后的准确总数
                    maxPlayers: room.maxPlayers
                });

                // 给新加入玩家发送房间信息
                const isHost = room.players.size === 1; // If only player, they are now host.
                socket.emit('room-joined', {
                    type: 'room-joined',
                    roomId: roomId,
                    name: room.name,
                    players: allPlayersAfterJoin,
                    maxPlayers: room.maxPlayers,
                    currentPlayerCount: updatedPlayersCount, // 【修复】在新玩家视角也准确保
                    status: 'waiting',
                    hostName: newPlayer.name,
                    private: room.private,
                    isHost: isHost // New player is host if they are alone
                });

                if(callback) callback({ 
                    success: true, 
                    roomId, 
                    name: room.name,
                    isHost: isHost,
                    currentPlayerCount: updatedPlayersCount // 【修复】callback也修正
                });
                
                console.log(`玩家 ${newPlayer.name} 成功加入房间 ${roomId}. 总人数: ${updatedPlayersCount}/${room.maxPlayers}`);
            } catch (err) {
                console.error('加入房间出错:', err);
                if(callback) callback({ success: false, message: '发生未知错误' });
            }
        });

        
        // 向新玩家发送房间信息
        const roomInfo = {
            type: 'room-joined',
            roomId: room.id,
            name: room.name,
            players: Array.from(room.players.values()),
            maxPlayers: room.maxPlayers,
            status: room.status,
            hostName: room.hostName,
            private: room.private,
            isHost: false
        };
        
        socket.emit('room-info', roomInfo);
        
        callback({ success: true, ...roomInfo });
        broadcastRoomList();
    });

    socket.on('startGame', (roomId) => {
        const room = rooms.get(roomId);
        if(room && room.actualHost === socket.id) {
            room.status = 'playing';
            io.to(roomId).emit('game-started', {
                roomId: roomId,
                status: 'playing'
            });
            broadcastRoomList();
        }
    });

    socket.on('disconnect', () => {
        handleDisconnect(socket.id);
    });
});
// 在 server.cjs 中找到 kick-all API
app.post('/api/admin/rooms/:roomId/kick-all', requireAdminAuth, (req, res) => {
    try {
        const roomId = req.params.roomId;
        const room = rooms.get(roomId);
        
        if (!room) {
            return res.status(404).json({ success: false, message: '房间不存在' });
        }
        
        // 记录被踢出的玩家数量
        const kickedPlayersCount = room.players.size;
        
        // 通知房间内所有玩家
        io.to(roomId).emit('room-kicked', {
            message: '房间被管理员清空，所有人被请出。'
        });
        
        // 强制断开所有玩家的连接
        for (const [playerId, player] of room.players.entries()) {
            const socket = io.sockets.sockets.get(player.socketId);
            if (socket) {
                socket.disconnect(true);
            }
        }
        
        // 清空房间玩家
        room.players.clear();
        
        // 将房间状态重置为等待
        room.status = 'waiting';
        
        // 广播更新后的房间列表
        broadcastRoomList();
        
        console.log(`[Admin] 房间 ${roomId} 的所有玩家已被请出，共 ${kickedPlayersCount} 人`);
        
        res.json({ success: true, message: `已请出 ${kickedPlayersCount} 名玩家` });
    } catch (error) {
        console.error('[API] 踢出玩家失败:', error);
        res.status(500).json({ success: false, message: '踢出玩家失败' });
    }
});
// 在 server.cjs 的 app.use(...) 路由下方添加
app.post('/api/admin/rooms/:roomId/system-message', requireAdminAuth, (req, res) => {
    try {
        const roomId = req.params.roomId;
        const { message, color = 'red' } = req.body; // 默认红色消息

        if (!message) {
            return res.status(400).json({ success: false, message: '消息内容不能为空' });
        }

        const room = rooms.get(roomId);
        if (!room) {
            return res.status(404).json({ success: false, message: '房间不存在' });
        }

        // 广播系统消息给房间内所有玩家
        io.to(roomId).emit('system-message', {
            text: `[服务器] ${message}`,
            color: color // 例如: 'red', 'green', 'yellow', 'blue'
        });

        console.log(`[Admin] 房间 ${roomId} 收到系统消息: ${message}`);
        
        res.json({ success: true, message: '消息发送成功' });

    } catch (error) {
        console.error('[API] 发送系统消息失败:', error);
        res.status(500).json({ success: false, message: '服务器内部错误' });
    }
});
// 在 server.cjs 中踢出所有玩家API之后添加
app.delete('/api/admin/rooms/:roomId/players/:playerId', requireAdminAuth, (req, res) => {
    try {
        const roomId = req.params.roomId;
        const playerIdToKick = req.params.playerId; // 这是玩家的ID (player.id)，不是socketId

        const room = rooms.get(roomId);
        if (!room) {
            return res.status(404).json({ success: false, message: '房间不存在' });
        }

        const playerToKick = room.players.get(playerIdToKick);
        if (!playerToKick) {
            return res.status(404).json({ success: false, message: '房间内未找到该玩家' });
        }

        const playerSocket = io.sockets.sockets.get(playerToKick.socketId);
        if (playerSocket) {
            // 通知被踢玩家
            playerSocket.emit('kicked-by-admin', { message: '你已被管理员踢出。' });
            // 断开连接
            playerSocket.disconnect(true);
            console.log(`[Admin] 管理员强制踢出玩家 ${playerToKick.name} (Socket ID: ${playerToKick.socketId})`);
        }

        // 从房间玩家列表中移除
        room.players.delete(playerIdToKick);

        // 广播给房间内其他玩家谁被踢了
        io.to(roomId).emit('player-kicked-by-admin', {
            playerName: playerToKick.name
        });
        
        // 如果踢出的是房主，需要触发正常的房主交接逻辑
        if (playerToKick.isHost && playerToKick.socketId === room.actualHost) {
            console.log(`[Admin] 被踢出的玩家是房主，触发房主交接...`);
            // 这里复用 handleDisconnect 中的交接逻辑
            if (room.players.size > 0) {
                const newHost = room.players.values().next().value;
                newHost.isHost = true;
                room.actualHost = newHost.socketId;

                io.to(newHost.socketId).emit('promoted-to-host', {
                    roomId: room.id,
                    message: '原房主被踢出，你已成为新任房主。'
                });
                
                io.to(roomId).emit('room-updated', { // 自定义事件，让前端快速刷新
                    type: 'host-changed',
                    newHostName: newHost.name
                });
            }
        }

        console.log(`[Server] 房间 ${roomId} 玩家 ${playerToKick.name} 已被移除。当前玩家数: ${room.players.size}`);
        broadcastRoomList(); // 通知所有人房间列表更新

        res.json({ success: true, message: `玩家 ${playerToKick.name} 已被踢出` });

    } catch (error) {
        console.error('[API] 踢出指定玩家失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});
// 在 server.cjs 中踢出指定玩家API之后添加
app.post('/api/admin/rooms/:roomId/clear-room', requireAdminAuth, (req, res) => {
    try {
        const roomId = req.params.roomId;
        const room = rooms.get(roomId);
        
        if (!room) {
            return res.status(404).json({ success: false, message: '房间不存在' });
        }

        const kickedPlayersCount = room.players.size;
        
        // 通知房间内所有玩家
        io.to(roomId).emit('room-cleared-by-admin', {
            message: '房间已被管理员清空并重置。'
        });

        // 强制断开所有玩家的连接
        for (const [playerId, player] of room.players.entries()) {
            const socket = io.sockets.sockets.get(player.socketId);
            if (socket) {
                socket.disconnect(true);
            }
        }

        // 【关键】重置房间状态
        room.players.clear();
        room.status = 'waiting'; // 重置为等待状态
        room.actualHost = null; // 清除房主信息

        console.log(`[Admin] 房间 ${roomId} 已被管理员清空并重置。共踢出 ${kickedPlayersCount} 人。`);
        
        broadcastRoomList();

        res.json({ success: true, message: `房间已清空并重置，共请出 ${kickedPlayersCount} 名玩家` });

    } catch (error) {
        console.error('[API] 清空房间失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});


function handleDisconnect(socketId) {
    console.log(`[Server] 用户断开连接: ${socketId}`);

    // 1. 在全局 'players' Map 中查找玩家
    const leavingPlayer = players.get(socketId);

    // 2. 如果玩家不存在（例如是被踢出后断开），直接返回
    if (!leavingPlayer) {
        console.log(`[Server] 找不到玩家 ${socketId}，可能是已经被移除。`);
        players.delete(socketId); // 清理一下以防万一
        return;
    }

    const room = rooms.get(leavingPlayer.roomId);
    if (!room) {
        console.log(`[Server] 玩家 ${leavingPlayer.name} 的房间 ${leavingPlayer.roomId} 已不存在。`);
        players.delete(socketId);
        return;
    }

    console.log(`[Server] 处理玩家 ${leavingPlayer.name} (房主: ${leavingPlayer.isHost}) 离开房间 ${room.id}`);

    // 3. 通知房间内所有其他玩家该玩家已离开
    // 发送给除了自己（虽然已断开，但io.to会处理）和离开玩家外的所有人
    const otherPlayerIds = Array.from(room.players.keys()).filter(id => id !== leavingPlayer.id);
    if (otherPlayerIds.length > 0) {
        io.to(leavingPlayer.roomId).emit('player-left', {
            playerId: leavingPlayer.id,
            playerName: leavingPlayer.name
        });
    }

    // 4. 从房间的玩家Map中移除该玩家
    room.players.delete(leavingPlayer.id);
    
    // 【关键】在这里再次检查，房间是否真的空了（只留下这次离开的玩家）
    if (room.players.size === 0) {
        console.log(`[Server] 房间 ${room.id} 因玩家 ${leavingPlayer.name} 离开而变空。`);
        // 如果房主离开后，房间空了，我们什么都不做，让房间自然等待下一次创建或被自动清理
        // 如果是普通玩家离开后房间空了，也什么都不做
    } else {
        // 5. 核心逻辑：处理房主断线情况（只有当房间还有其他玩家时才需要选新房主）
        if (leavingPlayer.isHost && leavingPlayer.socketId === room.actualHost) {
            console.log(`[Server] 房主 ${leavingPlayer.name} 离开了房间 ${room.id}，但房间内还有其他玩家。`);

            // A. 选举新房主
            const newHostData = room.players.values().next().value; // 获取房间里第一个玩家
            newHostData.isHost = true;
            room.actualHost = newHostData.socketId; // 更新房主的 socket ID

            console.log(`[Server] 选举 ${newHostData.name} 为新房主。`);

            // B. 通知新房主和所有其他玩家
            // 使用 broadcastRoomList 会让所有人看到房主更新
            broadcastRoomList();

            // 给新房主发送提升通知
            const newHostSocket = io.sockets.sockets.get(newHostData.socketId);
            if (newHostSocket) {
                newHostSocket.emit('promoted-to-host', {
                    roomId: room.id,
                    message: '房主离开，你已成为新任房主。'
                });
            }
        }
    }


    // 6. 最后，从全局 'players' Map 中彻底移除该玩家
    players.delete(socketId);
}
 

function getRoomInfo(room) {
    const host = room.players.get(room.actualHost) || 
                 Array.from(room.players.values()).find(p => p.isHost);
    
    return {
        id: room.id,
        name: room.name,
        players: Array.from(room.players.values()),
        maxPlayers: room.maxPlayers,
        status: room.status,
        hostName: host ? host.name : '未知玩家',
        private: room.private,
        isHost: false // 由Socket连接处理
    };
}

function broadcastRoomList() {
    const roomList = getAllRoomsList();
    io.emit('rooms-updated', roomList);
}

// 正确的自动清理逻辑
setInterval(() => {
    const now = Date.now();
    const ROOM_IDLE_TIME = 5 * 60 * 1000; // 例如：5分钟无人活动才清理

    for (const [roomId, room] of rooms.entries()) {
        // 【修复】判断条件必须是：房间内没有玩家，并且创建时间已超过阈值
        if (room.players.size === 0 && (now - room.createdAt > ROOM_IDLE_TIME)) {
            console.log(`[自动清理] 找到空闲房间 ${roomId} (${room.name})，正在删除...`);
            
            // 通知一下（虽然没人）
            io.to(roomId).emit('room-kicked', { message: '房间因长时间空闲被系统关闭。' });
            
            // 删除房间
            rooms.delete(roomId);
        }
    }
    // 广播更新后的房间列表
    broadcastRoomList();
}, 30000); // 每30秒检查一次


// 在服务器启动时初始化管理员密码
console.log('🚀 正在初始化服务器...');
initializeAdminPassword();

const PORT = process.env.PORT || 234;
server.listen(PORT, () => {
    console.log(`\n✅ 服务器运行在 http://localhost:${PORT}`);
    console.log(`📊 服务器状态: http://localhost:${PORT}/api/server-status`);
    console.log(`🏠 房间列表: http://localhost:${PORT}/api/rooms`);
    console.log(`👤 创建房间: http://localhost:${PORT}/api/create-room`);
    console.log(`Socket.IO 服务已启动\n`);
});
