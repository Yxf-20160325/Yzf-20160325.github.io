
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
// 配置CORS以支持跨网络连接
app.use(cors({
    origin: '*', // 允许所有来源
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], // 支持所有必要的HTTP方法
    allowedHeaders: '*', // 允许客户端自定义头（如 Client-Version、Admin-Auto-Connect），避免预检被拦
    credentials: true // 允许发送凭证信息
}));

// ===== 超级管理员 / 访问控制状态 =====
const superAdminTokens = new Map();      // 超级管理员令牌
let adminDisabled = false;               // 是否禁用普通管理员登录
let gameAccessDisabled = false;          // 是否对游戏页面返回 403

const SUPERADMIN_PASSWORD_PATH = path.join(__dirname, 'superadmin-password.txt');
// 数据目录：默认 ./data；部署到会清空运行目录的平台（如 onrender 免费版每次部署/冷启会清空运行时文件）时，
// 可通过环境变量 DATA_DIR 指向一块「持久磁盘」，否则遥测/审计会在重启后丢失。
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const ADMIN_STATE_FILE = path.join(DATA_DIR, 'admin-state.json');
const AUDIT_FILE = path.join(DATA_DIR, 'admin-audit.log');
const TELEMETRY_FILE = path.join(DATA_DIR, 'telemetry.log');

// 确保数据目录存在：避免部署后 data/ 不存在导致 append 静默失败（接口仍返回 success，但什么都没存）
function ensureDataDir() {
    try { if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true }); }
    catch (e) { console.error('[Data] 创建数据目录失败:', DATA_DIR, '->', e.message); }
}

// 超级管理员密码初始化（默认 11dev），仅首次启动创建一次
function initializeSuperAdminPassword() {
    if (!fs.existsSync(SUPERADMIN_PASSWORD_PATH)) {
        const hashed = bcrypt.hashSync('11dev', 10);
        fs.writeFileSync(SUPERADMIN_PASSWORD_PATH, hashed);
        console.log('🔑 超级管理员密码已初始化: 11dev');
    }
}

// 持久化读取/写入访问控制状态
function loadAdminState() {
    try {
        if (fs.existsSync(ADMIN_STATE_FILE)) {
            const s = JSON.parse(fs.readFileSync(ADMIN_STATE_FILE, 'utf8'));
            if (typeof s.adminDisabled === 'boolean') adminDisabled = s.adminDisabled;
            if (typeof s.gameAccessDisabled === 'boolean') gameAccessDisabled = s.gameAccessDisabled;
        }
    } catch (e) { console.error('[State] 加载管理状态失败:', e.message); }
}
function saveAdminState() {
    ensureDataDir();
    try { fs.writeFileSync(ADMIN_STATE_FILE, JSON.stringify({ adminDisabled, gameAccessDisabled })); }
    catch (e) { console.error('[State] 保存管理状态失败:', e.message); }
}

// 审计日志：记录谁(actor)在什么时间做了什么(action)
function appendAudit(actor, action, detail) {
    const entry = { ts: new Date().toISOString(), actor, action, detail: detail || '' };
    ensureDataDir();
    try { fs.appendFileSync(AUDIT_FILE, JSON.stringify(entry) + '\n'); }
    catch (e) { console.error('[审计] 写入失败:', e.message); }
    console.log('[审计]', entry.ts, actor, action, detail || '');
}
function readAudit(limit) {
    try {
        if (!fs.existsSync(AUDIT_FILE)) return [];
        const lines = fs.readFileSync(AUDIT_FILE, 'utf8').trim().split('\n').filter(Boolean);
        const arr = lines.map(l => { try { return JSON.parse(l); } catch (e) { return null; } }).filter(Boolean);
        return limit ? arr.slice(-limit) : arr;
    } catch (e) { return []; }
}

// 遥测数据：记录客户端上报的用户操作（需用户同意后才会上报）
// 返回 true/false，便于接口在写入失败时如实返回，而不是假成功
function appendTelemetry(entry) {
    ensureDataDir();
    try { fs.appendFileSync(TELEMETRY_FILE, JSON.stringify(entry) + '\n'); return true; }
    catch (e) { console.error('[遥测] 写入失败:', e.message); return false; }
}
function readTelemetry(limit, clientId) {
    try {
        if (!fs.existsSync(TELEMETRY_FILE)) return [];
        const lines = fs.readFileSync(TELEMETRY_FILE, 'utf8').trim().split('\n').filter(Boolean);
        let arr = lines.map(l => { try { return JSON.parse(l); } catch (e) { return null; } }).filter(Boolean);
        if (clientId) arr = arr.filter(e => e.clientId === clientId);
        return limit ? arr.slice(-limit) : arr;
    } catch (e) { return []; }
}

// 访问控制：gameAccessDisabled 开启时，任何 GET 游戏页面请求返回 403（管理员/超管页面除外）
// 必须在 express.static 之前注册，才能抢在静态文件返回游戏页之前拦截
app.use((req, res, next) => {
    if (gameAccessDisabled && req.method === 'GET') {
        const p = req.path;
        const isGamePage = p === '/' || (p.endsWith('.html') && p !== '/admin.html' && p !== '/superadmin.html');
        if (isGamePage) {
            res.status(403).type('text/plain; charset=utf-8').send('403 Forbidden - 游戏访问已被超级管理员关闭');
            return;
        }
    }
    next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// 添加安全头中间件
app.use((req, res, next) => {
    // 防止浏览器对响应内容进行MIME类型嗅探
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // 移除Express默认添加的X-Powered-By头
    res.removeHeader('X-Powered-By');
    
    // 使用Cache-Control替代Expires头
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    
    // 限制Server头只包含服务器名称
    res.setHeader('Server', 'MazeGameServer');
    
    // 设置Content-Type charset为utf-8
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    
    next();
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// 管理后台与超级管理员后台页面（游戏 403 拦截已排除这两个路径）
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/superadmin.html', (req, res) => res.sendFile(path.join(__dirname, 'superadmin.html')));

// 定义服务器的版本号
const SERVER_VERSION = "1.15.5";
// 服务端记住“见过的最高客户端版本号”。正常情况下等于 SERVER_VERSION；
// 一旦有更高版本的客户端连入（即发布了新客户端），会自动记录为最新，
// 从而让仍使用旧版（缓存）的客户端在进游戏时收到“有更新”的弹窗。
let latestClientVersion = SERVER_VERSION;

// 版本比较：a < b 返回 -1，a === b 返回 0，a > b 返回 1（按点分数字逐段比较，如 1.15 < 1.16）
function cmpVersion(a, b) {
    const pa = String(a || '').split('.').map(n => parseInt(n, 10) || 0);
    const pb = String(b || '').split('.').map(n => parseInt(n, 10) || 0);
    const len = Math.max(pa.length, pb.length);
    for (let i = 0; i < len; i++) {
        const x = pa[i] || 0, y = pb[i] || 0;
        if (x < y) return -1;
        if (x > y) return 1;
    }
    return 0;
}

// JWT 配置
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// 全局房间数据存储
const rooms = new Map(); // 存储所有房间信息 {roomId: roomData}
const players = new Map(); // 存储所有玩家信息 {socketId: playerData}
const pendingRooms = new Map(); // 存储等待连接的房间
const adminTokens = new Map(); // 存储管理员令牌
const userCoins = new Map(); // 用户金币余额（按 userId 存储，管理员发放/扣除的"账本"）
const userLevels = new Map(); // 用户等级（预留；游戏当前无升级系统，恒为 1，仅供兼容）
// 玩家真实金币（客户端上报，供管理员查看；与 userCoins 分开，避免覆盖管理员账本语义）
const reportedCoins = new Map();
// 玩家档案（客户端上报的 IP / 金币 / 时长 / 统计 / 游戏状态快照；持久保存最近一次，供管理后台离线查看）
const playerProfiles = new Map();

// 从请求中解析客户端 IP（兼容反向代理 x-forwarded-for）
function getClientIp(req) {
    try {
        const xff = req.headers && req.headers['x-forwarded-for'];
        if (xff) {
            const first = String(xff).split(',')[0].trim();
            if (first) return first;
        }
        return (req.socket && req.socket.remoteAddress) || req.ip || '';
    } catch (e) { return ''; }
}

// 合并/更新玩家档案（保留历史 IP 与最近一次上报的字段）
function savePlayerProfile(id, fields) {
    try {
        const prev = playerProfiles.get(id) || {};
        const next = Object.assign({}, prev, fields);
        next.lastSeen = Date.now();
        playerProfiles.set(id, next);
    } catch (e) {}
}

// ===== 新增：管理后台数据（用户访问控制 / 功能控制 / 在线玩家映射 / 热门迷宫） =====
const userAccess = new Map();      // userId -> 页面访问权限设置
const userFunctions = new Map();   // userId -> 功能控制设置
const userBans = new Map();        // userId(clientId) -> { multiplayer:bool, single:bool, puzzle:bool, chat:bool, reasons:{} }，管理员封禁状态
const cheatReports = [];           // 反作弊上报记录：{ id, clientId, type, detail, time }
const roomChats = new Map();       // roomId -> [{messageId, sender, clientId, message, image, isAdmin, time}]，房间聊天记录（客户端镜像上报，供管理员监管），每房间上限 200 条
const onlineSockets = new Map();   // playerId(peer id) -> socket.id，供远程控制精准投递
const onlinePlayers = new Map();   // clientId -> {id,name,socketId,roomId,joinedAt}，进入游戏即上线的玩家（含未进房的）
const mazes = new Map();           // mazeId -> 迷宫对象 {id,name,description,difficulty,size,data}
// 玩家关卡进度（客户端上报，供管理员查看过关历史）：clientId -> { unlockedLevel, completedLevels, puzzleCompletedLevels }
const reportedProgress = new Map();
// 玩家关卡权限（管理员设置）：clientId -> { "single:12": "forbidden"|"forced", "puzzle:5": "forbidden", ... }
const levelPermissions = new Map();
// 玩家成就数据（客户端上报 + 管理员授予）：clientId -> { allLevelsCompleted, multiplayerWins, trapHits, chineseEmojiUsed, puzzleMaster }
const reportedAchievements = new Map();
// 关卡总数上限（用于“全部通关”与“解密高手”自动判定）
const MAX_SINGLE_LEVEL = 80;
const MAX_PUZZLE_LEVEL = 60;
// 被管理员删除（撤销）的成就键集合：userId -> Set(key)。被撤销的键不会因客户端重新上报而恢复
const revokedAchievements = new Map();
// 合并客户端上报的成就数据（仅覆盖本次提供到的字段，管理员授予的字段优先保留）
function mergeAchievements(id, a) {
    if (!id || !a || typeof a !== 'object') return;
    const cur = reportedAchievements.get(id) || { allLevelsCompleted: false, multiplayerWins: 0, trapHits: 0, chineseEmojiUsed: false, puzzleMaster: false };
    if (typeof a.allLevelsCompleted === 'boolean') cur.allLevelsCompleted = cur.allLevelsCompleted || a.allLevelsCompleted;
    if (typeof a.multiplayerWins === 'number' && !isNaN(a.multiplayerWins)) cur.multiplayerWins = Math.max(cur.multiplayerWins, a.multiplayerWins);
    if (typeof a.trapHits === 'number' && !isNaN(a.trapHits)) cur.trapHits = Math.max(cur.trapHits, a.trapHits);
    if (typeof a.chineseEmojiUsed === 'boolean') cur.chineseEmojiUsed = cur.chineseEmojiUsed || a.chineseEmojiUsed;
    if (typeof a.puzzleMaster === 'boolean') cur.puzzleMaster = cur.puzzleMaster || a.puzzleMaster;
    // 管理员撤销的成就强制保持为初始值，避免客户端重新上报后“复活”
    const revoked = revokedAchievements.get(id);
    if (revoked) {
        revoked.forEach(k => {
            if (k === 'allLevelsCompleted' || k === 'chineseEmojiUsed' || k === 'puzzleMaster') cur[k] = false;
            else cur[k] = 0;
        });
    }
    reportedAchievements.set(id, cur);
}
// 返回某用户被撤销的成就键数组
function getRevokedKeys(userId) {
    const s = revokedAchievements.get(userId);
    return s ? Array.from(s) : [];
}
// 合并客户端上报的关卡进度：采用并集（保留双方已通关关卡），避免玩家下次上线
// 上报本地进度时把管理员“全部通关”授予的进度整体覆盖掉。
function mergeProgress(id, p) {
    if (!id || !p || typeof p !== 'object') return;
    const cur = reportedProgress.get(id) || { unlockedLevel: 1, completedLevels: [], puzzleCompletedLevels: [], lastReportedAt: null };
    if (typeof p.unlockedLevel === 'number' && !isNaN(p.unlockedLevel)) cur.unlockedLevel = Math.max(cur.unlockedLevel || 1, p.unlockedLevel);
    if (Array.isArray(p.completedLevels)) {
        const set = new Set([...(cur.completedLevels || []), ...p.completedLevels]);
        cur.completedLevels = Array.from(set).filter(n => typeof n === 'number' && n > 0).slice(0, 200);
    }
    if (Array.isArray(p.puzzleCompletedLevels)) {
        const set = new Set([...(cur.puzzleCompletedLevels || []), ...p.puzzleCompletedLevels]);
        cur.puzzleCompletedLevels = Array.from(set).filter(n => typeof n === 'number' && n > 0).slice(0, 200);
    }
    cur.lastReportedAt = Date.now();
    reportedProgress.set(id, cur);
    autoEvaluateAchievements(id);
}

// 自动判定“解密高手”成就：当玩家通关全部解密关卡（1..MAX_PUZZLE_LEVEL）时授予
function autoEvaluateAchievements(id) {
    if (!id) return;
    const prog = reportedProgress.get(id);
    if (!prog) return;
    const puzzleSet = new Set(Array.isArray(prog.puzzleCompletedLevels) ? prog.puzzleCompletedLevels : []);
    for (let i = 1; i <= MAX_PUZZLE_LEVEL; i++) {
        if (!puzzleSet.has(i)) return; // 尚有未通关的解密关卡
    }
    // 已被管理员撤销的成就不自动恢复
    const revoked = revokedAchievements.get(id);
    if (revoked && revoked.has('puzzleMaster')) return;
    const cur = reportedAchievements.get(id) || { allLevelsCompleted: false, multiplayerWins: 0, trapHits: 0, chineseEmojiUsed: false, puzzleMaster: false };
    if (!cur.puzzleMaster) {
        cur.puzzleMaster = true;
        reportedAchievements.set(id, cur);
        if (typeof io !== 'undefined' && io && io.emit) {
            io.emit('achievement-update', { clientId: id, achievements: cur });
        }
    }
}
const MAZES_FILE = path.join(__dirname, 'data', 'mazes.json');
function loadMazes() {
    try {
        if (fs.existsSync(MAZES_FILE)) {
            const arr = JSON.parse(fs.readFileSync(MAZES_FILE, 'utf8'));
            if (Array.isArray(arr)) {
                arr.forEach(m => mazes.set(m.id, m));
                console.log(`[迷宫] 已从 ${MAZES_FILE} 加载 ${mazes.size} 个热门迷宫`);
            }
        }
    } catch (e) {
        console.error('[迷宫] 加载热门迷宫失败:', e.message);
    }
}
function saveMazes() {
    try {
        fs.mkdirSync(path.dirname(MAZES_FILE), { recursive: true });
        fs.writeFileSync(MAZES_FILE, JSON.stringify(Array.from(mazes.values()), null, 2));
    } catch (e) {
        console.error('[迷宫] 保存热门迷宫失败:', e.message);
    }
}
loadMazes();

// 辅助函数
function generateRoomId() {
    // 生成5位纯数字房间ID
    return Math.floor(10000 + Math.random() * 90000).toString();
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

// ===== 超级管理员令牌与鉴权 =====
function verifySuperAdminToken(token) {
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return superAdminTokens.has(decoded.tokenId);
    } catch (err) {
        return false;
    }
}
function generateSuperAdminToken() {
    const tokenId = 'superadmin_' + Date.now();
    const token = jwt.sign({ tokenId }, JWT_SECRET, { expiresIn: '24h' });
    superAdminTokens.set(tokenId, true);
    return token;
}
function requireSuperAdminAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: '需要超级管理员身份验证' });
    }
    const token = authHeader.substring(7);
    if (!verifySuperAdminToken(token)) {
        return res.status(403).json({ success: false, message: '无效的超级管理员令牌' });
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
            id: roomId, // 修复: 使用Map的键作为房间ID，确保一致性
            name: room.name,
            players: playerCount,
            maxPlayers: room.maxPlayers,
            status: room.status,
            hostName: room.hostName,
            private: room.private || false,
            created: room.createdAt,
            hasPassword: room.password !== undefined
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

// API: 搜索房间
app.get('/api/rooms/search', (req, res) => {
    try {
        const { q, status, hostName } = req.query;
        console.log(`收到房间搜索请求: 查询=${q}, 状态=${status}, 房主=${hostName}`);
        
        let searchResults = getAllRoomsList();
        
        // 过滤公开房间
        searchResults = searchResults.filter(room => !room.private);
        
        // 按关键词搜索（房间名或房主名）
        if (q) {
            const query = q.toLowerCase();
            searchResults = searchResults.filter(room => 
                room.name.toLowerCase().includes(query) || 
                room.hostName.toLowerCase().includes(query)
            );
        }
        
        // 按状态过滤
        if (status) {
            searchResults = searchResults.filter(room => room.status === status);
        }
        
        // 按房主名过滤
        if (hostName) {
            const hostQuery = hostName.toLowerCase();
            searchResults = searchResults.filter(room => 
                room.hostName.toLowerCase().includes(hostQuery)
            );
        }
        
        console.log(`搜索完成，找到 ${searchResults.length} 个匹配的房间`);
        res.json({ success: true, rooms: searchResults });
    } catch (error) {
        console.error('[API] 房间搜索失败:', error);
        res.status(500).json({ success: false, message: '搜索失败' });
    }
});

// API: 获取所有房间的信息 (管理员专用)
// 返回格式与 admin.html 的 fetchRooms 渲染保持一致：
// 每个房间包含 {id, name, hostName, players(人数), maxPlayers, status, created, private, hasPassword}
app.get('/api/admin/rooms', requireAdminAuth, (req, res) => {
    try {
        console.log(`管理员请求获取所有房间列表，当前有 ${rooms.size} 个房间。`);
        const roomList = getAllRoomsList();
        res.json({
            success: true,
            rooms: roomList,
            totalRooms: roomList.length
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
// API: 管理员登录
// 使用 bcrypt 校验 admin-password.txt 中的密码哈希，避免明文硬编码密码的安全隐患，
// 且管理员可通过修改该文件真正改密（明文比较时改密文件完全失效）。
app.post('/api/admin/login', async (req, res) => {
    try {
        const { password } = req.body;
        
        console.log('收到管理员登录请求');
        
        if (!password) {
            return res.status(400).json({ success: false, message: '密码不能为空' });
        }

        // 管理员账号被超级管理员禁用时拒绝登录
        if (adminDisabled) {
            console.log('管理员登录被拒：账号已被超级管理员禁用');
            return res.status(403).json({ success: false, message: '管理员账号已被超级管理员禁用' });
        }

        const adminPasswordPath = path.join(__dirname, 'admin-password.txt');
        
        // 确保密码文件存在（首次启动由 initializeAdminPassword 创建）
        if (!fs.existsSync(adminPasswordPath)) {
            initializeAdminPassword();
        }
        
        const hashedPassword = fs.readFileSync(adminPasswordPath, 'utf8').trim();
        
        const isValid = await bcrypt.compare(password, hashedPassword);
        
        if (isValid) {
            const token = generateAdminToken();
            appendAudit('admin', 'login', '管理员登录');
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
// ===================== 超级管理员 API =====================
// 超级管理员登录（密码文件 superadmin-password.txt，初始 11dev）
app.post('/api/superadmin/login', async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ success: false, message: '密码不能为空' });
        if (!fs.existsSync(SUPERADMIN_PASSWORD_PATH)) initializeSuperAdminPassword();
        const hashed = fs.readFileSync(SUPERADMIN_PASSWORD_PATH, 'utf8').trim();
        const isValid = await bcrypt.compare(password, hashed);
        if (isValid) {
            const token = generateSuperAdminToken();
            appendAudit('superadmin', 'login', '超级管理员登录');
            return res.json({ success: true, token });
        }
        return res.status(401).json({ success: false, message: '密码错误' });
    } catch (e) {
        console.error('[SuperAdmin] 登录失败:', e);
        res.status(500).json({ success: false, message: '登录失败' });
    }
});

// 修改 superadmin / admin 密码
app.post('/api/superadmin/change-password', requireSuperAdminAuth, async (req, res) => {
    try {
        const { target, newPassword } = req.body || {};
        if (target !== 'superadmin' && target !== 'admin') {
            return res.status(400).json({ success: false, message: 'target 必须为 superadmin 或 admin' });
        }
        if (!newPassword || String(newPassword).length < 1) {
            return res.status(400).json({ success: false, message: '新密码不能为空' });
        }
        const filePath = target === 'admin' ? path.join(__dirname, 'admin-password.txt') : SUPERADMIN_PASSWORD_PATH;
        fs.writeFileSync(filePath, bcrypt.hashSync(String(newPassword), 10));
        if (target === 'admin') {
            adminTokens.clear(); // 改密后使旧管理员令牌失效
            appendAudit('superadmin', 'change-admin-password', '修改了管理员密码');
        } else {
            superAdminTokens.clear();
            appendAudit('superadmin', 'change-superadmin-password', '修改了超级管理员密码');
        }
        res.json({ success: true, message: `已更新 ${target} 密码` });
    } catch (e) {
        console.error('[SuperAdmin] 改密失败:', e);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 禁用 / 启用 管理员账号
app.post('/api/superadmin/set-admin-disabled', requireSuperAdminAuth, (req, res) => {
    try {
        const { disabled } = req.body || {};
        adminDisabled = !!disabled;
        saveAdminState();
        appendAudit('superadmin', 'set-admin-disabled', adminDisabled ? '禁用了管理员账号' : '启用了管理员账号');
        res.json({ success: true, adminDisabled });
    } catch (e) {
        console.error('[SuperAdmin] 设置失败:', e);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 开关游戏页面 403
app.post('/api/superadmin/set-game-disabled', requireSuperAdminAuth, (req, res) => {
    try {
        const { disabled } = req.body || {};
        gameAccessDisabled = !!disabled;
        saveAdminState();
        appendAudit('superadmin', 'set-game-disabled', gameAccessDisabled ? '已关闭游戏页面访问(403)' : '已恢复游戏页面访问');
        res.json({ success: true, gameAccessDisabled });
    } catch (e) {
        console.error('[SuperAdmin] 设置失败:', e);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 当前访问控制状态
app.get('/api/superadmin/state', requireSuperAdminAuth, (req, res) => {
    res.json({ success: true, adminDisabled, gameAccessDisabled });
});

// 审计日志
app.get('/api/superadmin/audit', requireSuperAdminAuth, (req, res) => {
    const limit = parseInt(req.query.limit) || 200;
    res.json({ success: true, logs: readAudit(limit) });
});

// 遥测：客户端上报操作数据（需用户在客户端同意遥测后才会调用；要求携带 clientId）
app.post('/api/telemetry', (req, res) => {
    try {
        const { clientId, name, event, detail } = req.body || {};
        if (!clientId || !event) {
            return res.status(400).json({ success: false, message: '缺少 clientId 或 event' });
        }
        const ok = appendTelemetry({
            ts: new Date().toISOString(),
            clientId: String(clientId),
            name: name ? String(name).slice(0, 30) : '',
            event: String(event).slice(0, 60),
            detail: detail != null ? String(detail).slice(0, 500) : ''
        });
        if (!ok) return res.status(500).json({ success: false, message: '遥测写入失败（服务器磁盘不可写）' });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: '上报失败' });
    }
});

// 遥测查看（管理员专用）：可指定 clientId 查看单个用户，或留空查看全部
app.get('/api/admin/telemetry', requireAdminAuth, (req, res) => {
    const limit = parseInt(req.query.limit) || 500;
    const clientId = req.query.clientId || '';
    res.json({ success: true, logs: readTelemetry(limit, clientId || null) });
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

// 展示用金币：优先用客户端上报的真实值，未上报时回退到管理员账本
function getDisplayCoins(id) {
    if (reportedCoins.has(id)) return reportedCoins.get(id);
    return userCoins.get(id) || 0;
}

// 聚合所有在线玩家，生成用户列表（服务器无独立账号系统，以在线玩家为准）
// 优先使用 onlinePlayers（进入游戏即上线的玩家，含未进房与已进房），再用 room.players 兜底未覆盖者
function getAllUsersList() {
    const userMap = new Map();
    // 1. 在线玩家（进入游戏即注册，含未进房与已进房）——在线状态的权威来源
    for (const player of onlinePlayers.values()) {
        if (!player || !player.id) continue;
        let roomId = null, roomName = null;
        if (player.roomId) {
            const r = rooms.get(player.roomId);
            roomId = player.roomId;
            roomName = r ? r.name : null;
        }
        userMap.set(player.id, {
            id: player.id,
            username: player.name || '未知用户',
            coins: getDisplayCoins(player.id),
            level: userLevels.get(player.id) || 1,
            roomId: roomId,
            roomName: roomName,
            online: true
        });
    }
    // 2. 兜底：room.players 中未在在线表出现的，按「名字」合并进已有在线条目（避免 peerId 产生重复条目）
    for (const room of rooms.values()) {
        if (!room.players) continue;
        for (const player of room.players.values()) {
            if (!player || !player.id) continue;
            if (userMap.has(player.id)) continue;
            // 尝试按名字找到已有的在线条目，把房间号合并进去
            let merged = false;
            for (const u of userMap.values()) {
                if (u.username === (player.name || '未知用户') && !u.roomId) {
                    u.roomId = room.id;
                    u.roomName = room.name;
                    merged = true;
                    break;
                }
            }
            if (merged) continue;
            // 实在找不到对应在线条目才新增（极少见）
            userMap.set(player.id, {
                id: player.id,
                username: player.name || '未知用户',
                coins: getDisplayCoins(player.id),
                level: userLevels.get(player.id) || 1,
                roomId: room.id,
                roomName: room.name,
                online: true
            });
        }
    }
    return Array.from(userMap.values());
}

// API: 获取用户列表（管理员专用）
app.get('/api/users', requireAdminAuth, (req, res) => {
    try {
        const users = getAllUsersList();
        console.log(`[Admin] 获取用户列表，共 ${users.length} 名在线用户`);
        res.json({ success: true, users });
    } catch (error) {
        console.error('[API] 获取用户列表失败:', error);
        res.status(500).json({ success: false, message: '获取用户列表失败' });
    }
});

// API: 玩家上线登记（开放接口，供游戏客户端调用）
// 使用 REST 而非 socket.io：实测 onrender 代理下 socket.io 的 polling 发送会丢包、
// websocket 又被部分浏览器/网络拦截，故改用普通 HTTPS POST 上报在线状态，最稳。
// 仅持久化到 onlinePlayers（管理后台 /api/users 的权威来源），不做任何鉴权（小游戏）。
app.post('/api/player-online', (req, res) => {
    try {
        const { id, name, coins, unlockedLevel, completedLevels, puzzleCompletedLevels, achievements, totalPlayTime, gameStats, gamestate } = req.body || {};
        if (!id) return res.json({ success: false, message: '缺少 id' });
        const existing = onlinePlayers.get(id) || {};
        // 记录玩家上报的真实金币（供管理员查看）
        const rc = parseInt(coins);
        if (!isNaN(rc)) reportedCoins.set(id, Math.max(0, rc));
        // 记录玩家上报的关卡进度（供管理员查看过关历史）
        mergeProgress(id, { unlockedLevel, completedLevels, puzzleCompletedLevels });
        // 记录玩家上报的成就数据（供管理员查看）
        if (achievements) mergeAchievements(id, achievements);
        const ip = getClientIp(req);
        onlinePlayers.set(id, {
            id: id,
            name: (name && String(name).trim()) || existing.name || '玩家',
            socketId: existing.socketId || null,   // 保留 socket 通道写入的连接标识
            roomId: existing.roomId || null,
            joinedAt: existing.joinedAt || Date.now(),
            ip: ip
        });
        onlineSockets.set(id, 'rest');
        // 持久化玩家档案（IP / 金币 / 时长 / 统计 / 游戏状态），供管理后台查看
        savePlayerProfile(id, {
            ip: ip,
            coins: isNaN(rc) ? (prevCoins(id)) : Math.max(0, rc),
            totalPlayTime: (typeof totalPlayTime === 'number') ? totalPlayTime : (prevPlayTime(id)),
            gameStats: (gameStats && typeof gameStats === 'object') ? gameStats : (prevStats(id)),
            gamestate: (gamestate && typeof gamestate === 'object') ? gamestate : (prevGamestate(id)),
            username: (name && String(name).trim()) || existing.name || '玩家'
        });
        console.log(`[Online] 玩家 ${name} (${id}) 上线(REST)，IP ${ip}，当前在线 ${onlinePlayers.size} 人`);
        // 把服务端已存（含管理员“全部通关”授予）的进度回传，客户端据此合入本地
        const prog = reportedProgress.get(id) || { unlockedLevel: 1, completedLevels: [], puzzleCompletedLevels: [] };
        res.json({
            success: true,
            progress: {
                unlockedLevel: prog.unlockedLevel || 1,
                completedLevels: Array.isArray(prog.completedLevels) ? prog.completedLevels : [],
                puzzleCompletedLevels: Array.isArray(prog.puzzleCompletedLevels) ? prog.puzzleCompletedLevels : []
            }
        });
    } catch (e) {
        res.json({ success: false, message: e.message });
    }
});

// 从已存档案中读取历史字段（上报不全时回退，避免清掉已有数据）
function prevCoins(id) { const p = playerProfiles.get(id); return p && typeof p.coins === 'number' ? p.coins : 0; }
function prevPlayTime(id) { const p = playerProfiles.get(id); return p && typeof p.totalPlayTime === 'number' ? p.totalPlayTime : 0; }
function prevStats(id) { const p = playerProfiles.get(id); return p && p.gameStats ? p.gameStats : null; }
function prevGamestate(id) { const p = playerProfiles.get(id); return p && p.gamestate ? p.gamestate : null; }

// API: 玩家下线（开放接口）
app.post('/api/player-offline', (req, res) => {
    try {
        const { id } = req.body || {};
        if (id) {
            const p = onlinePlayers.get(id);
            // 仅当该玩家不是经 socket 实时连着的（socketId 为 null 或标记 'rest'）才删除，避免误删 socket 在线者
            if (p && (!p.socketId || p.socketId === 'rest' || p.socketId === null)) onlinePlayers.delete(id);
            if (onlineSockets.get(id) === 'rest') onlineSockets.delete(id);
        }
        res.json({ success: true });
    } catch (e) {
        res.json({ success: false, message: e.message });
    }
});

// API: 为用户增减金币（管理员专用）
app.post('/api/users/:userId/coins', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const { amount } = req.body;

        if (amount === undefined || amount === null || isNaN(parseInt(amount))) {
            return res.status(400).json({ success: false, message: '金币数量无效' });
        }

        const delta = parseInt(amount);
        const current = userCoins.get(userId) || 0;
        const updated = current + delta;
        userCoins.set(userId, updated);

        console.log(`[Admin] 用户 ${userId} 金币变更 ${delta >= 0 ? '+' : ''}${delta}，当前余额 ${updated}`);
        appendAudit('admin', 'coins', `用户 ${userId} ${delta >= 0 ? '增加' : '扣除'} ${Math.abs(delta)} 金币，余额 ${updated}`);

        res.json({
            success: true,
            message: `已为 ${userId} ${delta >= 0 ? '增加' : '扣除'} ${Math.abs(delta)} 金币`,
            coins: updated
        });
    } catch (error) {
        console.error('[API] 调整金币失败:', error);
        res.status(500).json({ success: false, message: '调整金币失败' });
    }
});

// API: 获取用户详细信息（管理员专用）：封禁、IP、金币、游戏时长、gamestate、统计
app.get('/api/admin/users/:userId/info', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const ban = userBans.get(userId) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
        if (!ban.reasons) ban.reasons = {};
        const prof = playerProfiles.get(userId) || {};
        const p = onlinePlayers.get(userId);
        res.json({
            success: true,
            clientId: userId,
            username: prof.username || (p && p.name) || '',
            online: !!p,
            ip: prof.ip || (p && p.ip) || '',
            coins: (typeof prof.coins === 'number') ? prof.coins : (reportedCoins.get(userId) || 0),
            totalPlayTime: (typeof prof.totalPlayTime === 'number') ? prof.totalPlayTime : 0,
            gameStats: prof.gameStats || null,
            gamestate: prof.gamestate || null,
            bans: {
                multiplayer: !!ban.multiplayer, single: !!ban.single, puzzle: !!ban.puzzle, chat: !!ban.chat,
                reasons: {
                    multiplayer: ban.reasons.multiplayer || '',
                    single: ban.reasons.single || '',
                    puzzle: ban.reasons.puzzle || '',
                    chat: ban.reasons.chat || ''
                }
            }
        });
    } catch (e) {
        res.status(500).json({ success: false, message: '获取失败' });
    }
});

// API: 玩家拉取自己被管理员发放/扣除的金币余额（开放接口，供客户端同步钱包）
// userCoins[clientId] 是管理员操作后的"服务器金币账本"，客户端据此把差额并入本地钱包
app.get('/api/my-coins', (req, res) => {
    try {
        const id = req.query.id;
        if (!id) return res.json({ success: true, coins: 0 });
        const coins = userCoins.get(id) || 0;
        res.json({ success: true, coins });
    } catch (e) {
        res.json({ success: true, coins: 0 });
    }
});

// 反作弊：客户端上报可疑作弊行为（公开接口，仅需 clientId + type + detail）
app.post('/api/report-cheat', (req, res) => {
    try {
        const { clientId, type, detail } = req.body || {};
        if (!clientId || !type) return res.status(400).json({ success: false, message: '缺少 clientId 或 type' });
        const report = {
            id: Date.now() + '_' + Math.random().toString(36).substr(2, 6),
            clientId: String(clientId).slice(0, 64),
            type: String(type).slice(0, 40),
            detail: String(detail || '').slice(0, 500),
            time: new Date().toISOString()
        };
        cheatReports.push(report);
        if (cheatReports.length > 2000) cheatReports.shift(); // 防止无限增长
        // ===== 反作弊自动封禁：立即封禁其上报时所玩的玩法（管理员可在后台解封） =====
        const mode = (req.body && ['multiplayer', 'single', 'puzzle'].indexOf(req.body.mode) !== -1) ? req.body.mode : 'single';
        const cheatTypeNames = { coin_tamper: '金币存档篡改', coin_injection: '金币异常变动', impossible_speed: '异常通关速度', forged_complete: '伪造通关' };
        const autoBan = userBans.get(report.clientId) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
        if (!autoBan.reasons) autoBan.reasons = {};
        autoBan[mode] = true;
        autoBan.reasons[mode] = `反作弊系统自动封禁：检测到${cheatTypeNames[report.type] || report.type}。如有异议请联系管理员申诉解封。`;
        userBans.set(report.clientId, autoBan);
        const modeLabel = mode === 'multiplayer' ? '多人游戏' : (mode === 'single' ? '单人游戏' : '解密游戏');
        console.log(`[反作弊] 用户 ${report.clientId} 因 ${report.type} 被自动封禁${modeLabel}`);
        // 若该用户有实时 socket，立即推送最新封禁状态（否则由客户端 15s 轮询兜底）
        const cheatSocketId = onlineSockets.get(report.clientId);
        if (cheatSocketId && cheatSocketId !== 'rest') {
            const sock = io.sockets.sockets.get(cheatSocketId);
            if (sock) sock.emit('ban-update', {
                multiplayer: !!autoBan.multiplayer, single: !!autoBan.single, puzzle: !!autoBan.puzzle, chat: !!autoBan.chat,
                multiplayerReason: autoBan.reasons.multiplayer || '', singleReason: autoBan.reasons.single || '', puzzleReason: autoBan.reasons.puzzle || '', chatReason: autoBan.reasons.chat || ''
            });
        }
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: '服务器错误' });
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
        
        // 通知房间内所有玩家（socket.io 房间通道，兼容旧连接方式）
        io.to(roomId).emit('room-kicked', {
            message: '房间已被管理员删除'
        });
        // 全局广播房间删除事件：玩家的通知 socket 未 join socket.io 房间，
        // io.to(roomId) 实际到不了他们，必须全局广播、由客户端按 roomId 自行过滤（与 room-completed 同款模式）
        io.emit('room-deleted', {
            roomId: roomId,
            message: '房间已被管理员删除，所有玩家已被移出并断开多人游戏连接。'
        });
        
        // 强制断开所有玩家的连接
        for (const [playerId, player] of room.players.entries()) {
            const socket = io.sockets.sockets.get(player.socketId);
            if (socket) {
                socket.disconnect(true);
            }
        }
        
        // 清理在线玩家表中该房间的归属，避免残留
        for (const p of onlinePlayers.values()) {
            if (p && p.roomId === roomId) p.roomId = null;
        }
        
        // 删除房间与聊天记录
        rooms.delete(roomId);
        roomChats.delete(roomId);
        
        console.log(`[Admin] 房间 ${roomId} 已被管理员删除`);
        appendAudit('admin', 'delete-room', `删除房间 ${roomId}`);
        
        // 广播更新后的房间列表
        broadcastRoomList();
        
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
        appendAudit('admin', 'kick-all', `房间 ${roomId} 请出全部玩家，共 ${kickedPlayersCount} 人`);
        
        // 广播更新后的房间列表
        broadcastRoomList();
        
        res.json({ success: true, message: `已请出 ${kickedPlayersCount} 名玩家` });
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
        appendAudit('admin', 'room-privacy', `房间 ${roomId} 设为${isPrivate ? '私密' : '公开'}`);
        
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

// ===== 房间聊天监管（管理员可查看/发言/删除消息） =====
// 聊天走 PeerJS P2P、服务器天然看不到，因此由发送方客户端把消息"镜像上报"到这里留存。

// API: 客户端镜像上报聊天消息（公开接口）
app.post('/api/room-chat', (req, res) => {
    try {
        const { roomId, messageId, sender, clientId, message, image } = req.body || {};
        if (!roomId || !messageId || (!message && !image)) {
            return res.json({ success: false, message: '参数不完整' });
        }
        let list = roomChats.get(String(roomId));
        if (!list) { list = []; roomChats.set(String(roomId), list); }
        // 去重（同一 messageId 只存一次）
        if (list.some(m => m.messageId === messageId)) return res.json({ success: true });
        list.push({
            messageId: String(messageId),
            sender: String(sender || '玩家').slice(0, 50),
            clientId: clientId ? String(clientId) : null,
            message: message ? String(message).slice(0, 2000) : null,
            image: image ? String(image).slice(0, 500000) : null, // 图片 base64 上限 ~500KB
            isAdmin: false,
            time: Date.now()
        });
        if (list.length > 200) list.shift();
        res.json({ success: true });
    } catch (e) {
        res.json({ success: false, message: e.message });
    }
});

// API: 管理员查看房间聊天记录
app.get('/api/admin/rooms/:roomId/chat', requireAdminAuth, (req, res) => {
    try {
        const roomId = String(req.params.roomId);
        const list = roomChats.get(roomId) || [];
        res.json({ success: true, roomExists: rooms.has(roomId), messages: list });
    } catch (e) {
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// API: 管理员以 ADMIN 身份向房间发送消息（全局广播，客户端按 roomId 过滤展示）
app.post('/api/admin/rooms/:roomId/chat-send', requireAdminAuth, (req, res) => {
    try {
        const roomId = String(req.params.roomId);
        const message = (req.body && req.body.message) ? String(req.body.message).slice(0, 2000) : '';
        if (!message.trim()) return res.json({ success: false, message: '消息不能为空' });
        // 伪装发送：sender 可为任意名字（默认 ADMIN）；label 可为任意标签文本
        // label 未提供时：ADMIN → "管理员"；伪装名 → 无标签（看起来和普通玩家消息一样）
        const sender = ((req.body && req.body.sender) ? String(req.body.sender).trim().slice(0, 30) : '') || 'ADMIN';
        let label = (req.body && req.body.label !== undefined && req.body.label !== null)
            ? String(req.body.label).trim().slice(0, 20)
            : null;
        if (label === null) label = (sender === 'ADMIN') ? '管理员' : '';
        const messageId = 'adm_' + Date.now() + Math.random().toString(36).slice(2, 8);
        const record = {
            messageId, sender: sender, clientId: null, label: label,
            message: message, image: null, isAdmin: true, time: Date.now()
        };
        let list = roomChats.get(roomId);
        if (!list) { list = []; roomChats.set(roomId, list); }
        list.push(record);
        if (list.length > 200) list.shift();
        // 全局广播（通知 socket 未 join 房间，由客户端按 roomId 过滤）
        io.emit('admin-chat-message', { roomId, messageId, message, sender, label });
        console.log(`[Admin] 后台以 "${sender}"${label ? '[' + label + ']' : ''} 身份向房间 ${roomId} 发送消息: ${message}`);
        res.json({ success: true, messageId });
    } catch (e) {
        res.status(500).json({ success: false, message: '发送失败' });
    }
});

// API: 管理员删除房间内某条聊天消息（全局广播删除事件，客户端移除对应 DOM）
app.post('/api/admin/rooms/:roomId/chat-delete', requireAdminAuth, (req, res) => {
    try {
        const roomId = String(req.params.roomId);
        const messageId = (req.body && req.body.messageId) ? String(req.body.messageId) : '';
        if (!messageId) return res.json({ success: false, message: '缺少 messageId' });
        const list = roomChats.get(roomId) || [];
        const idx = list.findIndex(m => m.messageId === messageId);
        if (idx !== -1) list.splice(idx, 1);
        io.emit('admin-chat-delete', { roomId, messageId });
        console.log(`[Admin] 删除房间 ${roomId} 的消息 ${messageId}`);
        appendAudit('admin', 'chat-delete', `删除房间 ${roomId} 的聊天消息 ${messageId}`);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: '删除失败' });
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

        // ===== 安全检测：客户端不应再发送明文密码（新客户端只发送 SHA-256 哈希） =====
        // 合法密码要么是 undefined/空（无密码），要么是 64 位十六进制 SHA-256 哈希。
        // 收到非哈希的明文密码，判定为旧版/不安全客户端：拒绝建房并触发其版本检测。
        if (password && typeof password === 'string' && !/^[0-9a-f]{64}$/i.test(String(password).trim())) {
            console.warn('[安全] /api/create-room 检测到明文密码（疑似旧版客户端）。拒绝建房并通知其进行版本检测。');
            return res.status(400).json({
                success: false,
                code: 'PLAINTEXT_PASSWORD',
                message: '服务器检测到明文密码，你的客户端可能已过时',
                serverVersion: SERVER_VERSION
            });
        }

        // 私密房间不再强制要求密码（可仅凭房间号加入，不在列表公开）

        // 优先采用客户端传来的真实 Peer 房间号，确保服务器房间 ID 与 P2P 连接房间号一致；否则回退生成唯一 ID
        let roomId = (req.body.roomCode && typeof req.body.roomCode === 'string' && req.body.roomCode.trim()) ? req.body.roomCode.trim() : null;
        if (!roomId || rooms.has(roomId)) {
            roomId = generateRoomId();
            while (rooms.has(roomId)) roomId = generateRoomId();
        }
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
                players: new Map(), // 真实玩家由客户端经 socket 'mp-register' 注册，避免重复计数
                maxPlayers,
                status: 'waiting',
                hostName: playerName,
                private: isPrivate,
                password: password, // 存储房间密码
                createdAt: Date.now(),
                lastActivity: Date.now(), // 添加最后活动时间戳
                actualHost: null, // 存储实际的Socket ID
                waitingSocket: false, // 等待房主连接
                chatDisabled: false, // 房间级聊天开关（管理员可关闭）
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

    // 记录见过的最高客户端版本（自动发现新发布的客户端，无需改服务端即可提示老玩家刷新）
    if (clientVersion && cmpVersion(latestClientVersion, clientVersion) < 0) {
        latestClientVersion = String(clientVersion);
    }

    // 是否“过时”：仅当客户端版本低于“已知最新客户端版本(latestClientVersion)”时才算过时。
    // 旧逻辑用 clientVersion === SERVER_VERSION 判断，会导致【比服务器版本更高的客户端】被误判为
    // “过时”并要求用户“刷新/更新”（实为降级），与上方设计注释（按 latestClientVersion 自动发现新版本）相悖。
    const outdated = !!(clientVersion && cmpVersion(clientVersion, latestClientVersion) < 0);
    // 始终返回最新客户端版本，客户端据此判断是否弹“有更新”弹窗
    const responseData = {
        status: outdated ? 'outdated' : 'ok',
        version: SERVER_VERSION,
        serverVersion: SERVER_VERSION,
        latestClientVersion: latestClientVersion,
        clientVersion: clientVersion || null,
        message: outdated ? '检测到版本不匹配，请更新客户端或刷新页面。' : '服务器在线，版本匹配'
    };

    // 将处理好的数据以 JSON 格式返回给客户端
    res.json(responseData);
});

// 1. 首先，创建一个 HTTP 服务器
const server = http.createServer(app);
// socket.io 使用独立 CORS 配置（与 REST 中间件解耦）。
// origin: true 会反射请求的 Origin（含 file:// 的 null 与各类 http 来源），
// 配合 credentials: true 可稳妥通过跨域校验（不能用 "*" + credentials 组合）。
const io = new Server(server, {
    cors: {
        origin: true,
        methods: ["GET", "POST", "OPTIONS"],
        allowedHeaders: "*",
        credentials: true
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
            // ===== 安全检测：同 HTTP create-room，拒绝明文密码并通知版本检测 =====
            if (password && typeof password === 'string' && !/^[0-9a-f]{64}$/i.test(String(password).trim())) {
                console.warn('[安全] socket createRoom 检测到明文密码。拒绝建房并通知版本检测。');
                socket.emit('version-check-required', { serverVersion: SERVER_VERSION, reason: 'PLAINTEXT_PASSWORD' });
                return callback({ success: false, code: 'PLAINTEXT_PASSWORD', message: '服务器检测到明文密码，你的客户端可能已过时', serverVersion: SERVER_VERSION });
            }
            // 优先采用客户端传来的真实 Peer 房间号，确保服务器房间 ID 与 P2P 连接房间号一致；否则回退生成唯一 ID
            let roomId = (data.roomCode && typeof data.roomCode === 'string' && data.roomCode.trim()) ? data.roomCode.trim() : null;
            if (!roomId || rooms.has(roomId)) {
                roomId = generateRoomId();
                while (rooms.has(roomId)) roomId = generateRoomId();
            }
            
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
                createdAt: Date.now(),
                lastActivity: Date.now(), // 添加最后活动时间戳
                maze: null, // 保存迷宫数据
                chatDisabled: false // 房间级聊天开关（管理员可关闭）
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
        try {
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
            if (room.waitingSocket) {
                console.log(`玩家 ${playerName} 尝试加入正在等待房主连接的房间 ${roomId}`);
                return callback({ success: false, message: '房间正在等待房主连接，请稍后再试' });
            }
            if (room.players.size >= room.maxPlayers) {
                console.log(`房间 ${roomId} 已满，玩家 ${playerName} 加入失败`);
                return callback({ success: false, message: '房间已满' });
            }
            
            // 检查房主是否已连接
            if (!room.actualHost || room.actualHost === null) {
                console.log(`玩家 ${playerName} 尝试加入没有房主的房间 ${roomId}`);
                return callback({ success: false, message: '房间房主未连接，请稍后再试' });
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
            room.lastActivity = Date.now(); // 更新房间最后活动时间
            console.log(`玩家 ${newPlayer.name} (ID: ${playerId}) 成功加入房间 ${roomId}`);
            
            // 向房间内所有玩家广播新玩家加入消息
            io.to(roomId).emit('player-joined', {
                player: newPlayer,
                players: Array.from(room.players.values())
            });
            
            // 向新玩家发送房间信息，包含迷宫数据
            const roomInfo = {
                type: 'room-joined',
                roomId: room.id,
                name: room.name,
                players: Array.from(room.players.values()),
                maxPlayers: room.maxPlayers,
                status: room.status,
                hostName: room.hostName,
                private: room.private,
                isHost: false,
                maze: room.maze // 发送迷宫数据
            };
        
            socket.emit('room-info', roomInfo);
        
            callback({ success: true, ...roomInfo });
            broadcastRoomList();
        } catch (error) {
            console.error('处理joinRoom事件时发生错误:', error);
            callback({ success: false, message: '服务器内部错误，请稍后再试' });
        }
    });

    // 处理房主发送的迷宫数据
    socket.on('maze-generated', (data) => {
        try {
            const { roomId, maze } = data;
            const room = rooms.get(roomId);
            
            if (room && socket.id === room.actualHost) {
                // 更新房间的迷宫数据
                room.maze = maze;
                room.lastActivity = Date.now();
                console.log(`房主 ${socket.id} 更新了房间 ${roomId} 的迷宫数据`);
                
                // 向房间内所有玩家广播迷宫数据
                io.to(roomId).emit('maze-updated', {
                    maze: maze
                });
            }
        } catch (error) {
            console.error('处理maze-generated事件时发生错误:', error);
        }
    });

    // 处理玩家加入房间的请求
    socket.on('player-join', (data, callback) => {
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
            room.lastActivity = Date.now(); // 更新房间最后活动时间

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

    socket.on('startGame', (roomId) => {
        const room = rooms.get(roomId);
        if (room) {
            // REST 创建的房间房主 socket 未绑定时，首启即以当前连接为房主
            // （否则 actualHost 恒为 null，startGame 永远不会生效，房间永远停在 waiting）
            if (!room.actualHost) room.actualHost = socket.id;
            if (room.actualHost === socket.id) {
                room.status = 'playing';
                room.lastActivity = Date.now(); // 更新房间最后活动时间
                io.to(roomId).emit('game-started', {
                    roomId: roomId,
                    status: 'playing'
                });
                broadcastRoomList();
            }
        }
    });

    socket.on('disconnect', () => {
        handleDisconnect(socket.id);
    });

    // ===== 新增：进入游戏即上线（管理后台 /api/users 可见，无需进房间） =====
    // 客户端进入游戏、取名后调用，把自身登记为在线玩家（roomId 为 null 表示尚未进入任何房间）。
    socket.on('player-online', (data) => {
        try {
        const { id, name, coins, unlockedLevel, completedLevels, puzzleCompletedLevels, achievements, totalPlayTime, gameStats, gamestate } = data || {};
        if (!id) return;
        const ip = getClientIp(req);
        onlinePlayers.set(id, {
            id: id,
            name: (name && String(name).trim()) || '玩家',
            socketId: socket.id,
            roomId: null,
            joinedAt: Date.now(),
            ip: ip
        });
        const rc = parseInt(coins);
        if (!isNaN(rc)) reportedCoins.set(id, Math.max(0, rc));
        mergeProgress(id, { unlockedLevel, completedLevels, puzzleCompletedLevels });
        if (achievements) mergeAchievements(id, achievements);
        savePlayerProfile(id, {
            ip: ip,
            coins: isNaN(rc) ? prevCoins(id) : Math.max(0, rc),
            totalPlayTime: (typeof totalPlayTime === 'number') ? totalPlayTime : prevPlayTime(id),
            gameStats: (gameStats && typeof gameStats === 'object') ? gameStats : prevStats(id),
            gamestate: (gamestate && typeof gamestate === 'object') ? gamestate : prevGamestate(id),
            username: (name && String(name).trim()) || '玩家'
        });
            onlineSockets.set(id, socket.id);
            console.log(`[Online] 玩家 ${name} (${id}) 上线，IP ${ip}，当前在线 ${onlinePlayers.size} 人`);
        } catch (e) {
            console.error('[Online] player-online 处理出错:', e.message);
        }
    });

    // 玩家离开游戏（关闭/刷新页面前主动通知）
    socket.on('player-offline', (data) => {
        try {
            const { id } = data || {};
            if (!id) return;
            const p = onlinePlayers.get(id);
            if (p && p.socketId === socket.id) onlinePlayers.delete(id);
            onlineSockets.delete(id);
            console.log(`[Online] 玩家 ${id} 下线，当前在线 ${onlinePlayers.size} 人`);
        } catch (e) {
            console.error('[Online] player-offline 处理出错:', e.message);
        }
    });

    // ===== 新增：多人游戏真实玩家注册（供管理后台 /api/users 聚合在线用户） =====
    // 客户端（房主与加入者）在成功进入房间后，经此事件把自身注册到服务器 room.players，
    // 与 REST create-room 创建的房间（roomId = Peer 房间号）对应。同时同步到 onlinePlayers（带上房间号）。
    socket.on('mp-register', (data) => {
        try {
            const { roomId, player } = data || {};
            const room = rooms.get(roomId);
            if (!room || !player || !player.id) return;
            // room.players 仍以 peerId 为键（P2P 逻辑需要）
            room.players.set(player.id, {
                id: player.id,
                name: player.name || '玩家',
                socketId: socket.id,
                color: player.color || '#ffffff',
                clientId: player.clientId || null,
                // 房主身份以服务器记录的 actualHost（房主 socketId）为准，避免客户端误报
                isHost: socket.id === room.actualHost,
                joinedAt: Date.now()
            });
            // 在线表统一用 clientId 作为键（与 player-online 一致），避免同一玩家出现两条（clientId + peerId）
            const cid = player.clientId || player.id;
            const prev = onlinePlayers.get(cid) || {};
            onlinePlayers.set(cid, {
                id: cid,
                name: (player.name && String(player.name).trim()) || prev.name || '玩家',
                socketId: socket.id,
                color: player.color || '#ffffff',
                roomId: roomId || prev.roomId || null,
                joinedAt: prev.joinedAt || Date.now()
            });
            onlineSockets.set(cid, socket.id);
            // 清除可能残留的旧 peerId 条目，防止管理后台重复显示
            if (cid !== player.id) onlinePlayers.delete(player.id);
            room.lastActivity = Date.now();
            console.log(`[MP] 玩家 ${player.name} (${cid}) 已注册到房间 ${roomId}，当前在线 ${room.players.size} 人`);
        } catch (e) {
            console.error('[MP] mp-register 处理出错:', e.message);
        }
    });

    socket.on('mp-unregister', (data) => {
        try {
            const { roomId, playerId, clientId } = data || {};
            const room = rooms.get(roomId);
            if (room && playerId) {
                const p = room.players.get(playerId);
                if (p && p.socketId === socket.id) room.players.delete(playerId);
            }
            // 玩家离开房间但仍在线：按 clientId 清除在线表的房间号（不再删 onlinePlayers/onlineSockets）
            const cid = clientId || playerId;
            const op = onlinePlayers.get(cid);
            if (op && op.socketId === socket.id) op.roomId = null;
            if (room) room.lastActivity = Date.now();
        } catch (e) {
            console.error('[MP] mp-unregister 处理出错:', e.message);
        }
    });

    // 聊天消息处理
    socket.on('chat-message', (data) => {
        console.log('收到聊天消息:', data);
        // 获取房间ID
        const player = players.get(socket.id);
        if (player && player.roomId) {
            // 转发消息到房间内所有玩家
            io.to(player.roomId).emit('chat-message', data);
            console.log(`转发消息到房间 ${player.roomId} 来自 ${player.name}: ${data.message}`);
        } else {
            console.log('无法转发消息: 玩家未在房间内');
        }
    });

    // 消息撤回处理
    socket.on('message-recall', (messageId) => {
        console.log('收到消息撤回请求:', messageId);
        const player = players.get(socket.id);
        if (player && player.roomId) {
            io.to(player.roomId).emit('message-recalled', messageId);
            console.log(`${player.name} 撤回了消息 ${messageId}`);
        }
    });
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
        appendAudit('admin', 'system-message', `房间 ${roomId} 发送系统消息: ${String(message).slice(0, 80)}`);
        
        res.json({ success: true, message: '消息发送成功' });

    } catch (error) {
        console.error('[API] 发送系统消息失败:', error);
        res.status(500).json({ success: false, message: '服务器内部错误' });
    }
});

// API: 向所有在线客户端发送全局弹窗（管理员专用）
app.post('/api/admin/popup', requireAdminAuth, (req, res) => {
    try {
        const { title, message } = req.body;

        if (!title || !message) {
            return res.status(400).json({ success: false, message: '弹窗标题和内容不能为空' });
        }

        // 向所有连接的客户端广播弹窗事件（游戏端需监听 'admin-popup' 才能显示）
        io.emit('admin-popup', {
            title: title,
            message: message,
            timestamp: Date.now()
        });

        console.log(`[Admin] 已发送全局弹窗: ${title}`);
        appendAudit('admin', 'popup', `发送全局弹窗: ${String(title).slice(0, 80)}`);
        res.json({ success: true, message: '弹窗已发送给所有在线玩家' });
    } catch (error) {
        console.error('[API] 发送弹窗失败:', error);
        res.status(500).json({ success: false, message: '发送弹窗失败' });
    }
});

// ===== 新增：热门迷宫管理（管理员专用，持久化到 data/mazes.json） =====
function generateMazeId() {
    return 'maze_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 5);
}

// 公开接口：供游戏端读取热门迷宫列表（玩家侧也可见）
app.get('/api/mazes', (req, res) => {
    try {
        res.json({ success: true, mazes: Array.from(mazes.values()) });
    } catch (error) {
        res.status(500).json({ success: false, message: '获取迷宫列表失败' });
    }
});

// 管理员：获取全部迷宫
app.get('/api/admin/mazes', requireAdminAuth, (req, res) => {
    try {
        res.json({ success: true, mazes: Array.from(mazes.values()) });
    } catch (error) {
        res.status(500).json({ success: false, message: '获取迷宫列表失败' });
    }
});

// 管理员：新建迷宫
app.post('/api/admin/mazes', requireAdminAuth, (req, res) => {
    try {
        const { name, description, difficulty, size, data } = req.body || {};
        if (!name || !String(name).trim()) {
            return res.status(400).json({ success: false, message: '迷宫名称不能为空' });
        }
        const maze = {
            id: generateMazeId(),
            name: String(name).trim(),
            description: description || '',
            difficulty: difficulty || '简单',
            size: parseInt(size, 10) || 10,
            data: (data !== undefined) ? data : null,
            createdAt: Date.now()
        };
        mazes.set(maze.id, maze);
        saveMazes();
        console.log(`[Admin] 新建迷宫: ${maze.name} (${maze.id})`);
        res.json({ success: true, message: '迷宫创建成功', maze });
    } catch (error) {
        console.error('[API] 新建迷宫失败:', error);
        res.status(500).json({ success: false, message: '新建迷宫失败' });
    }
});

// 管理员：更新迷宫
app.put('/api/admin/mazes/:mazeId', requireAdminAuth, (req, res) => {
    try {
        const mazeId = req.params.mazeId;
        const maze = mazes.get(mazeId);
        if (!maze) return res.status(404).json({ success: false, message: '迷宫不存在' });
        const { name, description, difficulty, size, data } = req.body || {};
        if (name !== undefined) maze.name = String(name).trim() || maze.name;
        if (description !== undefined) maze.description = description;
        if (difficulty !== undefined) maze.difficulty = difficulty;
        if (size !== undefined) maze.size = parseInt(size, 10) || maze.size;
        if (data !== undefined) maze.data = data;
        maze.updatedAt = Date.now();
        mazes.set(mazeId, maze);
        saveMazes();
        console.log(`[Admin] 更新迷宫: ${maze.name} (${mazeId})`);
        res.json({ success: true, message: '迷宫更新成功', maze });
    } catch (error) {
        console.error('[API] 更新迷宫失败:', error);
        res.status(500).json({ success: false, message: '更新迷宫失败' });
    }
});

// 管理员：删除迷宫
app.delete('/api/admin/mazes/:mazeId', requireAdminAuth, (req, res) => {
    try {
        const mazeId = req.params.mazeId;
        if (!mazes.has(mazeId)) return res.status(404).json({ success: false, message: '迷宫不存在' });
        mazes.delete(mazeId);
        saveMazes();
        console.log(`[Admin] 删除迷宫: ${mazeId}`);
        res.json({ success: true, message: '迷宫删除成功' });
    } catch (error) {
        console.error('[API] 删除迷宫失败:', error);
        res.status(500).json({ success: false, message: '删除迷宫失败' });
    }
});

// ===== 新增：用户页面访问控制 / 功能控制（管理员专用） =====
app.post('/api/admin/access', requireAdminAuth, (req, res) => {
    try {
        const { userId, access } = req.body || {};
        if (!userId) return res.status(400).json({ success: false, message: '用户ID不能为空' });
        userAccess.set(userId, access || 'all');
        console.log(`[Admin] 用户 ${userId} 页面访问权限设为: ${access || 'all'}`);
        res.json({ success: true, message: `已为用户 ${userId} 设置访问权限: ${access || 'all'}`, access: userAccess.get(userId) });
    } catch (error) {
        console.error('[API] 设置访问权限失败:', error);
        res.status(500).json({ success: false, message: '设置失败' });
    }
});

app.post('/api/admin/function-control', requireAdminAuth, (req, res) => {
    try {
        const { userId, control } = req.body || {};
        if (!userId) return res.status(400).json({ success: false, message: '用户ID不能为空' });
        userFunctions.set(userId, control || 'enable');
        console.log(`[Admin] 用户 ${userId} 功能控制设为: ${control || 'enable'}`);
        res.json({ success: true, message: `已为用户 ${userId} 设置功能控制: ${control || 'enable'}`, control: userFunctions.get(userId) });
    } catch (error) {
        console.error('[API] 设置功能控制失败:', error);
        res.status(500).json({ success: false, message: '设置失败' });
    }
});

// ===== 新增：管理员封禁（按用户禁用多人/单人游戏） =====
// 封禁按 clientId（即在线用户列表中的 id）生效；客户端定时 REST 拉取自身封禁状态并应用。
// 兼容管理员填「名字」或「名字 (ID: xxx)」整段：自动解析为对应的 clientId 再存储。
function resolveUserId(raw) {
    if (!raw) return raw;
    const s = String(raw).trim();
    // 1) 已是 clientId（在线表或已有封禁记录）直接返回
    if (onlinePlayers.has(s) || userBans.has(s)) return s;
    // 2) 形如 "名字 (ID: xxx)" 或 "ID: xxx" —— 提取括号内的 id
    const m = s.match(/ID:\s*([^\s\)]+)/i);
    if (m && onlinePlayers.has(m[1])) return m[1];
    // 3) 按名字精确匹配在线玩家，取其 clientId（同名取第一个）
    for (const [cid, p] of onlinePlayers) {
        if (p && p.name === s) return cid;
    }
    // 4) 都匹配不到，原样返回（交由后续逻辑按原值处理）
    return s;
}
app.post('/api/admin/ban', requireAdminAuth, (req, res) => {
    try {
        const rawId = (req.body && req.body.userId) || '';
        if (!rawId) return res.status(400).json({ success: false, message: '用户ID不能为空' });
        const userId = resolveUserId(rawId);
        const { type, banned, reason } = req.body || {};
        if (type !== 'multiplayer' && type !== 'single' && type !== 'puzzle' && type !== 'chat') return res.status(400).json({ success: false, message: '类型无效（应为 multiplayer、single、puzzle 或 chat）' });
        const ban = userBans.get(userId) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
        if (!ban.reasons) ban.reasons = {};
        ban[type] = !!banned;
        // 记录/清除封禁理由（解封时清空）
        ban.reasons[type] = banned ? ((reason && String(reason).trim()) || '') : '';
        userBans.set(userId, ban);
        const banLabel = type === 'multiplayer' ? '多人游戏' : (type === 'single' ? '单人游戏' : (type === 'puzzle' ? '解密游戏' : '多人游戏聊天'));
        console.log(`[Admin] 用户 ${userId} 的${banLabel}已${banned ? '封禁' : '解封'}${banned && ban.reasons[type] ? '，理由: ' + ban.reasons[type] : ''}`);
        appendAudit('admin', 'ban', `用户 ${userId} 的${banLabel}${banned ? '封禁' : '解封'}${banned && ban.reasons[type] ? '，理由: ' + ban.reasons[type] : ''}`);
        // 若该用户当前有实时 socket，立即推送最新封禁状态（REST 注册的玩家无 socket，由客户端定时拉取兜底）
        const socketId = onlineSockets.get(userId);
        if (socketId && socketId !== 'rest') {
            const sock = io.sockets.sockets.get(socketId);
            if (sock) sock.emit('ban-update', {
                multiplayer: !!ban.multiplayer, single: !!ban.single, puzzle: !!ban.puzzle, chat: !!ban.chat,
                multiplayerReason: ban.reasons.multiplayer || '', singleReason: ban.reasons.single || '', puzzleReason: ban.reasons.puzzle || '', chatReason: ban.reasons.chat || ''
            });
        }
        res.json({ success: true, message: `已${banned ? '封禁' : '解封'}用户 ${userId} 的${banLabel}`, ban });
    } catch (error) {
        console.error('[API] 设置封禁失败:', error);
        res.status(500).json({ success: false, message: '设置失败' });
    }
});

// 客户端拉取自身封禁状态（开放接口，按 clientId 查询）
app.get('/api/my-ban', (req, res) => {
    try {
        const id = req.query.id;
        if (!id) return res.json({ success: true, multiplayer: false, single: false, puzzle: false, chat: false, multiplayerReason: '', singleReason: '', puzzleReason: '', chatReason: '' });
        const ban = userBans.get(id) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
        if (!ban.reasons) ban.reasons = {};
        res.json({
            success: true,
            multiplayer: !!ban.multiplayer, single: !!ban.single, puzzle: !!ban.puzzle, chat: !!ban.chat,
            multiplayerReason: ban.reasons.multiplayer || '',
            singleReason: ban.reasons.single || '',
            puzzleReason: ban.reasons.puzzle || '',
            chatReason: ban.reasons.chat || ''
        });
    } catch (e) {
        res.json({ success: true, multiplayer: false, single: false, puzzle: false, chat: false, multiplayerReason: '', singleReason: '', puzzleReason: '', chatReason: '' });
    }
});

// 玩家拉取自身关卡权限（forbidden / forced），供客户端拦截"禁止进入"的关卡
app.get('/api/my-level-permissions', (req, res) => {
    try {
        const id = req.query.id;
        if (!id) return res.json({ success: true, levels: {} });
        const perms = levelPermissions.get(id) || {};
        res.json({ success: true, levels: perms });
    } catch (e) {
        res.json({ success: true, levels: {} });
    }
});

// 反作弊：管理员查看作弊上报记录
app.get('/api/admin/cheats', requireAdminAuth, (req, res) => {
    try {
        const list = cheatReports.slice(-300).reverse(); // 最新在前
        res.json({ success: true, reports: list });
    } catch (e) {
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// 反作弊：管理员查看被反作弊系统自动封禁的玩家（理由以"反作弊系统自动封禁"开头的封禁）
app.get('/api/admin/cheat-bans', requireAdminAuth, (req, res) => {
    try {
        const modeNames = { multiplayer: '多人游戏', single: '单人游戏', puzzle: '解密游戏', chat: '多人聊天' };
        const list = [];
        for (const [uid, ban] of userBans.entries()) {
            if (!ban || !ban.reasons) continue;
            const bans = [];
            for (const mode of Object.keys(modeNames)) {
                if (ban[mode] && typeof ban.reasons[mode] === 'string' && ban.reasons[mode].indexOf('反作弊系统自动封禁') === 0) {
                    bans.push({ mode: mode, modeName: modeNames[mode], reason: ban.reasons[mode] });
                }
            }
            if (bans.length > 0) {
                const p = onlinePlayers.get(uid);
                list.push({ clientId: uid, username: (p && p.name) ? p.name : '', online: !!p, bans: bans });
            }
        }
        res.json({ success: true, users: list });
    } catch (e) {
        res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// ===== 新增：远程控制（管理员专用，精准投递到目标用户 socket） =====
app.post('/api/admin/remote', requireAdminAuth, (req, res) => {
    try {
        const { userId, action } = req.body || {};
        if (!userId || !action) return res.status(400).json({ success: false, message: '缺少 userId 或 action' });
        const socketId = onlineSockets.get(userId);
        if (!socketId) return res.status(404).json({ success: false, message: '目标用户不在线或未注册' });
        const sock = io.sockets.sockets.get(socketId);
        if (!sock) return res.status(404).json({ success: false, message: '目标用户连接已断开' });
        sock.emit('admin-command', { action, timestamp: Date.now() });
        console.log(`[Admin] 已向用户 ${userId} 发送远程指令: ${action}`);
        res.json({ success: true, message: `已向用户 ${userId} 发送指令: ${action}` });
    } catch (error) {
        console.error('[API] 远程控制失败:', error);
        res.status(500).json({ success: false, message: '远程控制失败' });
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
        appendAudit('admin', 'kick-player', `房间 ${roomId} 踢出玩家 ${playerToKick.name} (${playerIdToKick})`);

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
        appendAudit('admin', 'clear-room', `清空并重置房间 ${roomId}，共请出 ${kickedPlayersCount} 人`);
        
        broadcastRoomList();

        res.json({ success: true, message: `房间已清空并重置，共请出 ${kickedPlayersCount} 名玩家` });

    } catch (error) {
        console.error('[API] 清空房间失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// ===== 新增：房间管理（管理员专用） =====
// 1) 房间详情：返回房间信息 + 玩家列表（含坐标/clientId）+ 迷宫 + 聊天开关
app.get('/api/admin/rooms/:roomId/detail', requireAdminAuth, (req, res) => {
    try {
        const room = rooms.get(req.params.roomId);
        if (!room) return res.status(404).json({ success: false, message: '房间不存在' });
        const players = Array.from(room.players.values()).map(p => ({
            id: p.id,
            name: p.name,
            isHost: !!p.isHost,
            x: (typeof p.x === 'number') ? p.x : null,
            y: (typeof p.y === 'number') ? p.y : null,
            color: p.color || '#fff',
            clientId: p.clientId || null,
            socketId: !!p.socketId
        }));
        res.json({
            success: true,
            room: {
                id: room.id,
                name: room.name,
                hostName: room.hostName,
                status: room.status,
                maxPlayers: room.maxPlayers,
                private: !!room.private,
                hasPassword: room.password !== undefined && room.password !== null,
                chatDisabled: !!room.chatDisabled,
                playerCount: room.players.size,
                createdAt: room.createdAt,
                maze: room.maze || null
            },
            players
        });
    } catch (error) {
        console.error('[API] 获取房间详情失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 2) 关闭/开启房间聊天功能
app.post('/api/admin/rooms/:roomId/disable-chat', requireAdminAuth, (req, res) => {
    try {
        const room = rooms.get(req.params.roomId);
        if (!room) return res.status(404).json({ success: false, message: '房间不存在' });
        const disabled = req.body && req.body.disabled === true;
        room.chatDisabled = disabled;
        // 全局广播（玩家通知 socket 未 join socket.io 房间，必须全局 + 客户端按 roomId 过滤）
        io.emit('admin-room-chat-disabled', { roomId: room.id, disabled });
        appendAudit('admin', 'room-chat', `房间 ${room.id} ${disabled ? '关闭' : '开启'}聊天功能`);
        broadcastRoomList();
        res.json({ success: true, message: disabled ? '已关闭该房间聊天功能' : '已开启该房间聊天功能', disabled });
    } catch (error) {
        console.error('[API] 切换房间聊天失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 3) 更改地图：通知房主客户端重新生成迷宫并同步给所有玩家（复用客户端 generateMultiplayerMaze，最稳妥）
app.post('/api/admin/rooms/:roomId/change-map', requireAdminAuth, (req, res) => {
    try {
        const room = rooms.get(req.params.roomId);
        if (!room) return res.status(404).json({ success: false, message: '房间不存在' });
        io.emit('admin-regenerate-map', { roomId: room.id });
        console.log(`[Admin] 已请求房主重新生成房间 ${room.id} 的地图`);
        appendAudit('admin', 'change-map', `房间 ${room.id} 请求重新生成地图`);
        res.json({ success: true, message: '已发送重新生成地图指令（需房主在线以执行）' });
    } catch (error) {
        console.error('[API] 更改地图失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 4) 传送玩家到任意位置
app.post('/api/admin/rooms/:roomId/teleport', requireAdminAuth, (req, res) => {
    try {
        const room = rooms.get(req.params.roomId);
        if (!room) return res.status(404).json({ success: false, message: '房间不存在' });
        const { playerId, x, y } = req.body || {};
        if (!playerId) return res.status(400).json({ success: false, message: '缺少 playerId' });
        const px = parseInt(x), py = parseInt(y);
        if (isNaN(px) || isNaN(py)) return res.status(400).json({ success: false, message: '坐标无效' });
        const player = room.players.get(playerId);
        if (!player) return res.status(404).json({ success: false, message: '房间内未找到该玩家' });
        player.x = px;
        player.y = py;
        io.emit('admin-teleport', { roomId: room.id, playerId, x: px, y: py });
        appendAudit('admin', 'teleport', `将房间 ${room.id} 玩家 ${player.name} (${playerId}) 传送到 (${px}, ${py})`);
        res.json({ success: true, message: `已将 ${player.name} 传送到 (${px}, ${py})` });
    } catch (error) {
        console.error('[API] 传送玩家失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 5) 更改房主（转移房主权限给指定玩家）
app.post('/api/admin/rooms/:roomId/transfer-host', requireAdminAuth, (req, res) => {
    try {
        const room = rooms.get(req.params.roomId);
        if (!room) return res.status(404).json({ success: false, message: '房间不存在' });
        const { playerId } = req.body || {};
        if (!playerId) return res.status(400).json({ success: false, message: '缺少 playerId' });
        const newHost = room.players.get(playerId);
        if (!newHost) return res.status(404).json({ success: false, message: '房间内未找到该玩家' });
        // 清除旧房主标记
        for (const [, p] of room.players.entries()) {
            if (p.isHost && p.id !== playerId) p.isHost = false;
        }
        newHost.isHost = true;
        room.actualHost = newHost.socketId || room.actualHost;
        room.hostName = newHost.name;
        io.emit('admin-transfer-host', { roomId: room.id, newHostId: newHost.id, newHostName: newHost.name });
        appendAudit('admin', 'transfer-host', `房间 ${room.id} 房主转移给 ${newHost.name} (${newHost.id})`);
        broadcastRoomList();
        res.json({ success: true, message: `已将房主转移给 ${newHost.name}` });
    } catch (error) {
        console.error('[API] 转移房主失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 6) 修改房间人数上限
app.post('/api/admin/rooms/:roomId/change-max-players', requireAdminAuth, (req, res) => {
    try {
        const room = rooms.get(req.params.roomId);
        if (!room) return res.status(404).json({ success: false, message: '房间不存在' });
        const raw = req.body && req.body.maxPlayers;
        const max = parseInt(raw, 10);
        if (isNaN(max) || max < 1 || max > 99) {
            return res.status(400).json({ success: false, message: '人数上限需为 1~99 的整数' });
        }
        const old = room.maxPlayers;
        room.maxPlayers = max;
        // 通知房间内玩家与管理后台（若当前人数超过新上限，前端可选择提示，但服务器不强制踢人）
        io.emit('room-max-players-changed', { roomId: room.id, maxPlayers: max, oldMaxPlayers: old });
        appendAudit('admin', 'change-max-players', `房间 ${room.id} 人数上限从 ${old} 改为 ${max}`);
        broadcastRoomList();
        res.json({ success: true, message: `已将人数上限从 ${old} 改为 ${max}`, maxPlayers: max });
    } catch (error) {
        console.error('[API] 修改人数上限失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// ===== 玩家关卡进度 / 关卡权限管理（管理员） =====
// 查看某玩家的过关历史（单人已解锁关、已完成关；解密已完成关）
app.get('/api/admin/users/:userId/level-history', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const p = reportedProgress.get(userId) || { unlockedLevel: 1, completedLevels: [], puzzleCompletedLevels: [], lastReportedAt: null };
        res.json({
            success: true,
            userId: userId,
            unlockedLevel: p.unlockedLevel || 1,
            completedLevels: Array.isArray(p.completedLevels) ? p.completedLevels : [],
            puzzleCompletedLevels: Array.isArray(p.puzzleCompletedLevels) ? p.puzzleCompletedLevels : [],
            lastReportedAt: p.lastReportedAt || null,
            maxSingle: 80,
            maxPuzzle: 60
        });
    } catch (error) {
        console.error('[API] 获取过关历史失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 查看某玩家的关卡权限设置（forbidden / forced）
app.get('/api/admin/users/:userId/level-permissions', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const perms = levelPermissions.get(userId) || {};
        res.json({ success: true, userId: userId, levels: perms });
    } catch (error) {
        console.error('[API] 获取关卡权限失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 设置某玩家某关卡的权限状态
// key 形如 "single:12" / "puzzle:5"；state: "forbidden"(禁止进入) | "forced"(强制解锁) | "normal"(恢复正常)
app.post('/api/admin/users/:userId/level-permission', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const { key, state } = req.body || {};
        if (!/^(single|puzzle):\d+$/.test(key || '')) {
            return res.status(400).json({ success: false, message: 'key 格式应为 single:N 或 puzzle:N' });
        }
        if (!['forbidden', 'forced', 'normal'].includes(state)) {
            return res.status(400).json({ success: false, message: 'state 必须为 forbidden / forced / normal' });
        }
        const perms = levelPermissions.get(userId) || {};
        if (state === 'normal') {
            delete perms[key];
        } else {
            perms[key] = state;
        }
        if (Object.keys(perms).length === 0) levelPermissions.delete(userId);
        else levelPermissions.set(userId, perms);
        // 通知该玩家客户端即时应用（按 clientId 过滤；非在线则下次拉取生效）
        io.emit('level-permission-update', { clientId: userId, levels: perms });
        appendAudit('admin', 'level-permission', `用户 ${userId} 的关卡 ${key} 设为 ${state}`);
        res.json({ success: true, message: `已更新 ${key} 为 ${state}`, levels: perms });
    } catch (error) {
        console.error('[API] 设置关卡权限失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// ===== 成就管理接口 =====

// 玩家拉取自己的成就数据（含管理员授予的部分）
app.get('/api/my-achievements', (req, res) => {
    try {
        const id = req.query.id;
        if (!id) return res.status(400).json({ success: false, message: '缺少 id' });
        const a = reportedAchievements.get(id) || { allLevelsCompleted: false, multiplayerWins: 0, trapHits: 0, chineseEmojiUsed: false, puzzleMaster: false };
        res.json({ success: true, achievements: a, revoked: getRevokedKeys(id) });
    } catch (error) {
        console.error('[API] 获取成就失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 管理员查看某玩家的成就
app.get('/api/admin/users/:userId/achievements', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const a = reportedAchievements.get(userId) || { allLevelsCompleted: false, multiplayerWins: 0, trapHits: 0, chineseEmojiUsed: false, puzzleMaster: false };
        res.json({
            success: true,
            achievements: {
                allLevelsCompleted: !!a.allLevelsCompleted,
                multiplayerWins: a.multiplayerWins || 0,
                trapHits: a.trapHits || 0,
                chineseEmojiUsed: !!a.chineseEmojiUsed,
                puzzleMaster: !!a.puzzleMaster
            },
            revoked: getRevokedKeys(userId)
        });
    } catch (error) {
        console.error('[API] 获取玩家成就失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 管理员授予/设置某玩家的某项成就
// key: "allLevelsCompleted" | "multiplayerWins" | "trapHits" | "chineseEmojiUsed"
// value: 对 bool 型传 true 即授予；对计数型传目标值（如 10/30）
app.post('/api/admin/users/:userId/achievement', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const { key, value } = req.body || {};
        const validKeys = ['allLevelsCompleted', 'multiplayerWins', 'trapHits', 'chineseEmojiUsed', 'puzzleMaster'];
        if (!validKeys.includes(key)) {
            return res.status(400).json({ success: false, message: 'key 必须为 allLevelsCompleted / multiplayerWins / trapHits / chineseEmojiUsed / puzzleMaster' });
        }
        const cur = reportedAchievements.get(userId) || { allLevelsCompleted: false, multiplayerWins: 0, trapHits: 0, chineseEmojiUsed: false, puzzleMaster: false };
        if (key === 'allLevelsCompleted' || key === 'chineseEmojiUsed' || key === 'puzzleMaster') {
            cur[key] = !!value;
        } else {
            const n = parseInt(value);
            if (isNaN(n) || n < 0) return res.status(400).json({ success: false, message: '数值型成就需要非负整数 value' });
            cur[key] = Math.max(cur[key] || 0, n);
        }
        reportedAchievements.set(userId, cur);
        // 通知该玩家客户端即时应用
        io.emit('achievement-update', { clientId: userId, achievements: cur });
        appendAudit('admin', 'grant-achievement', `向用户 ${userId} 授予/设置成就 ${key}`);
        res.json({ success: true, message: `已设置 ${key}`, achievements: cur });
    } catch (error) {
        console.error('[API] 设置玩家成就失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 管理员删除（撤销）某玩家的某项成就
app.delete('/api/admin/users/:userId/achievement', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const { key } = req.body || {};
        const validKeys = ['allLevelsCompleted', 'multiplayerWins', 'trapHits', 'chineseEmojiUsed', 'puzzleMaster'];
        if (!validKeys.includes(key)) {
            return res.status(400).json({ success: false, message: 'key 必须为 allLevelsCompleted / multiplayerWins / trapHits / chineseEmojiUsed / puzzleMaster' });
        }
        const cur = reportedAchievements.get(userId) || { allLevelsCompleted: false, multiplayerWins: 0, trapHits: 0, chineseEmojiUsed: false, puzzleMaster: false };
        // 重置为初始值
        if (key === 'allLevelsCompleted' || key === 'chineseEmojiUsed' || key === 'puzzleMaster') cur[key] = false;
        else cur[key] = 0;
        reportedAchievements.set(userId, cur);
        // 标记撤销，避免客户端重新上报后“复活”
        const revoked = revokedAchievements.get(userId) || new Set();
        revoked.add(key);
        revokedAchievements.set(userId, revoked);
        io.emit('achievement-update', { clientId: userId, achievements: cur, revoked: Array.from(revoked) });
        appendAudit('admin', 'revoke-achievement', `撤销用户 ${userId} 的成就 ${key}`);
        res.json({ success: true, message: `已删除 ${key}`, achievements: cur, revoked: Array.from(revoked) });
    } catch (error) {
        console.error('[API] 删除玩家成就失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// ===== 管理员：将某玩家单人关卡 + 解密关卡全部标记为通关，并授予对应成就 =====
// 同时清除这两个成就可能被管理员撤销的标记，确保“全部通关”结果能保留
app.post('/api/admin/users/:userId/complete-all', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        if (!userId) return res.status(400).json({ success: false, message: '缺少 userId' });

        // 单人关卡 1..MAX_SINGLE_LEVEL 全部完成
        const completedLevels = [];
        for (let i = 1; i <= MAX_SINGLE_LEVEL; i++) completedLevels.push(i);
        // 解密关卡 1..MAX_PUZZLE_LEVEL 全部完成
        const puzzleCompletedLevels = [];
        for (let i = 1; i <= MAX_PUZZLE_LEVEL; i++) puzzleCompletedLevels.push(i);

        mergeProgress(userId, { unlockedLevel: MAX_SINGLE_LEVEL, completedLevels, puzzleCompletedLevels });

        // 授予成就：迷宫大师（全部单人通关）+ 解密高手（全部解密通关）
        const cur = reportedAchievements.get(userId) || { allLevelsCompleted: false, multiplayerWins: 0, trapHits: 0, chineseEmojiUsed: false, puzzleMaster: false };
        cur.allLevelsCompleted = true;
        cur.puzzleMaster = true;
        reportedAchievements.set(userId, cur);

        // 解除这两个成就的“撤销”状态，避免玩家下次上报进度时被自动重置
        const revoked = revokedAchievements.get(userId);
        if (revoked) {
            revoked.delete('allLevelsCompleted');
            revoked.delete('puzzleMaster');
            if (revoked.size === 0) revokedAchievements.delete(userId);
            else revokedAchievements.set(userId, revoked);
        }

        io.emit('achievement-update', { clientId: userId, achievements: cur });
        // 实时推送最新进度（已完成关卡 / 解密关卡 / 解锁关），让在线玩家的解密选关界面立即更新
        io.emit('progress-update', {
            clientId: userId,
            unlockedLevel: MAX_SINGLE_LEVEL,
            completedLevels: completedLevels,
            puzzleCompletedLevels: puzzleCompletedLevels
        });
        console.log(`[Admin] 已将 ${userId} 单人 / 解密全部通关，并授予 迷宫大师 + 解密高手`);
        appendAudit('admin', 'complete-all', `将 ${userId} 单人/解密全部通关`);
        res.json({ success: true, message: `已将 ${userId} 单人、解密全部通关`, achievements: cur });
    } catch (error) {
        console.error('[API] 全部通关失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 所有玩家到达终点 → 删除房间（由房主客户端在检测到全员到达时调用）
app.post('/api/rooms/:roomId/complete', (req, res) => {
    try {
        const roomId = req.params.roomId;
        const room = rooms.get(roomId);

        if (!room) {
            return res.status(404).json({ success: false, message: '房间不存在' });
        }

        const playerCount = room.players.size;

        // 通知所有客户端：该房间全员已到达终点（携带 roomId，客户端按自己当前房间号过滤，避免误伤其他房间）
        io.emit('room-completed', {
            roomId: roomId,
            message: '所有玩家都已到达终点，房间已关闭。'
        });

        // 同步清理全局 players 映射
        for (const p of room.players.values()) {
            if (p.socketId) players.delete(p.socketId);
            players.delete(p.id);
        }

        rooms.delete(roomId);
        totalRoomsCleaned++;
        broadcastRoomList();

        console.log(`[房间完成] 房间 ${roomId} (${room.name}) 因所有玩家到达终点而被删除，共 ${playerCount} 名玩家。`);
        res.json({ success: true, message: `房间已因全员到达终点而关闭`, players: playerCount });

    } catch (error) {
        console.error('[API] 房间完成处理失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});



function handleDisconnect(socketId) {
    console.log(`[Server] 用户断开连接: ${socketId}`);

    // 0. 清理在线玩家表（按 socketId 反查）
    for (const [pid, p] of onlinePlayers) {
        if (p && p.socketId === socketId) {
            onlinePlayers.delete(pid);
            onlineSockets.delete(pid);
            console.log(`[Online] 玩家 ${pid} 因断开连接下线，当前在线 ${onlinePlayers.size} 人`);
        }
    }

    // 1. 优先在全局 'players' Map 中查找玩家（socketId 为 key）
    let leavingPlayer = players.get(socketId);

    // 2. 兜底：遍历所有房间，按 player.socketId 匹配（处理 REST 建房 + socket 补全后 key 不一致的情况）
    if (!leavingPlayer) {
        for (const room of rooms.values()) {
            for (const p of room.players.values()) {
                if (p.socketId === socketId) {
                    leavingPlayer = p;
                    leavingPlayer.roomId = room.id;
                    break;
                }
            }
            if (leavingPlayer) break;
        }
    }

    // 3. 如果玩家不存在（例如是被踢出后断开），直接返回
    if (!leavingPlayer) {
        console.log(`[Server] 找不到玩家 ${socketId}，可能是已经被移除。`);
        players.delete(socketId); // 清理一下以防万一
        return;
    }

    const room = rooms.get(leavingPlayer.roomId);
    if (!room) {
        console.log(`[Server] 玩家 ${leavingPlayer.name} 的房间 ${leavingPlayer.roomId} 已不存在。`);
        players.delete(socketId);
        if (leavingPlayer.socketId) players.delete(leavingPlayer.socketId);
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


    // 6. 最后，从全局 'players' Map 中彻底移除该玩家（用 socketId 和原始 key 都试一次）
    players.delete(socketId);
    if (leavingPlayer.socketId && leavingPlayer.socketId !== socketId) {
        players.delete(leavingPlayer.socketId);
    }
    // 同步清理在线玩家映射（供远程控制精准投递）
    if (leavingPlayer.id) onlineSockets.delete(leavingPlayer.id);
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

// ===== 房间自动清理（升级版）=====
// 清理策略集中配置，支持环境变量覆盖（单位：秒），便于不同部署环境调整
const ROOM_CLEANUP_CONFIG = {
    checkInterval: (parseInt(process.env.CLEANUP_CHECK_INTERVAL, 10) || 30) * 1000,          // 检查周期，默认 30s
    emptyIdleTime: (parseInt(process.env.CLEANUP_EMPTY_IDLE, 10) || 15) * 1000,              // 空房间空闲上限，默认 15s（人走即清，无需久等）
    maxLifetime:   (parseInt(process.env.CLEANUP_MAX_LIFETIME, 10) || 24 * 60 * 60) * 1000,  // 房间最大存活时间，默认 24h
    minRoomAge:    (parseInt(process.env.CLEANUP_MIN_AGE, 10) || 5) * 1000,                   // 房间最小存活时间，防止刚创建瞬间被误删，默认 5s
};

let totalRoomsCleaned = 0; // 累计清理房间数，便于监控

// 移除房间内「socket 已断开」的僵尸玩家
// 作用：兜底处理异常断线（未触发 handleDisconnect）导致 room.players 残留死连接、房间永不空的情况
function purgeZombiePlayers(room) {
    let purged = 0;
    for (const [pid, p] of room.players.entries()) {
        // 对 REST 建房、socketId 仍为 null 的房主，直接视为可清（它还没建立有效连接）
        if (!p.socketId) {
            room.players.delete(pid);
            players.delete(pid);
            purged++;
            continue;
        }
        const sock = io.sockets.sockets.get(p.socketId);
        // socket 对象不存在，或已断开，或 ID 不匹配当前连接 → 视为僵尸
        if (!sock || sock.connected === false || sock.id !== p.socketId) {
            room.players.delete(pid);
            players.delete(p.socketId); // 同步清理全局 players 映射
            players.delete(pid);
            purged++;
        }
    }
    return purged;
}

// 主清理定时器
setInterval(() => {
    const now = Date.now();
    const cfg = ROOM_CLEANUP_CONFIG;
    let cleanedThisRound = 0;
    let purgedTotal = 0;

    for (const [roomId, room] of rooms.entries()) {
        // 0) 房间太新则不处理，避免刚创建瞬间被误删
        const age = now - (room.createdAt || now);
        if (age < cfg.minRoomAge) continue;

        // 1) 先清理房间内的僵尸玩家（含未建立连接的 null socketId 房主）
        const purged = purgeZombiePlayers(room);
        if (purged > 0) {
            purgedTotal += purged;
            console.log(`[自动清理] 房间 ${roomId} (${room.name}) 移除 ${purged} 个僵尸玩家，剩余 ${room.players.size}`);
        }

        const lastAct = room.lastActivity || room.createdAt || now;
        const idle = now - lastAct;
        const isEmpty = room.players.size === 0;

        // 2) 删除条件：
        //    a) 空房间且空闲超过阈值（人走即清，默认 15s）
        //    b) 超过最大存活时间（即便仍有活人，防止房间无限堆积）
        const idleTooLong = isEmpty && idle > cfg.emptyIdleTime;
        const tooOld = age > cfg.maxLifetime;

        if (idleTooLong || tooOld) {
            const reason = tooOld ? '超过最大存活时间' : '空房间空闲超时';
            console.log(`[自动清理] 删除房间 ${roomId} (${room.name})，原因: ${reason}（存活 ${Math.round(age / 60000)} 分钟，空闲 ${Math.round(idle / 60000)} 分钟）`);

            // 仅当房间还有活人时才发通知，避免给空房间发无意义消息
            if (room.players.size > 0) {
                io.to(roomId).emit('room-kicked', { message: '房间因长时间未活动被系统关闭。' });
                for (const p of room.players.values()) {
                    players.delete(p.socketId);
                    players.delete(p.id);
                }
            }
            rooms.delete(roomId);
            cleanedThisRound++;
            totalRoomsCleaned++;
        }
    }

    // 3) 仅在有变化时才广播，减少无谓的房间列表刷新
    if (cleanedThisRound > 0 || purgedTotal > 0) {
        broadcastRoomList();
        console.log(`[自动清理] 本轮删除 ${cleanedThisRound} 个房间（累计 ${totalRoomsCleaned}），移除僵尸 ${purgedTotal} 个，当前剩余 ${rooms.size} 个`);
    }
}, ROOM_CLEANUP_CONFIG.checkInterval);


// 在服务器启动时初始化管理员密码
console.log('🚀 正在初始化服务器...');
initializeAdminPassword();
initializeSuperAdminPassword();
loadAdminState();

const PORT = process.env.PORT || 234;
server.listen(PORT, () => {
    console.log(`\n✅ 服务器运行在 http://localhost:${PORT}`);
    console.log(`📊 服务器状态: http://localhost:${PORT}/api/server-status`);
    console.log(`🏠 房间列表: http://localhost:${PORT}/api/rooms`);
    console.log(`👤 创建房间: http://localhost:${PORT}/api/create-room`);
    console.log(`Socket.IO 服务已启动\n`);
});
