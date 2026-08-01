
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');

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

// ===== MySQL 数据层（默认连接已写入；可用同名环境变量覆盖）=====
// 连接配置优先级：process.env.DATABASE_URL > 环境变量 DB_* > 下面写死的默认值
let pool = null;
let DB_AVAILABLE = false;

// 默认数据库连接（已写入 server；部署到 onrender 等平台时，若设置了同名环境变量则覆盖此处默认值）。
// 你已配好的 DB_HOST / DB_PORT 通过环境变量传入即可覆盖下面两个默认值。
const DEFAULT_DB = {
    host: process.env.DB_HOST
    port: process.env.DB_PORT
    user: process.env.DB_USER || 'maze_graysetsor',
    password: process.env.DB_PASSWORD || '4c613aeb828b9923c8b12b63b11373f2a31a3357',
    database: process.env.DB_NAME || 'maze_graysetsor',
};

function parseDbUrl(url) {
    // mysql://user:password@host:port/database
    const m = String(url).match(/^mysql:\/\/([^:]+):([^@]+)@([^:/]+)(?::(\d+))?\/([^?]+)/);
    if (!m) return null;
    return { host: m[3], port: m[4] ? parseInt(m[4], 10) : 3306, user: m[1], password: decodeURIComponent(m[2]), database: m[5] };
}
function buildDbConfig() {
    if (process.env.DATABASE_URL) {
        const p = parseDbUrl(process.env.DATABASE_URL);
        if (p) return p;
    }
    const { DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME } = process.env;
    if (DB_HOST && DB_USER && DB_PASSWORD && DB_NAME) {
        return { host: DB_HOST, port: DB_PORT ? parseInt(DB_PORT, 10) : 3306, user: DB_USER, password: DB_PASSWORD, database: DB_NAME };
    }
    // 没有通过环境变量传入时，使用写死的默认值（保证 onrender 部署无需逐一配置 env 也能连库）
    return { ...DEFAULT_DB };
}
function parseJsonCol(v) {
    if (v == null) return null;
    if (typeof v === 'object') return v;
    try { return JSON.parse(v); } catch (_) { return null; }
}
const DB_TABLES_SQL = [
    `CREATE TABLE IF NOT EXISTS accounts (
        id VARCHAR(64) PRIMARY KEY,
        name VARCHAR(64) NOT NULL,
        role ENUM('admin','superadmin') NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_by VARCHAR(64),
        created_at VARCHAR(32),
        last_ip VARCHAR(64),
        disabled TINYINT(1) DEFAULT 0,
        UNIQUE KEY uniq_role_name (role, name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS user_roles (
        user_id VARCHAR(128) PRIMARY KEY,
        role VARCHAR(32) NOT NULL,
        set_by VARCHAR(64),
        set_at VARCHAR(32)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS home_profiles (
        client_id VARCHAR(128) PRIMARY KEY,
        name VARCHAR(32),
        avatar VARCHAR(16),
        color VARCHAR(16),
        bio TEXT,
        disabled TINYINT(1) DEFAULT 0,
        admin_overridden TINYINT(1) DEFAULT 0,
        updated_at VARCHAR(32)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS user_settings (
        user_id VARCHAR(128) PRIMARY KEY,
        admin_json JSON,
        client_json JSON
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        ts VARCHAR(32) NOT NULL,
        actor VARCHAR(64),
        action VARCHAR(64),
        detail TEXT,
        ip VARCHAR(64),
        INDEX idx_audit_ts (ts)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS telemetry (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        ts VARCHAR(32) NOT NULL,
        client_id VARCHAR(128),
        name VARCHAR(64),
        event VARCHAR(64),
        detail TEXT,
        INDEX idx_telemetry_client (client_id),
        INDEX idx_telemetry_ts (ts)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
];
async function createTables() {
    for (const sql of DB_TABLES_SQL) {
        await pool.query(sql);
    }
}
async function initDatabase() {
    const cfg = buildDbConfig();
    if (!cfg) {
        console.log('ℹ️ 未配置数据库连接（DATABASE_URL 或 DB_* 环境变量），继续使用 JSON 文件存储。');
        return;
    }
    // 免费托管库（如 filess.io）常限制并发连接数，连接池上限设小，避免触发拒绝
    const poolOpts = Object.assign({}, cfg, { waitForConnections: true, connectionLimit: 2, connectTimeout: 10000 });
    for (let attempt = 1; attempt <= 3; attempt++) {
        try {
            pool = mysql.createPool(poolOpts);
            const conn = await pool.getConnection();
            await conn.ping();
            conn.release();
            await createTables();
            DB_AVAILABLE = true;
            console.log('🗄️ 已连接 MySQL 数据库，数据将持久化到数据库。');
            return;
        } catch (e) {
            console.error(`[DB] 第 ${attempt} 次连接 MySQL 失败:`, e.message);
            try { if (pool) await pool.end(); } catch (_) {}
            pool = null;
            DB_AVAILABLE = false;
            if (attempt < 3) { await new Promise(r => setTimeout(r, 1500)); }
        }
    }
    console.error('[DB] 多次连接失败，回退到 JSON 文件存储。');
}

const ADMIN_STATE_FILE = path.join(DATA_DIR, 'admin-state.json');
const AUDIT_FILE = path.join(DATA_DIR, 'admin-audit.log');
const TELEMETRY_FILE = path.join(DATA_DIR, 'telemetry.log');
const GLOBAL_FUNCTIONS_FILE = path.join(DATA_DIR, 'global-functions.json');

// ===== 全局功能控制（管理员统一开关，影响所有游戏客户端）=====
// 各开关含义：
//   export          —— 导出进度（单人/解密）功能
//   importClear     —— 导入通关数据功能
//   multiplayerChat —— 多人联机聊天功能
//   multiplayer     —— 多人联机功能
//   debugInfo       —— 调试信息按钮是否显示
//   f12DevConsole   —— F12 打开的开发者控制台是否显示
//   ctrlShiftCD     —— CTRL+SHIFT+C/D 是否可以打开控制台/开发者模式
const GLOBAL_FUNCTIONS_DEFAULT = {
    export: true,
    importClear: true,
    multiplayerChat: true,
    multiplayer: true,
    debugInfo: true,
    f12DevConsole: true,
    ctrlShiftCD: true
};
let globalFunctions = Object.assign({}, GLOBAL_FUNCTIONS_DEFAULT);

function loadGlobalFunctions() {
    try {
        if (fs.existsSync(GLOBAL_FUNCTIONS_FILE)) {
            const s = JSON.parse(fs.readFileSync(GLOBAL_FUNCTIONS_FILE, 'utf8'));
            if (s && typeof s === 'object') {
                globalFunctions = Object.assign({}, GLOBAL_FUNCTIONS_DEFAULT, s);
            }
        }
    } catch (e) { console.error('[Func] 加载全局功能控制失败:', e.message); }
}
function saveGlobalFunctions() {
    ensureDataDir();
    try { fs.writeFileSync(GLOBAL_FUNCTIONS_FILE, JSON.stringify(globalFunctions, null, 2)); }
    catch (e) { console.error('[Func] 保存全局功能控制失败:', e.message); }
}

// ===== 多账号系统（超级管理员可创建 admin / superadmin 账号，自定义名称+密码）=====
const ACCOUNTS_FILE = path.join(DATA_DIR, 'accounts.json');
// 账号结构：{ id, name, role:'admin'|'superadmin', passwordHash, createdBy, createdAt, lastIp, disabled }
let accounts = [];

async function loadAccounts() {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT id, name, role, password_hash, created_by, created_at, last_ip, disabled FROM accounts');
            accounts = rows.map(r => ({
                id: r.id, name: r.name, role: r.role,
                passwordHash: r.password_hash, createdBy: r.created_by,
                createdAt: r.created_at, lastIp: r.last_ip, disabled: !!r.disabled
            }));
            if (accounts.length === 0) await seedDefaultAccounts();
            return;
        } catch (e) { console.error('[Accounts] DB 加载失败，回退 JSON:', e.message); }
    }
    try {
        if (fs.existsSync(ACCOUNTS_FILE)) {
            const arr = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8'));
            if (Array.isArray(arr)) accounts = arr;
        }
    } catch (e) { console.error('[Accounts] 加载账号失败:', e.message); }
    if (accounts.length === 0) seedDefaultAccounts();
}
async function saveAccounts() {
    // 始终保留一份 JSON 存档（无 DB 时也是主存储）
    ensureDataDir();
    try { fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify(accounts, null, 2)); }
    catch (e) { console.error('[Accounts] 保存账号失败:', e.message); }
    if (DB_AVAILABLE && pool) {
        try {
            for (const a of accounts) {
                await pool.query(
                    'INSERT INTO accounts (id,name,role,password_hash,created_by,created_at,last_ip,disabled) VALUES (?,?,?,?,?,?,?,?) ' +
                    'ON DUPLICATE KEY UPDATE name=VALUES(name),role=VALUES(role),password_hash=VALUES(password_hash),created_by=VALUES(created_by),created_at=VALUES(created_at),last_ip=VALUES(last_ip),disabled=VALUES(disabled)',
                    [a.id, a.name, a.role, a.passwordHash, a.createdBy, a.createdAt, a.lastIp, a.disabled ? 1 : 0]
                );
            }
        } catch (e) { console.error('[Accounts] DB 保存失败:', e.message); }
    }
}
// 首次启动：用现有密码文件（或默认密码）初始化默认 admin / superadmin 账号
async function seedDefaultAccounts() {
    const adminPath = path.join(__dirname, 'admin-password.txt');
    if (!fs.existsSync(adminPath)) initializeAdminPassword();
    const superPath = SUPERADMIN_PASSWORD_PATH;
    if (!fs.existsSync(superPath)) initializeSuperAdminPassword();
    const adminHash = fs.readFileSync(adminPath, 'utf8').trim();
    const superHash = fs.readFileSync(superPath, 'utf8').trim();
    accounts = [
        { id: 'acc_admin', name: 'admin', role: 'admin', passwordHash: adminHash, createdBy: 'system', createdAt: new Date().toISOString(), lastIp: null, disabled: false },
        { id: 'acc_superadmin', name: 'superadmin', role: 'superadmin', passwordHash: superHash, createdBy: 'system', createdAt: new Date().toISOString(), lastIp: null, disabled: false }
    ];
    await saveAccounts();
    console.log('👤 已初始化默认账号: admin(角色 admin) / superadmin(角色 superadmin)');
}
// 按角色+名称+密码查找账号；name 为空时按密码匹配该角色下任一账号（兼容旧版仅密码登录）
async function findAccountByCredentials(role, name, password) {
    const cand = accounts.filter(a => a.role === role && !a.disabled);
    let matches = cand;
    if (name) matches = cand.filter(a => a.name === name);
    for (const a of matches) {
        if (await bcrypt.compare(String(password || ''), a.passwordHash)) return a;
    }
    return null;
}
function getAccountById(id) { return accounts.find(a => a.id === id) || null; }

// ===== 审计来源 IP 捕获 =====
// 通过鉴权中间件在每次 REST 请求时写入当前操作者来源 IP；appendAudit 记录到审计条目。
let currentReqIp = null;
function clientIp(req) {
    if (!req) return null;
    const xff = req.headers && req.headers['x-forwarded-for'];
    if (xff && typeof xff === 'string' && xff.length) return xff.split(',')[0].trim();
    if (req.socket && req.socket.remoteAddress) return req.socket.remoteAddress;
    if (req.connection && req.connection.remoteAddress) return req.connection.remoteAddress;
    return null;
}

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

// ===== 玩家角色（游戏内权限：user / admin / superadmin）=====
const USER_ROLES_FILE = path.join(DATA_DIR, 'user-roles.json');
async function loadUserRoles() {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT user_id, role, set_by, set_at FROM user_roles');
            userRoles = new Map();
            rows.forEach(r => {
                if (r && r.user_id && ['user', 'admin', 'superadmin'].includes(r.role)) {
                    userRoles.set(r.user_id, { role: r.role, setBy: r.set_by || 'admin', setAt: r.set_at || new Date().toISOString() });
                }
            });
            return;
        } catch (e) { console.error('[Roles] DB 加载失败，回退 JSON:', e.message); }
    }
    try {
        if (fs.existsSync(USER_ROLES_FILE)) {
            const arr = JSON.parse(fs.readFileSync(USER_ROLES_FILE, 'utf8'));
            if (Array.isArray(arr)) arr.forEach(r => {
                if (r && r.userId && ['user', 'admin', 'superadmin'].includes(r.role)) {
                    userRoles.set(r.userId, { role: r.role, setBy: r.setBy || 'admin', setAt: r.setAt || new Date().toISOString() });
                }
            });
        }
    } catch (e) { console.error('[Roles] 加载玩家角色失败:', e.message); }
}
async function saveUserRoles() {
    ensureDataDir();
    try {
        const arr = [];
        for (const [userId, v] of userRoles) arr.push({ userId, role: v.role, setBy: v.setBy, setAt: v.setAt });
        fs.writeFileSync(USER_ROLES_FILE, JSON.stringify(arr, null, 2));
    } catch (e) { console.error('[Roles] 保存玩家角色失败:', e.message); }
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query('DELETE FROM user_roles');
            for (const [userId, v] of userRoles) {
                await pool.query('INSERT INTO user_roles (user_id, role, set_by, set_at) VALUES (?,?,?,?)', [userId, v.role, v.setBy || 'admin', v.setAt || new Date().toISOString()]);
            }
        } catch (e) { console.error('[Roles] DB 保存失败:', e.message); }
    }
}
function getUserRole(userId) {
    const v = userRoles.get(userId);
    return v ? v.role : 'user';
}

// ===== 玩家 UI 设置（客户端上传 + 管理员远程查看/修改）=====
const USER_SETTINGS_FILE = path.join(DATA_DIR, 'user-settings.json');
// 一次定义“已知设置字段”，用于清洗与默认值
const DEFAULT_UI_SETTINGS = {
    showControls: true,
    controlsPosition: 'bottom-left',
    controlsSize: 100,
    controlsOpacity: 60,
    showGameInfo: true,
    showLevelInfo: true,
    showTimeInfo: true,
    showMoveInfo: true,
    showKeyInfo: true,
    showRoomInfo: true,
    customX: null,
    customY: null,
    showPlayerList: true,
    musicEnabled: true,
    musicVolume: 50,
    musicSelected: 'game-music-1',
    customMusic: [],
    joystickEnabled: false,
    joystickSensitivity: 5,
    joystickDeadZone: 15,
    joystickRadius: 70,
    joystickPosition: 'bottom-right'
};
// 结构：userId -> { admin: <obj|null>, client: <obj|null> }
// admin 为管理员远程设置的覆盖项；client 为客户端最近一次上报的设置。
// 生效值 = 默认值 <- client <- admin（admin 优先）
let userSettings = new Map();
function sanitizeUISettings(obj) {
    if (!obj || typeof obj !== 'object') return null;
    const out = {};
    for (const k of Object.keys(DEFAULT_UI_SETTINGS)) {
        if (k === 'customMusic') {
            out.customMusic = Array.isArray(obj.customMusic)
                ? obj.customMusic.filter(m => m && typeof m === 'object')
                    .map(m => ({ id: m.id, name: String(m.name || ''), url: String(m.url || '') }))
                    .slice(0, 50)
                : [];
        } else {
            const v = obj[k];
            if (v === undefined) continue;
            out[k] = v;
        }
    }
    return out;
}
function getEffectiveUISettings(userId) {
    const rec = userSettings.get(userId) || {};
    const base = Object.assign({}, DEFAULT_UI_SETTINGS);
    if (rec.client && typeof rec.client === 'object') Object.assign(base, rec.client);
    if (rec.admin && typeof rec.admin === 'object') Object.assign(base, rec.admin);
    return base;
}
function setClientUISettings(userId, obj) {
    const rec = userSettings.get(userId) || { admin: null, client: null };
    const clean = sanitizeUISettings(obj);
    if (clean) rec.client = clean;
    userSettings.set(userId, rec);
    saveUserSettings();
}
function setAdminUISettings(userId, obj) {
    const rec = userSettings.get(userId) || { admin: null, client: null };
    rec.admin = (obj === null) ? null : (sanitizeUISettings(obj) || {});
    userSettings.set(userId, rec);
    saveUserSettings();
}
async function loadUserSettings() {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT user_id, admin_json, client_json FROM user_settings');
            userSettings = new Map();
            rows.forEach(r => {
                if (r && r.user_id) {
                    userSettings.set(r.user_id, {
                        admin: parseJsonCol(r.admin_json),
                        client: parseJsonCol(r.client_json)
                    });
                }
            });
            return;
        } catch (e) { console.error('[Settings] DB 加载失败，回退 JSON:', e.message); }
    }
    try {
        if (fs.existsSync(USER_SETTINGS_FILE)) {
            const arr = JSON.parse(fs.readFileSync(USER_SETTINGS_FILE, 'utf8'));
            if (Array.isArray(arr)) arr.forEach(r => {
                if (r && r.userId) {
                    userSettings.set(r.userId, { admin: r.admin || null, client: r.client || null });
                }
            });
        }
    } catch (e) { console.error('[Settings] 加载用户设置失败:', e.message); }
}
async function saveUserSettings() {
    ensureDataDir();
    try {
        const arr = [];
        for (const [userId, v] of userSettings) arr.push({ userId, admin: v.admin || null, client: v.client || null });
        fs.writeFileSync(USER_SETTINGS_FILE, JSON.stringify(arr, null, 2));
    } catch (e) { console.error('[Settings] 保存用户设置失败:', e.message); }
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query('DELETE FROM user_settings');
            for (const [userId, v] of userSettings) {
                await pool.query(
                    'INSERT INTO user_settings (user_id, admin_json, client_json) VALUES (?,?,?) ON DUPLICATE KEY UPDATE admin_json=VALUES(admin_json), client_json=VALUES(client_json)',
                    [userId, JSON.stringify(v.admin || null), JSON.stringify(v.client || null)]
                );
            }
        } catch (e) { console.error('[Settings] DB 保存失败:', e.message); }
    }
}
// 由请求头 Bearer 令牌判断操作者身份：superadmin / admin / null
function getOperatorRole(req) {
    const auth = (req.headers && req.headers.authorization) || '';
    const m = auth.match(/^Bearer\s+(.+)$/);
    if (!m) return null;
    try {
        const decoded = jwt.verify(m[1], JWT_SECRET);
        if (superAdminTokens.has(decoded.tokenId)) return 'superadmin';
        if (adminTokens.has(decoded.tokenId)) return 'admin';
    } catch (e) { /* 无效令牌 */ }
    return null;
}

// 审计日志：记录谁(actor)在什么时间做了什么(action)
function appendAudit(actor, action, detail, req) {
    const ip = (req && clientIp(req)) || currentReqIp || null;
    const entry = { ts: new Date().toISOString(), actor, action, detail: detail || '', ip };
    ensureDataDir();
    try { fs.appendFileSync(AUDIT_FILE, JSON.stringify(entry) + '\n'); }
    catch (e) { console.error('[审计] 写入失败:', e.message); }
    console.log('[审计]', entry.ts, actor, action, detail || '', ip ? ('(IP:' + ip + ')') : '');
    if (DB_AVAILABLE && pool) {
        pool.query('INSERT INTO audit_logs (ts, actor, action, detail, ip) VALUES (?,?,?,?,?)', [entry.ts, actor, action, entry.detail, ip])
            .catch(e => console.error('[审计] DB 写入失败:', e.message));
    }
}
async function readAudit(limit) {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT ts, actor, action, detail, ip FROM audit_logs ORDER BY id DESC LIMIT ?', [limit ? parseInt(limit, 10) : 1000000]);
            let arr = rows.map(r => ({ ts: r.ts, actor: r.actor, action: r.action, detail: r.detail, ip: r.ip }));
            return arr.reverse(); // 兼容原语义：旧 → 新
        } catch (e) { console.error('[审计] DB 读取失败，回退 JSON:', e.message); }
    }
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
    try { fs.appendFileSync(TELEMETRY_FILE, JSON.stringify(entry) + '\n'); }
    catch (e) { console.error('[遥测] 写入失败:', e.message); return false; }
    if (DB_AVAILABLE && pool) {
        pool.query('INSERT INTO telemetry (ts, client_id, name, event, detail) VALUES (?,?,?,?,?)', [entry.ts, entry.clientId, entry.name, entry.event, entry.detail])
            .catch(e => console.error('[遥测] DB 写入失败:', e.message));
    }
    return true;
}
async function readTelemetry(limit, clientId) {
    if (DB_AVAILABLE && pool) {
        try {
            let sql = 'SELECT id, ts, client_id, name, event, detail FROM telemetry';
            const params = [];
            if (clientId) { sql += ' WHERE client_id = ?'; params.push(clientId); }
            sql += ' ORDER BY id DESC LIMIT ?';
            params.push(limit ? parseInt(limit, 10) : 1000000);
            const [rows] = await pool.query(sql, params);
            let arr = rows.map(r => ({ id: r.id, ts: r.ts, clientId: r.client_id, name: r.name, event: r.event, detail: r.detail }));
            return arr.reverse();
        } catch (e) { console.error('[遥测] DB 读取失败，回退 JSON:', e.message); }
    }
    try {
        if (!fs.existsSync(TELEMETRY_FILE)) return [];
        const lines = fs.readFileSync(TELEMETRY_FILE, 'utf8').trim().split('\n').filter(Boolean);
        let arr = lines.map(l => { try { return JSON.parse(l); } catch (e) { return null; } }).filter(Boolean);
        if (clientId) arr = arr.filter(e => e.clientId === clientId);
        return limit ? arr.slice(-limit) : arr;
    } catch (e) { return []; }
}

// 超级管理员遥测管理：返回带 id 的记录（DB 模式为自增主键，JSON 回退模式用物理行号）。前端统一用 id 字段。
async function readTelemetryLines(clientId, limit) {
    if (DB_AVAILABLE && pool) {
        try {
            let sql = 'SELECT id, ts, client_id, name, event, detail FROM telemetry';
            const params = [];
            if (clientId) { sql += ' WHERE client_id = ?'; params.push(clientId); }
            sql += ' ORDER BY id DESC LIMIT ?';
            params.push(limit ? parseInt(limit, 10) : 1000000);
            const [rows] = await pool.query(sql, params);
            let arr = rows.map(r => ({ id: r.id, ts: r.ts, clientId: r.client_id, name: r.name, event: r.event, detail: r.detail }));
            return arr.reverse();
        } catch (e) { console.error('[遥测] DB 读取失败，回退 JSON:', e.message); }
    }
    try {
        if (!fs.existsSync(TELEMETRY_FILE)) return [];
        const rawLines = fs.readFileSync(TELEMETRY_FILE, 'utf8').split('\n');
        const arr = [];
        rawLines.forEach((l, idx) => {
            const s = l.trim();
            if (!s) return;
            try { const o = JSON.parse(s); o.id = idx; o.__line = idx; arr.push(o); } catch (e) {}
        });
        const filtered = clientId ? arr.filter(e => e.clientId === clientId) : arr;
        return limit ? filtered.slice(-limit) : filtered;
    } catch (e) { return []; }
}
async function deleteTelemetryLine(idOrLine) {
    if (DB_AVAILABLE && pool) {
        try {
            const [r] = await pool.query('DELETE FROM telemetry WHERE id = ?', [parseInt(idOrLine, 10)]);
            return !!(r && r.affectedRows > 0);
        } catch (e) { console.error('[遥测] DB 删除失败:', e.message); return false; }
    }
    try {
        const rawLines = fs.readFileSync(TELEMETRY_FILE, 'utf8').split('\n');
        const idx = Number(idOrLine);
        if (!Number.isInteger(idx) || idx < 0 || idx >= rawLines.length) return false;
        if (!rawLines[idx].trim()) return false;
        rawLines.splice(idx, 1);
        fs.writeFileSync(TELEMETRY_FILE, rawLines.join('\n'));
        return true;
    } catch (e) { return false; }
}
async function updateTelemetryLine(idOrLine, patch) {
    if (DB_AVAILABLE && pool) {
        try {
            const id = parseInt(idOrLine, 10);
            const fields = [];
            const params = [];
            if (patch.clientId !== undefined) { fields.push('client_id = ?'); params.push(String(patch.clientId).slice(0, 60)); }
            if (patch.name !== undefined) { fields.push('name = ?'); params.push(String(patch.name).slice(0, 30)); }
            if (patch.event !== undefined) { fields.push('event = ?'); params.push(String(patch.event).slice(0, 60)); }
            if (patch.detail !== undefined) { fields.push('detail = ?'); params.push(String(patch.detail).slice(0, 500)); }
            if (fields.length === 0) return true;
            params.push(id);
            const [r] = await pool.query('UPDATE telemetry SET ' + fields.join(', ') + ' WHERE id = ?', params);
            return !!(r && r.affectedRows > 0);
        } catch (e) { console.error('[遥测] DB 更新失败:', e.message); return false; }
    }
    try {
        const rawLines = fs.readFileSync(TELEMETRY_FILE, 'utf8').split('\n');
        const idx = Number(idOrLine);
        if (!Number.isInteger(idx) || idx < 0 || idx >= rawLines.length) return false;
        const s = rawLines[idx].trim();
        if (!s) return false;
        const o = JSON.parse(s);
        if (patch.clientId !== undefined) o.clientId = String(patch.clientId).slice(0, 60);
        if (patch.name !== undefined) o.name = String(patch.name).slice(0, 30);
        if (patch.event !== undefined) o.event = String(patch.event).slice(0, 60);
        if (patch.detail !== undefined) o.detail = String(patch.detail).slice(0, 500);
        rawLines[idx] = JSON.stringify(o);
        fs.writeFileSync(TELEMETRY_FILE, rawLines.join('\n'));
        return true;
    } catch (e) { return false; }
}
function stripTelemetryLine(o) { const { __line, ...rest } = o; return rest; }
function csvQuoteCell(v) { const s = (v == null) ? '' : String(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }

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

// 判断某 IP 是否已被管理员封禁
function isIPBanned(ip) {
    if (!ip) return false;
    return bannedIPs.has(String(ip));
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
const bannedIPs = new Map();     // ip -> { reason, bannedAt }，管理员按 IP 封禁（所有功能禁用 + 客户端强制全屏弹窗）
// 玩家角色（游戏内权限）：userId -> { role:'user'|'admin'|'superadmin', setBy, setAt }
let userRoles = new Map();
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

// 生成管理员令牌（携带账号 id/name，便于审计记录操作者）
function generateAdminToken(accountId, name) {
    const tokenId = 'admin_' + Date.now();
    const token = jwt.sign({ tokenId, role: 'admin', accountId: accountId || null, name: name || null }, JWT_SECRET, { expiresIn: '24h' });
    adminTokens.set(tokenId, { role: 'admin', accountId: accountId || null, name: name || null });
    return token;
}

// 检查管理员权限中间件（管理员 或 超级管理员 令牌均可，超级管理员为管理员的上位身份）
function requireAdminAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: '需要管理员身份验证' });
    }
    currentReqIp = clientIp(req);
    const token = authHeader.substring(7);
    if (verifyAdminToken(token) || verifySuperAdminToken(token)) {
        return next();
    }

    return res.status(403).json({ success: false, message: '无效的管理员令牌' });
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
function generateSuperAdminToken(accountId, name) {
    const tokenId = 'superadmin_' + Date.now();
    const token = jwt.sign({ tokenId, role: 'superadmin', accountId: accountId || null, name: name || null }, JWT_SECRET, { expiresIn: '24h' });
    superAdminTokens.set(tokenId, { role: 'superadmin', accountId: accountId || null, name: name || null });
    return token;
}
function requireSuperAdminAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: '需要超级管理员身份验证' });
    }
    currentReqIp = clientIp(req);
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
        const { password, name } = req.body || {};
        
        console.log('收到管理员登录请求', name ? ('(账号: ' + name + ')') : '(共享密码)');
        
        if (!password) {
            return res.status(400).json({ success: false, message: '密码不能为空' });
        }

        // 管理员账号被超级管理员禁用时拒绝登录
        if (adminDisabled) {
            console.log('管理员登录被拒：账号已被超级管理员禁用');
            return res.status(403).json({ success: false, message: '管理员账号已被超级管理员禁用' });
        }

        const acc = await findAccountByCredentials('admin', name, password);
        if (acc) {
            const token = generateAdminToken(acc.id, acc.name);
            appendAudit('admin', 'login', '管理员登录' + (name ? ('（账号 ' + name + '）') : '（共享密码）'), req);
            console.log('管理员登录成功', name || '(共享)');
            return res.json({ success: true, message: '登录成功', token, name: acc.name });
        } else {
            console.log('管理员密码验证失败');
            return res.status(401).json({ success: false, message: '密码或账号名称错误' });
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
        const { password, name } = req.body || {};
        if (!password) return res.status(400).json({ success: false, message: '密码不能为空' });
        const acc = await findAccountByCredentials('superadmin', name, password);
        if (acc) {
            const token = generateSuperAdminToken(acc.id, acc.name);
            appendAudit('superadmin', 'login', '超级管理员登录' + (name ? ('（账号 ' + name + '）') : '（共享密码）'), req);
            return res.json({ success: true, token, name: acc.name });
        }
        return res.status(401).json({ success: false, message: '密码或账号名称错误' });
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
        // 同步更新默认账号（acc_admin / acc_superadmin）的密码哈希，保持一致
        const defId = target === 'admin' ? 'acc_admin' : 'acc_superadmin';
        const defAcc = getAccountById(defId);
        if (defAcc) { defAcc.passwordHash = bcrypt.hashSync(String(newPassword), 10); saveAccounts(); }
        if (target === 'admin') {
            adminTokens.clear(); // 改密后使旧管理员令牌失效
            appendAudit('superadmin', 'change-admin-password', '修改了管理员密码', req);
        } else {
            superAdminTokens.clear();
            appendAudit('superadmin', 'change-superadmin-password', '修改了超级管理员密码', req);
        }
        res.json({ success: true, message: `已更新 ${target} 密码` });
    } catch (e) {
        console.error('[SuperAdmin] 改密失败:', e);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 超级管理员创建 admin / superadmin 账号（自定义名称 + 密码）
app.post('/api/superadmin/create-account', requireSuperAdminAuth, async (req, res) => {
    try {
        const { name, password, role } = req.body || {};
        if (role !== 'admin' && role !== 'superadmin') {
            return res.status(400).json({ success: false, message: 'role 必须为 admin 或 superadmin' });
        }
        if (!name || String(name).trim().length < 1) {
            return res.status(400).json({ success: false, message: '账号名称不能为空' });
        }
        if (!password || String(password).length < 1) {
            return res.status(400).json({ success: false, message: '密码不能为空' });
        }
        const nm = String(name).trim();
        // 同角色下名称唯一（跨角色允许同名，因登录时已按角色区分）
        if (accounts.some(a => a.role === role && a.name === nm)) {
            return res.status(409).json({ success: false, message: `已存在同名 ${role} 账号: ${nm}` });
        }
        // 操作者信息（来自令牌）
        let opName = 'superadmin';
        try {
            const decoded = jwt.verify(req.headers.authorization.substring(7), JWT_SECRET);
            if (decoded && decoded.name) opName = decoded.name;
        } catch (_) {}
        const acc = {
            id: 'acc_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
            name: nm,
            role,
            passwordHash: bcrypt.hashSync(String(password), 10),
            createdBy: opName,
            createdAt: new Date().toISOString(),
            lastIp: clientIp(req),
            disabled: false
        };
        accounts.push(acc);
        saveAccounts();
        appendAudit('superadmin', 'create-account', `创建了 ${role} 账号「${nm}」（创建者 ${opName}）`, req);
        console.log(`[Accounts] 超级管理员 ${opName} 创建了 ${role} 账号: ${nm}`);
        res.json({ success: true, message: `已创建 ${role} 账号 ${nm}`, account: { id: acc.id, name: acc.name, role: acc.role } });
    } catch (e) {
        console.error('[SuperAdmin] 创建账号失败:', e);
        res.status(500).json({ success: false, message: '创建失败' });
    }
});

// 账号列表（超级管理员查看）
app.get('/api/superadmin/accounts', requireSuperAdminAuth, (req, res) => {
    const list = accounts.map(a => ({
        id: a.id, name: a.name, role: a.role,
        createdBy: a.createdBy, createdAt: a.createdAt, lastIp: a.lastIp, disabled: !!a.disabled
    }));
    res.json({ success: true, accounts: list });
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

// ===== 个人主页（多人联机可查看对方名称/头像/简介）=====
const HOME_PROFILES_FILE = path.join(DATA_DIR, 'home-profiles.json');
// 结构：{ name, avatar(emoji), color(hex), bio, disabled, adminOverridden }
let homeProfiles = new Map();

async function loadHomeProfiles() {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT client_id, name, avatar, color, bio, disabled, admin_overridden, updated_at FROM home_profiles');
            homeProfiles = new Map();
            rows.forEach(r => { if (r && r.client_id) homeProfiles.set(r.client_id, { name: r.name, avatar: r.avatar, color: r.color, bio: r.bio, disabled: !!r.disabled, adminOverridden: !!r.admin_overridden, updatedAt: r.updated_at }); });
            return;
        } catch (e) { console.error('[Home] DB 加载失败，回退 JSON:', e.message); }
    }
    try {
        if (fs.existsSync(HOME_PROFILES_FILE)) {
            const arr = JSON.parse(fs.readFileSync(HOME_PROFILES_FILE, 'utf8'));
            if (Array.isArray(arr)) arr.forEach(r => { if (r && r.clientId) homeProfiles.set(r.clientId, r); });
        }
    } catch (e) { console.error('[Home] 加载个人主页失败:', e.message); }
}
async function saveHomeProfiles() {
    ensureDataDir();
    try {
        const arr = [];
        for (const [clientId, p] of homeProfiles) arr.push(Object.assign({ clientId }, p));
        fs.writeFileSync(HOME_PROFILES_FILE, JSON.stringify(arr, null, 2));
    } catch (e) { console.error('[Home] 保存个人主页失败:', e.message); }
    if (DB_AVAILABLE && pool) {
        try {
            for (const [clientId, p] of homeProfiles) {
                await pool.query(
                    'INSERT INTO home_profiles (client_id, name, avatar, color, bio, disabled, admin_overridden, updated_at) VALUES (?,?,?,?,?,?,?,?) ' +
                    'ON DUPLICATE KEY UPDATE name=VALUES(name),avatar=VALUES(avatar),color=VALUES(color),bio=VALUES(bio),disabled=VALUES(disabled),admin_overridden=VALUES(admin_overridden),updated_at=VALUES(updated_at)',
                    [clientId, p.name || '', p.avatar || '🙂', p.color || '#4CAF50', p.bio || '', p.disabled ? 1 : 0, p.adminOverridden ? 1 : 0, p.updatedAt || new Date().toISOString()]
                );
            }
        } catch (e) { console.error('[Home] DB 保存失败:', e.message); }
    }
}
// 归一化并限制大小，防止滥用
function sanitizeHomeProfile(input) {
    const p = {};
    if (input && typeof input === 'object') {
        p.name = (typeof input.name === 'string' && input.name.trim()) ? input.name.trim().slice(0, 24) : '';
        // 头像：emoji 或单字符；不允许 HTML
        p.avatar = (typeof input.avatar === 'string' && input.avatar.trim()) ? input.avatar.trim().slice(0, 8) : '🙂';
        // 颜色：仅允许 #RRGGBB 或 #RGB
        const c = (typeof input.color === 'string') ? input.color.trim() : '';
        p.color = /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(c) ? c : '#4CAF50';
        // 简介：纯文本，长度限制（渲染时再转义，防止 XSS）
        p.bio = (typeof input.bio === 'string') ? input.bio.slice(0, 200) : '';
    }
    return p;
}

// 当前访问控制状态
app.get('/api/superadmin/state', requireSuperAdminAuth, (req, res) => {
    res.json({ success: true, adminDisabled, gameAccessDisabled });
});

// 审计日志
app.get('/api/superadmin/audit', requireSuperAdminAuth, async (req, res) => {
    const limit = parseInt(req.query.limit) || 200;
    res.json({ success: true, logs: await readAudit(limit) });
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
app.get('/api/admin/telemetry', requireAdminAuth, async (req, res) => {
    const limit = parseInt(req.query.limit) || 500;
    const clientId = req.query.clientId || '';
    res.json({ success: true, logs: await readTelemetry(limit, clientId || null) });
});

// 个人主页：公开读取（游戏内点击对方名称时拉取）
app.get('/api/profile/:clientId', (req, res) => {
    const p = homeProfiles.get(req.params.clientId);
    if (!p) return res.json({ success: true, profile: null });
    res.json({ success: true, profile: Object.assign({ clientId: req.params.clientId }, p) });
});

// 个人主页：管理员修改 / 禁用某玩家的主页
app.put('/api/admin/users/:userId/profile', requireAdminAuth, (req, res) => {
    try {
        const clientId = req.params.userId;
        const prev = homeProfiles.get(clientId) || {};
        const body = req.body || {};
        const merged = Object.assign({}, prev);
        // 仅当管理员显式提供了字段才覆盖，保留玩家原有的头像/颜色/简介/名称
        if (typeof body.avatar === 'string') merged.avatar = body.avatar.slice(0, 8);
        if (typeof body.color === 'string' && /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(body.color.trim())) merged.color = body.color.trim();
        if (typeof body.bio === 'string') merged.bio = body.bio.slice(0, 200);
        if (typeof body.name === 'string') merged.name = body.name.slice(0, 24);
        // 禁用 / 启用（管理员操作，标记覆盖）
        if (typeof body.disabled === 'boolean') {
            merged.disabled = body.disabled;
            merged.adminOverridden = true;
        }
        // 管理员修改了任意主页信息字段，同样标记为覆盖
        if (typeof body.avatar === 'string' || typeof body.color === 'string' || typeof body.bio === 'string' || typeof body.name === 'string') {
            merged.adminOverridden = true;
        }
        merged.updatedAt = new Date().toISOString();
        homeProfiles.set(clientId, merged);
        saveHomeProfiles();
        io.emit('player-profile', Object.assign({ clientId }, merged));
        appendAudit('admin', 'edit-profile', `修改/禁用玩家 ${clientId} 的个人主页${merged.disabled ? '（已禁用）' : ''}`, req);
        res.json({ success: true, profile: Object.assign({ clientId }, merged) });
    } catch (e) {
        console.error('[Admin] 修改主页失败:', e);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 遥测下载（管理员）：服务端直接返回文件并记审计（含来源 IP），供 superadmin 审计可见
app.get('/api/admin/telemetry/download', requireAdminAuth, async (req, res) => {
    try {
        const format = (req.query.format === 'json') ? 'json' : 'csv';
        const logs = await readTelemetry(0);
        let content, filename, mime;
        if (format === 'json') {
            const out = logs.map(e => { const { __line, ...rest } = e; return rest; });
            content = JSON.stringify(out, null, 2);
            mime = 'application/json';
            filename = 'telemetry.json';
        } else {
            const headers = ['ts', 'clientId', 'name', 'event', 'detail'];
            const esc = v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
            const rows = logs.map(e => headers.map(h => esc(e[h])).join(','));
            content = '﻿' + headers.join(',') + '\n' + rows.join('\n');
            mime = 'text/csv';
            filename = 'telemetry.csv';
        }
        appendAudit('admin', 'telemetry-download', `下载遥测数据（格式 ${format}，共 ${logs.length} 条）`, req);
        res.setHeader('Content-Type', mime + '; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.send(content);
    } catch (e) {
        console.error('[Admin] 遥测下载失败:', e);
        res.status(500).json({ success: false, message: '下载失败' });
    }
});

// 遥测管理（超级管理员专用）：列出（带物理行号）/ 删除 / 编辑 / 下载
app.get('/api/superadmin/telemetry', requireSuperAdminAuth, async (req, res) => {
    const limit = parseInt(req.query.limit) || 1000;
    const clientId = req.query.clientId || '';
    res.json({ success: true, logs: await readTelemetryLines(clientId || null, limit) });
});
app.delete('/api/superadmin/telemetry/:line', requireSuperAdminAuth, async (req, res) => {
    try {
        const ok = await deleteTelemetryLine(req.params.line);
        if (!ok) return res.status(404).json({ success: false, message: '记录不存在或已删除' });
        appendAudit('superadmin', 'telemetry-delete', `删除遥测记录 id=${req.params.line}`);
        res.json({ success: true, message: '已删除' });
    } catch (e) { res.status(500).json({ success: false, message: '删除失败' }); }
});
app.put('/api/superadmin/telemetry/:line', requireSuperAdminAuth, async (req, res) => {
    try {
        const ok = await updateTelemetryLine(req.params.line, req.body || {});
        if (!ok) return res.status(404).json({ success: false, message: '记录不存在或已删除' });
        appendAudit('superadmin', 'telemetry-edit', `编辑遥测记录 id=${req.params.line}`);
        res.json({ success: true, message: '已保存' });
    } catch (e) { res.status(500).json({ success: false, message: '保存失败' }); }
});
app.get('/api/superadmin/telemetry/download', requireSuperAdminAuth, async (req, res) => {
    try {
        const fmt = (req.query.format === 'json') ? 'json' : 'csv';
        const clientId = req.query.clientId || '';
        const logs = await readTelemetryLines(clientId || null, 0);
        let content, mime, ext;
        if (fmt === 'json') {
            content = JSON.stringify(logs.map(stripTelemetryLine), null, 2);
            mime = 'application/json'; ext = 'json';
        } else {
            const headers = ['ts', 'clientId', 'name', 'event', 'detail'];
            const rows = logs.map(e => headers.map(h => csvQuoteCell(e[h])).join(','));
            content = [headers.join(','), ...rows].join('\n');
            mime = 'text/csv'; ext = 'csv';
        }
        const fname = `telemetry_${new Date().toISOString().slice(0, 10)}.${ext}`;
        res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
        res.setHeader('Content-Type', mime + '; charset=utf-8');
        res.send('﻿' + content);
    } catch (e) { res.status(500).send('下载失败'); }
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
        const { id, name, coins, unlockedLevel, completedLevels, puzzleCompletedLevels, achievements, totalPlayTime, gameStats, gamestate, uiSettings } = req.body || {};
        if (!id) return res.json({ success: false, message: '缺少 id' });
        // 客户端上报的 UI 设置（供管理员后台查看/修改）
        if (uiSettings) setClientUISettings(id, uiSettings);
        const existing = onlinePlayers.get(id) || {};
        // 记录玩家上报的真实金币（供管理员查看）
        const rc = parseInt(coins);
        if (!isNaN(rc)) reportedCoins.set(id, Math.max(0, rc));
        // 记录玩家上报的关卡进度（供管理员查看过关历史）
        mergeProgress(id, { unlockedLevel, completedLevels, puzzleCompletedLevels });
        // 记录玩家上报的成就数据（供管理员查看）
        if (achievements) mergeAchievements(id, achievements);
        const ip = getClientIp(req);
        const role = getUserRole(id);
        onlinePlayers.set(id, {
            id: id,
            name: (name && String(name).trim()) || existing.name || '玩家',
            socketId: existing.socketId || null,   // 保留 socket 通道写入的连接标识
            roomId: existing.roomId || null,
            joinedAt: existing.joinedAt || Date.now(),
            ip: ip,
            role: role
        });
        onlineSockets.set(id, 'rest');
        // 持久化玩家档案（IP / 金币 / 时长 / 统计 / 游戏状态），供管理后台查看
        // 若管理员已锁定统计（手动改过），则客户端上报不再覆盖 gameStats / totalPlayTime，保留管理员的数值
        const _prof0 = playerProfiles.get(id) || {};
        const _locked = _prof0.statsAdminLocked === true;
        const _gsLocked = _prof0.gamestateAdminLocked === true;
        savePlayerProfile(id, {
            ip: ip,
            coins: isNaN(rc) ? (prevCoins(id)) : Math.max(0, rc),
            totalPlayTime: _locked ? prevPlayTime(id) : ((typeof totalPlayTime === 'number') ? totalPlayTime : (prevPlayTime(id))),
            gameStats: _locked ? prevStats(id) : ((gameStats && typeof gameStats === 'object') ? gameStats : (prevStats(id))),
            gamestate: _gsLocked ? prevGamestate(id) : ((gamestate && typeof gamestate === 'object') ? gamestate : (prevGamestate(id))),
            username: (name && String(name).trim()) || existing.name || '玩家'
        });
        // 若客户端 IP 已被封禁，则对该用户启用全部功能封禁，并通知客户端弹全屏封禁框
        let ipBanned = false, ipBanReason = '';
        if (isIPBanned(ip)) {
            const ban = userBans.get(id) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
            if (!ban.reasons) ban.reasons = {};
            const rec = bannedIPs.get(String(ip)) || {};
            ban.multiplayer = ban.single = ban.puzzle = ban.chat = true;
            const reason = (rec.reason && String(rec.reason).trim()) || '';
            const msg = 'IP 封禁：' + (reason || '管理员封禁此 IP');
            ban.reasons.multiplayer = ban.reasons.single = ban.reasons.puzzle = ban.reasons.chat = msg;
            userBans.set(id, ban);
            ipBanned = true; ipBanReason = msg;
        }
        console.log(`[Online] 玩家 ${name} (${id}) 上线(REST)，IP ${ip}，当前在线 ${onlinePlayers.size} 人`);
        // 把服务端已存（含管理员“全部通关”授予）的进度回传，客户端据此合入本地
        const prog = reportedProgress.get(id) || { unlockedLevel: 1, completedLevels: [], puzzleCompletedLevels: [] };
        res.json({
            success: true,
            ipBanned: ipBanned,
            ipBanReason: ipBanReason,
            role: role,
            uiSettings: getEffectiveUISettings(id),
            adminOverridden: !!(userSettings.get(id) || {}).admin,
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

// API: 客户端上传自己的 UI 设置（开放接口，供管理员后台查看；管理员覆盖项不受影响）
app.post('/api/user/settings', (req, res) => {
    try {
        const { id, uiSettings } = req.body || {};
        if (!id) return res.json({ success: false, message: '缺少 id' });
        setClientUISettings(id, uiSettings);
        res.json({
            success: true,
            uiSettings: getEffectiveUISettings(id),
            adminOverridden: !!(userSettings.get(id) || {}).admin
        });
    } catch (e) {
        res.json({ success: false, message: e.message });
    }
});

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
        const ipNow = prof.ip || (p && p.ip) || '';
        const ipRec = bannedIPs.get(String(ipNow)) || null;
        res.json({
            success: true,
            clientId: userId,
            username: prof.username || (p && p.name) || '',
            online: !!p,
            role: getUserRole(userId),
            ip: ipNow,
            ipBanned: isIPBanned(ipNow),
            ipBanReason: ipRec ? (ipRec.reason || '') : '',
            coins: (typeof prof.coins === 'number') ? prof.coins : (reportedCoins.get(userId) || 0),
            totalPlayTime: (typeof prof.totalPlayTime === 'number') ? prof.totalPlayTime : 0,
            gameStats: prof.gameStats || null,
            gamestate: prof.gamestate || null,
            statsAdminLocked: !!prof.statsAdminLocked,
            gamestateAdminLocked: !!prof.gamestateAdminLocked,
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

// 鉴权中间件：管理员 或 超级管理员 均可（用于角色管理等需要两种身份的操作）
function requireAnyAdminAuth(req, res, next) {
    const auth = (req.headers && req.headers.authorization) || '';
    const m = auth.match(/^Bearer\s+(.+)$/);
    if (!m) return res.status(401).json({ success: false, message: '需要身份验证' });
    try {
        const decoded = jwt.verify(m[1], JWT_SECRET);
        if (superAdminTokens.has(decoded.tokenId)) return next();
        if (adminTokens.has(decoded.tokenId)) return next();
        return res.status(403).json({ success: false, message: '无效的管理员令牌' });
    } catch (e) {
        return res.status(403).json({ success: false, message: '无效的管理员令牌' });
    }
}

// API: 查询当前操作者身份（admin / superadmin），供后台 UI 控制可用操作
app.get('/api/admin/role', requireAnyAdminAuth, (req, res) => {
    try {
        res.json({ success: true, role: getOperatorRole(req) });
    } catch (e) {
        res.status(500).json({ success: false, message: '查询失败' });
    }
});

// API: 设置玩家角色（user / admin / superadmin）
// 权限规则（后台运营视角）：
//  - 任何已登录管理员（管理员令牌或超级管理员令牌）均可直接将用户设为 超级管理员 / 管理员，或降级为用户
//  - 仅保留最高层级保护：普通管理员不能更改/取消 已有的 超级管理员 角色（超级管理员角色由超级管理员管理）
//  - 层级：超级管理员 > 管理员 > 用户；超级管理员角色的管辖对象为「角色=管理员」的玩家
// 管理员：读取某玩家的 UI 设置（生效值 + 是否被管理员覆盖 + 客户端上报的原值）
app.get('/api/admin/users/:userId/settings', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const rec = userSettings.get(userId) || { admin: null, client: null };
        res.json({
            success: true,
            settings: getEffectiveUISettings(userId),
            adminOverridden: !!rec.admin,
            clientSettings: rec.client || null
        });
    } catch (e) {
        res.json({ success: false, message: e.message });
    }
});

// 管理员：设置/清除某玩家的 UI 设置（settings:null 表示清除管理员覆盖，恢复客户端上报值）
app.post('/api/admin/users/:userId/settings', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const body = req.body || {};
        setAdminUISettings(userId, (body.settings === null ? null : body.settings));
        const eff = getEffectiveUISettings(userId);
        // 若该玩家在线，实时推送使其立即生效
        const p = onlinePlayers.get(userId);
        if (p && p.socketId && p.socketId !== 'rest') {
            try { io.to(p.socketId).emit('settings-update', { uiSettings: eff, adminOverridden: true }); } catch (_) {}
        }
        appendAudit('admin', 'user-settings', `修改用户 ${userId} 的 UI 设置`);
        res.json({ success: true, settings: eff, adminOverridden: !!(userSettings.get(userId) || {}).admin });
    } catch (e) {
        res.json({ success: false, message: e.message });
    }
});

app.post('/api/admin/users/:userId/role', requireAnyAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const { role } = req.body || {};
        const allowed = ['user', 'admin', 'superadmin'];
        if (!allowed.includes(role)) return res.status(400).json({ success: false, message: '无效的角色' });
        const operator = getOperatorRole(req);
        const current = getUserRole(userId);
        // 授予“超级管理员”角色：后台运营（管理员或超级管理员令牌）均可直接授予（满足“后台可直接设为超级管理员”）。
        // 仅保留最高层级保护：普通管理员不能更改/取消 已有的 超级管理员 角色（防止管理员撤销超级管理员）。
        if (current === 'superadmin' && operator !== 'superadmin') {
            return res.status(403).json({ success: false, message: '只有超级管理员可以更改或取消 超级管理员 的角色' });
        }
        if (role === 'user') {
            userRoles.delete(userId);
        } else {
            userRoles.set(userId, { role, setBy: operator || 'admin', setAt: new Date().toISOString() });
        }
        saveUserRoles();
        // 若该玩家在线，实时推送最新角色给其客户端
        const sockId = onlineSockets.get(userId);
        if (sockId && sockId !== 'rest') {
            const s = io.sockets.sockets.get(sockId);
            if (s) s.emit('role-info', { role });
        }
        appendAudit('admin', 'set-role', `用户 ${userId} 角色变更为 ${role}（操作者: ${operator}）`);
        res.json({ success: true, role: role, message: `已将角色设置为 ${role}` });
    } catch (e) {
        console.error('[API] 设置角色失败:', e.message);
        res.status(500).json({ success: false, message: '设置失败' });
    }
});

// API: 管理员修改玩家昵称（不消耗金币）
app.post('/api/admin/users/:userId/rename', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const { name } = req.body || {};
        if (!name || !String(name).trim()) return res.status(400).json({ success: false, message: '昵称不能为空' });
        const newName = String(name).trim().slice(0, 30);
        // 更新在线表（管理后台用户列表的权威来源）
        const op = onlinePlayers.get(userId);
        if (op) { op.name = newName; onlinePlayers.set(userId, op); }
        // 同步房间内玩家名字（多人游戏列表实时显示）
        for (const room of rooms.values()) {
            if (room.players && room.players.has(userId)) {
                const rp = room.players.get(userId);
                rp.name = newName;
                room.players.set(userId, rp);
            }
        }
        // 持久化到玩家档案（供离线 / 玩家信息面板查看）
        savePlayerProfile(userId, { username: newName });
        // 实时推送给在线客户端（无需重新登录即生效）
        const sockId = onlineSockets.get(userId);
        if (sockId && sockId !== 'rest') {
            const s = io.sockets.sockets.get(sockId);
            if (s) s.emit('name-changed', { name: newName, byAdmin: true });
        }
        appendAudit('admin', 'rename', `将玩家 ${userId} 改名为 ${newName}`);
        res.json({ success: true, username: newName, message: '改名成功' });
    } catch (e) {
        console.error('[API] 改名失败:', e.message);
        res.status(500).json({ success: false, message: '改名失败' });
    }
});

// API: 后台用户行「踢出」按钮 → 强制关闭该玩家的游戏标签页（按 userId 定位在线 socket）
app.post('/api/admin/users/:userId/kick', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const reason = (req.body && req.body.reason) ? String(req.body.reason).slice(0, 200) : '你已被管理员踢出。';
        const sockId = onlineSockets.get(userId);
        const p = onlinePlayers.get(userId);
        const name = (p && p.name) ? p.name : userId;
        if (!sockId || sockId === 'rest') {
            return res.json({ success: false, message: `玩家「${name}」当前不在线，无法踢出` });
        }
        const playerSocket = io.sockets.sockets.get(sockId);
        if (playerSocket) {
            // 通知客户端关闭标签页（客户端收到后尝试 window.close() 并显示全屏遮罩兜底）
            playerSocket.emit('admin-kick-tab', { message: reason, close: true });
            // 延迟断开，确保事件送达；客户端关页后此断开自然失效（try 保护幂等）
            setTimeout(() => { try { playerSocket.disconnect(true); } catch (_) {} }, 600);
        }
        // 若在某房间内，一并从房间移除并做必要的房主交接
        for (const [roomId, room] of rooms) {
            if (room.players && room.players.has(userId)) {
                const rp = room.players.get(userId);
                room.players.delete(userId);
                io.to(roomId).emit('player-kicked-by-admin', { playerName: name });
                if (rp.isHost && rp.socketId === room.actualHost && room.players.size > 0) {
                    const newHost = room.players.values().next().value;
                    newHost.isHost = true;
                    room.actualHost = newHost.socketId;
                    io.to(newHost.socketId).emit('promoted-to-host', { roomId: room.id, message: '原房主被踢出，你已成为新任房主。' });
                    io.to(roomId).emit('room-updated', { type: 'host-changed', newHostName: newHost.name });
                }
            }
        }
        appendAudit('admin', 'kick-player', `后台踢出(关页)玩家 ${name} (${userId})`);
        res.json({ success: true, message: `已踢出玩家「${name}」，其游戏页面将被关闭` });
    } catch (e) {
        console.error('[API] 踢出玩家失败:', e.message);
        res.status(500).json({ success: false, message: '踢出失败' });
    }
});

// API: 管理员踢出所有在线用户（批量关页）。exclude 为可选 clientId 列表，用于避免踢出操作者自身
app.post('/api/admin/users/kick-all', requireAdminAuth, (req, res) => {
    try {
        const reason = (req.body && req.body.reason) ? String(req.body.reason).slice(0, 200) : '你已被管理员踢出。';
        const exclude = (req.body && Array.isArray(req.body.exclude)) ? req.body.exclude : [];
        let count = 0;
        const kicked = [];
        for (const [userId, sockId] of onlineSockets.entries()) {
            if (!sockId || sockId === 'rest') continue;
            if (exclude.includes(userId)) continue;
            const playerSocket = io.sockets.sockets.get(sockId);
            if (!playerSocket) continue;
            const p = onlinePlayers.get(userId);
            const name = (p && p.name) ? p.name : userId;
            // 通知客户端关闭标签页（客户端收到后先提示，5 秒后尝试关闭）
            playerSocket.emit('admin-kick-tab', { message: reason, close: true });
            setTimeout(() => { try { playerSocket.disconnect(true); } catch (_) {} }, 600);
            // 若在某房间内，一并从房间移除并做必要的房主交接
            for (const [roomId, room] of rooms) {
                if (room.players && room.players.has(userId)) {
                    const rp = room.players.get(userId);
                    room.players.delete(userId);
                    io.to(roomId).emit('player-kicked-by-admin', { playerName: name });
                    if (rp.isHost && rp.socketId === room.actualHost && room.players.size > 0) {
                        const newHost = room.players.values().next().value;
                        newHost.isHost = true;
                        room.actualHost = newHost.socketId;
                        io.to(newHost.socketId).emit('promoted-to-host', { roomId: room.id, message: '原房主被踢出，你已成为新任房主。' });
                        io.to(roomId).emit('room-updated', { type: 'host-changed', newHostName: newHost.name });
                    }
                }
            }
            count++;
            kicked.push(name);
        }
        appendAudit('admin', 'kick-all', `后台批量踢出 ${count} 名在线玩家`);
        res.json({ success: true, message: `已踢出 ${count} 名在线玩家`, count, kicked });
    } catch (e) {
        console.error('[API] 批量踢出失败:', e.message);
        res.status(500).json({ success: false, message: '批量踢出失败' });
    }
});

// API: 管理员按 IP 封禁（该 IP 下所有玩家全部功能禁用，并强制弹出全屏封禁框）
app.post('/api/admin/ban-ip', requireAdminAuth, (req, res) => {
    try {
        const { ip, reason } = req.body || {};
        if (!ip || !String(ip).trim()) return res.status(400).json({ success: false, message: '缺少 ip' });
        const ipKey = String(ip).trim();
        bannedIPs.set(ipKey, { reason: (reason && String(reason).trim()) || '', bannedAt: new Date().toISOString() });
        // 对当前在线的同 IP 玩家：全部功能封禁 + 推送全屏封禁框
        const msg = 'IP 封禁：' + ((reason && String(reason).trim()) || '管理员封禁此 IP');
        for (const [uid, pl] of onlinePlayers.entries()) {
            if (pl && pl.ip === ipKey) {
                const ban = userBans.get(uid) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
                if (!ban.reasons) ban.reasons = {};
                ban.multiplayer = ban.single = ban.puzzle = ban.chat = true;
                ban.reasons.multiplayer = ban.reasons.single = ban.reasons.puzzle = ban.reasons.chat = msg;
                userBans.set(uid, ban);
                const sockId = onlineSockets.get(uid);
                if (sockId && sockId !== 'rest') {
                    const sock = io.sockets.sockets.get(sockId);
                    if (sock) sock.emit('ip-banned', { reason: msg, permanent: true });
                }
            }
        }
        appendAudit('admin', 'ban-ip', `封禁 IP ${ipKey}${reason ? '，理由: ' + reason : ''}`);
        res.json({ success: true, ip: ipKey, bannedIPs: Array.from(bannedIPs.keys()) });
    } catch (e) {
        res.status(500).json({ success: false, message: '封禁失败' });
    }
});

// API: 管理员解除 IP 封禁
app.post('/api/admin/unban-ip', requireAdminAuth, (req, res) => {
    try {
        const { ip } = req.body || {};
        if (!ip || !String(ip).trim()) return res.status(400).json({ success: false, message: '缺少 ip' });
        const ipKey = String(ip).trim();
        bannedIPs.delete(ipKey);
        // 对当前在线的同 IP 玩家：解除全部封禁 + 通知客户端关闭全屏框
        for (const [uid, pl] of onlinePlayers.entries()) {
            if (pl && pl.ip === ipKey) {
                const ban = userBans.get(uid) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
                if (!ban.reasons) ban.reasons = {};
                ban.multiplayer = ban.single = ban.puzzle = ban.chat = false;
                ban.reasons.multiplayer = ban.reasons.single = ban.reasons.puzzle = ban.reasons.chat = '';
                userBans.set(uid, ban);
                const sockId = onlineSockets.get(uid);
                if (sockId && sockId !== 'rest') {
                    const sock = io.sockets.sockets.get(sockId);
                    if (sock) sock.emit('ip-unbanned', {});
                }
            }
        }
        appendAudit('admin', 'unban-ip', `解封 IP ${ipKey}`);
        res.json({ success: true, ip: ipKey, bannedIPs: Array.from(bannedIPs.keys()) });
    } catch (e) {
        res.status(500).json({ success: false, message: '解封失败' });
    }
});

// API: 管理员查看已封禁 IP 列表
app.get('/api/admin/banned-ips', requireAdminAuth, (req, res) => {
    try {
        const list = Array.from(bannedIPs.entries()).map(([ip, v]) => ({ ip, reason: v.reason || '', bannedAt: v.bannedAt || '' }));
        res.json({ success: true, bannedIPs: list });
    } catch (e) {
        res.status(500).json({ success: false, message: '查询失败' });
    }
});

// API: 管理员修改玩家 gamestate（合并更新；修改后锁定，客户端上报不再覆盖）
app.post('/api/admin/users/:userId/gamestate', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const { gamestate } = req.body || {};
        if (!gamestate || typeof gamestate !== 'object') return res.status(400).json({ success: false, message: '缺少 gamestate' });
        const prof = playerProfiles.get(userId) || {};
        const cur = (prof.gamestate && typeof prof.gamestate === 'object') ? prof.gamestate : {};
        const merged = Object.assign({}, cur);
        // 仅合并客户端原本上报过的字段（白名单），避免写入无关键
        const allowed = ['currentScreen', 'developerMode', 'devMode', 'coins', 'unlockedLevel', 'currentLevel', 'roomId', 'controlsReversed', 'invincible', 'multiplayerDisabled', 'singlePlayerDisabled', 'puzzleDisabled', 'chatDisabled', 'completedLevelsCount'];
        for (const k of allowed) {
            if (k in gamestate) {
                let v = gamestate[k];
                if (typeof v === 'string') v = v.trim();
                if (typeof v === 'number' && isNaN(v)) v = 0;
                merged[k] = v;
            }
        }
        const next = Object.assign({}, prof, { gamestate: merged, gamestateAdminLocked: true, lastSeen: Date.now() });
        playerProfiles.set(userId, next);
        appendAudit('admin', 'edit-gamestate', `修改玩家 ${userId} gamestate`);
        res.json({ success: true, gamestate: merged, gamestateAdminLocked: true });
    } catch (e) {
        res.status(500).json({ success: false, message: '修改失败' });
    }
});

// API: 管理员解除 gamestate 锁定，恢复客户端上报同步
app.post('/api/admin/users/:userId/gamestate/unlock', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const prof = playerProfiles.get(userId) || {};
        prof.gamestateAdminLocked = false;
        prof.lastSeen = Date.now();
        playerProfiles.set(userId, prof);
        appendAudit('admin', 'unlock-gamestate', `恢复玩家 ${userId} 客户端 gamestate 同步`);
        res.json({ success: true, gamestateAdminLocked: false });
    } catch (e) {
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// API: 管理员修改玩家统计数据（合并更新；修改后锁定，客户端上报不再覆盖）
app.post('/api/admin/users/:userId/stats', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const { totalPlayTime, gameStats } = req.body || {};
        const prof = playerProfiles.get(userId) || {};
        const next = Object.assign({}, prof);
        if (typeof totalPlayTime === 'number' && totalPlayTime >= 0) {
            next.totalPlayTime = Math.round(totalPlayTime);
            if (next.gameStats && typeof next.gameStats === 'object') next.gameStats.totalPlayTime = next.totalPlayTime;
        }
        if (gameStats && typeof gameStats === 'object') {
            const cur = (next.gameStats && typeof next.gameStats === 'object') ? next.gameStats : {};
            const merged = Object.assign({}, cur);
            const allowed = ['timeChallengeBest', 'puzzleLevelsCompleted', 'totalLevelsCompleted', 'totalPlayTime', 'totalMoves', 'totalTrapsTriggered', 'totalCoinsCollected', 'averageMovesPerLevel', 'completionRate'];
            for (const k of allowed) {
                if (typeof gameStats[k] === 'number') merged[k] = Math.max(0, Math.round(gameStats[k]));
            }
            next.gameStats = merged;
        }
        next.statsAdminLocked = true; // 管理员已接管，客户端上报不再覆盖
        next.lastSeen = Date.now();
        playerProfiles.set(userId, next);
        appendAudit('admin', 'edit-stats', `修改玩家 ${userId} 统计数据`);
        res.json({ success: true, totalPlayTime: next.totalPlayTime, gameStats: next.gameStats, statsAdminLocked: true });
    } catch (e) {
        res.status(500).json({ success: false, message: '修改失败' });
    }
});

// API: 管理员重置玩家统计数据为 0（并锁定，客户端上报不再覆盖）
app.post('/api/admin/users/:userId/stats/reset', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const prof = playerProfiles.get(userId) || {};
        const zeroStats = {
            timeChallengeBest: 0, puzzleLevelsCompleted: 0, totalLevelsCompleted: 0,
            totalPlayTime: 0, totalMoves: 0, totalTrapsTriggered: 0,
            totalCoinsCollected: 0, averageMovesPerLevel: 0, completionRate: 0
        };
        const next = Object.assign({}, prof, { totalPlayTime: 0, gameStats: zeroStats, statsAdminLocked: true, lastSeen: Date.now() });
        playerProfiles.set(userId, next);
        appendAudit('admin', 'reset-stats', `重置玩家 ${userId} 统计数据`);
        res.json({ success: true, totalPlayTime: 0, gameStats: zeroStats, statsAdminLocked: true });
    } catch (e) {
        res.status(500).json({ success: false, message: '重置失败' });
    }
});

// API: 管理员解除统计锁定，恢复客户端上报同步（下次玩家上线会用客户端真实值覆盖）
app.post('/api/admin/users/:userId/stats/unlock', requireAdminAuth, (req, res) => {
    try {
        const userId = req.params.userId;
        const prof = playerProfiles.get(userId) || {};
        prof.statsAdminLocked = false;
        prof.lastSeen = Date.now();
        playerProfiles.set(userId, prof);
        appendAudit('admin', 'unlock-stats', `恢复玩家 ${userId} 客户端统计同步`);
        res.json({ success: true, statsAdminLocked: false });
    } catch (e) {
        res.status(500).json({ success: false, message: '操作失败' });
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
        appendAudit('admin', 'chat-send', `房间 ${roomId} 以「${sender}」身份发送消息: ${message.slice(0, 80)}`);
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
        const { id, name, coins, unlockedLevel, completedLevels, puzzleCompletedLevels, achievements, totalPlayTime, gameStats, gamestate, uiSettings } = data || {};
        if (!id) return;
        const ip = getClientIp(socket.request);
        const role = getUserRole(id);
        // 客户端上报的 UI 设置（供管理员后台查看/修改）
        if (uiSettings) setClientUISettings(id, uiSettings);
        onlinePlayers.set(id, {
            id: id,
            name: (name && String(name).trim()) || '玩家',
            socketId: socket.id,
            roomId: null,
            joinedAt: Date.now(),
            ip: ip,
            role: role
        });
        // 实时把当前角色推送给客户端（管理员/超级管理员据此开放调试信息与踢人权限）
        socket.emit('role-info', { role: role });
        // 若管理员已远程覆盖该玩家设置，连接时即下发，使其立即生效
        if ((userSettings.get(id) || {}).admin) {
            socket.emit('settings-update', { uiSettings: getEffectiveUISettings(id), adminOverridden: true });
        }
        const rc = parseInt(coins);
        if (!isNaN(rc)) reportedCoins.set(id, Math.max(0, rc));
        mergeProgress(id, { unlockedLevel, completedLevels, puzzleCompletedLevels });
        if (achievements) mergeAchievements(id, achievements);
        const _prof0 = playerProfiles.get(id) || {};
        const _locked = _prof0.statsAdminLocked === true;
        const _gsLocked = _prof0.gamestateAdminLocked === true;
        savePlayerProfile(id, {
            ip: ip,
            coins: isNaN(rc) ? prevCoins(id) : Math.max(0, rc),
            totalPlayTime: _locked ? prevPlayTime(id) : ((typeof totalPlayTime === 'number') ? totalPlayTime : prevPlayTime(id)),
            gameStats: _locked ? prevStats(id) : ((gameStats && typeof gameStats === 'object') ? gameStats : prevStats(id)),
            gamestate: _gsLocked ? prevGamestate(id) : ((gamestate && typeof gamestate === 'object') ? gamestate : prevGamestate(id)),
            username: (name && String(name).trim()) || '玩家'
        });
            onlineSockets.set(id, socket.id);
            // 若客户端 IP 已被封禁，则对该用户启用全部功能封禁，并立即推送全屏封禁框
            if (isIPBanned(ip)) {
                const ban = userBans.get(id) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
                if (!ban.reasons) ban.reasons = {};
                const rec = bannedIPs.get(String(ip)) || {};
                ban.multiplayer = ban.single = ban.puzzle = ban.chat = true;
                const reason = (rec.reason && String(rec.reason).trim()) || '';
                const msg = 'IP 封禁：' + (reason || '管理员封禁此 IP');
                ban.reasons.multiplayer = ban.reasons.single = ban.reasons.puzzle = ban.reasons.chat = msg;
                userBans.set(id, ban);
                socket.emit('ip-banned', { reason: msg, permanent: true });
            }
            console.log(`[Online] 玩家 ${name} (${id}) 上线，IP ${ip}，当前在线 ${onlinePlayers.size} 人`);
        } catch (e) {
            console.error('[Online] player-online 处理出错:', e.message);
        }
    });

    // 玩家更新个人主页（名称/头像/简介）；服务器存储并实时广播给所有在线客户端
    socket.on('set-profile', (data) => {
        try {
            const { clientId } = data || {};
            if (!clientId) return;
            const prev = homeProfiles.get(clientId) || {};
            const clean = sanitizeHomeProfile(data);
            // 合并：玩家只更新提供的字段，保留其它已有字段（避免只改简介时清空头像/颜色）
            const merged = Object.assign({}, prev, clean);
            // 保留管理员设置的禁用/覆盖标记，玩家自己不能清除
            if (prev.disabled) merged.disabled = true;
            if (prev.adminOverridden) merged.adminOverridden = true;
            merged.updatedAt = new Date().toISOString();
            homeProfiles.set(clientId, merged);
            saveHomeProfiles();
            io.emit('player-profile', Object.assign({ clientId }, merged));
            console.log('[Home] 更新个人主页:', clientId);
        } catch (e) {
            console.error('[Home] set-profile 出错:', e.message);
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

    // 游戏内管理员/超级管理员踢人：无需房主身份，由角色鉴权
    socket.on('admin-kick-player', (data) => {
        try {
            const { requesterId, targetId, reason } = data || {};
            if (!requesterId || !targetId) return;
            if (requesterId === targetId) return; // 不能踢自己
            const rRole = getUserRole(requesterId);
            if (rRole !== 'admin' && rRole !== 'superadmin') return; // 仅管理员/超管可踢
            // 查找目标所在房间（room.players 以 player.id 为键）
            let found = null;
            for (const [roomId, room] of rooms) {
                if (room.players && room.players.has(targetId)) { found = { roomId, room }; break; }
            }
            if (!found) {
                socket.emit('admin-kick-result', { success: false, message: '目标玩家不在任何房间中' });
                return;
            }
            const { roomId, room } = found;
            const playerToKick = room.players.get(targetId);
            const playerSocket = io.sockets.sockets.get(playerToKick.socketId);
            if (playerSocket) {
                playerSocket.emit('kicked-by-admin', { message: reason || '你已被管理员踢出。' });
                playerSocket.disconnect(true);
            }
            room.players.delete(targetId);
            appendAudit('admin', 'kick-player', `（角色 ${rRole}）房间 ${roomId} 踢出玩家 ${playerToKick.name} (${targetId})`);
            io.to(roomId).emit('player-kicked-by-admin', { playerName: playerToKick.name });
            // 房主交接（如被踢者是房主）
            if (playerToKick.isHost && playerToKick.socketId === room.actualHost && room.players.size > 0) {
                const newHost = room.players.values().next().value;
                newHost.isHost = true;
                room.actualHost = newHost.socketId;
                io.to(newHost.socketId).emit('promoted-to-host', { roomId: room.id, message: '原房主被踢出，你已成为新任房主。' });
                io.to(roomId).emit('room-updated', { type: 'host-changed', newHostName: newHost.name });
            }
            socket.emit('admin-kick-result', { success: true, message: `已踢出 ${playerToKick.name}` });
        } catch (e) {
            console.error('[kick] admin-kick-player 处理出错:', e.message);
        }
    });

    // ===== 新增：游戏内超级管理员管理面板 =====
    // 获取当前所有在线玩家（id / name / 当前角色），供游戏内超管面板列出可管理对象
    socket.on('admin-get-online-users', (data) => {
        try {
            const { requesterId } = data || {};
            // 仅游戏内超级管理员可查询
            if (requesterId && getUserRole(requesterId) !== 'superadmin') return;
            const users = [];
            for (const [pid, p] of onlinePlayers) {
                if (!pid) continue;
                users.push({
                    id: pid,
                    name: (p && p.name) || '玩家',
                    role: (p && p.role) || getUserRole(pid),
                    roomId: (p && p.roomId) || null
                });
            }
            socket.emit('online-users-list', { users });
        } catch (e) {
            console.error('[role] admin-get-online-users 处理出错:', e.message);
        }
    });

    // 游戏内超级管理员改其他玩家角色（与 REST /api/admin/users/:id/role 同源逻辑，但由游戏内角色鉴权）
    socket.on('admin-set-role', (data) => {
        try {
            const { requesterId, targetId, role } = data || {};
            if (!requesterId || !targetId || !role) return;
            const allowed = ['user', 'admin', 'superadmin'];
            if (!allowed.includes(role)) return;
            // 仅游戏内超级管理员可经此通道改角色（普通管理员/用户无权）
            const opRole = getUserRole(requesterId);
            if (opRole !== 'superadmin') return;
            // 与 REST 端点一致：user 表示清除角色，其余写入 userRoles
            if (role === 'user') {
                userRoles.delete(targetId);
            } else {
                userRoles.set(targetId, { role, setBy: 'superadmin(client)', setAt: new Date().toISOString() });
            }
            saveUserRoles();
            // 若目标在线，实时推送最新角色给其客户端（开放/收回调试信息与踢人权限）
            const sockId = onlineSockets.get(targetId);
            if (sockId && sockId !== 'rest') {
                const s = io.sockets.sockets.get(sockId);
                if (s) s.emit('role-info', { role });
            }
            appendAudit('admin', 'set-role', `（游戏内超级管理员 ${requesterId}）用户 ${targetId} 角色变更为 ${role}`);
            socket.emit('admin-set-role-result', { success: true, targetId, role, message: `已将 ${targetId} 设为 ${role}` });
        } catch (e) {
            console.error('[role] admin-set-role 处理出错:', e.message);
            socket.emit('admin-set-role-result', { success: false, message: e.message });
        }
    });

    // ===== 游戏内超级管理员：复用改角色同源鉴权，扩展其余后台管理能力 =====
    // 统一鉴权：仅“游戏内超级管理员”（getUserRole 校验为 superadmin）可执行这些通道
    function assertSuperadminOp(requesterId) {
        return !!(requesterId && getUserRole(requesterId) === 'superadmin');
    }
    function saLiveSocket(userId) {
        const sockId = onlineSockets.get(userId);
        if (!sockId || sockId === 'rest') return null;
        return io.sockets.sockets.get(sockId) || null;
    }

    // 改名（不消耗金币，实时生效）
    socket.on('admin-rename', (data) => {
        try {
            const { requesterId, targetId, name } = data || {};
            if (!assertSuperadminOp(requesterId)) return;
            if (!targetId) return socket.emit('admin-action-result', { success: false, message: '缺少目标玩家' });
            if (!name || !String(name).trim()) return socket.emit('admin-action-result', { success: false, message: '昵称不能为空' });
            const newName = String(name).trim().slice(0, 30);
            const op = onlinePlayers.get(targetId);
            if (op) { op.name = newName; onlinePlayers.set(targetId, op); }
            for (const room of rooms.values()) {
                if (room.players && room.players.has(targetId)) {
                    const rp = room.players.get(targetId);
                    rp.name = newName; room.players.set(targetId, rp);
                }
            }
            savePlayerProfile(targetId, { username: newName });
            const s = saLiveSocket(targetId);
            if (s) s.emit('name-changed', { name: newName, byAdmin: true });
            appendAudit('superadmin', 'rename', `（游戏内超级管理员 ${requesterId}）将 ${targetId} 改名为 ${newName}`);
            socket.emit('admin-action-result', { success: true, message: `已将 ${targetId} 改名为 ${newName}` });
        } catch (e) { socket.emit('admin-action-result', { success: false, message: e.message }); }
    });

    // 踢出（强制关闭标签页）
    socket.on('admin-kick', (data) => {
        try {
            const { requesterId, targetId, reason } = data || {};
            if (!assertSuperadminOp(requesterId)) return;
            if (!targetId) return socket.emit('admin-action-result', { success: false, message: '缺少目标玩家' });
            if (targetId === requesterId) return socket.emit('admin-action-result', { success: false, message: '不能踢出自己' });
            const r = (reason && String(reason).trim()) || '你已被管理员踢出。';
            const p = onlinePlayers.get(targetId);
            const nm = (p && p.name) ? p.name : targetId;
            const playerSocket = saLiveSocket(targetId);
            if (!playerSocket) return socket.emit('admin-action-result', { success: false, message: `玩家「${nm}」当前不在线` });
            playerSocket.emit('admin-kick-tab', { message: r, close: true });
            setTimeout(() => { try { playerSocket.disconnect(true); } catch (_) {} }, 600);
            for (const [roomId, room] of rooms) {
                if (room.players && room.players.has(targetId)) {
                    const rp = room.players.get(targetId);
                    room.players.delete(targetId);
                    io.to(roomId).emit('player-kicked-by-admin', { playerName: nm });
                    if (rp.isHost && rp.socketId === room.actualHost && room.players.size > 0) {
                        const nh = room.players.values().next().value;
                        nh.isHost = true; room.actualHost = nh.socketId;
                        io.to(nh.socketId).emit('promoted-to-host', { roomId: room.id, message: '原房主被踢出，你已成为新任房主。' });
                        io.to(roomId).emit('room-updated', { type: 'host-changed', newHostName: nh.name });
                    }
                }
            }
            appendAudit('superadmin', 'kick-player', `（游戏内SA）踢出玩家 ${nm} (${targetId})`);
            socket.emit('admin-action-result', { success: true, message: `已踢出「${nm}」` });
        } catch (e) { socket.emit('admin-action-result', { success: false, message: e.message }); }
    });

    // 封禁/解封（多人/单人/解密/聊天）
    socket.on('admin-ban', (data) => {
        try {
            const { requesterId, targetId, type, banned, reason } = data || {};
            if (!assertSuperadminOp(requesterId)) return;
            if (!targetId) return socket.emit('admin-action-result', { success: false, message: '缺少目标玩家' });
            if (!['multiplayer', 'single', 'puzzle', 'chat'].includes(type)) return socket.emit('admin-action-result', { success: false, message: '类型无效' });
            const userId = resolveUserId(targetId);
            const ban = userBans.get(userId) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
            if (!ban.reasons) ban.reasons = {};
            ban[type] = !!banned;
            ban.reasons[type] = banned ? ((reason && String(reason).trim()) || '') : '';
            userBans.set(userId, ban);
            const sock = saLiveSocket(userId);
            if (sock) sock.emit('ban-update', {
                multiplayer: !!ban.multiplayer, single: !!ban.single, puzzle: !!ban.puzzle, chat: !!ban.chat,
                multiplayerReason: ban.reasons.multiplayer || '', singleReason: ban.reasons.single || '',
                puzzleReason: ban.reasons.puzzle || '', chatReason: ban.reasons.chat || ''
            });
            const label = { multiplayer: '多人游戏', single: '单人游戏', puzzle: '解密游戏', chat: '多人聊天' }[type];
            appendAudit('superadmin', 'ban', `（游戏内SA）用户 ${userId} 的${label}${banned ? '封禁' : '解封'}`);
            socket.emit('admin-action-result', { success: true, message: `已${banned ? '封禁' : '解封'} ${userId} 的${label}` });
        } catch (e) { socket.emit('admin-action-result', { success: false, message: e.message }); }
    });

    // 单人 + 解密全部通关，并授予 迷宫大师 + 解密高手
    socket.on('admin-complete-all', (data) => {
        try {
            const { requesterId, targetId } = data || {};
            if (!assertSuperadminOp(requesterId)) return;
            if (!targetId) return socket.emit('admin-action-result', { success: false, message: '缺少目标玩家' });
            const completedLevels = []; for (let i = 1; i <= MAX_SINGLE_LEVEL; i++) completedLevels.push(i);
            const puzzleCompletedLevels = []; for (let i = 1; i <= MAX_PUZZLE_LEVEL; i++) puzzleCompletedLevels.push(i);
            mergeProgress(targetId, { unlockedLevel: MAX_SINGLE_LEVEL, completedLevels, puzzleCompletedLevels });
            const cur = reportedAchievements.get(targetId) || { allLevelsCompleted: false, multiplayerWins: 0, trapHits: 0, chineseEmojiUsed: false, puzzleMaster: false };
            cur.allLevelsCompleted = true; cur.puzzleMaster = true;
            reportedAchievements.set(targetId, cur);
            const revoked = revokedAchievements.get(targetId);
            if (revoked) { revoked.delete('allLevelsCompleted'); revoked.delete('puzzleMaster'); if (revoked.size === 0) revokedAchievements.delete(targetId); else revokedAchievements.set(targetId, revoked); }
            io.emit('achievement-update', { clientId: targetId, achievements: cur });
            io.emit('progress-update', { clientId: targetId, unlockedLevel: MAX_SINGLE_LEVEL, completedLevels, puzzleCompletedLevels });
            appendAudit('superadmin', 'complete-all', `（游戏内SA）将 ${targetId} 单人/解密全部通关`);
            socket.emit('admin-action-result', { success: true, message: `已将 ${targetId} 单人、解密全部通关` });
        } catch (e) { socket.emit('admin-action-result', { success: false, message: e.message }); }
    });

    // 读取某玩家 UI 设置（供游戏内超管面板编辑）
    socket.on('admin-get-settings', (data) => {
        try {
            const { requesterId, targetId } = data || {};
            if (!assertSuperadminOp(requesterId)) return;
            if (!targetId) return socket.emit('admin-action-result', { success: false, message: '缺少目标玩家' });
            const rec = userSettings.get(targetId) || { admin: null, client: null };
            socket.emit('admin-user-settings', { targetId, settings: getEffectiveUISettings(targetId), adminOverridden: !!rec.admin, clientSettings: rec.client || null });
        } catch (e) { socket.emit('admin-action-result', { success: false, message: e.message }); }
    });

    // 保存某玩家 UI 设置（管理员覆盖）
    socket.on('admin-save-settings', (data) => {
        try {
            const { requesterId, targetId, settings } = data || {};
            if (!assertSuperadminOp(requesterId)) return;
            if (!targetId) return socket.emit('admin-action-result', { success: false, message: '缺少目标玩家' });
            setAdminUISettings(targetId, (settings === null ? null : settings));
            const eff = getEffectiveUISettings(targetId);
            const s = saLiveSocket(targetId);
            if (s) try { s.emit('settings-update', { uiSettings: eff, adminOverridden: true }); } catch (_) {}
            appendAudit('superadmin', 'user-settings', `（游戏内SA）修改 ${targetId} 的 UI 设置`);
            socket.emit('admin-action-result', { success: true, message: `已保存 ${targetId} 的设置` });
        } catch (e) { socket.emit('admin-action-result', { success: false, message: e.message }); }
    });

    // 按玩家在线 IP 封禁（该 IP 下所有玩家全部功能禁用 + 强制弹窗），仅游戏内超级管理员
    socket.on('admin-ban-ip', (data) => {
        try {
            const { requesterId, targetId, reason } = data || {};
            if (!assertSuperadminOp(requesterId)) return;
            if (!targetId) return socket.emit('admin-action-result', { success: false, message: '缺少目标玩家' });
            const p = onlinePlayers.get(targetId);
            const ip = (p && p.ip) || (data && data.ip);
            if (!ip) return socket.emit('admin-action-result', { success: false, message: '无法获取该玩家 IP（可能已离线）' });
            const ipKey = String(ip).trim();
            bannedIPs.set(ipKey, { reason: (reason && String(reason).trim()) || '', bannedAt: new Date().toISOString() });
            const msg = 'IP 封禁：' + ((reason && String(reason).trim()) || '管理员封禁此 IP');
            for (const [uid, pl] of onlinePlayers.entries()) {
                if (pl && pl.ip === ipKey) {
                    const ban = userBans.get(uid) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
                    if (!ban.reasons) ban.reasons = {};
                    ban.multiplayer = ban.single = ban.puzzle = ban.chat = true;
                    ban.reasons.multiplayer = ban.reasons.single = ban.reasons.puzzle = ban.reasons.chat = msg;
                    userBans.set(uid, ban);
                    const s = saLiveSocket(uid);
                    if (s) s.emit('ip-banned', { reason: msg, permanent: true });
                }
            }
            appendAudit('superadmin', 'ban-ip', `（游戏内SA）封禁 IP ${ipKey}`);
            socket.emit('admin-action-result', { success: true, message: `已封禁 IP ${ipKey}` });
        } catch (e) { socket.emit('admin-action-result', { success: false, message: e.message }); }
    });

    // 解除按玩家 IP 的封禁（其下玩家恢复全部功能），仅游戏内超级管理员
    socket.on('admin-unban-ip', (data) => {
        try {
            const { requesterId, targetId } = data || {};
            if (!assertSuperadminOp(requesterId)) return;
            if (!targetId) return socket.emit('admin-action-result', { success: false, message: '缺少目标玩家' });
            const p = onlinePlayers.get(targetId);
            const ip = (p && p.ip) || (data && data.ip);
            if (!ip) return socket.emit('admin-action-result', { success: false, message: '无法获取该玩家 IP' });
            const ipKey = String(ip).trim();
            bannedIPs.delete(ipKey);
            for (const [uid, pl] of onlinePlayers.entries()) {
                if (pl && pl.ip === ipKey) {
                    const ban = userBans.get(uid) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
                    if (!ban.reasons) ban.reasons = {};
                    ban.multiplayer = ban.single = ban.puzzle = ban.chat = false;
                    ban.reasons.multiplayer = ban.reasons.single = ban.reasons.puzzle = ban.reasons.chat = '';
                    userBans.set(uid, ban);
                    const s = saLiveSocket(uid);
                    if (s) s.emit('ip-unbanned', {});
                }
            }
            appendAudit('superadmin', 'unban-ip', `（游戏内SA）解封 IP ${ipKey}`);
            socket.emit('admin-action-result', { success: true, message: `已解封 IP ${ipKey}` });
        } catch (e) { socket.emit('admin-action-result', { success: false, message: e.message }); }
    });

    // 游戏内超管：拉取某玩家完整信息（与后台 /api/admin/users/:userId/info 同口径）
    socket.on('admin-get-player-info', (data) => {
        try {
            const requesterId = (data && data.requesterId) || '';
            if (!assertSuperadminOp(requesterId)) return;
            const userId = (data && data.targetId) || '';
            if (!userId) return socket.emit('admin-player-info', { success: false, message: '缺少目标玩家' });
            const ban = userBans.get(userId) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
            if (!ban.reasons) ban.reasons = {};
            const prof = playerProfiles.get(userId) || {};
            const p = onlinePlayers.get(userId);
            const ipNow = prof.ip || (p && p.ip) || '';
            const ipRec = bannedIPs.get(String(ipNow)) || null;
            socket.emit('admin-player-info', {
                success: true,
                clientId: userId,
                username: prof.username || (p && p.name) || '',
                online: !!p,
                role: getUserRole(userId),
                ip: ipNow,
                ipBanned: isIPBanned(ipNow),
                ipBanReason: ipRec ? (ipRec.reason || '') : '',
                coins: (typeof prof.coins === 'number') ? prof.coins : (reportedCoins.get(userId) || 0),
                totalPlayTime: (typeof prof.totalPlayTime === 'number') ? prof.totalPlayTime : 0,
                gameStats: prof.gameStats || null,
                gamestate: prof.gamestate || null,
                statsAdminLocked: !!prof.statsAdminLocked,
                gamestateAdminLocked: !!prof.gamestateAdminLocked,
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
        } catch (e) { socket.emit('admin-player-info', { success: false, message: e.message }); }
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
        appendAudit('admin', 'maze-create', `新建迷宫 ${maze.name} (${maze.id})`);
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
        appendAudit('admin', 'maze-update', `更新迷宫 ${maze.name} (${mazeId})`);
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
        appendAudit('admin', 'maze-delete', `删除迷宫 ${mazeId}`);
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
        appendAudit('admin', 'access-control', `用户 ${userId} 页面访问权限设为: ${access || 'all'}`);
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
        appendAudit('admin', 'function-control', `用户 ${userId} 功能控制设为: ${control || 'enable'}`);
        res.json({ success: true, message: `已为用户 ${userId} 设置功能控制: ${control || 'enable'}`, control: userFunctions.get(userId) });
    } catch (error) {
        console.error('[API] 设置功能控制失败:', error);
        res.status(500).json({ success: false, message: '设置失败' });
    }
});

// ===== 全局功能控制（管理员统一开关，影响所有在线游戏客户端）=====
// 读取当前全局功能开关（公开，供游戏客户端初始化时拉取；仅返回开关，不含敏感信息）
app.get('/api/admin/global-functions', (req, res) => {
    res.json({ success: true, functions: Object.assign({}, globalFunctions) });
});

// 修改全局功能开关（需管理员或超级管理员权限；保存后实时广播给所有客户端）
app.put('/api/admin/global-functions', requireAdminAuth, (req, res) => {
    try {
        const body = req.body || {};
        const validKeys = Object.keys(GLOBAL_FUNCTIONS_DEFAULT);
        const next = Object.assign({}, GLOBAL_FUNCTIONS_DEFAULT);
        for (const k of validKeys) {
            if (typeof body[k] === 'boolean') next[k] = body[k];
        }
        globalFunctions = next;
        saveGlobalFunctions();
        // 实时广播给所有已连接的游戏客户端
        try { io.emit('global-function-update', Object.assign({}, globalFunctions)); } catch (_) {}
        const changed = validKeys.filter(k => GLOBAL_FUNCTIONS_DEFAULT[k] !== globalFunctions[k]);
        appendAudit('admin', 'function-control', `全局功能设定更新: {${changed.map(k => `${k}=${globalFunctions[k]}`).join(', ')}}`);
        console.log('[Admin] 全局功能设定更新:', globalFunctions);
        res.json({ success: true, message: '全局功能设定已保存并广播', functions: Object.assign({}, globalFunctions) });
    } catch (error) {
        console.error('[API] 保存全局功能设定失败:', error);
        res.status(500).json({ success: false, message: '保存失败' });
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
        appendAudit('admin', 'remote-command', `向用户 ${userId} 发送远程指令: ${action}`);
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

(async () => {
    await initDatabase();
    loadAdminState();
    await loadUserRoles();
    await loadUserSettings();
    loadGlobalFunctions();
    await loadAccounts();
    await loadHomeProfiles();

    const PORT = process.env.PORT || 234;
    server.listen(PORT, () => {
        console.log(`\n✅ 服务器运行在 http://localhost:${PORT}`);
        console.log(`📊 服务器状态: http://localhost:${PORT}/api/server-status`);
        console.log(`🏠 房间列表: http://localhost:${PORT}/api/rooms`);
        console.log(`👤 创建房间: http://localhost:${PORT}/api/create-room`);
        console.log(`Socket.IO 服务已启动\n`);
    });
})();
