
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs'); // 纯 JS 实现，避免 onrender 等环境因原生模块编译失败导致部署崩溃（哈希格式与原生 bcrypt 兼容）
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const crypto = require('crypto'); // 内置：TOTP(HMAC-SHA1) 二次认证，无需额外依赖
// 二维码（otpauth://）为可选项：安装 qrcode 后扫码更方便；未安装时前端降级为「手动输入密钥」，同样兼容 2FA 浏览器插件。
let QRCode = null;
try { QRCode = require('qrcode'); } catch (e) { QRCode = null; }

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
    host: process.env.DB_HOST || 'nu3uys.h.filess.io',
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 3307,
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

// ===== 服务器异常捕获与日志（供 admin 后台查看）=====
// 目标：服务器任何意外报错都不再直接崩溃退出，而是被捕获、记录，并可在 admin 后台查看报错信息与运行日志。
const SERVER_ERRORS_FILE = path.join(DATA_DIR, 'server-errors.log');
const MAX_ERROR_LOG = 200;     // 内存中保留的最多异常条数
const MAX_RECENT_LOG = 800;    // 内存中保留的最近日志条数
let serverErrors = [];         // 异常记录：{ id, time, type, message, stack }
let recentLogs = [];           // 最近控制台日志：{ time, level, message }
let errorSeq = 0;

function safeStringify(o) {
    try { return JSON.stringify(o); } catch (_) { return String(o); }
}
// 把一条日志压入内存环形缓冲（最新在末尾）
function pushRecentLog(level, args) {
    const msg = args.map(a => (typeof a === 'string' ? a : (a && a.stack ? a.stack : safeStringify(a)))).join(' ');
    recentLogs.push({ time: new Date().toISOString(), level, message: msg });
    if (recentLogs.length > MAX_RECENT_LOG) recentLogs.shift();
}
// 记录一条异常（内存 + 落盘，落盘文件超量时裁剪）
function recordServerError(type, err) {
    const entry = {
        id: ++errorSeq,
        time: new Date().toISOString(),
        type,
        message: err && err.message ? String(err.message) : String(err),
        stack: err && err.stack ? String(err.stack) : ''
    };
    serverErrors.push(entry);
    if (serverErrors.length > MAX_ERROR_LOG) serverErrors.shift();
    try {
        fs.appendFileSync(SERVER_ERRORS_FILE, JSON.stringify(entry) + '\n');
        const lines = fs.readFileSync(SERVER_ERRORS_FILE, 'utf8').split('\n').filter(Boolean);
        if (lines.length > MAX_ERROR_LOG * 2) {
            fs.writeFileSync(SERVER_ERRORS_FILE, lines.slice(-MAX_ERROR_LOG).join('\n') + '\n');
        }
    } catch (_) { /* 日志写入失败不应影响主流程 */ }
}
// 启动时从落盘文件恢复已记录的异常（跨重启保留）
function loadServerErrorsFromFile() {
    try {
        if (fs.existsSync(SERVER_ERRORS_FILE)) {
            const lines = fs.readFileSync(SERVER_ERRORS_FILE, 'utf8').split('\n').filter(Boolean);
            serverErrors = lines.map(l => { try { return JSON.parse(l); } catch (_) { return null; } }).filter(Boolean);
            if (serverErrors.length) errorSeq = serverErrors[serverErrors.length - 1].id || serverErrors.length;
            if (serverErrors.length > MAX_ERROR_LOG) serverErrors = serverErrors.slice(-MAX_ERROR_LOG);
        }
    } catch (_) {}
}
// 包裹 console.*：保留原样输出，同时记入 recentLogs 供 admin 查看
['log', 'info', 'warn', 'error'].forEach(level => {
    const orig = console[level].bind(console);
    console[level] = (...args) => { pushRecentLog(level, args); orig(...args); };
});
// 全局兜底：未捕获异常 / 未处理的 Promise 拒绝 —— 记录但不退出进程，保证服务持续可用
process.on('uncaughtException', (err) => { recordServerError('uncaughtException', err); });
process.on('unhandledRejection', (reason) => {
    const e = (reason instanceof Error) ? reason : new Error('UnhandledRejection: ' + safeStringify(reason));
    recordServerError('unhandledRejection', e);
});

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
        can_view_others TINYINT(1) DEFAULT 1,
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
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS announcements (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        priority INT DEFAULT 0,
        active TINYINT(1) DEFAULT 1,
        created_by VARCHAR(64),
        created_at VARCHAR(32),
        INDEX idx_ann_active_created (active, created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS global_functions (
        id VARCHAR(32) PRIMARY KEY,
        data JSON NOT NULL,
        updated_at VARCHAR(32)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS daily_challenge_config (
        id VARCHAR(32) PRIMARY KEY,
        data JSON NOT NULL,
        updated_at VARCHAR(32)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS cloud_storage_accounts (
        username VARCHAR(64) PRIMARY KEY,
        password_hash VARCHAR(255) NOT NULL,
        created_at VARCHAR(32),
        updated_at VARCHAR(32),
        max_mazes INT NOT NULL DEFAULT 5,
        client_id VARCHAR(64),
        disabled TINYINT(1) NOT NULL DEFAULT 0,
        two_factor_enabled TINYINT(1) NOT NULL DEFAULT 0,
        creator_client_id VARCHAR(64),
        totp_secret VARCHAR(64),
        totp_scopes VARCHAR(255)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS cloud_storage_mazes (
        id VARCHAR(64) PRIMARY KEY,
        username VARCHAR(64) NOT NULL,
        name VARCHAR(128) NOT NULL,
        maze JSON NOT NULL,
        size JSON,
        teleporters JSON,
        enemy_speed INT DEFAULT 1,
        show_shop TINYINT(1) DEFAULT 1,
        description TEXT,
        difficulty VARCHAR(32),
        created_at VARCHAR(32),
        updated_at VARCHAR(32),
        INDEX idx_cloud_user (username)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS cloud_sessions (
        id VARCHAR(64) PRIMARY KEY,
        username VARCHAR(64) NOT NULL,
        device VARCHAR(128),
        ip VARCHAR(64),
        created_at VARCHAR(32),
        last_active_at VARCHAR(32),
        INDEX idx_cloud_session_user (username)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS cloud_expansion_codes (
        code VARCHAR(64) PRIMARY KEY,
        max_uses INT NOT NULL DEFAULT 1,
        used INT NOT NULL DEFAULT 0,
        allowed_ips TEXT,
        capacity INT NOT NULL DEFAULT 5,
        created_at VARCHAR(32),
        created_by VARCHAR(64),
        note VARCHAR(255),
        active TINYINT(1) DEFAULT 1,
        redeemed_by TEXT
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS cloud_storage_progress (
        username VARCHAR(64) PRIMARY KEY,
        progress JSON,
        updated_at VARCHAR(32)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS cloud_link_accounts (
        username VARCHAR(64) PRIMARY KEY,
        password_hash VARCHAR(255) NOT NULL,
        created_at VARCHAR(32),
        updated_at VARCHAR(32),
        client_id VARCHAR(64),
        disabled TINYINT(1) NOT NULL DEFAULT 0,
        two_factor_enabled TINYINT(1) NOT NULL DEFAULT 0,
        creator_client_id VARCHAR(64),
        totp_secret VARCHAR(64),
        totp_scopes VARCHAR(255)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS cloud_links (
        code VARCHAR(32) PRIMARY KEY,
        username VARCHAR(64) NOT NULL,
        name VARCHAR(128),
        data JSON NOT NULL,
        views INT NOT NULL DEFAULT 0,
        disabled TINYINT(1) NOT NULL DEFAULT 0,
        created_at VARCHAR(32),
        updated_at VARCHAR(32),
        INDEX idx_cloud_link_user (username)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS cloud_link_visits (
        id VARCHAR(64) PRIMARY KEY,
        code VARCHAR(32) NOT NULL,
        link_name VARCHAR(128),
        username VARCHAR(64) NOT NULL,
        source VARCHAR(16) DEFAULT 'player',
        client_id VARCHAR(64),
        ip VARCHAR(64),
        created_at VARCHAR(32),
        INDEX idx_clv_code (code),
        INDEX idx_clv_user (username),
        INDEX idx_clv_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS cloud_link_sessions (
        id VARCHAR(64) PRIMARY KEY,
        username VARCHAR(64) NOT NULL,
        device VARCHAR(128),
        ip VARCHAR(64),
        created_at VARCHAR(32),
        last_active_at VARCHAR(32),
        INDEX idx_cloud_link_sess_user (username)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS banned_ips (
        ip VARCHAR(64) PRIMARY KEY,
        reason TEXT,
        banned_at VARCHAR(32),
        expires_at VARCHAR(32) DEFAULT NULL,
        banned_by VARCHAR(64),
        username VARCHAR(128),
        client_id VARCHAR(64),
        INDEX idx_banned_expires (expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS ban_appeals (
        id VARCHAR(64) PRIMARY KEY,
        client_id VARCHAR(64),
        username VARCHAR(128),
        ban_type VARCHAR(16) NOT NULL,
        target VARCHAR(128) NOT NULL,
        message TEXT,
        status VARCHAR(16) NOT NULL DEFAULT 'pending',
        created_at VARCHAR(32),
        handled_by VARCHAR(64),
        handled_at VARCHAR(32),
        INDEX idx_appeal_status (status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS ban_history (
        id VARCHAR(64) PRIMARY KEY,
        type VARCHAR(16) NOT NULL,
        target VARCHAR(160) NOT NULL,
        username VARCHAR(128),
        client_id VARCHAR(64),
        reason TEXT,
        banned_at VARCHAR(32),
        expires_at VARCHAR(32) DEFAULT NULL,
        unbanned_at VARCHAR(32) DEFAULT NULL,
        unbanned_by VARCHAR(64),
        banned_by VARCHAR(64),
        INDEX idx_banhist_banned_at (banned_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS cheat_log (
        id VARCHAR(64) PRIMARY KEY,
        client_id VARCHAR(64),
        username VARCHAR(128),
        ip VARCHAR(64),
        cheat_type VARCHAR(40),
        reason VARCHAR(500),
        banned_at VARCHAR(32),
        expires_at VARCHAR(32) DEFAULT NULL,
        created_at VARCHAR(32),
        INDEX idx_cheatlog_client (client_id),
        INDEX idx_cheatlog_banned_at (banned_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS popular_mazes (
        id VARCHAR(64) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        difficulty VARCHAR(32),
        size INT,
        data JSON,
        teleporters JSON,
        enemy_speed INT DEFAULT 1,
        show_shop TINYINT(1) DEFAULT 1,
        source_maze_id VARCHAR(64),
        author VARCHAR(64),
        author_name VARCHAR(64),
        created_at VARCHAR(32),
        updated_at VARCHAR(32),
        INDEX idx_popular_updated (updated_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS cloud_backup_accounts (
        username VARCHAR(64) PRIMARY KEY,
        password_hash VARCHAR(255) NOT NULL,
        created_at VARCHAR(32),
        updated_at VARCHAR(32),
        client_id VARCHAR(64),
        disabled TINYINT(1) NOT NULL DEFAULT 0,
        banned_until VARCHAR(32),
        two_factor_enabled TINYINT(1) NOT NULL DEFAULT 0,
        creator_client_id VARCHAR(64),
        totp_secret VARCHAR(64),
        totp_scopes VARCHAR(255)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS cloud_backups (
        username VARCHAR(64) NOT NULL,
        kind VARCHAR(32) NOT NULL,
        data JSON,
        created_at VARCHAR(32),
        updated_at VARCHAR(32),
        PRIMARY KEY (username, kind),
        INDEX idx_cloud_backup_user (username)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS cloud_backup_sessions (
        id VARCHAR(64) PRIMARY KEY,
        username VARCHAR(64) NOT NULL,
        device VARCHAR(128),
        ip VARCHAR(64),
        created_at VARCHAR(32),
        last_active_at VARCHAR(32),
        INDEX idx_cloud_backup_sess_user (username)
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
    // 托管 MySQL（filess.io 等）通常要求 TLS 连接；onrender 跨云连库没 SSL 会握手失败。
    // 本地/特殊环境若不兼容可用 DB_SSL=false 关闭。
    if (process.env.DB_SSL !== 'false') {
        poolOpts.ssl = { rejectUnauthorized: false };
    }
    for (let attempt = 1; attempt <= 3; attempt++) {
        try {
            pool = mysql.createPool(poolOpts);
            const conn = await pool.getConnection();
            await conn.ping();
            conn.release();
            await createTables();
            // 迁移：为已存在的 cloud_storage_accounts 表补充 max_mazes 列。
            // 旧库账号表在加入扩容码功能前已建好，CREATE TABLE IF NOT EXISTS 不会补列，
            // 会导致 dbSaveCloudAccount 写入 max_mazes 时报 "Unknown column" 被吞掉、
            // 扩容容量回退默认 5（即"扩容码没用"）。
            try {
                const [dbRow] = await pool.query('SELECT DATABASE() AS db');
                const dbName = (dbRow && dbRow[0] && dbRow[0].db) || '';
                const [cols] = await pool.query(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='cloud_storage_accounts' AND COLUMN_NAME='max_mazes'",
                    [dbName]
                );
                if (!cols || cols.length === 0) {
                    await pool.query('ALTER TABLE cloud_storage_accounts ADD COLUMN max_mazes INT NOT NULL DEFAULT 5');
                    console.log('🗄️ 已为 cloud_storage_accounts 表补充 max_mazes 列（支持云空间扩容）');
                }
                // 补充 client_id 列：用于把云储存账号与管理端游戏用户(clientId)关联，
                // 否则 admin 用游戏用户名查云账号永远查不到（两套独立命名空间）。
                const [cidCols] = await pool.query(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='cloud_storage_accounts' AND COLUMN_NAME='client_id'",
                    [dbName]
                );
                if (!cidCols || cidCols.length === 0) {
                    await pool.query('ALTER TABLE cloud_storage_accounts ADD COLUMN client_id VARCHAR(64)');
                    console.log('🗄️ 已为 cloud_storage_accounts 表补充 client_id 列（关联游戏用户）');
                }
                // 补充 disabled 列：用于封禁云储存账号
                const [disCols] = await pool.query(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='cloud_storage_accounts' AND COLUMN_NAME='disabled'",
                    [dbName]
                );
                if (!disCols || disCols.length === 0) {
                    await pool.query('ALTER TABLE cloud_storage_accounts ADD COLUMN disabled TINYINT(1) NOT NULL DEFAULT 0');
                    console.log('🗄️ 已为 cloud_storage_accounts 表补充 disabled 列（封禁账号）');
                }
                // 补充 banned_until 列：限时封禁的解封时间（NULL=永久封禁）
                const [banCols] = await pool.query(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='cloud_storage_accounts' AND COLUMN_NAME='banned_until'",
                    [dbName]
                );
                if (!banCols || banCols.length === 0) {
                    await pool.query('ALTER TABLE cloud_storage_accounts ADD COLUMN banned_until VARCHAR(32)');
                    console.log('🗄️ 已为 cloud_storage_accounts 表补充 banned_until 列（限时封禁）');
                }
                // 补充 two_factor_enabled 列：云储存账号二次认证（2FA）开关
                const [tfaCols] = await pool.query(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='cloud_storage_accounts' AND COLUMN_NAME='two_factor_enabled'",
                    [dbName]
                );
                if (!tfaCols || tfaCols.length === 0) {
                    await pool.query('ALTER TABLE cloud_storage_accounts ADD COLUMN two_factor_enabled TINYINT(1) NOT NULL DEFAULT 0');
                    console.log('🗄️ 已为 cloud_storage_accounts 表补充 two_factor_enabled 列（二次认证）');
                }
                // 补充 cloud_link_accounts 表的 two_factor_enabled 列
                const [ltfaCols] = await pool.query(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='cloud_link_accounts' AND COLUMN_NAME='two_factor_enabled'",
                    [dbName]
                );
                if (!ltfaCols || ltfaCols.length === 0) {
                    await pool.query('ALTER TABLE cloud_link_accounts ADD COLUMN two_factor_enabled TINYINT(1) NOT NULL DEFAULT 0');
                    console.log('🗄️ 已为 cloud_link_accounts 表补充 two_factor_enabled 列（二次认证）');
                }
                // 补充 creator_client_id 列：记录「创建该账号的人」的客户端标识（注册时固定，登录不改），用于 2FA 授权身份判定
                const [cCols] = await pool.query(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='cloud_storage_accounts' AND COLUMN_NAME='creator_client_id'",
                    [dbName]
                );
                if (!cCols || cCols.length === 0) {
                    await pool.query('ALTER TABLE cloud_storage_accounts ADD COLUMN creator_client_id VARCHAR(64)');
                    console.log('🗄️ 已为 cloud_storage_accounts 表补充 creator_client_id 列（创建者标识）');
                }
                const [lcCols] = await pool.query(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='cloud_link_accounts' AND COLUMN_NAME='creator_client_id'",
                    [dbName]
                );
                if (!lcCols || lcCols.length === 0) {
                    await pool.query('ALTER TABLE cloud_link_accounts ADD COLUMN creator_client_id VARCHAR(64)');
                    console.log('🗄️ 已为 cloud_link_accounts 表补充 creator_client_id 列（创建者标识）');
                }
                // 补充 totp_secret 列：标准 TOTP（RFC 6238）密钥，兼容 2FA 浏览器插件
                const [tCols] = await pool.query(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='cloud_storage_accounts' AND COLUMN_NAME='totp_secret'",
                    [dbName]
                );
                if (!tCols || tCols.length === 0) {
                    await pool.query('ALTER TABLE cloud_storage_accounts ADD COLUMN totp_secret VARCHAR(64)');
                    console.log('🗄️ 已为 cloud_storage_accounts 表补充 totp_secret 列（TOTP 密钥）');
                }
                const [ltCols] = await pool.query(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='cloud_link_accounts' AND COLUMN_NAME='totp_secret'",
                    [dbName]
                );
                if (!ltCols || ltCols.length === 0) {
                    await pool.query('ALTER TABLE cloud_link_accounts ADD COLUMN totp_secret VARCHAR(64)');
                    console.log('🗄️ 已为 cloud_link_accounts 表补充 totp_secret 列（TOTP 密钥）');
                }
                // 补充 totp_scopes 列：2FA 作用范围（哪些敏感操作需要动态码；空 = 全部需要）
                const [tsCols] = await pool.query(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='cloud_storage_accounts' AND COLUMN_NAME='totp_scopes'",
                    [dbName]
                );
                if (!tsCols || tsCols.length === 0) {
                    await pool.query('ALTER TABLE cloud_storage_accounts ADD COLUMN totp_scopes VARCHAR(255)');
                    console.log('🗄️ 已为 cloud_storage_accounts 表补充 totp_scopes 列（2FA 作用范围）');
                }
                const [ltsCols] = await pool.query(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='cloud_link_accounts' AND COLUMN_NAME='totp_scopes'",
                    [dbName]
                );
                if (!ltsCols || ltsCols.length === 0) {
                    await pool.query('ALTER TABLE cloud_link_accounts ADD COLUMN totp_scopes VARCHAR(255)');
                    console.log('🗄️ 已为 cloud_link_accounts 表补充 totp_scopes 列（2FA 作用范围）');
                }
                // 补充 ip 列：记录会话登录 IP，供"管理设备"展示
                const [sessIpCols] = await pool.query(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='cloud_sessions' AND COLUMN_NAME='ip'",
                    [dbName]
                );
                if (!sessIpCols || sessIpCols.length === 0) {
                    await pool.query('ALTER TABLE cloud_sessions ADD COLUMN ip VARCHAR(64)');
                    console.log('🗄️ 已为 cloud_sessions 表补充 ip 列（记录登录 IP）');
                }
                // 补充 banned_ips 表的 username / client_id 列：用于反作弊标签页展示被封玩家身份 + 客户端申诉定位
                const [biUserCols] = await pool.query(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='banned_ips' AND COLUMN_NAME='username'",
                    [dbName]
                );
                if (!biUserCols || biUserCols.length === 0) {
                    await pool.query('ALTER TABLE banned_ips ADD COLUMN username VARCHAR(128)');
                    console.log('🗄️ 已为 banned_ips 表补充 username 列（封禁展示用）');
                }
                const [biCidCols] = await pool.query(
                    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='banned_ips' AND COLUMN_NAME='client_id'",
                    [dbName]
                );
                if (!biCidCols || biCidCols.length === 0) {
                    await pool.query('ALTER TABLE banned_ips ADD COLUMN client_id VARCHAR(64)');
                    console.log('🗄️ 已为 banned_ips 表补充 client_id 列（封禁展示/申诉用）');
                }
            } catch (e) { console.error('[迁移] 检查/补充 max_mazes 列失败:', e.message); }
            DB_AVAILABLE = true;
            loadCloudSessions().catch(e => console.error('[云储存] 会话载入失败:', e.message)); // DB 模式下启动后从库载入已有会话到内存，供鉴权校验
            loadBannedIPs().catch(e => console.error('[IP封禁] 载入失败:', e.message));        // 从库恢复 IP 封禁（含限时封禁的剩余时长）
            loadCheatLog().catch(e => console.error('[作弊日志] 载入失败:', e.message));       // 从库恢复作弊封禁日志
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
//   mazeJsonShare   —— 玩家工坊「查看/分享迷宫（JSON）」功能，关闭后隐藏入口且禁止创建云链接
//   antiDevtools    —— 反调试：开启后客户端强制无限 debugger 断点 + 全屏警告弹窗，
//                      检测到浏览器开发者工具关闭后自动刷新页面。
//                      注意：这是唯一「默认关闭」的开关（默认 false），开启才生效，
//                      避免影响正常开发调试。
const GLOBAL_FUNCTIONS_DEFAULT = {
    export: true,
    importClear: true,
    multiplayerChat: true,
    multiplayer: true,
    debugInfo: true,
    f12DevConsole: true,
    ctrlShiftCD: true,
    cloudStorage: true,
    mazeJsonShare: true,
    cloudLinkEnabled: true,
    cloud2fa: true,        // 云储存用户是否允许使用二次认证（2FA）
    cloudLink2fa: true,    // 云链接用户是否允许使用二次认证（2FA）
    backup: true,          // 云备份功能总开关
    backup2fa: true,       // 云备份用户是否允许使用二次认证（2FA）
    antiDevtools: false,
    showAntiCheatTab: true,
    newUi: { mode: 'probability', prob: 100 }
};
let globalFunctions = Object.assign({}, GLOBAL_FUNCTIONS_DEFAULT);

// 加载全局功能控制：DB 优先（global_functions 表，单例行 id='global'），失败回退 JSON 文件
async function loadGlobalFunctions() {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query("SELECT data FROM global_functions WHERE id='global'");
            if (rows && rows.length && rows[0].data) {
                const parsed = (typeof rows[0].data === 'string') ? JSON.parse(rows[0].data) : rows[0].data;
                if (parsed && typeof parsed === 'object') {
                    globalFunctions = Object.assign({}, GLOBAL_FUNCTIONS_DEFAULT, parsed);
                    return;
                }
            }
        } catch (e) {
            console.error('[Func] DB 读取失败，回退 JSON:', e.message);
        }
    }
    // DB 无数据或不可用 → 尝试从 JSON 文件加载（保留历史配置）
    try {
        if (fs.existsSync(GLOBAL_FUNCTIONS_FILE)) {
            const s = JSON.parse(fs.readFileSync(GLOBAL_FUNCTIONS_FILE, 'utf8'));
            if (s && typeof s === 'object') {
                globalFunctions = Object.assign({}, GLOBAL_FUNCTIONS_DEFAULT, s);
            }
        }
    } catch (e) { console.error('[Func] 加载全局功能控制失败:', e.message); }
    // 若 DB 可用但尚无记录，把当前（默认值或 JSON 内容）写回 DB，使 SQL 成为权威存储
    if (DB_AVAILABLE && pool) {
        try { await saveGlobalFunctions(); } catch (_) {}
    }
}
// 保存全局功能控制：DB 优先（UPSERT 单行），失败回退 JSON 文件
async function saveGlobalFunctions() {
    if (DB_AVAILABLE && pool) {
        try {
            const updatedAt = new Date().toISOString();
            await pool.query(
                "INSERT INTO global_functions (id, data, updated_at) VALUES ('global', ?, ?) " +
                "ON DUPLICATE KEY UPDATE data=VALUES(data), updated_at=VALUES(updated_at)",
                [JSON.stringify(globalFunctions), updatedAt]
            );
            return; // DB 写入成功，无需再写 JSON（JSON 仅作兜底）
        } catch (e) {
            console.error('[Func] DB 写入失败，回退 JSON:', e.message);
        }
    }
    ensureDataDir();
    try { fs.writeFileSync(GLOBAL_FUNCTIONS_FILE, JSON.stringify(globalFunctions, null, 2)); }
    catch (e) { console.error('[Func] 保存全局功能控制失败:', e.message); }
}

// ===== 每日挑战自定义配置（admin 可编辑并设持续天数，默认1天）=====
const DAILY_CHALLENGE_FILE = path.join(DATA_DIR, 'daily-challenge-config.json');
// 结构：{ enabled, type, level(0=自动), durationDays(默认1), startDate(YYYY-MM-DD), rewards:{coins,stars}|null, createdAt, createdBy }
let dailyChallengeConfig = {
    enabled: false,
    type: 'speed',
    level: 0,
    durationDays: 1,
    startDate: '',
    rewards: null,
    createdAt: null,
    createdBy: null
};

function serverTodayString() {
    return new Date().toISOString().split('T')[0];
}
// 在 YYYY-MM-DD 上加 n 天，返回 YYYY-MM-DD
function addDaysToDateString(dateStr, n) {
    const d = new Date(dateStr + 'T00:00:00Z');
    d.setUTCDate(d.getUTCDate() + n);
    return d.toISOString().split('T')[0];
}

// 加载每日挑战配置：DB 优先（daily_challenge_config 表，单例行 id='current'），失败回退 JSON 文件
async function loadDailyChallengeConfig() {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query("SELECT data FROM daily_challenge_config WHERE id='current'");
            if (rows && rows.length && rows[0].data) {
                const parsed = (typeof rows[0].data === 'string') ? JSON.parse(rows[0].data) : rows[0].data;
                if (parsed && typeof parsed === 'object') {
                    dailyChallengeConfig = Object.assign({}, dailyChallengeConfig, parsed);
                    return;
                }
            }
        } catch (e) {
            console.error('[DailyChallenge] DB 读取失败，回退 JSON:', e.message);
        }
    }
    try {
        if (fs.existsSync(DAILY_CHALLENGE_FILE)) {
            const s = JSON.parse(fs.readFileSync(DAILY_CHALLENGE_FILE, 'utf8'));
            if (s && typeof s === 'object') {
                dailyChallengeConfig = Object.assign({}, dailyChallengeConfig, s);
            }
        }
    } catch (e) { console.error('[DailyChallenge] 加载失败:', e.message); }
    if (DB_AVAILABLE && pool) {
        try { await saveDailyChallengeConfig(); } catch (_) {}
    }
}
// 保存每日挑战配置：DB 优先（UPSERT 单行），失败回退 JSON 文件
async function saveDailyChallengeConfig() {
    if (DB_AVAILABLE && pool) {
        try {
            const updatedAt = new Date().toISOString();
            await pool.query(
                "INSERT INTO daily_challenge_config (id, data, updated_at) VALUES ('current', ?, ?) " +
                "ON DUPLICATE KEY UPDATE data=VALUES(data), updated_at=VALUES(updated_at)",
                [JSON.stringify(dailyChallengeConfig), updatedAt]
            );
            return;
        } catch (e) {
            console.error('[DailyChallenge] DB 写入失败，回退 JSON:', e.message);
        }
    }
    ensureDataDir();
    try { fs.writeFileSync(DAILY_CHALLENGE_FILE, JSON.stringify(dailyChallengeConfig, null, 2)); }
    catch (e) { console.error('[DailyChallenge] 保存失败:', e.message); }
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
    joystickPosition: 'bottom-right',
    uiMode: 'new'
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
    // 若 actor 是通用角色字面量、且本次请求携带真实管理员身份，则附加账号名，
    // 便于追溯「哪个管理员对哪个用户做了什么」（detail 中已写明被操作的目标用户）
    if ((actor === 'admin' || actor === 'superadmin') && req && req.admin) {
        const nm = req.admin.name;
        const role = req.admin.role || actor;
        actor = nm ? (nm + '（' + role + '）') : role;
    }
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
const SERVER_VERSION = "1.15.7";
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
// 管理员是否调整过该用户金币（调整后以管理员账本为准，客户端下次上报需直接覆盖本地，否则被玩家本地值冲掉）
const adminCoinOverride = new Map();
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

// 判断某 IP 是否处于封禁中。expiresAt 为 null/空表示永久封禁；
// 已到期的记录在此处惰性清理（内存 + 持久层），确保判定与存储始终一致。
function isIPBanned(ip) {
    if (!ip) return false;
    const key = String(ip);
    const rec = bannedIPs.get(key);
    if (!rec) return false;
    if (ipBanExpired(rec)) {
        bannedIPs.delete(key);
        Promise.resolve(dbDeleteBannedIP(key)).catch(() => {});
        return false;
    }
    return true;
}

// 封禁记录是否已到期（永久封禁恒为 false）
function ipBanExpired(rec) {
    if (!rec || !rec.expiresAt) return false;
    const t = Date.parse(rec.expiresAt);
    return !isNaN(t) && t <= Date.now();
}

// 取有效封禁记录（已到期返回 null，不做清理）
function getIPBan(ip) {
    if (!ip) return null;
    const rec = bannedIPs.get(String(ip));
    if (!rec || ipBanExpired(rec)) return null;
    return rec;
}

// 人类可读的封禁期限描述，用于弹窗/日志
function describeIPBan(rec) {
    if (!rec || !rec.expiresAt) return '永久';
    const ms = Date.parse(rec.expiresAt) - Date.now();
    if (isNaN(ms) || ms <= 0) return '已到期';
    const d = Math.floor(ms / 86400000);
    const h = Math.floor((ms % 86400000) / 3600000);
    const m = Math.floor((ms % 3600000) / 60000);
    if (d > 0) return `剩余 ${d} 天 ${h} 小时`;
    if (h > 0) return `剩余 ${h} 小时 ${m} 分钟`;
    return `剩余 ${Math.max(1, m)} 分钟`;
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
// ip -> { ip, reason, bannedAt, expiresAt, bannedBy }，管理员按 IP 封禁（所有功能禁用 + 客户端强制全屏弹窗）
// expiresAt 为 null 表示永久封禁，否则为 ISO 时间字符串（到期自动解封）。持久化到 banned_ips 表，JSON 兜底。
const bannedIPs = new Map();

// ===== IP 封禁持久化（DB 优先 + JSON 兜底，重启不丢失）=====
const BANNED_IPS_FILE = path.join(DATA_DIR, 'banned-ips.json');

function saveBannedIPsJson() {
    try {
        ensureDataDir();
        fs.writeFileSync(BANNED_IPS_FILE, JSON.stringify(Array.from(bannedIPs.values()), null, 2));
    } catch (e) { console.error('[IP封禁] JSON 保存失败:', e.message); }
}

// 统一把一行 DB 记录/JSON 记录归一化为内存结构
function normalizeBanRecord(r) {
    if (!r) return null;
    return {
        ip: String(r.ip || ''),
        reason: r.reason || '',
        bannedAt: r.bannedAt || r.banned_at || '',
        expiresAt: r.expiresAt || r.expires_at || null,   // null = 永久
        bannedBy: r.bannedBy || r.banned_by || 'admin',
        username: r.username || null,
        clientId: r.clientId || r.client_id || null
    };
}

async function loadBannedIPs() {
    try {
        if (DB_AVAILABLE && pool) {
            const [rows] = await pool.query('SELECT * FROM banned_ips');
            if (rows) rows.forEach(r => {
                const rec = normalizeBanRecord(r);
                if (rec && rec.ip) bannedIPs.set(rec.ip, rec);
            });
        } else if (fs.existsSync(BANNED_IPS_FILE)) {
            const arr = JSON.parse(fs.readFileSync(BANNED_IPS_FILE, 'utf8'));
            if (Array.isArray(arr)) arr.forEach(r => {
                const rec = normalizeBanRecord(r);
                if (rec && rec.ip) bannedIPs.set(rec.ip, rec);
            });
        }
        // 启动即清掉已到期的记录，避免脏数据长期驻留
        let expired = 0;
        for (const [ip, rec] of Array.from(bannedIPs.entries())) {
            if (ipBanExpired(rec)) { bannedIPs.delete(ip); await dbDeleteBannedIP(ip); expired++; }
        }
        console.log(`[IP封禁] 已载入 ${bannedIPs.size} 条封禁记录${expired ? `（清理过期 ${expired} 条）` : ''}`);
    } catch (e) { console.error('[IP封禁] 载入失败:', e.message); }
}

async function dbSaveBannedIP(rec) {
    if (!rec || !rec.ip) return;
    bannedIPs.set(rec.ip, rec);
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query(
                'INSERT INTO banned_ips (ip, reason, banned_at, expires_at, banned_by, username, client_id) VALUES (?,?,?,?,?,?,?) ' +
                'ON DUPLICATE KEY UPDATE reason=VALUES(reason), banned_at=VALUES(banned_at), expires_at=VALUES(expires_at), banned_by=VALUES(banned_by), username=VALUES(username), client_id=VALUES(client_id)',
                [rec.ip, rec.reason || '', rec.bannedAt || '', rec.expiresAt || null, rec.bannedBy || 'admin', rec.username || null, rec.clientId || null]);
            return;
        } catch (e) { console.error('[IP封禁] DB 写入失败:', e.message); }
    }
    saveBannedIPsJson();
}

async function dbDeleteBannedIP(ip) {
    if (!ip) return;
    bannedIPs.delete(String(ip));
    if (DB_AVAILABLE && pool) {
        try { await pool.query('DELETE FROM banned_ips WHERE ip=?', [String(ip)]); return; }
        catch (e) { console.error('[IP封禁] DB 删除失败:', e.message); }
    }
    saveBannedIPsJson();
}

// ===== 封禁历史（统一记录 IP / 云账号的封禁与解封，供反作弊标签页完整展示）=====
// 与 banned_ips / cloud_storage_accounts 的区别：这里保留历史——即使已解封也不删除，
// 只标记 unbanned_at，从而反作弊标签页能展示「已解封 / 未解封」并设置 10 天时间窗。
const banHistory = new Map(); // id -> 归一化记录
const BAN_HISTORY_FILE = path.join(DATA_DIR, 'ban-history.json');

function saveBanHistoryJson() {
    try { ensureDataDir(); fs.writeFileSync(BAN_HISTORY_FILE, JSON.stringify(Array.from(banHistory.values()), null, 2)); }
    catch (e) { console.error('[封禁历史] JSON 保存失败:', e.message); }
}

function normalizeBanHistory(r) {
    if (!r) return null;
    return {
        id: r.id || ('bh_' + (r.type || 'ip') + '_' + (r.target || '')),
        type: String(r.type || 'ip'),
        target: String(r.target || ''),
        username: r.username || null,
        clientId: r.client_id || r.clientId || null,
        reason: r.reason || '',
        bannedAt: r.bannedAt || r.banned_at || '',
        expiresAt: r.expiresAt || r.expires_at || null,
        unbannedAt: r.unbannedAt || r.unbanned_at || null,
        unbannedBy: r.unbannedBy || r.unbanned_by || null,
        bannedBy: r.bannedBy || r.banned_by || 'admin'
    };
}

async function loadBanHistory() {
    try {
        if (DB_AVAILABLE && pool) {
            const [rows] = await pool.query('SELECT * FROM ban_history');
            if (rows) rows.forEach(r => { const rec = normalizeBanHistory(r); if (rec && rec.id) banHistory.set(rec.id, rec); });
        } else if (fs.existsSync(BAN_HISTORY_FILE)) {
            const arr = JSON.parse(fs.readFileSync(BAN_HISTORY_FILE, 'utf8'));
            if (Array.isArray(arr)) arr.forEach(r => { const rec = normalizeBanHistory(r); if (rec && rec.id) banHistory.set(rec.id, rec); });
        }
        console.log(`[封禁历史] 已载入 ${banHistory.size} 条记录`);
    } catch (e) { console.error('[封禁历史] 载入失败:', e.message); }
}

// 写入/更新一条封禁历史（按 id 幂等：重新封禁会覆盖并清掉旧的解封标记）
async function dbSaveBanHistory(rec) {
    if (!rec || !rec.id) return;
    const norm = normalizeBanHistory(rec);
    banHistory.set(norm.id, norm);
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query(
                'INSERT INTO ban_history (id, type, target, username, client_id, reason, banned_at, expires_at, unbanned_at, unbanned_by, banned_by) VALUES (?,?,?,?,?,?,?,?,?,?,?) ' +
                'ON DUPLICATE KEY UPDATE type=VALUES(type), target=VALUES(target), username=VALUES(username), client_id=VALUES(client_id), reason=VALUES(reason), banned_at=VALUES(banned_at), expires_at=VALUES(expires_at), unbanned_at=VALUES(unbanned_at), unbanned_by=VALUES(unbanned_by), banned_by=VALUES(banned_by)',
                [norm.id, norm.type, norm.target, norm.username || null, norm.clientId || null, norm.reason || '', norm.bannedAt || '', norm.expiresAt || null, norm.unbannedAt || null, norm.unbannedBy || null, norm.bannedBy || 'admin']);
            return;
        } catch (e) { console.error('[封禁历史] DB 写入失败:', e.message); }
    }
    saveBanHistoryJson();
}

// ===== 作弊封禁日志（cheat_log 表）：记录所有因作弊被封禁的玩家（client_id / 用户名 / ip / 封禁时间）=====
const CHEAT_LOG_FILE = path.join(DATA_DIR, 'cheat-log.json');
const cheatLog = new Map(); // id -> { id, clientId, username, ip, cheatType, reason, bannedAt, expiresAt, createdAt }

function normalizeCheatLog(r) {
    if (!r) return null;
    return {
        id: String(r.id || ''),
        clientId: r.client_id || r.clientId || null,
        username: r.username || null,
        ip: r.ip || null,
        cheatType: r.cheat_type || r.cheatType || null,
        reason: r.reason || null,
        bannedAt: r.banned_at || r.bannedAt || null,
        expiresAt: (r.expires_at !== undefined ? r.expires_at : r.expiresAt) || null,
        createdAt: r.created_at || r.createdAt || null
    };
}

async function loadCheatLog() {
    try {
        if (DB_AVAILABLE && pool) {
            const [rows] = await pool.query('SELECT * FROM cheat_log');
            if (rows) rows.forEach(r => { const rec = normalizeCheatLog(r); if (rec && rec.id) cheatLog.set(rec.id, rec); });
        } else if (fs.existsSync(CHEAT_LOG_FILE)) {
            const arr = JSON.parse(fs.readFileSync(CHEAT_LOG_FILE, 'utf8'));
            if (Array.isArray(arr)) arr.forEach(r => { const rec = normalizeCheatLog(r); if (rec && rec.id) cheatLog.set(rec.id, rec); });
        }
        console.log(`[作弊日志] 已载入 ${cheatLog.size} 条记录`);
    } catch (e) { console.error('[作弊日志] 载入失败:', e.message); }
}

function saveCheatLogJson() {
    try { fs.writeFileSync(CHEAT_LOG_FILE, JSON.stringify(Array.from(cheatLog.values()), null, 2)); }
    catch (e) { console.error('[作弊日志] 写入失败:', e.message); }
}

async function dbSaveCheatLog(rec) {
    if (!rec || !rec.id) return;
    const norm = normalizeCheatLog(rec);
    cheatLog.set(norm.id, norm);
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query(
                'INSERT INTO cheat_log (id, client_id, username, ip, cheat_type, reason, banned_at, expires_at, created_at) VALUES (?,?,?,?,?,?,?,?,?) ' +
                'ON DUPLICATE KEY UPDATE client_id=VALUES(client_id), username=VALUES(username), ip=VALUES(ip), cheat_type=VALUES(cheat_type), reason=VALUES(reason), banned_at=VALUES(banned_at), expires_at=VALUES(expires_at), created_at=VALUES(created_at)',
                [norm.id, norm.clientId || null, norm.username || null, norm.ip || null, norm.cheatType || null, norm.reason || '', norm.bannedAt || null, norm.expiresAt || null, norm.createdAt || null]
            );
            return;
        } catch (e) { console.error('[作弊日志] DB 写入失败:', e.message); }
    }
    saveCheatLogJson();
}

// 标记历史为「已解封」：同一 type+target 可能有多条独立记录（每次封禁一条），
// 取 bannedAt 最新的一条未解封记录标记（代表当前生效的那次封禁）
async function dbUpdateBanHistoryUnban(type, target, by) {
    if (!target) return;
    let latest = null;
    for (const rec of banHistory.values()) {
        if (rec.type !== type || rec.target !== target) continue;
        if (rec.unbannedAt) continue;
        if (!latest || String(rec.bannedAt) > String(latest.bannedAt)) latest = rec;
    }
    if (!latest) return; // 没有未解封记录则无需更新
    latest.unbannedAt = new Date().toISOString();
    latest.unbannedBy = by || 'admin';
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query('UPDATE ban_history SET unbanned_at=?, unbanned_by=? WHERE id=?',
                [latest.unbannedAt, latest.unbannedBy, latest.id]);
            return;
        } catch (e) { console.error('[封禁历史] DB 解封更新失败:', e.message); }
    }
    saveBanHistoryJson();
}

// 读取全部封禁历史（DB 优先 + JSON 兜底）
async function dbGetBanHistory() {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT * FROM ban_history');
            if (rows && rows.length) return rows.map(r => normalizeBanHistory(r)).filter(r => r && r.id);
        } catch (e) { console.error('[封禁历史] DB 读取失败:', e.message); }
    }
    return Array.from(banHistory.values());
}

// 模块加载时先按 JSON 兜底载入；若随后 MySQL 连接成功，initDatabase 会再从库覆盖载入一次
loadBannedIPs().catch(e => console.error('[IP封禁] 载入失败:', e.message));
loadBanHistory().catch(e => console.error('[封禁历史] 载入失败:', e.message));
loadCheatLog().catch(e => console.error('[作弊日志] 载入失败:', e.message));

// 解析封禁时长请求体 -> expiresAt（null 表示永久）
// 支持：{ permanent:true } | { durationDays:5 } | { durationHours:12 } | { durationMinutes:30 } | { expiresAt:'ISO' }
// 三者可叠加（如 1天+12小时）。未指定任何时长时默认永久，与旧版行为保持一致。
function parseBanExpiry(body) {
    const b = body || {};
    if (b.permanent === true) return null;
    if (b.expiresAt) {
        const t = Date.parse(b.expiresAt);
        if (!isNaN(t) && t > Date.now()) return new Date(t).toISOString();
    }
    const days = Number(b.durationDays) || 0;
    const hours = Number(b.durationHours) || 0;
    const minutes = Number(b.durationMinutes) || 0;
    const ms = days * 86400000 + hours * 3600000 + minutes * 60000;
    if (ms > 0) return new Date(Date.now() + ms).toISOString();
    return null; // 未指定 -> 永久
}

// 统一封禁入口：写持久层 + 封禁该 IP 下所有在线玩家的全部玩法 + 实时推送全屏弹窗
// expiresAt 为 null 表示永久封禁
// meta: { username, clientId } 可选，用于反作弊标签页展示被封玩家身份 + 客户端申诉定位
async function applyIPBan(ipKey, reason, expiresAt, actor, meta) {
    const rec = {
        ip: String(ipKey),
        reason: (reason && String(reason).trim()) || '',
        bannedAt: new Date().toISOString(),
        expiresAt: expiresAt || null,
        bannedBy: actor || 'admin',
        username: (meta && meta.username) ? String(meta.username).slice(0, 128) : null,
        clientId: (meta && meta.clientId) ? String(meta.clientId).slice(0, 64) : null
    };
    await dbSaveBannedIP(rec);
    // 写入封禁历史（供反作弊标签页展示，含后续解封状态）
    await dbSaveBanHistory({
        id: 'bh_ip_' + rec.ip + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        type: 'ip',
        target: rec.ip,
        username: rec.username,
        clientId: rec.clientId,
        reason: rec.reason,
        bannedAt: rec.bannedAt,
        expiresAt: rec.expiresAt,
        unbannedAt: null,
        unbannedBy: null,
        bannedBy: rec.bannedBy
    });

    const term = describeIPBan(rec);
    const msg = 'IP 封禁：' + (rec.reason || '管理员封禁此 IP') + `（${term}）`;
    for (const [uid, pl] of onlinePlayers.entries()) {
        if (pl && pl.ip === rec.ip) {
            const ban = userBans.get(uid) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
            if (!ban.reasons) ban.reasons = {};
            ban.multiplayer = ban.single = ban.puzzle = ban.chat = true;
            ban.reasons.multiplayer = ban.reasons.single = ban.reasons.puzzle = ban.reasons.chat = msg;
            userBans.set(uid, ban);
            const sockId = onlineSockets.get(uid);
            if (sockId && sockId !== 'rest') {
                const sock = io.sockets.sockets.get(sockId);
                if (sock) sock.emit('ip-banned', {
                    reason: rec.reason,
                    permanent: !rec.expiresAt,
                    expiresAt: rec.expiresAt,
                    term: term,
                    ip: rec.ip || null,
                    username: rec.username || null,
                    clientId: rec.clientId || null
                });
            }
        }
    }
    return rec;
}

// 统一解封入口：删持久层 + 解除该 IP 下在线玩家封禁 + 通知客户端关闭弹窗
// by: 操作来源（'admin' | 'system' | 'appeal' 等），用于标记历史解封人
async function removeIPBan(ipKey, by) {
    const ip = String(ipKey);
    await dbDeleteBannedIP(ip);
    await dbUpdateBanHistoryUnban('ip', ip, by || 'admin');
    for (const [uid, pl] of onlinePlayers.entries()) {
        if (pl && pl.ip === ip) {
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
}

// 到期自动解封：每分钟扫描一次限时封禁记录，到点即恢复并通知在线客户端
setInterval(() => {
    try {
        for (const [ip, rec] of Array.from(bannedIPs.entries())) {
            if (ipBanExpired(rec)) {
                removeIPBan(ip, 'system')
                    .then(() => console.log(`[IP封禁] ${ip} 封禁到期，已自动解封`))
                    .catch(e => console.error('[IP封禁] 自动解封失败:', e.message));
            }
        }
    } catch (e) { console.error('[IP封禁] 到期扫描异常:', e.message); }
}, 60 * 1000);
// 玩家角色（游戏内权限）：userId -> { role:'user'|'admin'|'superadmin', setBy, setAt }
let userRoles = new Map();
const cheatReports = [];           // 反作弊上报记录：{ id, clientId, type, detail, time }
// 作弊类型 -> 中文名（用于封禁提示与审计日志）
const CHEAT_TYPE_NAMES = {
    coin_tamper: '金币存档篡改',
    coin_injection: '金币异常变动',
    impossible_speed: '异常通关速度',
    forged_complete: '伪造通关',
    anti_debug_tamper: '篡改/移除反调试警告遮罩',
    devtools_open: '打开开发者工具'
};
// 触发「直接按 IP 封禁」的严重作弊类型 -> 封禁天数
// 这类行为是主动对抗反作弊系统本身，故按 IP 封禁而不仅仅封单个账号
const IP_BAN_CHEAT_TYPES = {
    anti_debug_tamper: 5,
    devtools_open: 5
};
// 反调试类封禁时长：首次 3 小时，按被封次数翻倍递增，封顶 7 天（168 小时）
// 用于「打开开发者工具 / 篡改反调试遮罩」这类对抗行为的渐进式惩罚
const DEVTOOLS_BAN_BASE_HOURS = 3;
const DEVTOOLS_BAN_MAX_HOURS = 24 * 7;

// 统计某 clientId 历史上的反调试类 IP 封禁次数（用于按次数递增封禁时长）
async function countDevtoolsBans(clientId) {
    if (!clientId) return 0;
    const key = String(clientId).slice(0, 64);
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query(
                "SELECT COUNT(*) AS c FROM ban_history WHERE client_id=? AND type='ip' AND (reason LIKE ? OR reason LIKE ?)",
                [key, '%开发者工具%', '%反调试%']
            );
            return (rows[0] && rows[0].c) || 0;
        } catch (e) { /* 回退 JSON 模式 */ }
    }
    let c = 0;
    banHistory.forEach(r => {
        if (r.clientId === key && r.type === 'ip' && /开发者工具|反调试/.test(r.reason || '')) c++;
    });
    return c;
}
const roomChats = new Map();       // roomId -> [{messageId, sender, clientId, message, image, isAdmin, time}]，房间聊天记录（客户端镜像上报，供管理员监管），每房间上限 200 条
const onlineSockets = new Map();   // playerId(peer id) -> socket.id，供远程控制精准投递
const notificationSockets = new Map(); // clientId -> 通知 socket 的 id（好友/好友请求/私聊等统一推到通知 socket）
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
    const cur = reportedProgress.get(id) || { unlockedLevel: 1, completedLevels: [], puzzleCompletedLevels: [], customCompletedLevels: [], lastReportedAt: null };
    if (typeof p.unlockedLevel === 'number' && !isNaN(p.unlockedLevel)) cur.unlockedLevel = Math.max(cur.unlockedLevel || 1, p.unlockedLevel);
    if (Array.isArray(p.completedLevels)) {
        const set = new Set([...(cur.completedLevels || []), ...p.completedLevels]);
        cur.completedLevels = Array.from(set).filter(n => typeof n === 'number' && n > 0).slice(0, 200);
    }
    if (Array.isArray(p.puzzleCompletedLevels)) {
        const set = new Set([...(cur.puzzleCompletedLevels || []), ...p.puzzleCompletedLevels]);
        cur.puzzleCompletedLevels = Array.from(set).filter(n => typeof n === 'number' && n > 0).slice(0, 200);
    }
    if (Array.isArray(p.customCompletedLevels)) {
        const set = new Set([...(cur.customCompletedLevels || []), ...p.customCompletedLevels]);
        cur.customCompletedLevels = Array.from(set).filter(n => typeof n === 'number' && n > 0).slice(0, 200);
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
// 加载热门迷宫：DB 优先（popular_mazes 表），失败回退 JSON 文件（data/mazes.json）
async function loadMazes() {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT * FROM popular_mazes');
            if (rows && rows.length) {
                mazes.clear();
                rows.forEach(r => {
                    mazes.set(r.id, {
                        id: r.id,
                        name: r.name,
                        description: r.description,
                        difficulty: r.difficulty,
                        size: r.size,
                        data: parseJsonCol(r.data),
                        teleporters: parseJsonCol(r.teleporters) || [],
                        enemySpeed: r.enemy_speed,
                        showShop: !!r.show_shop,
                        sourceMazeId: r.source_maze_id,
                        author: r.author,
                        authorName: r.author_name,
                        createdAt: r.created_at ? Number(r.created_at) : null,
                        updatedAt: r.updated_at ? Number(r.updated_at) : null
                    });
                });
                console.log(`[迷宫] 已从数据库加载 ${mazes.size} 个热门迷宫`);
                return;
            }
            // DB 表为空：若内存已有数据（来自启动时 JSON 兜底），写回 DB 完成迁移
            if (mazes.size) {
                try { await saveMazes(); console.log('[迷宫] 已将 JSON 兜底数据迁移至数据库'); } catch (_) {}
            }
            return;
        } catch (e) {
            console.error('[迷宫] DB 读取失败，回退 JSON:', e.message);
        }
    }
    // JSON 兜底
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
// 保存热门迷宫：DB 优先（全量同步到 popular_mazes 表），失败回退 JSON 文件
async function saveMazes() {
    if (DB_AVAILABLE && pool) {
        try {
            const arr = Array.from(mazes.values());
            await pool.query('DELETE FROM popular_mazes');
            for (const m of arr) {
                await pool.query(
                    'INSERT INTO popular_mazes (id,name,description,difficulty,size,data,teleporters,enemy_speed,show_shop,source_maze_id,author,author_name,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    [
                        m.id, m.name, m.description || '', m.difficulty || '简单',
                        m.size || 10, JSON.stringify(m.data || null), JSON.stringify(m.teleporters || []),
                        m.enemySpeed || 1, m.showShop !== false ? 1 : 0, m.sourceMazeId || null,
                        m.author || null, m.authorName || null,
                        String(m.createdAt || Date.now()), String(m.updatedAt || Date.now())
                    ]
                );
            }
            return; // DB 写入成功，JSON 仅作兜底
        } catch (e) {
            console.error('[迷宫] DB 写入失败，回退 JSON:', e.message);
        }
    }
    // JSON 兜底
    try {
        ensureDataDir();
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
    // 解析令牌中的操作者身份，便于记录「公告发布者」等信息
    let decoded = null;
    try { decoded = jwt.verify(token, JWT_SECRET); } catch (err) { decoded = null; }
    if (verifyAdminToken(token) || verifySuperAdminToken(token)) {
        req.admin = {
            name: decoded ? decoded.name : null,
            role: decoded ? decoded.role : 'admin',
            accountId: decoded ? decoded.accountId : null
        };
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
        if (!newPassword || String(newPassword).length < 1) {
            return res.status(400).json({ success: false, message: '新密码不能为空' });
        }
        // target 可以是内置角色 'admin'/'superadmin'，也可以是自定义账号 id（acc_xxx）
        const isBuiltIn = target === 'admin' || target === 'superadmin';
        const account = isBuiltIn ? null : getAccountById(target);
        if (!isBuiltIn && !account) {
            return res.status(404).json({ success: false, message: '账号不存在' });
        }
        const hash = bcrypt.hashSync(String(newPassword), 10);
        if (isBuiltIn) {
            const filePath = target === 'admin' ? path.join(__dirname, 'admin-password.txt') : SUPERADMIN_PASSWORD_PATH;
            fs.writeFileSync(filePath, hash);
            // 同步更新默认账号（acc_admin / acc_superadmin）的密码哈希，保持一致
            const defId = target === 'admin' ? 'acc_admin' : 'acc_superadmin';
            const defAcc = getAccountById(defId);
            if (defAcc) { defAcc.passwordHash = hash; await saveAccounts(); }
            if (target === 'admin') {
                adminTokens.clear(); // 改密后使旧管理员令牌失效
                appendAudit('superadmin', 'change-admin-password', '修改了管理员密码', req);
            } else {
                superAdminTokens.clear();
                appendAudit('superadmin', 'change-superadmin-password', '修改了超级管理员密码', req);
            }
            res.json({ success: true, message: `已更新 ${target} 密码` });
        } else {
            account.passwordHash = hash;
            await saveAccounts();
            // 使该角色所有令牌失效，确保被改密账号立即下线
            if (account.role === 'superadmin') superAdminTokens.clear(); else adminTokens.clear();
            appendAudit('superadmin', 'change-account-password', `修改了 ${account.role} 账号「${account.name}」的密码`, req);
            res.json({ success: true, message: `已更新账号 ${account.name} 的密码` });
        }
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

// 删除自定义账号（不能删除内置默认账号 acc_admin / acc_superadmin）
app.delete('/api/superadmin/accounts/:accountId', requireSuperAdminAuth, async (req, res) => {
    try {
        const accountId = req.params.accountId;
        if (accountId === 'acc_admin' || accountId === 'acc_superadmin') {
            return res.status(400).json({ success: false, message: '不能删除内置默认账号' });
        }
        const idx = accounts.findIndex(a => a.id === accountId);
        if (idx === -1) return res.status(404).json({ success: false, message: '账号不存在' });
        const account = accounts[idx];
        accounts.splice(idx, 1);
        // 同步从数据库删除
        if (DB_AVAILABLE && pool) {
            try { await pool.query('DELETE FROM accounts WHERE id=?', [accountId]); }
            catch (e) { console.error('[Accounts] DB 删除账号失败:', e.message); }
        }
        await saveAccounts();
        // 使该角色所有令牌失效，确保被删除账号立即下线
        if (account.role === 'superadmin') superAdminTokens.clear(); else adminTokens.clear();
        appendAudit('superadmin', 'delete-account', `删除了 ${account.role} 账号「${account.name}」`, req);
        res.json({ success: true, message: `已删除账号 ${account.name}` });
    } catch (e) {
        console.error('[SuperAdmin] 删除账号失败:', e);
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

// ===== 个人主页（多人联机可查看对方名称/头像/简介）=====
const HOME_PROFILES_FILE = path.join(DATA_DIR, 'home-profiles.json');
// 结构：{ name, avatar(emoji), color(hex), bio, disabled, adminOverridden }
let homeProfiles = new Map();

// 为已存在的 home_profiles 表补齐 can_view_others 列（幂等：列已存在则忽略报错）
async function ensureHomeProfilesCanViewOthers() {
    if (!DB_AVAILABLE || !pool) return;
    try {
        await pool.query('ALTER TABLE home_profiles ADD COLUMN can_view_others TINYINT(1) DEFAULT 1');
    } catch (e) {
        // 1060 = Duplicate column name；其他错误也忽略（只要列已存在即可）
        if (e && e.code !== 'ER_DUP_FIELDNAME' && !/duplicate column/i.test(e.message || '')) {
            console.error('[Home] 增加 can_view_others 列失败:', e.message);
        }
    }
}
async function loadHomeProfiles() {
    if (DB_AVAILABLE && pool) {
        try {
            await ensureHomeProfilesCanViewOthers();
            const [rows] = await pool.query('SELECT client_id, name, avatar, color, bio, disabled, admin_overridden, can_view_others, updated_at FROM home_profiles');
            homeProfiles = new Map();
            rows.forEach(r => { if (r && r.client_id) homeProfiles.set(r.client_id, { name: r.name, avatar: r.avatar, color: r.color, bio: r.bio, disabled: !!r.disabled, adminOverridden: !!r.admin_overridden, canViewOthers: r.can_view_others == null ? true : !!r.can_view_others, updatedAt: r.updated_at }); });
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
                    'INSERT INTO home_profiles (client_id, name, avatar, color, bio, disabled, admin_overridden, can_view_others, updated_at) VALUES (?,?,?,?,?,?,?,?,?) ' +
                    'ON DUPLICATE KEY UPDATE name=VALUES(name),avatar=VALUES(avatar),color=VALUES(color),bio=VALUES(bio),disabled=VALUES(disabled),admin_overridden=VALUES(admin_overridden),can_view_others=VALUES(can_view_others),updated_at=VALUES(updated_at)',
                    [clientId, p.name || '', p.avatar || '🙂', p.color || '#4CAF50', p.bio || '', p.disabled ? 1 : 0, p.adminOverridden ? 1 : 0, (p.canViewOthers === false ? 0 : 1), p.updatedAt || new Date().toISOString()]
                );
            }
        } catch (e) { console.error('[Home] DB 保存失败:', e.message); }
    }
}
// ===== 好友系统：好友请求 / 好友关系 / 好友私聊 =====
// 持久化到 data/friends.json（内存 Map + JSON 文件）。本项目“优先 MySQL、未配 DB 回退 JSON”，
// 好友属新增自包含关系数据，且私聊消息高频，为避免在共享 filess.io 库上频繁建表/写库触发连接上限，
// 此处采用 JSON 文件存储（即回退路径），稳定且零迁移风险；后续如需可补 MySQL 表。
const FRIENDS_FILE = path.join(DATA_DIR, 'friends.json');
// friendRequests: Map requestId -> {id, fromClientId, fromName, toClientId, toName, status, createdAt, updatedAt}
// friendships:   Map `${a}|${b}`(a<b) -> {userA, userB, createdAt}
// friendMessages: Map chatId `${a}|${b}`(a<b) -> [{id, fromClientId, toClientId, message, createdAt}]
let friendRequests = new Map();
let friendships = new Map();
let friendMessages = new Map();
let _friendReqSeq = 1;

function friendshipKey(a, b) { return [String(a), String(b)].sort().join('|'); }

function loadFriends() {
    try {
        if (fs.existsSync(FRIENDS_FILE)) {
            const d = JSON.parse(fs.readFileSync(FRIENDS_FILE, 'utf8')) || {};
            (d.requests || []).forEach(r => { if (r && r.id) friendRequests.set(r.id, r); });
            (d.friendships || []).forEach(f => { if (f && f.userA && f.userB) friendships.set(friendshipKey(f.userA, f.userB), f); });
            (d.messages || []).forEach(m => {
                if (m && m.fromClientId && m.toClientId) {
                    const k = friendshipKey(m.fromClientId, m.toClientId);
                    if (!friendMessages.has(k)) friendMessages.set(k, []);
                    friendMessages.get(k).push(m);
                }
            });
        }
    } catch (e) { console.error('[Friends] 加载失败:', e.message); }
    for (const r of friendRequests.keys()) {
        const n = parseInt(String(r).replace(/[^0-9]/g, ''), 10);
        if (!isNaN(n) && n >= _friendReqSeq) _friendReqSeq = n + 1;
    }
}
function saveFriends() {
    ensureDataDir();
    try {
        const msgs = [];
        for (const arr of friendMessages.values()) arr.forEach(m => msgs.push(m));
        const data = {
            requests: Array.from(friendRequests.values()),
            friendships: Array.from(friendships.values()),
            messages: msgs
        };
        fs.writeFileSync(FRIENDS_FILE, JSON.stringify(data, null, 2));
    } catch (e) { console.error('[Friends] 保存失败:', e.message); }
}
function areFriends(a, b) { return friendships.has(friendshipKey(a, b)); }
// 找到 a、b 之间处于 pending 的请求（任意方向），返回该请求或 null
function findPendingRequest(a, b) {
    for (const r of friendRequests.values()) {
        if (r.status !== 'pending') continue;
        if ((r.fromClientId === a && r.toClientId === b) || (r.fromClientId === b && r.toClientId === a)) return r;
    }
    return null;
}
// 向指定 clientId 推送 socket 事件（仅当其有活跃 socket 连接时；仅 REST 在线的玩家无法实时收到）
function pushToClientSocket(clientId, event, data) {
    const sid = onlineSockets.get(clientId);
    if (sid && sid !== 'rest') { try { io.to(sid).emit(event, data); } catch (_) {} }
}
// 好友相关推送专用：定向到通知 socket（前端只在 notificationSocket 上监听 friend-* 事件；
// onlineSockets 会被 mp-register / REST 上线覆盖成游戏 socket / 'rest'，不能复用它推好友消息）
function pushToNotificationSocket(clientId, event, data) {
    const sid = notificationSockets.get(clientId);
    if (sid) { try { io.to(sid).emit(event, data); } catch (_) {} }
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

// 好友搜索：按显示名搜索当前在线玩家（公开，无鉴权）
// 仅遍历 onlinePlayers（进入游戏即上线的玩家），匹配不区分大小写的子串；
// 返回轻量预览（头像/颜色/简介），点击后客户端再用 showPlayerProfileModal 拉取完整主页。
app.get('/api/players/search', (req, res) => {
    try {
        const q = (req.query.q || '').toString().trim().toLowerCase();
        if (!q) return res.json({ success: true, players: [] });
        const limit = Math.min(parseInt(req.query.limit) || 50, 100);
        const out = [];
        for (const [clientId, p] of onlinePlayers.entries()) {
            if (!p) continue;
            const name = (p.name || '').toString();
            // 按显示名 或 clientId 匹配（同名玩家可贴 ID 精确查找）
            if (name.toLowerCase().indexOf(q) !== -1 || clientId.toLowerCase().indexOf(q) !== -1) {
                const prof = homeProfiles.get(clientId) || {};
                out.push({
                    clientId: clientId,
                    name: name,
                    avatar: prof.avatar || '😀',
                    color: prof.color || '#4CAF50',
                    bio: (prof.bio || '').toString().slice(0, 60),
                    online: true,
                    roomId: p.roomId || null
                });
                if (out.length >= limit) break;
            }
        }
        res.json({ success: true, players: out });
    } catch (e) {
        console.error('[Search] 好友搜索失败:', e);
        res.status(500).json({ success: false, message: '搜索失败' });
    }
});

// ===== 好友系统 REST 接口（公开，无鉴权；与 player-online 等同属小游戏社交接口）=====

// 发送好友请求
app.post('/api/friends/request', (req, res) => {
    try {
        const { fromClientId, toClientId, fromName, toName } = req.body || {};
        if (!fromClientId || !toClientId) return res.json({ success: false, message: '缺少账号信息' });
        if (fromClientId === toClientId) return res.json({ success: false, message: '不能添加自己为好友' });
        if (areFriends(fromClientId, toClientId)) return res.json({ success: false, message: '你们已经是好友了' });
        if (findPendingRequest(fromClientId, toClientId)) return res.json({ success: false, message: '好友请求已存在，请等待对方通过' });
        const id = 'fr_' + Date.now().toString(36) + '_' + (_friendReqSeq++);
        const now = new Date().toISOString();
        const reqObj = {
            id, fromClientId, fromName: (fromName || '').toString().slice(0, 24),
            toClientId, toName: (toName || '').toString().slice(0, 24),
            status: 'pending', createdAt: now, updatedAt: now
        };
        friendRequests.set(id, reqObj);
        saveFriends();
        pushToNotificationSocket(toClientId, 'friend-request-received', {
            requestId: id, fromClientId, fromName: reqObj.fromName, toClientId, toName: reqObj.toName, createdAt: now
        });
        console.log(`[Friends] ${reqObj.fromName}(${fromClientId}) 请求添加 ${reqObj.toName}(${toClientId}) 为好友`);
        res.json({ success: true, requestId: id });
    } catch (e) {
        console.error('[Friends] 发送请求失败:', e);
        res.status(500).json({ success: false, message: '发送失败' });
    }
});

// 收到的好友请求列表（pending）
app.get('/api/friends/requests', (req, res) => {
    try {
        const clientId = (req.query.clientId || '').toString();
        if (!clientId) return res.json({ success: true, requests: [] });
        const list = [];
        for (const r of friendRequests.values()) {
            if (r.status === 'pending' && r.toClientId === clientId) list.push(r);
        }
        list.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
        res.json({ success: true, requests: list });
    } catch (e) {
        res.status(500).json({ success: false, message: '查询失败' });
    }
});

// 接受 / 拒绝好友请求
app.post('/api/friends/respond', (req, res) => {
    try {
        const { requestId, clientId, action } = req.body || {};
        if (!requestId || !clientId) return res.json({ success: false, message: '缺少参数' });
        const r = friendRequests.get(requestId);
        if (!r) return res.json({ success: false, message: '请求不存在' });
        if (r.toClientId !== clientId) return res.json({ success: false, message: '无权操作该请求' });
        if (r.status !== 'pending') return res.json({ success: false, message: '该请求已处理' });
        if (action === 'accept') {
            r.status = 'accepted'; r.updatedAt = new Date().toISOString();
            const key = friendshipKey(r.fromClientId, r.toClientId);
            if (!friendships.has(key)) friendships.set(key, { userA: r.fromClientId, userB: r.toClientId, createdAt: r.updatedAt });
            saveFriends();
            pushToNotificationSocket(r.fromClientId, 'friend-accepted', {
                friendClientId: r.toClientId, friendName: r.toName, requestId
            });
            console.log(`[Friends] ${r.toName}(${clientId}) 通过了 ${r.fromName}(${r.fromClientId}) 的好友请求`);
            res.json({ success: true, action: 'accept' });
        } else {
            r.status = 'rejected'; r.updatedAt = new Date().toISOString();
            saveFriends();
            res.json({ success: true, action: 'reject' });
        }
    } catch (e) {
        console.error('[Friends] 处理请求失败:', e);
        res.status(500).json({ success: false, message: '处理失败' });
    }
});

// 好友列表（含在线状态）
app.get('/api/friends/list', (req, res) => {
    try {
        const clientId = (req.query.clientId || '').toString();
        if (!clientId) return res.json({ success: true, friends: [] });
        const friends = [];
        for (const f of friendships.values()) {
            let other = null;
            if (f.userA === clientId) other = f.userB;
            else if (f.userB === clientId) other = f.userA;
            else continue;
            const op = onlinePlayers.get(other) || {};
            const prof = homeProfiles.get(other) || {};
            friends.push({
                clientId: other,
                name: (op.name || prof.name || '玩家').toString(),
                avatar: prof.avatar || '😀',
                color: prof.color || '#4CAF50',
                online: !!onlinePlayers.has(other)
            });
        }
        res.json({ success: true, friends });
    } catch (e) {
        res.status(500).json({ success: false, message: '查询失败' });
    }
});

// 查询两人关系（用于个人主页按钮状态）
app.get('/api/friends/relation', (req, res) => {
    try {
        const a = (req.query.clientId || '').toString();
        const b = (req.query.otherClientId || '').toString();
        if (!a || !b) return res.json({ success: true, relation: 'none' });
        if (a === b) return res.json({ success: true, relation: 'self' });
        if (areFriends(a, b)) return res.json({ success: true, relation: 'friends' });
        const pend = findPendingRequest(a, b);
        if (pend) {
            if (pend.fromClientId === a && pend.toClientId === b) return res.json({ success: true, relation: 'pending_sent', requestId: pend.id });
            if (pend.fromClientId === b && pend.toClientId === a) return res.json({ success: true, relation: 'pending_received', requestId: pend.id });
        }
        res.json({ success: true, relation: 'none' });
    } catch (e) {
        res.status(500).json({ success: false, message: '查询失败' });
    }
});

// 发送好友私聊消息
app.post('/api/friends/message', (req, res) => {
    try {
        const { fromClientId, toClientId, message } = req.body || {};
        if (!fromClientId || !toClientId) return res.json({ success: false, message: '缺少账号信息' });
        if (!areFriends(fromClientId, toClientId)) return res.json({ success: false, message: '只有好友才能聊天' });
        const text = (message || '').toString();
        if (!text.trim()) return res.json({ success: false, message: '消息不能为空' });
        const msg = {
            id: 'fm_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 6),
            fromClientId, toClientId,
            message: text.slice(0, 2000),
            createdAt: new Date().toISOString()
        };
        const k = friendshipKey(fromClientId, toClientId);
        if (!friendMessages.has(k)) friendMessages.set(k, []);
        friendMessages.get(k).push(msg);
        const arr = friendMessages.get(k);
        if (arr.length > 500) friendMessages.set(k, arr.slice(-500));
        saveFriends();
        pushToNotificationSocket(toClientId, 'friend-message-received', {
            fromClientId, fromName: (onlinePlayers.get(fromClientId) || {}).name || (homeProfiles.get(fromClientId) || {}).name || '玩家',
            toClientId, message: msg.message, createdAt: msg.createdAt, id: msg.id
        });
        res.json({ success: true, message: msg });
    } catch (e) {
        console.error('[Friends] 发送消息失败:', e);
        res.status(500).json({ success: false, message: '发送失败' });
    }
});

// 获取与某好友的聊天记录
app.get('/api/friends/messages', (req, res) => {
    try {
        const a = (req.query.clientId || '').toString();
        const b = (req.query.friendClientId || '').toString();
        if (!a || !b) return res.json({ success: true, messages: [] });
        const k = friendshipKey(a, b);
        const arr = friendMessages.get(k) || [];
        const out = arr.slice(-200).map(m => ({
            id: m.id, fromClientId: m.fromClientId, toClientId: m.toClientId,
            message: m.message, createdAt: m.createdAt
        }));
        res.json({ success: true, messages: out });
    } catch (e) {
        res.status(500).json({ success: false, message: '查询失败' });
    }
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
        // 是否允许该玩家查看他人主页（管理员权限控制，默认允许）
        if (typeof body.canViewOthers === 'boolean') {
            merged.canViewOthers = body.canViewOthers;
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
            online: true,
            platform: player.platform || 'web'
        });
    }
    // 2. 兜底：room.players 中未在在线表出现的，按「clientId」唯一加入（不再按名字合并，
    //    统一以 clientId 为键，与第 1 步在线表去重，避免 peerId/名字重复计数）
    for (const room of rooms.values()) {
        if (!room.players) continue;
        for (const player of room.players.values()) {
            if (!player) continue;
            const cid = player.clientId || player.id;
            if (!cid) continue;
            if (userMap.has(cid)) {
                const u = userMap.get(cid);
                if (!u.roomId && room.id) { u.roomId = room.id; u.roomName = room.name; }
                continue;
            }
            userMap.set(cid, {
                id: cid,
                username: player.name || '未知用户',
                coins: getDisplayCoins(cid),
                level: userLevels.get(cid) || 1,
                roomId: room.id,
                roomName: room.name,
                online: true,
                platform: player.platform || 'web'
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
        const { id, name, coins, unlockedLevel, completedLevels, puzzleCompletedLevels, customCompletedLevels, achievements, totalPlayTime, gameStats, gamestate, uiSettings } = req.body || {};
        if (!id) return res.json({ success: false, message: '缺少 id' });
        // 客户端上报的 UI 设置（供管理员后台查看/修改）
        if (uiSettings) setClientUISettings(id, uiSettings);
        const existing = onlinePlayers.get(id) || {};
        // 记录玩家上报的真实金币（供管理员查看）
        const rc = parseInt(coins);
        if (!isNaN(rc)) reportedCoins.set(id, Math.max(0, rc));
        // 记录玩家上报的关卡进度（供管理员查看过关历史）
        mergeProgress(id, { unlockedLevel, completedLevels, puzzleCompletedLevels, customCompletedLevels });
        // 记录玩家上报的成就数据（供管理员查看）
        if (achievements) mergeAchievements(id, achievements);
        const ip = getClientIp(req);
        const role = getUserRole(id);
        // 平台来源：微信小程序内嵌 web-view 上报 'miniprogram'，普通浏览器上报 'web'（默认 web）
        const platform = (req.body && req.body.platform) ? String(req.body.platform).slice(0, 20) : 'web';
        onlinePlayers.set(id, {
            id: id,
            name: (name && String(name).trim()) || existing.name || '玩家',
            socketId: existing.socketId || null,   // 保留 socket 通道写入的连接标识
            roomId: existing.roomId || null,
            joinedAt: existing.joinedAt || Date.now(),
            ip: ip,
            role: role,
            platform: platform
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
        let ipBanned = false, ipBanReason = '', ipBanExpiresAt = null, ipBanTerm = '';
        let rec = null;
        if (isIPBanned(ip)) {
            const ban = userBans.get(id) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
            if (!ban.reasons) ban.reasons = {};
            rec = bannedIPs.get(String(ip)) || {};
            ban.multiplayer = ban.single = ban.puzzle = ban.chat = true;
            const reason = (rec.reason && String(rec.reason).trim()) || '';
            ipBanExpiresAt = rec.expiresAt || null;
            ipBanTerm = describeIPBan(rec);
            const msg = 'IP 封禁：' + (reason || '管理员封禁此 IP') + `（${ipBanTerm}）`;
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
            ipBanExpiresAt: ipBanExpiresAt,      // null = 永久封禁
            ipBanPermanent: ipBanned && !ipBanExpiresAt,
            ipBanTerm: ipBanTerm,
            ipBanIp: (rec && rec.ip) || null,
            ipBanUsername: (rec && rec.username) || null,
            ipBanClientId: (rec && rec.clientId) || null,
            role: role,
            uiSettings: getEffectiveUISettings(id),
            adminOverridden: !!(userSettings.get(id) || {}).admin,
            // admin 分功能封禁状态（封禁单人/解密/多人/聊天），无 socket 的小程序靠此响应生效
            banned: (() => {
                const b = userBans.get(id) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
                if (!b.reasons) b.reasons = {};
                return { single: !!b.single, multiplayer: !!b.multiplayer, puzzle: !!b.puzzle, chat: !!b.chat, reasons: b.reasons };
            })(),
            progress: {
                coins: getDisplayCoins(id),                       // admin 调整金币后以此为准
                adminCoinOverride: !!adminCoinOverride.get(id),   // true = 客户端需直接覆盖本地金币
                unlockedLevel: prog.unlockedLevel || 1,
                completedLevels: Array.isArray(prog.completedLevels) ? prog.completedLevels : [],
                puzzleCompletedLevels: Array.isArray(prog.puzzleCompletedLevels) ? prog.puzzleCompletedLevels : [],
                customCompletedLevels: Array.isArray(prog.customCompletedLevels) ? prog.customCompletedLevels : []
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
        // 同步到上报账本 + 标记管理员覆盖：客户端下次 player-online 需以此值为准（直接覆盖本地）
        reportedCoins.set(userId, Math.max(0, updated));
        adminCoinOverride.set(userId, true);

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
            ipBanExpiresAt: ipRec ? (ipRec.expiresAt || null) : null,   // null = 永久
            ipBanPermanent: ipRec ? !ipRec.expiresAt : false,
            ipBanTerm: ipRec ? describeIPBan(ipRec) : '',
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
// 支持永久封禁与限时封禁：body 传 { permanent:true } 或 { durationDays/durationHours/durationMinutes }
app.post('/api/admin/ban-ip', requireAdminAuth, async (req, res) => {
    try {
        const { ip, reason, clientId, username } = req.body || {};
        if (!ip || !String(ip).trim()) return res.status(400).json({ success: false, message: '缺少 ip' });
        const ipKey = String(ip).trim();
        const expiresAt = parseBanExpiry(req.body);
        const rec = await applyIPBan(ipKey, reason, expiresAt, 'admin', { clientId: clientId || null, username: username || null });
        const term = describeIPBan(rec);
        appendAudit('admin', 'ban-ip', `封禁 IP ${ipKey}（${expiresAt ? '限时至 ' + expiresAt : '永久'}）${reason ? '，理由: ' + reason : ''}`, req);
        res.json({ success: true, ip: ipKey, expiresAt: rec.expiresAt, permanent: !rec.expiresAt, term, bannedIPs: Array.from(bannedIPs.keys()) });
    } catch (e) {
        res.status(500).json({ success: false, message: '封禁失败' });
    }
});

// API: 管理员解除 IP 封禁
app.post('/api/admin/unban-ip', requireAdminAuth, async (req, res) => {
    try {
        const { ip } = req.body || {};
        if (!ip || !String(ip).trim()) return res.status(400).json({ success: false, message: '缺少 ip' });
        const ipKey = String(ip).trim();
        await removeIPBan(ipKey, 'admin');
        appendAudit('admin', 'unban-ip', `解封 IP ${ipKey}`, req);
        res.json({ success: true, ip: ipKey, bannedIPs: Array.from(bannedIPs.keys()) });
    } catch (e) {
        res.status(500).json({ success: false, message: '解封失败' });
    }
});

// API: 管理员查看已封禁 IP 列表（含到期时间与剩余时长，已过期的不返回）
app.get('/api/admin/banned-ips', requireAdminAuth, (req, res) => {
    try {
        const list = [];
        for (const [ip, v] of bannedIPs.entries()) {
            if (ipBanExpired(v)) continue;
            list.push({
                ip,
                reason: v.reason || '',
                bannedAt: v.bannedAt || '',
                expiresAt: v.expiresAt || null,
                permanent: !v.expiresAt,
                term: describeIPBan(v),
                bannedBy: v.bannedBy || 'admin'
            });
        }
        list.sort((a, b) => String(b.bannedAt).localeCompare(String(a.bannedAt)));
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
        // 注意：上报作弊是反作弊「功能」，与「是否显示反作弊标签页」无关——标签页只是展示层，
        // 关闭标签页(showAntiCheatTab=false)不拦截上报，避免功能失效/误封无法记录。
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

        // ===== 严重违规：直接按 IP 封禁 =====
        // 篡改/移除反调试遮罩属于主动对抗反作弊系统的行为，比普通作弊更严重，
        // 因此不只封玩法，而是连同 IP 一起封禁。反调试类按次数递增时长（见下方）。
        const ipBanDays = IP_BAN_CHEAT_TYPES[report.type];
        if (ipBanDays) {
            const cheatIp = getClientIp(req);
            if (cheatIp) {
                const isDevtoolsType = (report.type === 'devtools_open' || report.type === 'anti_debug_tamper');
                let banReason = `反作弊系统自动封禁：检测到${CHEAT_TYPE_NAMES[report.type] || report.type}`;
                Promise.resolve()
                    .then(async () => {
                        // 优先用游戏内玩家名展示身份，其次回退云账号名（不再默认显示云账号名）
                        const acc = await dbGetCloudAccountByClient(report.clientId).catch(() => null);
                        const banUsername = (req.body && req.body.playerName) ? String(req.body.playerName).slice(0, 128) : (acc ? acc.username : null);
                        let expiresAt, durationText;
                        if (isDevtoolsType) {
                            // 反调试类：首次 3 小时，按历史次数翻倍递增，封顶 7 天
                            const prev = await countDevtoolsBans(report.clientId); // 历史次数（不含本次）
                            const nextCount = prev + 1;
                            let hours = DEVTOOLS_BAN_BASE_HOURS * Math.pow(2, prev);
                            const permanent = hours >= DEVTOOLS_BAN_MAX_HOURS;
                            if (permanent) hours = DEVTOOLS_BAN_MAX_HOURS;
                            expiresAt = permanent ? null : new Date(Date.now() + hours * 3600000).toISOString();
                            durationText = permanent ? '永久' : (hours + ' 小时');
                            banReason += `（第 ${nextCount} 次，封禁 ${durationText}）`;
                            report._devCount = nextCount;
                            report._devDurationText = durationText;
                        } else {
                            expiresAt = new Date(Date.now() + ipBanDays * 86400000).toISOString();
                            durationText = ipBanDays + ' 天';
                        }
                        report._devExpiresAt = expiresAt;
                        return { banUsername, expiresAt, durationText };
                    })
                    .then(async ({ banUsername, expiresAt, durationText }) => {
                        // 先独立写入作弊封禁日志（不依赖 applyIPBan 成败，避免封禁异常吞掉日志）
                        try {
                            await dbSaveCheatLog({
                                id: 'cheat_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
                                clientId: report.clientId,
                                username: banUsername,
                                ip: cheatIp,
                                cheatType: report.type,
                                reason: banReason,
                                bannedAt: new Date().toISOString(),
                                expiresAt: expiresAt || null,
                                createdAt: new Date().toISOString()
                            });
                        } catch (e) { console.error('[作弊日志] 写入失败:', e.message); }
                        // 再执行真实 IP 封禁
                        return applyIPBan(cheatIp, banReason, expiresAt, 'anti-cheat', { username: banUsername, clientId: report.clientId });
                    })
                    .then(() => {
                        const dt = report._devDurationText || (ipBanDays + ' 天');
                        const times = report._devCount ? `（第 ${report._devCount} 次）` : '';
                        const expiresTxt = report._devExpiresAt || '永久';
                        console.log(`[反作弊] IP ${cheatIp} 因 ${report.type} 被自动封禁 ${dt}${times}（至 ${expiresTxt}）`);
                        appendAudit('anti-cheat', 'ban-ip', `反作弊自动封禁 IP ${cheatIp} ${dt}${times}（${report.type}，clientId=${report.clientId}）`, req);
                    })
                    .catch(e => console.error('[反作弊] 自动封禁 IP 失败:', e.message));
            } else {
                console.warn(`[反作弊] ${report.type} 触发，但无法获取客户端 IP，已跳过 IP 封禁`);
            }
        }

        // ===== 反作弊自动封禁：立即封禁其上报时所玩的玩法（管理员可在后台解封） =====
        const mode = (req.body && ['multiplayer', 'single', 'puzzle'].indexOf(req.body.mode) !== -1) ? req.body.mode : 'single';
        const cheatTypeNames = CHEAT_TYPE_NAMES;
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

// ===== 聊天脏话屏蔽（服务端兜底）=====
// 聊天走 PeerJS P2P，正常情况由发送方客户端过滤后再广播；但改过的客户端可能把脏话直接
// 发给本镜像上报接口，故服务端再过滤一次，保证管理员监管记录里也不会出现脏话。
const PROFANITY_WORDS = [
    '傻逼', '操你妈', '草泥马', '去死', '垃圾', '废物', '蠢货',
    '脑残', '智障', '二百五', '王八蛋', '龟儿子', '杂种', '畜生',
    '禽兽', '色狼', '变态', '婊子', '贱人', '傻屌', '妈蛋', '滚蛋',
    '我操你妈', '我草泥马', '自杀', '紫砂', '毒品', '冰糖', '神经病', '圣经并',
    '杜平', '毒瓶',
    'fuck', 'shit', 'damn', 'bitch', 'asshole', 'dick', 'pussy',
    'cunt', 'bastard', 'nigger', 'nigga', 'faggot', 'dyke', 'retard',
    'whore', 'slut', 'douche', 'ass', 'shithead', 'sb', 'sbm', 'wcnm', 'fw',
    'bt', 'die'
];
const PROFANITY_LEET = { '4': 'a', '@': 'a', '1': 'i', '!': 'i', '|': 'i', '0': 'o', '3': 'e', '$': 's', '5': 's', '7': 't', '8': 'b', '9': 'g', '6': 'b' };
function profanityIsAlnumCJK(c) { return (c && /[a-z0-9一-鿿]/.test(c)); }
function profanityIsCJK(c) { return (c && /[一-鿿]/.test(c)); }
function profanityCleanFull(s) {
    s = (s || '').toLowerCase();
    let clean = ''; const om = [];
    for (let i = 0; i < s.length; i++) {
        const ch = s[i];
        if (PROFANITY_LEET[ch] !== undefined) { clean += PROFANITY_LEET[ch]; om.push(i); }
        else if (profanityIsAlnumCJK(ch)) { clean += ch; om.push(i); }
    }
    return { clean, om };
}
function profanityBoundaryOk(text, om, s, e) {
    let bOk = (s === 0);
    if (!bOk) { const p = om[s] - 1; bOk = (p < 0) || !profanityIsAlnumCJK(text[p]) || profanityIsCJK(text[p]); }
    let aOk = (e >= om.length);
    if (!aOk) { const afterOrig = om[e - 1] + 1; aOk = (afterOrig >= text.length) || !profanityIsAlnumCJK(text[afterOrig]) || profanityIsCJK(text[afterOrig]); }
    return bOk && aOk;
}
function filterProfanityServer(text) {
    if (!text) return text;
    const { clean, om } = profanityCleanFull(text);
    if (!clean) return text;
    const bad = new Array(clean.length).fill(false);
    for (const w of PROFANITY_WORDS) {
        const cw = profanityCleanFull(w).clean;
        if (!cw) continue;
        let idx = 0;
        while ((idx = clean.indexOf(cw, idx)) !== -1) {
            const s = idx, e = idx + cw.length;
            if (profanityBoundaryOk(text, om, s, e)) {
                for (let i = s; i < e; i++) bad[i] = true;
            }
            idx = e;
        }
    }
    if (!bad.some(Boolean)) return text;
    let ci = 0, out = '';
    for (const ch of text) {
        const lc = ch.toLowerCase();
        if (profanityIsAlnumCJK(lc) || PROFANITY_LEET[lc] !== undefined) {
            out += bad[ci] ? '*' : ch;
            ci++;
        } else out += ch;
    }
    return out;
}

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
            message: message ? filterProfanityServer(String(message)).slice(0, 2000) : null,
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
        // 清理通知 socket 映射：该连接若是某玩家的通知 socket，则移除
        for (const [cid, sid] of notificationSockets) {
            if (sid === socket.id) { notificationSockets.delete(cid); break; }
        }
        handleDisconnect(socket.id);
    });

    // ===== 新增：进入游戏即上线（管理后台 /api/users 可见，无需进房间） =====
    // 客户端进入游戏、取名后调用，把自身登记为在线玩家（roomId 为 null 表示尚未进入任何房间）。
    socket.on('player-online', (data) => {
        try {
        const { id, name, coins, unlockedLevel, completedLevels, puzzleCompletedLevels, customCompletedLevels, achievements, totalPlayTime, gameStats, gamestate, uiSettings } = data || {};
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
        mergeProgress(id, { unlockedLevel, completedLevels, puzzleCompletedLevels, customCompletedLevels });
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
            notificationSockets.set(id, socket.id);
            // 若客户端 IP 已被封禁，则对该用户启用全部功能封禁，并立即推送全屏封禁框
            if (isIPBanned(ip)) {
                const ban = userBans.get(id) || { multiplayer: false, single: false, puzzle: false, chat: false, reasons: {} };
                if (!ban.reasons) ban.reasons = {};
                const rec = bannedIPs.get(String(ip)) || {};
                ban.multiplayer = ban.single = ban.puzzle = ban.chat = true;
                const reason = (rec.reason && String(rec.reason).trim()) || '';
                const term = describeIPBan(rec);
                const msg = 'IP 封禁：' + (reason || '管理员封禁此 IP') + `（${term}）`;
                ban.reasons.multiplayer = ban.reasons.single = ban.reasons.puzzle = ban.reasons.chat = msg;
                userBans.set(id, ban);
                socket.emit('ip-banned', { reason: reason, permanent: !rec.expiresAt, expiresAt: rec.expiresAt || null, term: term, ip: rec.ip || null, username: rec.username || null, clientId: rec.clientId || null });
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
            appendAudit('superadmin', 'kick-player', `（游戏内SA ${requesterId}）踢出玩家 ${nm} (${targetId})`);
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
            appendAudit('superadmin', 'ban', `（游戏内SA ${requesterId}）用户 ${userId} 的${label}${banned ? '封禁' : '解封'}`);
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
            const customCompletedLevels = []; for (let i = 1; i <= MAX_PUZZLE_LEVEL; i++) customCompletedLevels.push(i);
            mergeProgress(targetId, { unlockedLevel: MAX_SINGLE_LEVEL, completedLevels, puzzleCompletedLevels, customCompletedLevels });
            const cur = reportedAchievements.get(targetId) || { allLevelsCompleted: false, multiplayerWins: 0, trapHits: 0, chineseEmojiUsed: false, puzzleMaster: false };
            cur.allLevelsCompleted = true; cur.puzzleMaster = true;
            reportedAchievements.set(targetId, cur);
            const revoked = revokedAchievements.get(targetId);
            if (revoked) { revoked.delete('allLevelsCompleted'); revoked.delete('puzzleMaster'); if (revoked.size === 0) revokedAchievements.delete(targetId); else revokedAchievements.set(targetId, revoked); }
            io.emit('achievement-update', { clientId: targetId, achievements: cur });
            io.emit('progress-update', { clientId: targetId, unlockedLevel: MAX_SINGLE_LEVEL, completedLevels, puzzleCompletedLevels, customCompletedLevels });
            appendAudit('superadmin', 'complete-all', `（游戏内SA ${requesterId}）将 ${targetId} 单人/解密/自定义全部通关`);
            socket.emit('admin-action-result', { success: true, message: `已将 ${targetId} 单人、解密、自定义全部通关` });
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
            appendAudit('superadmin', 'user-settings', `（游戏内SA ${requesterId}）修改 ${targetId} 的 UI 设置`);
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
            // 支持限时封禁：data 可带 permanent / durationDays / durationHours / durationMinutes
            const expiresAt = parseBanExpiry(data);
            applyIPBan(ipKey, reason, expiresAt, 'superadmin', { clientId: targetId, username: (p && p.name) || null }).then(rec => {
                const term = describeIPBan(rec);
                appendAudit('superadmin', 'ban-ip', `（游戏内SA ${requesterId}）封禁 IP ${ipKey}（${expiresAt ? '限时至 ' + expiresAt : '永久'}）`);
                socket.emit('admin-action-result', { success: true, message: `已封禁 IP ${ipKey}（${term}）` });
            }).catch(e => socket.emit('admin-action-result', { success: false, message: e.message }));
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
            removeIPBan(ipKey, 'admin').then(() => {
                appendAudit('superadmin', 'unban-ip', `（游戏内SA ${requesterId}）解封 IP ${ipKey}`);
                socket.emit('admin-action-result', { success: true, message: `已解封 IP ${ipKey}` });
            }).catch(e => socket.emit('admin-action-result', { success: false, message: e.message }));
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
                ipBanExpiresAt: ipRec ? (ipRec.expiresAt || null) : null,
                ipBanPermanent: ipRec ? !ipRec.expiresAt : false,
                ipBanTerm: ipRec ? describeIPBan(ipRec) : '',
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
// 记录最近一次发送的管理员弹窗，供无 socket 的客户端（微信小游戏 REST 拉取）启动时展示
let lastAdminPopup = null;

app.post('/api/admin/popup', requireAdminAuth, (req, res) => {
    try {
        const { title, message } = req.body;

        if (!title || !message) {
            return res.status(400).json({ success: false, message: '弹窗标题和内容不能为空' });
        }

        // 向所有连接的客户端广播弹窗事件（游戏端需监听 'admin-popup' 才能显示）
        const popup = { title: title, message: message, timestamp: Date.now() };
        io.emit('admin-popup', popup);
        lastAdminPopup = popup; // 供小程序 REST 拉取

        console.log(`[Admin] 已发送全局弹窗: ${title}`);
        appendAudit('admin', 'popup', `发送全局弹窗: ${String(title).slice(0, 80)}`);
        res.json({ success: true, message: '弹窗已发送给所有在线玩家' });
    } catch (error) {
        console.error('[API] 发送弹窗失败:', error);
        res.status(500).json({ success: false, message: '发送弹窗失败' });
    }
});

// 小程序/其他无 socket 客户端：启动时拉取最近一次管理员弹窗（公开，无需鉴权）
app.get('/api/admin/popup', (req, res) => {
    res.json({ success: true, popup: lastAdminPopup });
});

// ===== 公告功能（管理员发布，持久化到 announcements 表 / JSON 兜底）=====
const ANNOUNCEMENTS_FILE = path.join(DATA_DIR, 'announcements.json');

// 从存储读取全部公告（DB 优先，失败回退 JSON）
async function loadAnnouncementsFromStore() {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query(
                'SELECT id, title, content, priority, active, created_by, created_at FROM announcements ORDER BY created_at DESC'
            );
            return rows.map(r => ({
                id: r.id,
                title: r.title,
                content: r.content,
                priority: r.priority,
                active: r.active,
                createdBy: r.created_by,
                createdAt: r.created_at
            }));
        } catch (e) {
            console.error('[公告] DB 读取失败，回退 JSON:', e.message);
        }
    }
    try {
        if (fs.existsSync(ANNOUNCEMENTS_FILE)) {
            const arr = JSON.parse(fs.readFileSync(ANNOUNCEMENTS_FILE, 'utf8'));
            if (Array.isArray(arr)) return arr;
        }
    } catch (e) { console.error('[公告] JSON 读取失败:', e.message); }
    return [];
}

async function saveAnnouncementsToJsonStore(arr) {
    ensureDataDir();
    try { fs.writeFileSync(ANNOUNCEMENTS_FILE, JSON.stringify(arr, null, 2)); }
    catch (e) { console.error('[公告] JSON 写入失败:', e.message); }
}

// 创建公告（返回创建的记录）。DB 优先，失败回退 JSON 文件。
async function createAnnouncement({ title, content, priority, createdBy }) {
    const createdAt = new Date().toISOString();
    const rec = {
        id: null,
        title: String(title).trim(),
        content: String(content),
        priority: parseInt(priority, 10) || 0,
        active: 1,
        createdBy: createdBy || 'admin',
        createdAt
    };
    if (DB_AVAILABLE && pool) {
        try {
            const [result] = await pool.query(
                'INSERT INTO announcements (title, content, priority, active, created_by, created_at) VALUES (?,?,?,?,?,?)',
                [rec.title, rec.content, rec.priority, rec.active, rec.createdBy, rec.createdAt]
            );
            rec.id = result.insertId;
            return rec;
        } catch (e) {
            console.error('[公告] DB 写入失败，回退 JSON:', e.message);
        }
    }
    const arr = await loadAnnouncementsFromStore();
    rec.id = 'a_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6);
    arr.push(rec);
    saveAnnouncementsToJsonStore(arr);
    return rec;
}

// 删除公告（按 id）。DB 优先，失败回退 JSON 文件。
async function deleteAnnouncementById(id) {
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query('DELETE FROM announcements WHERE id = ?', [id]);
            return true;
        } catch (e) {
            console.error('[公告] DB 删除失败，回退 JSON:', e.message);
        }
    }
    const arr = await loadAnnouncementsFromStore();
    const next = arr.filter(a => String(a.id) !== String(id));
    saveAnnouncementsToJsonStore(next);
    return true;
}

// 管理员：发布公告（持久化 + 实时广播给所有在线客户端）
app.post('/api/admin/announcements', requireAdminAuth, async (req, res) => {
    try {
        const { title, content, priority } = req.body || {};
        if (!title || !String(title).trim()) {
            return res.status(400).json({ success: false, message: '公告标题不能为空' });
        }
        if (!content || !String(content).trim()) {
            return res.status(400).json({ success: false, message: '公告内容不能为空' });
        }
        const publisher = (req.admin && req.admin.name) || (req.admin && req.admin.role) || 'admin';
        const rec = await createAnnouncement({ title, content, priority, createdBy: publisher });
        appendAudit('admin', 'announcement-create', `发布公告: ${String(title).slice(0, 80)}`);
        // 实时推送给所有在线客户端（游戏端监听 'announcement-new' 全屏弹出）
        io.emit('announcement-new', rec);
        console.log(`[Admin] 已发布公告: ${rec.title} (id=${rec.id})`);
        res.json({ success: true, message: '公告已发布', announcement: rec });
    } catch (error) {
        console.error('[API] 发布公告失败:', error);
        res.status(500).json({ success: false, message: '发布公告失败' });
    }
});

// 管理员：获取全部公告（用于后台管理列表）
app.get('/api/admin/announcements', requireAdminAuth, async (req, res) => {
    try {
        const list = await loadAnnouncementsFromStore();
        res.json({ success: true, announcements: list });
    } catch (error) {
        console.error('[API] 获取公告失败:', error);
        res.status(500).json({ success: false, message: '获取公告失败' });
    }
});

// 管理员：删除公告
app.delete('/api/admin/announcements/:id', requireAdminAuth, async (req, res) => {
    try {
        const id = req.params.id;
        await deleteAnnouncementById(id);
        appendAudit('admin', 'announcement-delete', `删除公告 id=${id}`);
        console.log(`[Admin] 已删除公告 id=${id}`);
        res.json({ success: true, message: '公告已删除' });
    } catch (error) {
        console.error('[API] 删除公告失败:', error);
        res.status(500).json({ success: false, message: '删除公告失败' });
    }
});

// 公开接口：游戏客户端拉取当前生效（active）公告，按优先级、时间排序
app.get('/api/announcements', async (req, res) => {
    try {
        const all = await loadAnnouncementsFromStore();
        const active = all
            .filter(a => a.active !== 0 && a.active !== false)
            .sort((a, b) => ((b.priority || 0) - (a.priority || 0)) || (a.createdAt < b.createdAt ? 1 : -1));
        res.json({ success: true, announcements: active });
    } catch (error) {
        console.error('[API] 获取公告失败:', error);
        res.status(500).json({ success: false, message: '获取公告失败' });
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
app.post('/api/admin/mazes', requireAdminAuth, async (req, res) => {
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
        await saveMazes();
        console.log(`[Admin] 新建迷宫: ${maze.name} (${maze.id})`);
        appendAudit('admin', 'maze-create', `新建迷宫 ${maze.name} (${maze.id})`);
        res.json({ success: true, message: '迷宫创建成功', maze });
    } catch (error) {
        console.error('[API] 新建迷宫失败:', error);
        res.status(500).json({ success: false, message: '新建迷宫失败' });
    }
});

// 管理员：更新迷宫
app.put('/api/admin/mazes/:mazeId', requireAdminAuth, async (req, res) => {
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
        await saveMazes();
        console.log(`[Admin] 更新迷宫: ${maze.name} (${mazeId})`);
        appendAudit('admin', 'maze-update', `更新迷宫 ${maze.name} (${mazeId})`);
        res.json({ success: true, message: '迷宫更新成功', maze });
    } catch (error) {
        console.error('[API] 更新迷宫失败:', error);
        res.status(500).json({ success: false, message: '更新迷宫失败' });
    }
});

// 管理员：删除迷宫
app.delete('/api/admin/mazes/:mazeId', requireAdminAuth, async (req, res) => {
    try {
        const mazeId = req.params.mazeId;
        if (!mazes.has(mazeId)) return res.status(404).json({ success: false, message: '迷宫不存在' });
        mazes.delete(mazeId);
        await saveMazes();
        console.log(`[Admin] 删除迷宫: ${mazeId}`);
        appendAudit('admin', 'maze-delete', `删除迷宫 ${mazeId}`);
        res.json({ success: true, message: '迷宫删除成功' });
    } catch (error) {
        console.error('[API] 删除迷宫失败:', error);
        res.status(500).json({ success: false, message: '删除迷宫失败' });
    }
});

// ===== 玩家工坊地图（玩家保存/分享，按作者归属；admin 可查看/删除/禁用/禁止分享）=====
const playerMazes = new Map(); // mazeId -> 玩家地图对象
const PLAYER_MAZES_FILE = path.join(DATA_DIR, 'player-mazes.json');
function loadPlayerMazes() {
    try {
        if (fs.existsSync(PLAYER_MAZES_FILE)) {
            const arr = JSON.parse(fs.readFileSync(PLAYER_MAZES_FILE, 'utf8'));
            if (Array.isArray(arr)) {
                arr.forEach(m => playerMazes.set(m.id, m));
                console.log(`[工坊] 已从 ${PLAYER_MAZES_FILE} 加载 ${playerMazes.size} 个玩家地图`);
            }
        }
    } catch (e) { console.error('[工坊] 加载玩家地图失败:', e.message); }
}
function savePlayerMazes() {
    try {
        ensureDataDir();
        fs.writeFileSync(PLAYER_MAZES_FILE, JSON.stringify(Array.from(playerMazes.values()), null, 2));
    } catch (e) { console.error('[工坊] 保存玩家地图失败:', e.message); }
}
loadPlayerMazes();

// =============== 云储存（玩家注册账号，每个账号最多 5 个地图）===============
// 存储：DB 优先（cloud_storage_accounts / cloud_storage_mazes 表），失败回退 JSON 文件（data/cloud-storage.json）。
const CLOUD_STORAGE_FILE = path.join(DATA_DIR, 'cloud-storage.json');
const CLOUD_MAX_MAZES = 5;
// 管理员直接创建的云账号使用此哨兵值表示「无限量储存」（MySQL INT 上限），
// 上传配额检查 existingList.length >= maxMazes 实际上永远无法触及。
const CLOUD_UNLIMITED_MAZES = 2147483647;
const CLOUD_UNLIMITED_THRESHOLD = 2000000000; // >= 此值即视为无限量（用于前端展示）
let cloudAccounts = new Map(); // username -> { username, password_hash, created_at, updated_at }
let cloudMazes = new Map();    // mazeId -> { id, username, name, maze, size, teleporters, enemy_speed, show_shop, description, difficulty, created_at, updated_at }
let cloudProgress = new Map(); // username -> { username, progress: {...}, updated_at }
function loadCloudStorage() {
    try {
        if (fs.existsSync(CLOUD_STORAGE_FILE)) {
            const s = JSON.parse(fs.readFileSync(CLOUD_STORAGE_FILE, 'utf8'));
            if (s && s.accounts) s.accounts.forEach(a => cloudAccounts.set(a.username, a));
            if (s && s.mazes) s.mazes.forEach(m => cloudMazes.set(m.id, m));
            if (s && s.progress) s.progress.forEach(p => cloudProgress.set(p.username, p));
            console.log(`[云储存] 已从 ${CLOUD_STORAGE_FILE} 加载 ${cloudAccounts.size} 账号 / ${cloudMazes.size} 地图 / ${cloudProgress.size} 通关进度`);
        }
    } catch (e) { console.error('[云储存] 加载失败:', e.message); }
}
function saveCloudStorage() {
    try {
        ensureDataDir();
        fs.writeFileSync(CLOUD_STORAGE_FILE, JSON.stringify({
            accounts: Array.from(cloudAccounts.values()),
            mazes: Array.from(cloudMazes.values()),
            progress: Array.from(cloudProgress.values())
        }, null, 2));
    } catch (e) { console.error('[云储存] 保存失败:', e.message); }
}
function cloudMazesOf(username) {
    return Array.from(cloudMazes.values())
        .filter(m => m.username === username)
        .sort((a, b) => (b.updated_at || '').localeCompare(a.updated_at || ''));
}
// DB 优先：读取账号（返回带 password_hash 的对象或 null）
async function dbGetCloudAccount(username) {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT * FROM cloud_storage_accounts WHERE username=?', [username]);
            if (rows && rows.length) return rows[0];
        } catch (e) { console.error('[云储存] DB 读账号失败:', e.message); }
    }
    return cloudAccounts.get(username) || null;
}
// 按游戏 clientId 反查云储存账号（用于管理端从游戏用户定位其云账号）
async function dbGetCloudAccountByClient(clientId) {
    if (!clientId) return null;
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT * FROM cloud_storage_accounts WHERE client_id=?', [clientId]);
            if (rows && rows.length) return rows[0];
        } catch (e) { console.error('[云储存] DB 读账号(clientId)失败:', e.message); }
    }
    for (const acc of cloudAccounts.values()) {
        if (acc.client_id === clientId) return acc;
    }
    return null;
}
// 云账号表可能缺失的列及其类型：写入失败（迁移未执行）时自愈补列，
// 避免扩容码写入 max_mazes / 登录写 client_id / 封禁写 disabled 被静默吞掉。
const CLOUD_ACCOUNT_COLUMNS = {
    max_mazes: 'INT NOT NULL DEFAULT 5',
    client_id: 'VARCHAR(64)',
    disabled: 'TINYINT(1) NOT NULL DEFAULT 0',
    banned_until: 'VARCHAR(32)',
    two_factor_enabled: 'TINYINT(1) NOT NULL DEFAULT 0',
    creator_client_id: 'VARCHAR(64)',
    totp_secret: 'VARCHAR(64)',
    totp_scopes: 'VARCHAR(255)'
};
const _healedAccountCols = {};
// 自愈补列：默认补 cloud_storage_accounts；传入 tableName 可补 cloud_link_accounts（两表结构同款）
async function _healAccountColumn(col, tableName) {
    const t = tableName || 'cloud_storage_accounts';
    const key = t + '.' + col;
    if (_healedAccountCols[key] || !CLOUD_ACCOUNT_COLUMNS[col]) return false;
    try {
        await pool.query('ALTER TABLE ' + t + ' ADD COLUMN ' + col + ' ' + CLOUD_ACCOUNT_COLUMNS[col]);
        console.log('🗄️ 自愈：已为 ' + t + ' 补充列 ' + col);
        _healedAccountCols[key] = true;
        return true;
    } catch (e) {
        console.error('[云储存] 自愈补列 ' + t + '.' + col + ' 失败:', e.message);
        return false;
    }
}
async function dbSaveCloudAccount(acc) {
    const maxMazes = Number(acc.max_mazes != null ? acc.max_mazes : CLOUD_MAX_MAZES);
    const clientId = (acc.client_id != null) ? acc.client_id : null;
    const disabled = (acc.disabled != null) ? (acc.disabled ? 1 : 0) : 0;
    const bannedUntil = (acc.banned_until != null && acc.banned_until !== '') ? String(acc.banned_until) : null;
    const twoFactor = (acc.two_factor_enabled != null) ? (acc.two_factor_enabled ? 1 : 0) : 0;
    // creator_client_id 仅注册时写入，登录/其它更新时保持不变（不可变）
    const creatorClientId = (acc.creator_client_id != null && acc.creator_client_id !== '') ? acc.creator_client_id : null;
    const totpSecret = (acc.totp_secret != null && acc.totp_secret !== '') ? acc.totp_secret : null;
    const totpScopes = (acc.totp_scopes != null && acc.totp_scopes !== '') ? String(acc.totp_scopes) : null;
    const SQL = 'INSERT INTO cloud_storage_accounts (username, password_hash, created_at, updated_at, max_mazes, client_id, disabled, banned_until, two_factor_enabled, creator_client_id, totp_secret, totp_scopes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ' +
        'ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash), updated_at=VALUES(updated_at), max_mazes=VALUES(max_mazes), client_id=VALUES(client_id), disabled=VALUES(disabled), banned_until=VALUES(banned_until), two_factor_enabled=VALUES(two_factor_enabled), totp_secret=VALUES(totp_secret), totp_scopes=VALUES(totp_scopes)';
    const PARAMS = [acc.username, acc.password_hash, acc.created_at, acc.updated_at, maxMazes, clientId, disabled, bannedUntil, twoFactor, creatorClientId, totpSecret, totpScopes];
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query(SQL, PARAMS);
            return;
        } catch (e) {
            // 自愈：生产库若缺任意一列（迁移未执行），自动补列并重试一次
            const m = String(e.message || '');
            const mm = m.match(/Unknown column ['"]?([a-z_]+)['"]?/i);
            if (mm && CLOUD_ACCOUNT_COLUMNS[mm[1]] && await _healAccountColumn(mm[1])) {
                try { await pool.query(SQL, PARAMS); return; }
                catch (e2) { console.error('[云储存] 自愈补列后写入仍失败:', e2.message); }
            }
            console.error('[云储存] DB 写账号失败:', e.message);
        }
    }
    cloudAccounts.set(acc.username, Object.assign({}, acc, { max_mazes: maxMazes, client_id: clientId, disabled, banned_until: bannedUntil, two_factor_enabled: twoFactor, creator_client_id: creatorClientId, totp_secret: totpSecret, totp_scopes: totpScopes }));
    saveCloudStorage();
}
// 读取某账号允许的云地图数量（受扩容码影响）；缺省回退常量
async function cloudMaxMazes(username) {
    const acc = await dbGetCloudAccount(username);
    if (acc && acc.max_mazes != null) return Number(acc.max_mazes);
    return CLOUD_MAX_MAZES;
}
// 云账号当前是否处于封禁期（限时封禁过期视为未封禁）
function cloudAccountIsBanned(acc) {
    if (!acc || !acc.disabled) return false;
    if (acc.banned_until == null || acc.banned_until === '') return true; // 永久封禁
    try { return new Date(acc.banned_until).getTime() > Date.now(); } catch (e) { return true; }
}
// 限时封禁是否已过期（用于自动解封）
function cloudAccountBanExpired(acc) {
    if (!acc || !acc.disabled) return false;
    if (acc.banned_until == null || acc.banned_until === '') return false; // 永久封禁不过期
    try { return new Date(acc.banned_until).getTime() <= Date.now(); } catch (e) { return false; }
}
// 人类可读的封禁提示（登录/鉴权被拒时返回给客户端展示，如「你的账号被管理员封禁 5 天」）
function cloudAccountBanMessage(acc) {
    if (!acc || !acc.disabled) return '';
    const bu = (acc.banned_until != null && acc.banned_until !== '') ? String(acc.banned_until) : null;
    if (!bu) return '你的账号被管理员永久封禁';
    const ms = new Date(bu).getTime() - Date.now();
    if (isNaN(ms) || ms <= 0) return '你的账号被管理员封禁（已到期，请重新登录）';
    const d = Math.floor(ms / 86400000);
    const h = Math.floor((ms % 86400000) / 3600000);
    const m = Math.max(1, Math.floor((ms % 3600000) / 60000));
    if (d >= 1) return '你的账号被管理员封禁 ' + d + ' 天';
    if (h >= 1) return '你的账号被管理员封禁 ' + h + ' 小时';
    return '你的账号被管理员封禁 ' + m + ' 分钟';
}
// 限时封禁剩余天数（向上取整；永久封禁返回 null），供客户端展示
function cloudAccountBanDays(acc) {
    if (!acc || !acc.disabled) return null;
    const bu = (acc.banned_until != null && acc.banned_until !== '') ? String(acc.banned_until) : null;
    if (!bu) return null;
    const ms = new Date(bu).getTime() - Date.now();
    if (isNaN(ms) || ms <= 0) return 0;
    return Math.max(1, Math.ceil(ms / 86400000));
}
async function dbDeleteCloudMaze(mazeId) {
    if (DB_AVAILABLE && pool) {
        try { await pool.query('DELETE FROM cloud_storage_mazes WHERE id=?', [mazeId]); } catch (e) { console.error('[云储存] DB 删图失败:', e.message); }
    }
    cloudMazes.delete(mazeId);
    saveCloudStorage();
}
async function dbUpsertCloudMaze(m) {
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query(
                'INSERT INTO cloud_storage_mazes (id, username, name, maze, size, teleporters, enemy_speed, show_shop, description, difficulty, created_at, updated_at) ' +
                'VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE ' +
                'name=VALUES(name), maze=VALUES(maze), size=VALUES(size), teleporters=VALUES(teleporters), ' +
                'enemy_speed=VALUES(enemy_speed), show_shop=VALUES(show_shop), description=VALUES(description), ' +
                'difficulty=VALUES(difficulty), updated_at=VALUES(updated_at)',
                [m.id, m.username, m.name,
                 (typeof m.maze === 'string') ? m.maze : JSON.stringify(m.maze),
                 (typeof m.size === 'string') ? m.size : JSON.stringify(m.size || null),
                 (typeof m.teleporters === 'string') ? m.teleporters : JSON.stringify(m.teleporters || []),
                 m.enemy_speed || 1, m.show_shop !== false ? 1 : 0, m.description || '', m.difficulty || '中等',
                 m.created_at, m.updated_at]);
            return;
        } catch (e) { console.error('[云储存] DB 写图失败:', e.message); }
    }
    cloudMazes.set(m.id, m);
    saveCloudStorage();
}
async function dbGetCloudMazes(username) {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT * FROM cloud_storage_mazes WHERE username=? ORDER BY updated_at DESC', [username]);
            if (rows) return rows;
        } catch (e) { console.error('[云储存] DB 读图失败:', e.message); }
    }
    return cloudMazesOf(username);
}
// ===== 云储存「通关数据」：每个账号一条进度记录 =====
// 规范化前端传来的进度，仅保留通关相关字段并做数值校验
function normalizeCloudProgress(p) {
    const out = { unlockedLevel: 1, completedLevels: [], puzzleCompletedLevels: [], customCompletedLevels: [] };
    if (p && typeof p === 'object') {
        let ul = Number(p.unlockedLevel);
        if (isFinite(ul) && ul >= 1 && Number.isInteger(ul)) out.unlockedLevel = ul;
        if (Array.isArray(p.completedLevels)) {
            out.completedLevels = p.completedLevels.filter(n => Number.isFinite(Number(n)) && Number(n) >= 1 && Number.isInteger(Number(n))).map(Number);
        }
        if (Array.isArray(p.puzzleCompletedLevels)) {
            out.puzzleCompletedLevels = p.puzzleCompletedLevels.filter(n => Number.isFinite(Number(n)) && Number(n) >= 1 && Number.isInteger(Number(n))).map(Number);
        }
        if (Array.isArray(p.customCompletedLevels)) {
            out.customCompletedLevels = p.customCompletedLevels.filter(n => Number.isFinite(Number(n)) && Number(n) >= 1 && Number.isInteger(Number(n))).map(Number);
        }
    }
    return out;
}
// 合并两条进度：关卡数取最大，已通关列表取并集（进度只增不减）
function mergeCloudProgress(a, b) {
    const na = normalizeCloudProgress(a), nb = normalizeCloudProgress(b);
    const setLv = new Set([...na.completedLevels, ...nb.completedLevels]);
    const setPz = new Set([...na.puzzleCompletedLevels, ...nb.puzzleCompletedLevels]);
    const setCz = new Set([...na.customCompletedLevels, ...nb.customCompletedLevels]);
    return {
        unlockedLevel: Math.max(na.unlockedLevel, nb.unlockedLevel),
        completedLevels: Array.from(setLv).sort((x, y) => x - y),
        puzzleCompletedLevels: Array.from(setPz).sort((x, y) => x - y),
        customCompletedLevels: Array.from(setCz).sort((x, y) => x - y)
    };
}
function cloudProgressOf(username) {
    return cloudProgress.get(username) || null;
}
async function dbGetCloudProgress(username) {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT * FROM cloud_storage_progress WHERE username=?', [username]);
            if (rows && rows.length) {
                let prog = rows[0].progress;
                if (typeof prog === 'string') { try { prog = JSON.parse(prog); } catch (e) { prog = null; } }
                return { progress: normalizeCloudProgress(prog), updated_at: rows[0].updated_at || null };
            }
            return { progress: null, updated_at: null };
        } catch (e) { console.error('[云储存] DB 读进度失败:', e.message); }
    }
    const p = cloudProgressOf(username);
    return p ? { progress: normalizeCloudProgress(p.progress), updated_at: p.updated_at || null } : { progress: null, updated_at: null };
}
async function dbSaveCloudProgress(username, incoming) {
    const now = new Date().toISOString();
    const cur = await dbGetCloudProgress(username);
    const merged = mergeCloudProgress(cur.progress, incoming);
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query(
                'INSERT INTO cloud_storage_progress (username, progress, updated_at) VALUES (?,?,?) ' +
                'ON DUPLICATE KEY UPDATE progress=VALUES(progress), updated_at=VALUES(updated_at)',
                [username, JSON.stringify(merged), now]);
            return { progress: merged, updated_at: now };
        } catch (e) { console.error('[云储存] DB 写进度失败:', e.message); }
    }
    cloudProgress.set(username, { username, progress: merged, updated_at: now });
    saveCloudStorage();
    return { progress: merged, updated_at: now };
}
async function dbGetAllCloudAccounts() {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT username, created_at, updated_at, client_id, disabled, max_mazes, banned_until, two_factor_enabled FROM cloud_storage_accounts ORDER BY created_at DESC');
            if (rows) return rows.map(r => ({ username: r.username, created_at: r.created_at, updated_at: r.updated_at, client_id: r.client_id || null, disabled: !!r.disabled, max_mazes: r.max_mazes != null ? Number(r.max_mazes) : null, banned_until: (r.banned_until != null && r.banned_until !== '') ? r.banned_until : null, two_factor_enabled: r.two_factor_enabled ? 1 : 0 }));
        } catch (e) { console.error('[云储存] DB 读账号列表失败:', e.message); }
    }
    return Array.from(cloudAccounts.values()).map(a => ({ username: a.username, created_at: a.created_at, updated_at: a.updated_at, client_id: a.client_id || null, disabled: !!a.disabled, max_mazes: a.max_mazes != null ? Number(a.max_mazes) : null, banned_until: (a.banned_until != null && a.banned_until !== '') ? a.banned_until : null, two_factor_enabled: (a.two_factor_enabled != null ? (a.two_factor_enabled ? 1 : 0) : 0) }));
}

// 级联删除云储存账号：删除账号本身 + 其全部地图 + 全部会话（内存与 DB 双写）
async function dbDeleteCloudAccount(username) {
    // 删除地图
    const mazes = await dbGetCloudMazes(username);
    for (const m of mazes) { await dbDeleteCloudMaze(m.id); }
    // 删除会话
    if (DB_AVAILABLE && pool) {
        try { await pool.query('DELETE FROM cloud_sessions WHERE username=?', [username]); } catch (e) { console.error('[云储存] DB 删会话失败:', e.message); }
    }
    for (const [k, s] of cloudSessions) if (s.username === username) cloudSessions.delete(k);
    saveCloudSessions();
    // 删除账号
    if (DB_AVAILABLE && pool) {
        try { await pool.query('DELETE FROM cloud_storage_accounts WHERE username=?', [username]); } catch (e) { console.error('[云储存] DB 删账号失败:', e.message); }
    }
    cloudAccounts.delete(username);
    saveCloudStorage();
}
loadCloudStorage();

// ===== 云储存会话（设备）管理：记录每个账号在哪些设备/浏览器登录，支持远端退登 =====
const CLOUD_SESSIONS_FILE = path.join(DATA_DIR, 'cloud-sessions.json');
let cloudSessions = new Map(); // id -> { id, username, device, created_at, last_active_at, _lastTouch? }
async function loadCloudSessions() {
    try {
        if (DB_AVAILABLE && pool) {
            try {
                const [rows] = await pool.query('SELECT * FROM cloud_sessions');
                if (rows) rows.forEach(s => cloudSessions.set(s.id, s));
                return; // DB 成功 → 以 DB 为准
            } catch (e) { console.error('[云储存] DB 会话载入失败，回退 JSON:', e.message); }
        }
        if (fs.existsSync(CLOUD_SESSIONS_FILE)) {
            const arr = JSON.parse(fs.readFileSync(CLOUD_SESSIONS_FILE, 'utf8'));
            if (Array.isArray(arr)) arr.forEach(s => cloudSessions.set(s.id, s));
        }
    } catch (e) { console.error('[云储存] 会话载入失败:', e.message); }
}
function saveCloudSessions() {
    try { ensureDataDir(); fs.writeFileSync(CLOUD_SESSIONS_FILE, JSON.stringify(Array.from(cloudSessions.values()), null, 2)); }
    catch (e) { console.error('[云储存] 会话保存失败:', e.message); }
}
async function dbGetCloudSessions(username) {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT * FROM cloud_sessions WHERE username=? ORDER BY last_active_at DESC', [username]);
            if (rows) { rows.forEach(s => cloudSessions.set(s.id, s)); return rows; }
        } catch (e) { console.error('[云储存] DB 读会话失败:', e.message); }
    }
    return Array.from(cloudSessions.values()).filter(s => s.username === username)
        .sort((a, b) => (b.last_active_at || '').localeCompare(a.last_active_at || ''));
}
async function dbUpsertCloudSession(s) {
    cloudSessions.set(s.id, s); // 内存始终同步，保证 requireCloudAuth 校验可用
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query(
                'INSERT INTO cloud_sessions (id, username, device, ip, created_at, last_active_at) VALUES (?,?,?,?,?,?) ' +
                'ON DUPLICATE KEY UPDATE device=VALUES(device), last_active_at=VALUES(last_active_at)',
                [s.id, s.username, s.device, s.ip || '', s.created_at, s.last_active_at]);
            return;
        } catch (e) { console.error('[云储存] DB 写会话失败:', e.message); }
    }
    saveCloudSessions();
}
async function dbDeleteCloudSession(id) {
    cloudSessions.delete(id);
    if (DB_AVAILABLE && pool) {
        try { await pool.query('DELETE FROM cloud_sessions WHERE id=?', [id]); } catch (e) { console.error('[云储存] DB 删会话失败:', e.message); }
    }
    saveCloudSessions();
}
async function dbDeleteCloudSessionsExcept(username, exceptId) {
    if (DB_AVAILABLE && pool) {
        try { await pool.query('DELETE FROM cloud_sessions WHERE username=? AND id<>?', [username, exceptId]); } catch (e) { console.error('[云储存] DB 删会话失败:', e.message); }
    }
    for (const [k, s] of cloudSessions) if (s.username === username && k !== exceptId) cloudSessions.delete(k);
    saveCloudSessions();
}
// 退登某账号的全部设备（封禁时强制下线）
async function dbDeleteCloudSessionsByUser(username) {
    if (!username) return;
    if (DB_AVAILABLE && pool) {
        try { await pool.query('DELETE FROM cloud_sessions WHERE username=?', [username]); } catch (e) { console.error('[云储存] DB 删会话失败:', e.message); }
    }
    for (const [k, s] of cloudSessions) if (s.username === username) cloudSessions.delete(k);
    saveCloudSessions();
}
function genSessionId() { return 'cs_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 12); }
function makeCloudSession(username, device, ip) {
    const id = genSessionId();
    const now = new Date().toISOString();
    const s = { id, username, device: (device || '未知设备').toString().slice(0, 128), ip: (ip || '').toString().slice(0, 64), created_at: now, last_active_at: now };
    dbUpsertCloudSession(s).catch(e => console.error('[云储存] 创建会话失败:', e.message));
    return s;
}
// 更新会话活跃时间（内存即时更新；DB 写入节流到每 60 秒一次，避免请求级写库打满连接池）
function touchCloudSession(sess) {
    sess.last_active_at = new Date().toISOString();
    const now = Date.now();
    if (!sess._lastTouch || now - sess._lastTouch > 60000) {
        sess._lastTouch = now;
        dbUpsertCloudSession(sess).catch(() => {});
    }
}
loadCloudSessions().catch(e => console.error('[云储存] 会话载入失败:', e.message));

// =============== 云空间扩容码 ===============
// 管理员生成、客户端兑换：可自定义使用次数 / 允许 IP / 扩容到的容量。
// 存储：DB 优先（cloud_expansion_codes 表），失败回退 JSON 文件（data/cloud-codes.json）。
const CLOUD_CODES_FILE = path.join(DATA_DIR, 'cloud-codes.json');
let cloudCodes = new Map(); // code -> { code, max_uses, used, allowed_ips, capacity, created_at, created_by, note, active, redeemed_by[] }
function loadCloudCodes() {
    try {
        if (fs.existsSync(CLOUD_CODES_FILE)) {
            const arr = JSON.parse(fs.readFileSync(CLOUD_CODES_FILE, 'utf8'));
            if (Array.isArray(arr)) arr.forEach(c => cloudCodes.set(c.code, c));
            console.log(`[云储存] 已从 ${CLOUD_CODES_FILE} 加载 ${cloudCodes.size} 个扩容码`);
        }
    } catch (e) { console.error('[云储存] 扩容码载入失败:', e.message); }
}
function saveCloudCodes() {
    try { ensureDataDir(); fs.writeFileSync(CLOUD_CODES_FILE, JSON.stringify(Array.from(cloudCodes.values()), null, 2)); }
    catch (e) { console.error('[云储存] 扩容码保存失败:', e.message); }
}
async function dbGetCloudCode(code) {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT * FROM cloud_expansion_codes WHERE code=?', [code]);
            if (rows && rows.length) {
                const c = rows[0];
                c.redeemed_by = c.redeemed_by ? (Array.isArray(c.redeemed_by) ? c.redeemed_by : JSON.parse(c.redeemed_by || '[]')) : [];
                c.allowed_ips = (c.allowed_ips === '*') ? '*' : (c.allowed_ips ? (Array.isArray(c.allowed_ips) ? c.allowed_ips : String(c.allowed_ips).split(',').map(s => s.trim()).filter(Boolean)) : []);
                return c;
            }
        } catch (e) { console.error('[云储存] DB 读扩容码失败:', e.message); }
    }
    const c = cloudCodes.get(code);
    if (c) return c;
    return null;
}
async function dbAllCloudCodes() {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT * FROM cloud_expansion_codes ORDER BY created_at DESC');
            if (rows) return rows.map(c => {
                c.redeemed_by = c.redeemed_by ? (Array.isArray(c.redeemed_by) ? c.redeemed_by : JSON.parse(c.redeemed_by || '[]')) : [];
                c.allowed_ips = (c.allowed_ips === '*') ? '*' : (c.allowed_ips ? (Array.isArray(c.allowed_ips) ? c.allowed_ips : String(c.allowed_ips).split(',').map(s => s.trim()).filter(Boolean)) : []);
                return c;
            });
        } catch (e) { console.error('[云储存] DB 读扩容码列表失败:', e.message); }
    }
    return Array.from(cloudCodes.values());
}
async function dbUpsertCloudCode(c) {
    cloudCodes.set(c.code, c); // 内存同步，保证兑换校验即时可用
    if (DB_AVAILABLE && pool) {
        try {
            const allowedIps = (c.allowed_ips === '*') ? '*' : (Array.isArray(c.allowed_ips) ? c.allowed_ips.join(',') : (c.allowed_ips || ''));
            const redeemedBy = Array.isArray(c.redeemed_by) ? JSON.stringify(c.redeemed_by) : (c.redeemed_by || '[]');
            await pool.query(
                'INSERT INTO cloud_expansion_codes (code, max_uses, used, allowed_ips, capacity, created_at, created_by, note, active, redeemed_by) ' +
                'VALUES (?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE used=VALUES(used), allowed_ips=VALUES(allowed_ips), active=VALUES(active), redeemed_by=VALUES(redeemed_by)',
                [c.code, c.max_uses, c.used, allowedIps, c.capacity, c.created_at, c.created_by, c.note || '', c.active ? 1 : 0, redeemedBy]);
            return;
        } catch (e) { console.error('[云储存] DB 写扩容码失败:', e.message); }
    }
    saveCloudCodes();
}
async function dbDeleteCloudCode(code) {
    cloudCodes.delete(code);
    if (DB_AVAILABLE && pool) {
        try { await pool.query('DELETE FROM cloud_expansion_codes WHERE code=?', [code]); } catch (e) { console.error('[云储存] DB 删扩容码失败:', e.message); }
    }
    saveCloudCodes();
}
// 生成可读扩容码：MZ + 16 位 base32，分组展示
function genExpansionCode() {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 去掉易混字符 I O 0 1
    let raw = '';
    for (let i = 0; i < 16; i++) raw += alphabet[Math.floor(Math.random() * alphabet.length)];
    return 'MZ' + raw;
}
loadCloudCodes();

// =============== 云链接（分享迷宫为可游玩的网页链接） ===============
// 独立于「云储存」的一套轻量账号体系：玩家在工坊「查看/分享迷宫」里把一张迷宫发布成云链接，
// 任何人打开 <服务器>/m/<code> 即可直接游玩该迷宫（无需登录）。
// 存储：DB 优先（cloud_link_accounts / cloud_links 表），失败回退 JSON 文件（data/cloud-links.json）。
const CLOUD_LINKS_FILE = path.join(DATA_DIR, 'cloud-links.json');
const CLOUD_LINK_MAX_PER_USER = 20; // 每个云链接账号最多可创建的链接数
let cloudLinkAccounts = new Map(); // username -> { username, password_hash, created_at, updated_at, client_id, disabled }
let cloudLinks = new Map();        // code -> { code, username, name, data, views, disabled, created_at, updated_at }
function loadCloudLinks() {
    try {
        if (fs.existsSync(CLOUD_LINKS_FILE)) {
            const s = JSON.parse(fs.readFileSync(CLOUD_LINKS_FILE, 'utf8'));
            if (s && s.accounts) s.accounts.forEach(a => cloudLinkAccounts.set(a.username, a));
            if (s && s.links) s.links.forEach(l => cloudLinks.set(l.code, l));
            console.log(`[云链接] 已从 ${CLOUD_LINKS_FILE} 加载 ${cloudLinkAccounts.size} 账号 / ${cloudLinks.size} 链接`);
        }
    } catch (e) { console.error('[云链接] 加载失败:', e.message); }
}
function saveCloudLinksFile() {
    try {
        ensureDataDir();
        fs.writeFileSync(CLOUD_LINKS_FILE, JSON.stringify({
            accounts: Array.from(cloudLinkAccounts.values()),
            links: Array.from(cloudLinks.values())
        }, null, 2));
    } catch (e) { console.error('[云链接] 保存失败:', e.message); }
}
loadCloudLinks();

// ===== 云链接访问记录：谁访问过哪条链接（管理端可查）。DB 优先（cloud_link_visits 表），失败回退 JSON 文件。 =====
const CLOUD_LINK_VISITS_FILE = path.join(DATA_DIR, 'cloud-link-visits.json');
let cloudLinkVisits = []; // { id, code, link_name, username, source: 'account'|'player', client_id, ip, created_at }，新记录在前
const CLOUD_LINK_VISITS_MAX = 5000; // 内存/JSON 最多保留条数（DB 模式不限制，仅防止 JSON 模式无限膨胀）
function loadCloudLinkVisits() {
    try {
        if (fs.existsSync(CLOUD_LINK_VISITS_FILE)) {
            const arr = JSON.parse(fs.readFileSync(CLOUD_LINK_VISITS_FILE, 'utf8'));
            if (Array.isArray(arr)) cloudLinkVisits = arr.slice(0, CLOUD_LINK_VISITS_MAX);
        }
    } catch (e) { console.error('[云链接] 访问记录加载失败:', e.message); }
}
function saveCloudLinkVisits() {
    try {
        ensureDataDir();
        fs.writeFileSync(CLOUD_LINK_VISITS_FILE, JSON.stringify(cloudLinkVisits.slice(0, CLOUD_LINK_VISITS_MAX), null, 2));
    } catch (e) { console.error('[云链接] 访问记录保存失败:', e.message); }
}
async function dbAddLinkVisit(v) {
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query(
                'INSERT INTO cloud_link_visits (id, code, link_name, username, source, client_id, ip, created_at) VALUES (?,?,?,?,?,?,?,?)',
                [v.id, v.code, v.link_name, v.username, v.source, v.client_id || null, v.ip || null, v.created_at]);
            return;
        } catch (e) { console.error('[云链接] DB 写访问记录失败:', e.message); }
    }
    cloudLinkVisits.unshift(v);
    if (cloudLinkVisits.length > CLOUD_LINK_VISITS_MAX) cloudLinkVisits.length = CLOUD_LINK_VISITS_MAX;
    saveCloudLinkVisits();
}
async function dbRemoveLinkVisits(code) {
    if (DB_AVAILABLE && pool) {
        try { await pool.query('DELETE FROM cloud_link_visits WHERE code=?', [code]); } catch (e) { console.error('[云链接] DB 删访问记录失败:', e.message); }
    }
    cloudLinkVisits = cloudLinkVisits.filter(v => v.code !== code);
    saveCloudLinkVisits();
}
async function dbAllLinkVisits(q, limit) {
    q = (q || '').toString().trim();
    limit = Math.min(Math.max(Number(limit) || 500, 1), 2000);
    if (DB_AVAILABLE && pool) {
        try {
            if (q) {
                const like = '%' + q + '%';
                const [rows] = await pool.query(
                    'SELECT * FROM cloud_link_visits WHERE code LIKE ? OR username LIKE ? OR link_name LIKE ? ORDER BY created_at DESC LIMIT ?',
                    [like, like, like, limit]);
                if (rows) return rows;
            } else {
                const [rows] = await pool.query('SELECT * FROM cloud_link_visits ORDER BY created_at DESC LIMIT ?', [limit]);
                if (rows) return rows;
            }
        } catch (e) { console.error('[云链接] DB 读访问记录失败:', e.message); }
    }
    let list = cloudLinkVisits.slice(0, limit);
    if (q) list = list.filter(v => (v.code || '').includes(q) || (v.username || '').includes(q) || (v.link_name || '').includes(q));
    return list;
}
// 玩家端：按短链码精确查该链接的访问记录（仅属主可见；DB 优先，失败回退内存/JSON）
async function dbLinkVisitsByCode(code, limit) {
    limit = Math.min(Math.max(Number(limit) || 200, 1), 1000);
    if (DB_AVAILABLE && pool) {
        try { const [rows] = await pool.query('SELECT * FROM cloud_link_visits WHERE code=? ORDER BY created_at DESC LIMIT ?', [code, limit]); if (rows) return rows; } catch (e) { console.error('[云链接] DB 读链接访问记录失败:', e.message); }
    }
    return cloudLinkVisits.filter(v => v.code === code).slice(0, limit);
}
loadCloudLinkVisits();

// 生成短链码：8 位去混淆字符（无 I O 0 1），冲突则重试
function genLinkCode() {
    const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
    let s = '';
    for (let i = 0; i < 8; i++) s += alphabet[Math.floor(Math.random() * alphabet.length)];
    return s;
}
// 统一解析 data 字段（DB 可能返回字符串或对象）
function parseLinkData(d) {
    if (d == null) return null;
    if (typeof d === 'string') { try { return JSON.parse(d); } catch (e) { return null; } }
    return d;
}
async function dbGetLinkAccount(username) {
    if (!username) return null;
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT * FROM cloud_link_accounts WHERE username=?', [username]);
            if (rows && rows.length) return rows[0];
        } catch (e) { console.error('[云链接] DB 读账号失败:', e.message); }
    }
    return cloudLinkAccounts.get(username) || null;
}
async function dbSaveLinkAccount(acc) {
    const clientId = (acc.client_id != null) ? acc.client_id : null;
    const disabled = acc.disabled ? 1 : 0;
    const twoFactor = acc.two_factor_enabled ? 1 : 0;
    // creator_client_id 仅注册时写入，登录/其它更新时保持不变（不可变）
    const creatorClientId = (acc.creator_client_id != null && acc.creator_client_id !== '') ? acc.creator_client_id : null;
    const totpSecret = (acc.totp_secret != null && acc.totp_secret !== '') ? acc.totp_secret : null;
    const totpScopes = (acc.totp_scopes != null && acc.totp_scopes !== '') ? String(acc.totp_scopes) : null;
    const SQL = 'INSERT INTO cloud_link_accounts (username, password_hash, created_at, updated_at, client_id, disabled, two_factor_enabled, creator_client_id, totp_secret, totp_scopes) VALUES (?,?,?,?,?,?,?,?,?,?) ' +
        'ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash), updated_at=VALUES(updated_at), client_id=VALUES(client_id), disabled=VALUES(disabled), two_factor_enabled=VALUES(two_factor_enabled), totp_secret=VALUES(totp_secret), totp_scopes=VALUES(totp_scopes)';
    const PARAMS = [acc.username, acc.password_hash, acc.created_at, acc.updated_at, clientId, disabled, twoFactor, creatorClientId, totpSecret, totpScopes];
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query(SQL, PARAMS);
            return;
        } catch (e) {
            // 自愈：云链接表缺列（迁移未执行）时补列并重试一次，避免整个写库失败落到 JSON 丢密钥
            const m = String(e.message || '');
            const mm = m.match(/Unknown column ['"]?([a-z_]+)['"]?/i);
            if (mm && CLOUD_ACCOUNT_COLUMNS[mm[1]] && await _healAccountColumn(mm[1], 'cloud_link_accounts')) {
                try { await pool.query(SQL, PARAMS); return; }
                catch (e2) { console.error('[云链接] 自愈补列后写入仍失败:', e2.message); }
            }
            console.error('[云链接] DB 写账号失败:', e.message);
        }
    }
    cloudLinkAccounts.set(acc.username, Object.assign({}, acc, { client_id: clientId, disabled, two_factor_enabled: twoFactor, creator_client_id: creatorClientId, totp_secret: totpSecret, totp_scopes: totpScopes }));
    saveCloudLinksFile();
}
async function dbAllLinkAccounts() {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT username, created_at, updated_at, client_id, disabled, two_factor_enabled FROM cloud_link_accounts ORDER BY created_at DESC');
            if (rows) return rows.map(r => ({ username: r.username, created_at: r.created_at, updated_at: r.updated_at, client_id: r.client_id || null, disabled: !!r.disabled, two_factor_enabled: r.two_factor_enabled ? 1 : 0 }));
        } catch (e) { console.error('[云链接] DB 读账号列表失败:', e.message); }
    }
    return Array.from(cloudLinkAccounts.values())
        .map(a => ({ username: a.username, created_at: a.created_at, updated_at: a.updated_at, client_id: a.client_id || null, disabled: !!a.disabled, two_factor_enabled: (a.two_factor_enabled != null ? (a.two_factor_enabled ? 1 : 0) : 0) }))
        .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
}
async function dbGetLink(code) {
    if (!code) return null;
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT * FROM cloud_links WHERE code=?', [code]);
            if (rows && rows.length) { const l = rows[0]; l.data = parseLinkData(l.data); return l; }
        } catch (e) { console.error('[云链接] DB 读链接失败:', e.message); }
    }
    return cloudLinks.get(code) || null;
}
async function dbGetLinksOf(username) {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT * FROM cloud_links WHERE username=? ORDER BY created_at DESC', [username]);
            if (rows) return rows.map(l => { l.data = parseLinkData(l.data); return l; });
        } catch (e) { console.error('[云链接] DB 读链接列表失败:', e.message); }
    }
    return Array.from(cloudLinks.values())
        .filter(l => l.username === username)
        .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
}
async function dbUpsertLink(l) {
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query(
                'INSERT INTO cloud_links (code, username, name, data, views, disabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?) ' +
                'ON DUPLICATE KEY UPDATE name=VALUES(name), data=VALUES(data), views=VALUES(views), disabled=VALUES(disabled), updated_at=VALUES(updated_at)',
                [l.code, l.username, l.name || '未命名迷宫',
                 (typeof l.data === 'string') ? l.data : JSON.stringify(l.data || {}),
                 Number(l.views || 0), l.disabled ? 1 : 0, l.created_at, l.updated_at]);
            return;
        } catch (e) { console.error('[云链接] DB 写链接失败:', e.message); }
    }
    cloudLinks.set(l.code, l);
    saveCloudLinksFile();
}
async function dbDeleteLink(code) {
    if (DB_AVAILABLE && pool) {
        try { await pool.query('DELETE FROM cloud_links WHERE code=?', [code]); } catch (e) { console.error('[云链接] DB 删链接失败:', e.message); }
        try { await pool.query('DELETE FROM cloud_link_visits WHERE code=?', [code]); } catch (e) { console.error('[云链接] DB 删访问记录失败:', e.message); }
    }
    cloudLinks.delete(code);
    cloudLinkVisits = cloudLinkVisits.filter(v => v.code !== code);
    saveCloudLinksFile();
    saveCloudLinkVisits();
}
async function dbDeleteLinkAccount(username) {
    if (DB_AVAILABLE && pool) {
        try { await pool.query('DELETE FROM cloud_links WHERE username=?', [username]); } catch (e) { console.error('[云链接] DB 删账号链接失败:', e.message); }
        try { await pool.query('DELETE FROM cloud_link_accounts WHERE username=?', [username]); } catch (e) { console.error('[云链接] DB 删账号失败:', e.message); }
        try { await pool.query('DELETE FROM cloud_link_sessions WHERE username=?', [username]); } catch (e) { console.error('[云链接] DB 删账号会话失败:', e.message); }
    }
    for (const [k, v] of cloudLinks) if (v.username === username) cloudLinks.delete(k);
    for (const [k, s] of cloudLinkSessions) if (s.username === username) cloudLinkSessions.delete(k);
    cloudLinkAccounts.delete(username);
    saveCloudLinksFile();
    saveCloudLinkSessions(); // 同步持久化：注销账号时一并清除其所有会话，避免残留无效设备记录
}
// 浏览计数（DB 优先，失败落内存）；失败不影响正常读取
async function dbBumpLinkViews(code) {
    if (DB_AVAILABLE && pool) {
        try { await pool.query('UPDATE cloud_links SET views=views+1 WHERE code=?', [code]); return; } catch (e) { /* 忽略 */ }
    }
    const l = cloudLinks.get(code);
    if (l) { l.views = Number(l.views || 0) + 1; saveCloudLinksFile(); }
}

// ===== 云链接会话（设备）管理：记录账号在哪些设备/浏览器登录，支持远端退登 =====
const CLOUD_LINK_SESSIONS_FILE = path.join(DATA_DIR, 'cloud-link-sessions.json');
let cloudLinkSessions = new Map(); // id -> { id, username, device, ip, created_at, last_active_at, _lastTouch? }
async function loadCloudLinkSessions() {
    try {
        if (DB_AVAILABLE && pool) {
            try {
                const [rows] = await pool.query('SELECT * FROM cloud_link_sessions');
                if (rows) rows.forEach(s => cloudLinkSessions.set(s.id, s));
                return; // DB 成功 → 以 DB 为准
            } catch (e) { console.error('[云链接] DB 会话载入失败，回退 JSON:', e.message); }
        }
        if (fs.existsSync(CLOUD_LINK_SESSIONS_FILE)) {
            const arr = JSON.parse(fs.readFileSync(CLOUD_LINK_SESSIONS_FILE, 'utf8'));
            if (Array.isArray(arr)) arr.forEach(s => cloudLinkSessions.set(s.id, s));
        }
    } catch (e) { console.error('[云链接] 会话载入失败:', e.message); }
}
function saveCloudLinkSessions() {
    try { ensureDataDir(); fs.writeFileSync(CLOUD_LINK_SESSIONS_FILE, JSON.stringify(Array.from(cloudLinkSessions.values()), null, 2)); }
    catch (e) { console.error('[云链接] 会话保存失败:', e.message); }
}
async function dbGetCloudLinkSessions(username) {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT * FROM cloud_link_sessions WHERE username=? ORDER BY last_active_at DESC', [username]);
            if (rows) { rows.forEach(s => cloudLinkSessions.set(s.id, s)); return rows; }
        } catch (e) { console.error('[云链接] DB 读会话失败:', e.message); }
    }
    return Array.from(cloudLinkSessions.values()).filter(s => s.username === username)
        .sort((a, b) => (b.last_active_at || '').localeCompare(a.last_active_at || ''));
}
async function dbUpsertCloudLinkSession(s) {
    cloudLinkSessions.set(s.id, s); // 内存始终同步，保证 requireLinkAuth 校验可用
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query(
                'INSERT INTO cloud_link_sessions (id, username, device, ip, created_at, last_active_at) VALUES (?,?,?,?,?,?) ' +
                'ON DUPLICATE KEY UPDATE device=VALUES(device), last_active_at=VALUES(last_active_at)',
                [s.id, s.username, s.device, s.ip || '', s.created_at, s.last_active_at]);
            return;
        } catch (e) { console.error('[云链接] DB 写会话失败:', e.message); }
    }
    saveCloudLinkSessions();
}
async function dbDeleteCloudLinkSession(id) {
    cloudLinkSessions.delete(id);
    if (DB_AVAILABLE && pool) {
        try { await pool.query('DELETE FROM cloud_link_sessions WHERE id=?', [id]); } catch (e) { console.error('[云链接] DB 删会话失败:', e.message); }
    }
    saveCloudLinkSessions();
}
async function dbDeleteCloudLinkSessionsExcept(username, exceptId) {
    if (DB_AVAILABLE && pool) {
        try { await pool.query('DELETE FROM cloud_link_sessions WHERE username=? AND id<>?', [username, exceptId]); } catch (e) { console.error('[云链接] DB 删会话失败:', e.message); }
    }
    for (const [k, s] of cloudLinkSessions) if (s.username === username && k !== exceptId) cloudLinkSessions.delete(k);
    saveCloudLinkSessions();
}
// 退登某账号的全部设备（注销账号 / 管理员封禁时强制下线）
async function dbDeleteCloudLinkSessionsByUser(username) {
    if (!username) return;
    if (DB_AVAILABLE && pool) {
        try { await pool.query('DELETE FROM cloud_link_sessions WHERE username=?', [username]); } catch (e) { console.error('[云链接] DB 删会话失败:', e.message); }
    }
    for (const [k, s] of cloudLinkSessions) if (s.username === username) cloudLinkSessions.delete(k);
    saveCloudLinkSessions();
}
function genLinkSessionId() { return 'cl_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 12); }
function makeCloudLinkSession(username, device, ip) {
    const id = genLinkSessionId();
    const now = new Date().toISOString();
    const s = { id, username, device: (device || '未知设备').toString().slice(0, 128), ip: (ip || '').toString().slice(0, 64), created_at: now, last_active_at: now };
    dbUpsertCloudLinkSession(s).catch(e => console.error('[云链接] 创建会话失败:', e.message));
    return s;
}
// 更新会话活跃时间（内存即时更新；DB 写入节流到每 60 秒一次，避免请求级写库打满连接池）
function touchCloudLinkSession(sess) {
    sess.last_active_at = new Date().toISOString();
    const now = Date.now();
    if (!sess._lastTouch || now - sess._lastTouch > 60000) {
        sess._lastTouch = now;
        dbUpsertCloudLinkSession(sess).catch(() => {});
    }
}
loadCloudLinkSessions().catch(e => console.error('[云链接] 会话载入失败:', e.message));

// 「查看/分享迷宫（JSON）」总开关：同时管辖云链接的创建
function mazeJsonShareEnabled() { return globalFunctions.mazeJsonShare !== false; }

// 反作弊功能总开关：管理员关闭「显示反作弊标签页」(showAntiCheatTab=false) 时，
// 玩家端反作弊相关 API（上报作弊 / 查询封禁名单）一律返回 403，防止绕过前端直接调用。
function antiCheatEnabled() { return globalFunctions.showAntiCheatTab !== false; }

// 云链接功能总开关（master switch）：控制整套云链接账号/分享/游玩是否可用
function cloudLinkEnabled() { return globalFunctions.cloudLinkEnabled !== false; }

// 云链接鉴权：Authorization: Bearer <jwt>（type=clink）
async function requireLinkAuth(req, res, next) {
    const h = req.headers.authorization || '';
    if (!h.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '未登录' });
    try {
        const decoded = jwt.verify(h.substring(7), JWT_SECRET);
        if (decoded.type !== 'clink' || !decoded.username) return res.status(401).json({ success: false, message: '无效的登录令牌' });
        const acc = await dbGetLinkAccount(decoded.username);
        if (!acc) return res.status(401).json({ success: false, message: '账号不存在，请重新注册' });
        if (acc.disabled) return res.status(403).json({ success: false, disabled: true, message: '该云链接账号已被管理员封禁' });
        req.linkUser = decoded.username;
        // 会话校验（新版令牌带 sid；旧版无 sid 向后兼容）
        const sid = decoded.sid;
        if (sid) {
            let sess = cloudLinkSessions.get(sid);
            if (!sess) {
                // 内存会话丢失（服务端重启 / 冷启动 DB 未就绪）→ 回 DB 重hydrate，避免有效令牌被误判“已退出登录”
                try { await dbGetCloudLinkSessions(decoded.username); sess = cloudLinkSessions.get(sid); } catch (e) {}
            }
            if (!sess || sess.username !== decoded.username) return res.status(401).json({ success: false, message: '该设备已被退出登录，请重新登录' });
            touchCloudLinkSession(sess);
            req.linkSessionId = sid;
        } else {
            req.linkSessionId = null;
        }
        next();
    } catch (e) { res.status(401).json({ success: false, message: '登录已过期，请重新登录' }); }
}

// 规范化前端提交的迷宫数据（只保留游玩所需字段）
function normalizeLinkMaze(b) {
    if (!b || !Array.isArray(b.maze) || b.maze.length === 0) return null;
    const grid = b.maze;
    return {
        name: (b.name || '未命名迷宫').toString().slice(0, 128),
        description: (b.description || '').toString().slice(0, 500),
        difficulty: (b.difficulty || '中等').toString().slice(0, 32),
        size: b.size || { width: (grid[0] || []).length, height: grid.length },
        maze: grid,
        teleporters: Array.isArray(b.teleporters) ? b.teleporters : [],
        enemySpeed: Number(b.enemySpeed) || 5,
        showShop: b.showShop !== false,
        // 机关配置（压力板/联动门/限时门/连锁开关/密码锁等）——若不保留，分享后机关格子会"锁死/无交互"
        mech: (b.mech && typeof b.mech === 'object') ? b.mech : null,
        author: (b.author || '').toString().slice(0, 64)
    };
}

// 公开：云链接功能是否可用（跟随 cloudLinkEnabled 总开关）
app.get('/api/cloud-links/enabled', (req, res) => {
    res.json({ success: true, enabled: cloudLinkEnabled(), jsonShare: mazeJsonShareEnabled() });
});

// 注册云链接账号
app.post('/api/cloud-links/register', async (req, res) => {
    if (!cloudLinkEnabled()) return res.status(403).json({ success: false, message: '云链接功能已关闭' });
    try {
        const username = (req.body.username || '').toString().trim();
        const password = (req.body.password || '').toString();
        if (!username || !password) return res.status(400).json({ success: false, message: '用户名和密码不能为空' });
        if (username.length > 64 || password.length < 4) return res.status(400).json({ success: false, message: '用户名过长或密码至少 4 位' });
        if (await dbGetLinkAccount(username)) return res.status(409).json({ success: false, message: '该用户名已被注册' });
        const now = new Date().toISOString();
        const acc = {
            username,
            password_hash: bcrypt.hashSync(password, 10),
            created_at: now, updated_at: now,
            client_id: (req.body.clientId || '').toString().trim() || null,
            creator_client_id: (req.body.clientId || '').toString().trim() || null,
            disabled: 0
        };
        await dbSaveLinkAccount(acc);
        const device = (req.body.device || req.headers['user-agent'] || '未知设备').toString().slice(0, 128);
        const ip = getClientIp(req);
        const sess = makeCloudLinkSession(username, device, ip);
        const token = jwt.sign({ username, type: 'clink', sid: sess.id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ success: true, token, username, sid: sess.id });
    } catch (e) {
        console.error('[云链接] 注册失败:', e);
        res.status(500).json({ success: false, message: '注册失败' });
    }
});

// 云链接账号登录
app.post('/api/cloud-links/login', async (req, res) => {
    if (!cloudLinkEnabled()) return res.status(403).json({ success: false, message: '云链接功能已关闭' });
    try {
        const username = (req.body.username || '').toString().trim();
        const password = (req.body.password || '').toString();
        const acc = await dbGetLinkAccount(username);
        if (!acc || !bcrypt.compareSync(password, acc.password_hash)) {
            return res.status(401).json({ success: false, message: '用户名或密码错误' });
        }
        if (acc.disabled) return res.status(403).json({ success: false, disabled: true, message: '该云链接账号已被管理员封禁' });
        // 二次认证：已开启 2FA 的账号必须在登录时提供正确动态码（管理员关闭该模块 2FA 时跳过，避免锁死）
        if (acc.two_factor_enabled && twofaGlobalEnabledFor(acc)) {
            const code = read2faCode(req);
            if (!code) return res.status(401).json({ success: false, twoFactorRequired: true, message: '该账号已开启二次认证，请输入动态验证码' });
            const deny = assert2faCode(acc, code);
            if (deny) return res.status(401).json({ success: false, twoFactorRequired: true, message: deny });
        }
        const clientId = (req.body.clientId || '').toString().trim() || null;
        if (clientId && acc.client_id !== clientId) {
            acc.client_id = clientId; acc.updated_at = new Date().toISOString();
            await dbSaveLinkAccount(acc);
        }
        const device = (req.body.device || req.headers['user-agent'] || '未知设备').toString().slice(0, 128);
        const ip = getClientIp(req);
        const sess = makeCloudLinkSession(username, device, ip);
        const token = jwt.sign({ username, type: 'clink', sid: sess.id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ success: true, token, username, sid: sess.id });
    } catch (e) {
        console.error('[云链接] 登录失败:', e);
        res.status(500).json({ success: false, message: '登录失败' });
    }
});

// ===== 云链接账号自助管理（需登录态）=====
// 自助修改密码：需验证原密码
app.put('/api/cloud-links/password', requireLinkAuth, async (req, res) => {
    if (!cloudLinkEnabled()) return res.status(403).json({ success: false, message: '云链接功能已关闭' });
    try {
        const oldPassword = ((req.body && req.body.oldPassword) || '').toString();
        const newPassword = ((req.body && req.body.newPassword) || '').toString();
        if (!oldPassword || !newPassword) return res.status(400).json({ success: false, message: '请输入原密码和新密码' });
        if (newPassword.length < 4) return res.status(400).json({ success: false, message: '新密码至少 4 位' });
        const acc = await dbGetLinkAccount(req.linkUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        const denyPw = assert2faScope(acc, 'password', read2faCode(req));
        if (denyPw) return res.status(403).json({ success: false, message: denyPw });
        if (!bcrypt.compareSync(oldPassword, acc.password_hash)) {
            return res.status(400).json({ success: false, message: '原密码错误' });
        }
        acc.password_hash = bcrypt.hashSync(newPassword, 10);
        acc.updated_at = new Date().toISOString();
        await dbSaveLinkAccount(acc);
        appendAudit(req.linkUser || 'clink', 'cloud-link-account-password-change', `云链接账号「${req.linkUser}」修改密码`, req);
        res.json({ success: true, message: '密码已修改' });
    } catch (e) { res.status(500).json({ success: false, message: '修改失败' }); }
});

// 自助注销账号：需验证密码（级联删除全部云链接、会话与登录态）
app.delete('/api/cloud-links/account', requireLinkAuth, async (req, res) => {
    if (!cloudLinkEnabled()) return res.status(403).json({ success: false, message: '云链接功能已关闭' });
    try {
        const password = ((req.body && req.body.password) || '').toString();
        if (!password) return res.status(400).json({ success: false, message: '请输入密码以确认注销' });
        const acc = await dbGetLinkAccount(req.linkUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        const denyDel = assert2faScope(acc, 'account', read2faCode(req));
        if (denyDel) return res.status(403).json({ success: false, message: denyDel });
        if (!bcrypt.compareSync(password, acc.password_hash)) {
            return res.status(400).json({ success: false, message: '密码错误' });
        }
        await dbDeleteLinkAccount(req.linkUser);
        appendAudit(req.linkUser || 'clink', 'cloud-link-account-delete', `云链接账号「${req.linkUser}」自行注销`, req);
        res.json({ success: true, message: '账号已注销' });
    } catch (e) { res.status(500).json({ success: false, message: '注销失败' }); }
});

// ===== 云链接账号「二次认证（2FA）」开关查询与设置 =====
app.get('/api/cloud-links/2fa', requireLinkAuth, async (req, res) => {
    try {
        const acc = await dbGetLinkAccount(req.linkUser);
        res.json({ success: true, enabled: !!(acc && acc.two_factor_enabled) });
    } catch (e) { res.status(500).json({ success: false, message: '获取失败' }); }
});
// 2FA 作用范围：哪些敏感操作需要动态码（登录始终强制，不在 scope 内）
app.get('/api/cloud-links/2fa/scopes', requireLinkAuth, async (req, res) => {
    try {
        const acc = await dbGetLinkAccount(req.linkUser);
        const enabled = !!(acc && acc.two_factor_enabled);
        const scopes = {};
        TOTP_SCOPES.forEach(s => { scopes[s] = enabled && twofaScopeEnabled(acc, s); });
        res.json({ success: true, enabled, login: true, scopes });
    } catch (e) { res.status(500).json({ success: false, message: '获取失败' }); }
});
// 保存 2FA 作用范围：仅 2FA 开启时可修改，且必须提供正确动态码（防止拿到密码就能关掉全部保护）
app.put('/api/cloud-links/2fa/scopes', requireLinkAuth, async (req, res) => {
    if (!cloudLinkEnabled()) return res.status(403).json({ success: false, message: '云链接功能已关闭' });
    if (!cloudLink2faEnabled()) return res.status(403).json({ success: false, message: '管理员已关闭二次认证功能' });
    try {
        const acc = await dbGetLinkAccount(req.linkUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        if (!acc.two_factor_enabled) return res.status(400).json({ success: false, message: '未开启二次认证，无需配置' });
        const deny = assert2faCode(acc, read2faCode(req));
        if (deny) return res.status(403).json({ success: false, message: deny });
        const reqScopes = (req.body && req.body.scopes) || {};
        const list = TOTP_SCOPES.filter(s => !!reqScopes[s]);
        acc.totp_scopes = (list.length === TOTP_SCOPES.length) ? null : JSON.stringify(list); // 全选 = 默认（全部需要）
        acc.updated_at = new Date().toISOString();
        await dbSaveLinkAccount(acc);
        const scopes = {};
        TOTP_SCOPES.forEach(s => { scopes[s] = twofaScopeEnabled(acc, s); });
        res.json({ success: true, enabled: true, login: true, scopes });
    } catch (e) { res.status(500).json({ success: false, message: '保存失败' }); }
});
// 获取开启二次认证所需信息：生成 TOTP 密钥、otpauth URI 与可扫码二维码。
// 浏览器 2FA 插件（如 Authenticator）扫码或手动填入密钥即可添加该账号。
app.get('/api/cloud-links/2fa/setup', requireLinkAuth, async (req, res) => {
    if (!cloudLinkEnabled()) return res.status(403).json({ success: false, message: '云链接功能已关闭' });
    if (!cloudLink2faEnabled()) return res.status(403).json({ success: false, message: '管理员已关闭二次认证功能' });
    try {
        const secret = totpGenSecret();
        const label = encodeURIComponent('迷宫探险:' + req.linkUser);
        const issuer = encodeURIComponent('迷宫探险');
        const otpauthUri = 'otpauth://totp/' + label + '?secret=' + secret + '&issuer=' + issuer + '&algorithm=SHA1&digits=6&period=30';
        let qr = '';
        if (QRCode) { try { qr = await QRCode.toDataURL(otpauthUri); } catch (e) { qr = ''; } }
        res.json({ success: true, secret, otpauthUri, qr });
    } catch (e) { res.status(500).json({ success: false, message: '生成失败' }); }
});
app.put('/api/cloud-links/2fa', requireLinkAuth, async (req, res) => {
    if (!cloudLinkEnabled()) return res.status(403).json({ success: false, message: '云链接功能已关闭' });
    try {
        const password = ((req.body && req.body.password) || '').toString();
        const enabled = !!((req.body && req.body.enabled));
        if (enabled && !cloudLink2faEnabled()) return res.status(403).json({ success: false, message: '管理员已关闭二次认证功能' });
        if (!password) return res.status(400).json({ success: false, message: '请输入密码以确认操作' });
        const acc = await dbGetLinkAccount(req.linkUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        if (!bcrypt.compareSync(password, acc.password_hash)) {
            return res.status(400).json({ success: false, message: '密码错误' });
        }
        if (enabled) {
            // ① 绑定阶段：校验密码 + 插件首个动态码，密钥先进待确认区。
            // **不落库、不改账号状态**——防止误触（账号原本已开启 / 中途放弃 / 确认失败）时把已开启的 2FA 静默关掉。
            const secret = ((req.body && req.body.secret) || '').toString().trim();
            const code = ((req.body && req.body.code) || '').toString().trim();
            if (!secret) return res.status(400).json({ success: false, message: '缺少 TOTP 密钥' });
            if (!totpVerify(secret, code)) return res.status(400).json({ success: false, message: '动态验证码错误，请确认浏览器插件时间已同步' });
            pending2faPut('clink', req.linkUser, secret, code);
            return res.json({
                success: true, enabled: false, pendingConfirm: true,
                message: '绑定成功，请等待插件刷新出下一个验证码后再输入一次以完成确认'
            });
        }
        // 关闭：清空密钥并作废任何待确认绑定
        pending2faDrop('clink', req.linkUser);
        acc.totp_secret = null;
        acc.two_factor_enabled = 0;
        acc.updated_at = new Date().toISOString();
        await dbSaveLinkAccount(acc);
        appendAudit(req.linkUser || 'clink', 'cloud-link-2fa-change', `云链接账号「${req.linkUser}」二次认证关闭`, req);
        res.json({ success: true, enabled: false, message: '已关闭二次认证' });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});
// ② 确认阶段：必须再验证一次动态码（且不能复用绑定时那一个），通过才真正开启。
// 一旦验证失败 → 丢弃待确认密钥并强制关闭二次认证，用户需从头重新开启。
app.post('/api/cloud-links/2fa/confirm', requireLinkAuth, async (req, res) => {
    if (!cloudLinkEnabled()) return res.status(403).json({ success: false, message: '云链接功能已关闭' });
    if (!cloudLink2faEnabled()) return res.status(403).json({ success: false, message: '管理员已关闭二次认证功能' });
    try {
        const code = ((req.body && req.body.code) || '').toString().trim();
        const acc = await dbGetLinkAccount(req.linkUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        const pend = pending2faTake('clink', req.linkUser);
        if (!pend) {
            return res.status(400).json({ success: false, expired: true, enabled: false, message: '绑定已超时失效，请重新开启二次认证' });
        }
        // 复用绑定时那一个码不算有效确认：必须等插件刷新出新码，避免"复制粘贴同一个码"糊弄过关
        if (code && code === pend.bindCode) {
            return res.status(400).json({ success: false, sameCode: true, message: '请等待插件刷新出【新的】验证码，不能重复使用刚才那一个' });
        }
        if (!totpVerify(pend.secret, code)) {
            // 确认失败 → 保留待确认密钥，允许在有效期内重试（不强制作废，避免误输一次就前功尽弃）
            appendAudit(req.linkUser || 'clink', 'cloud-link-2fa-confirm-fail', `云链接账号「${req.linkUser}」二次认证确认失败（动态码错误，密钥保留可重试）`, req);
            return res.status(400).json({ success: false, retryable: true, enabled: false, message: '动态码不正确，请确认你的 2FA 插件显示的验证码后重试（不能重复使用绑定时的那个码，需等插件刷新出新码）' });
        }
        pending2faDrop('clink', req.linkUser);
        acc.totp_secret = pend.secret;
        acc.two_factor_enabled = 1;
        acc.updated_at = new Date().toISOString();
        await dbSaveLinkAccount(acc);
        appendAudit(req.linkUser || 'clink', 'cloud-link-2fa-change', `云链接账号「${req.linkUser}」二次认证开启（已通过二次确认）`, req);
        res.json({ success: true, enabled: true, message: '二次认证已开启' });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});
// 二次认证「升级验证」：敏感操作前校验账号密码
app.post('/api/cloud-links/verify', requireLinkAuth, async (req, res) => {
    if (!cloudLinkEnabled()) return res.status(403).json({ success: false, message: '云链接功能已关闭' });
    try {
        const password = ((req.body && req.body.password) || '').toString();
        const acc = await dbGetLinkAccount(req.linkUser);
        if (!acc || !bcrypt.compareSync(password, acc.password_hash)) {
            return res.status(400).json({ success: false, message: '密码错误' });
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: '验证失败' }); }
});
// 二次认证「授权」：敏感操作（打开账号设置/管理设备/踢出设备）前的身份校验。
// 必须由创建该账号的人（creator_client_id 匹配）点击授权按钮放行，否则拒绝。
app.post('/api/cloud-links/authorize', requireLinkAuth, async (req, res) => {
    if (!cloudLinkEnabled()) return res.status(403).json({ success: false, message: '云链接功能已关闭' });
    try {
        const acc = await dbGetLinkAccount(req.linkUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        if (!acc.two_factor_enabled) return res.json({ success: true, required: false });
        const provided = (req.body && req.body.clientId) || '';
        const deny = assert2faScope(acc, 'authorize', read2faCode(req));
        if (deny) return res.status(403).json({ success: false, message: deny });
        res.json({ success: true, required: true });
    } catch (e) { res.status(500).json({ success: false, message: '授权校验失败' }); }
});

// 查看本账号登录过的设备/会话
app.get('/api/cloud-links/sessions', requireLinkAuth, async (req, res) => {
    try {
        const acc = await dbGetLinkAccount(req.linkUser);
        const provided = (req.query && req.query.clientId) || '';
        const deny = assert2faScope(acc, 'sessions', read2faCode(req));
        if (deny) return res.status(403).json({ success: false, message: deny });
        const list = await dbGetCloudLinkSessions(req.linkUser);
        const out = list.map(s => ({
            id: s.id,
            device: s.device || '未知设备',
            ip: s.ip || '',
            created_at: s.created_at,
            last_active_at: s.last_active_at,
            current: (req.linkSessionId && s.id === req.linkSessionId)
        }));
        res.json({ success: true, sessions: out });
    } catch (e) { res.status(500).json({ success: false, message: '获取失败' }); }
});

// 退登其他所有设备（保留当前设备）
app.delete('/api/cloud-links/sessions', requireLinkAuth, async (req, res) => {
    try {
        const acc = await dbGetLinkAccount(req.linkUser);
        const provided = (req.body && req.body.clientId) || '';
        const deny = assert2faScope(acc, 'sessions', read2faCode(req));
        if (deny) return res.status(403).json({ success: false, message: deny });
        const exceptId = req.linkSessionId || '';
        await dbDeleteCloudLinkSessionsExcept(req.linkUser, exceptId);
        res.json({ success: true, message: '已退出其他所有设备' });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});

// 退登指定设备（传入 current=true 表示退登当前设备，等价于退出登录）
app.delete('/api/cloud-links/sessions/:id', requireLinkAuth, async (req, res) => {
    try {
        const acc = await dbGetLinkAccount(req.linkUser);
        const provided = (req.body && req.body.clientId) || '';
        const deny = assert2faScope(acc, 'sessions', read2faCode(req));
        if (deny) return res.status(403).json({ success: false, message: deny });
        const id = decodeURIComponent(req.params.id || '');
        if (!id) return res.status(400).json({ success: false, message: '缺少会话 id' });
        const s = cloudLinkSessions.get(id);
        if (!s || s.username !== req.linkUser) return res.status(404).json({ success: false, message: '会话不存在' });
        await dbDeleteCloudLinkSession(id);
        const isCurrent = (req.linkSessionId && id === req.linkSessionId);
        res.json({ success: true, message: isCurrent ? '已退出当前设备' : '已退登该设备', current: !!isCurrent });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});

// 我的云链接列表
app.get('/api/cloud-links/mine', requireLinkAuth, async (req, res) => {
    try {
        const list = await dbGetLinksOf(req.linkUser);
        res.json({
            success: true,
            max: CLOUD_LINK_MAX_PER_USER,
            links: list.map(l => ({
                code: l.code, name: l.name, views: Number(l.views || 0), disabled: !!l.disabled,
                created_at: l.created_at, updated_at: l.updated_at
            }))
        });
    } catch (e) {
        console.error('[云链接] 读取列表失败:', e);
        res.status(500).json({ success: false, message: '获取失败' });
    }
});

// 创建云链接（把一张迷宫发布为可游玩的公开链接）
app.post('/api/cloud-links', requireLinkAuth, async (req, res) => {
    try {
        if (!cloudLinkEnabled()) return res.status(403).json({ success: false, message: '管理员已关闭云链接功能' });
        const data = normalizeLinkMaze(req.body || {});
        if (!data) return res.status(400).json({ success: false, message: '迷宫数据无效' });
        const list = await dbGetLinksOf(req.linkUser);
        if (list.length >= CLOUD_LINK_MAX_PER_USER) {
            return res.status(403).json({ success: false, message: `每个账号最多创建 ${CLOUD_LINK_MAX_PER_USER} 个云链接，请先删除旧链接` });
        }
        let code = genLinkCode();
        for (let i = 0; i < 6 && await dbGetLink(code); i++) code = genLinkCode();
        const now = new Date().toISOString();
        const link = { code, username: req.linkUser, name: data.name, data, views: 0, disabled: 0, created_at: now, updated_at: now };
        await dbUpsertLink(link);
        res.json({ success: true, code, name: data.name, path: '/m/' + code });
    } catch (e) {
        console.error('[云链接] 创建失败:', e);
        res.status(500).json({ success: false, message: '创建失败' });
    }
});

// 删除自己的云链接
app.delete('/api/cloud-links/:code', requireLinkAuth, async (req, res) => {
    try {
        const l = await dbGetLink(req.params.code);
        if (!l || l.username !== req.linkUser) return res.status(404).json({ success: false, message: '链接不存在' });
        await dbDeleteLink(req.params.code);
        res.json({ success: true, message: '已删除' });
    } catch (e) {
        console.error('[云链接] 删除失败:', e);
        res.status(500).json({ success: false, message: '删除失败' });
    }
});

// 公开：按短链码读取迷宫数据（游戏客户端凭 ?mazeLink=code 拉取后直接开玩）
// 同时记录访问者：优先取云链接账号（Authorization Bearer），其次玩家名（?name=），兜底 clientId
app.get('/api/maze-link/:code', async (req, res) => {
    try {
        if (!cloudLinkEnabled()) return res.status(403).json({ success: false, message: '云链接功能已关闭' });
        const l = await dbGetLink(req.params.code);
        if (!l) return res.status(404).json({ success: false, message: '链接不存在或已被删除' });
        if (l.disabled) return res.status(403).json({ success: false, message: '该链接已被管理员停用' });
        const data = parseLinkData(l.data);
        if (!data) return res.status(500).json({ success: false, message: '迷宫数据损坏' });
        dbBumpLinkViews(l.code).catch(() => {});
            // —— 记录访问者（失败不影响正常读取）——
            // 名字优先取「游戏内玩家名」（?name=，非云账号名）；无玩家名时兜底云链接账号名 / clientId。
            // client_id 始终记录，供前端展示"谁 + ID"。
            try {
                let visitUser = '', visitSource = 'player';
                const ah = req.headers.authorization || '';
                let accountName = '';
                if (ah.startsWith('Bearer ')) {
                    try {
                        const dec = jwt.verify(ah.substring(7), JWT_SECRET);
                        if (dec && dec.type === 'clink' && dec.username) accountName = String(dec.username).slice(0, 64);
                    } catch (e) { /* 令牌无效则忽略 */ }
                }
                const pname = (req.query.name || '').toString().trim().slice(0, 64);
                const clid = (req.query.clientId || '').toString().trim().slice(0, 64);
                visitUser = pname || accountName;
                visitSource = pname ? 'player' : (accountName ? 'account' : 'player');
                if (!visitUser && clid) { visitUser = 'player:' + clid; }
                if (visitUser) {
                    await dbAddLinkVisit({
                        id: 'v' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
                        code: l.code, link_name: l.name || '未命名迷宫',
                        username: visitUser, source: visitSource,
                        client_id: clid || null, ip: getClientIp(req),
                        created_at: new Date().toISOString()
                    });
                }
            } catch (e) { /* 记录失败忽略 */ }
        res.json({ success: true, code: l.code, name: l.name, author: l.username, views: Number(l.views || 0) + 1, maze: data });
    } catch (e) {
        console.error('[云链接] 读取失败:', e);
        res.status(500).json({ success: false, message: '读取失败' });
    }
});

// 短链入口：/m/<code> → 打开游戏页并自动载入该迷宫
app.get('/m/:code', (req, res) => {
    const code = (req.params.code || '').toString().replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 32);
    res.redirect(302, '/?mazeLink=' + encodeURIComponent(code));
});

// ===== 管理端：云链接账号 / 链接管理 =====
// 账号列表（含每个账号的链接数与总浏览量）
app.get('/api/admin/cloud-links/accounts', requireAdminAuth, async (req, res) => {
    try {
        const q = (req.query.q || '').toString().trim().toLowerCase();
        let accounts = await dbAllLinkAccounts();
        if (q) accounts = accounts.filter(a => (a.username || '').toLowerCase().includes(q) || (a.client_id || '').toLowerCase().includes(q));
        const out = [];
        for (const a of accounts) {
            const links = await dbGetLinksOf(a.username);
            // 明确白名单字段：绝不能把 password_hash / totp_secret 下发到管理端前端
            out.push({
                username: a.username,
                created_at: a.created_at,
                updated_at: a.updated_at,
                client_id: a.client_id || null,
                disabled: !!a.disabled,
                twoFactor: !!a.two_factor_enabled,
                linkCount: links.length,
                totalViews: links.reduce((s, l) => s + Number(l.views || 0), 0)
            });
        }
        res.json({ success: true, accounts: out });
    } catch (e) {
        console.error('[云链接] 管理端读账号失败:', e);
        res.status(500).json({ success: false, message: '获取失败' });
    }
});

// 某账号（或全部）的链接列表
app.get('/api/admin/cloud-links', requireAdminAuth, async (req, res) => {
    try {
        const username = (req.query.username || '').toString().trim();
        let list;
        if (username) {
            list = await dbGetLinksOf(username);
        } else if (DB_AVAILABLE && pool) {
            const [rows] = await pool.query('SELECT * FROM cloud_links ORDER BY created_at DESC LIMIT 500');
            list = (rows || []).map(l => { l.data = parseLinkData(l.data); return l; });
        } else {
            list = Array.from(cloudLinks.values()).sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
        }
        res.json({
            success: true,
            links: list.map(l => {
                const d = parseLinkData(l.data) || {};
                return {
                    code: l.code, username: l.username, name: l.name, views: Number(l.views || 0),
                    disabled: !!l.disabled, created_at: l.created_at, updated_at: l.updated_at,
                    difficulty: d.difficulty || '', size: d.size || null
                };
            })
        });
    } catch (e) {
        console.error('[云链接] 管理端读链接失败:', e);
        res.status(500).json({ success: false, message: '获取失败' });
    }
});

// 链接访问记录：所有访问过链接的用户（可筛链接码/用户名/链接名）
app.get('/api/admin/cloud-links/visits', requireAdminAuth, async (req, res) => {
    try {
        const q = (req.query.q || '').toString().trim();
        const limit = Math.min(Math.max(Number(req.query.limit) || 500, 1), 2000);
        const rows = await dbAllLinkVisits(q, limit);
        res.json({
            success: true,
            visits: (rows || []).map(v => ({
                id: v.id, code: v.code, link_name: v.link_name || '',
                username: v.username, source: v.source === 'account' ? 'account' : 'player',
                client_id: v.client_id || null, ip: v.ip || null, created_at: v.created_at
            }))
        });
    } catch (e) {
        console.error('[云链接] 管理端读访问记录失败:', e);
        res.status(500).json({ success: false, message: '获取失败' });
    }
});

// 玩家：查看自己某条链接的访问者名单（仅链接属主可见，校验 username）
app.get('/api/cloud-links/:code/visits', requireLinkAuth, async (req, res) => {
    try {
        const l = await dbGetLink(req.params.code);
        if (!l || l.username !== req.linkUser) return res.status(404).json({ success: false, message: '链接不存在' });
        const limit = Math.min(Math.max(Number(req.query.limit) || 200, 1), 1000);
        const rows = await dbLinkVisitsByCode(l.code, limit);
        res.json({
            success: true,
            code: l.code,
            name: l.name || '',
            visits: (rows || []).map(v => ({
                username: v.username, source: v.source === 'account' ? 'account' : 'player',
                client_id: v.client_id || null, created_at: v.created_at
            }))
        });
    } catch (e) {
        console.error('[云链接] 玩家读访问记录失败:', e);
        res.status(500).json({ success: false, message: '获取失败' });
    }
});

// 修改链接（重命名 / 停用与恢复）
app.put('/api/admin/cloud-links/:code', requireAdminAuth, async (req, res) => {
    try {
        const l = await dbGetLink(req.params.code);
        if (!l) return res.status(404).json({ success: false, message: '链接不存在' });
        if (req.body.name != null) l.name = req.body.name.toString().trim().slice(0, 128) || l.name;
        if (req.body.disabled != null) l.disabled = req.body.disabled ? 1 : 0;
        l.data = parseLinkData(l.data);
        if (l.data && req.body.name != null) l.data.name = l.name; // 同步到迷宫数据，游玩页标题一致
        l.updated_at = new Date().toISOString();
        await dbUpsertLink(l);
        res.json({ success: true, message: '已更新', link: { code: l.code, name: l.name, disabled: !!l.disabled } });
    } catch (e) {
        console.error('[云链接] 管理端修改失败:', e);
        res.status(500).json({ success: false, message: '修改失败' });
    }
});

// 删除链接
app.delete('/api/admin/cloud-links/:code', requireAdminAuth, async (req, res) => {
    try {
        const l = await dbGetLink(req.params.code);
        if (!l) return res.status(404).json({ success: false, message: '链接不存在' });
        await dbDeleteLink(req.params.code);
        res.json({ success: true, message: '已删除' });
    } catch (e) {
        console.error('[云链接] 管理端删除失败:', e);
        res.status(500).json({ success: false, message: '删除失败' });
    }
});

// 封禁 / 解封云链接账号
app.put('/api/admin/cloud-links/accounts/:username/ban', requireAdminAuth, async (req, res) => {
    try {
        const acc = await dbGetLinkAccount(req.params.username);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        acc.disabled = req.body.disabled ? 1 : 0;
        acc.updated_at = new Date().toISOString();
        await dbSaveLinkAccount(acc);
        if (acc.disabled) await dbDeleteCloudLinkSessionsByUser(acc.username); // 封禁即退登全部设备
        res.json({ success: true, message: acc.disabled ? '已封禁' : '已解封' });
    } catch (e) {
        console.error('[云链接] 管理端封禁失败:', e);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 重置云链接账号密码
app.put('/api/admin/cloud-links/accounts/:username/password', requireAdminAuth, async (req, res) => {
    try {
        const acc = await dbGetLinkAccount(req.params.username);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        const password = (req.body.password || '').toString();
        if (password.length < 4) return res.status(400).json({ success: false, message: '密码至少 4 位' });
        acc.password_hash = bcrypt.hashSync(password, 10);
        acc.updated_at = new Date().toISOString();
        await dbSaveLinkAccount(acc);
        res.json({ success: true, message: '密码已重置' });
    } catch (e) {
        console.error('[云链接] 管理端改密失败:', e);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 管理员强制关闭某云链接账号的二次认证（用户丢失 2FA 插件时的救援通道）。
// 只支持「关闭」：开启必须由用户本人绑定密钥并完成二次确认。
app.put('/api/admin/cloud-links/accounts/:username/2fa', requireAdminAuth, async (req, res) => {
    try {
        const username = decodeURIComponent(req.params.username || '');
        const enabled = !!(req.body && req.body.enabled);
        if (enabled) return res.status(400).json({ success: false, message: '管理员只能关闭二次认证；开启需用户本人绑定 2FA 插件并完成确认' });
        const acc = await dbGetLinkAccount(username);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        pending2faDrop('clink', username);
        acc.totp_secret = null;
        acc.two_factor_enabled = 0;
        acc.updated_at = new Date().toISOString();
        await dbSaveLinkAccount(acc);
        appendAudit('admin', 'cloud-link-2fa-admin-disable', `管理员强制关闭云链接账号「${username}」的二次认证`, req);
        res.json({ success: true, enabled: false, message: '已强制关闭该账号的二次认证' });
    } catch (e) {
        console.error('[云链接] 管理端关闭 2FA 失败:', e);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 删除云链接账号（级联删除其全部链接）
app.delete('/api/admin/cloud-links/accounts/:username', requireAdminAuth, async (req, res) => {
    try {
        const acc = await dbGetLinkAccount(req.params.username);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        await dbDeleteLinkAccount(req.params.username);
        res.json({ success: true, message: '已删除账号及其全部链接' });
    } catch (e) {
        console.error('[云链接] 管理端删账号失败:', e);
        res.status(500).json({ success: false, message: '删除失败' });
    }
});

// 云储存功能总开关（受全局功能设定 cloudStorage 控制）
function cloudStorageEnabled() { return globalFunctions.cloudStorage !== false; }
// 云储存用户 2FA 可用开关（admin「功能设定」控制；关闭后禁止开启/配置，已开启的暂停生效）
function cloud2faEnabled() { return globalFunctions.cloud2fa !== false; }
// 云链接用户 2FA 可用开关
function cloudLink2faEnabled() { return globalFunctions.cloudLink2fa !== false; }
// 根据账号归属模块查对应的 2FA 全局开关（云储存账号带 max_mazes 字段，云链接账号无）
function twofaGlobalEnabledFor(acc) {
    if (!acc) return true;
    if (acc.__kind === 'backup') return backup2faEnabled();
    if (acc.max_mazes != null) return cloud2faEnabled();
    return cloudLink2faEnabled();
}

// 云储存鉴权：校验 Authorization: Bearer <jwt>
async function requireCloudAuth(req, res, next) {
    const h = req.headers.authorization || '';
    if (!h.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '未登录' });
    try {
        const decoded = jwt.verify(h.substring(7), JWT_SECRET);
        if (decoded.type !== 'cloud' || !decoded.username) return res.status(401).json({ success: false, message: '无效的登录令牌' });
        req.cloudUser = decoded.username;
        // 封禁账号拦截（优先于会话校验：封禁会退登全部设备，确保被封号看到封禁提示而非「已退出登录」）；限时封禁过期自动解封
        const acc = await dbGetCloudAccount(decoded.username);
        if (acc && acc.disabled) {
            if (cloudAccountBanExpired(acc)) {
                acc.disabled = 0; acc.banned_until = null; acc.updated_at = new Date().toISOString();
                await dbSaveCloudAccount(acc);
                await dbUpdateBanHistoryUnban('cloud', decoded.username, 'system');
            } else {
                return res.status(403).json({ success: false, disabled: true, code: 'ACCOUNT_DISABLED', message: cloudAccountBanMessage(acc), bannedUntil: acc.banned_until || null, banMessage: cloudAccountBanMessage(acc), bannedDays: cloudAccountBanDays(acc) });
            }
        }
        const sid = decoded.sid;
        if (sid) {
            // 新令牌带会话 id：校验会话未被远端退登
            let sess = cloudSessions.get(sid);
            if (!sess) {
                // 内存会话丢失（服务端重启 / 冷启动 DB 未就绪）→ 回 DB 重hydrate，避免有效令牌被误判“已退出登录”
                try { await dbGetCloudSessions(decoded.username); sess = cloudSessions.get(sid); } catch (e) {}
            }
            if (!sess || sess.username !== decoded.username) return res.status(401).json({ success: false, message: '该设备已被退出登录，请重新登录' });
            touchCloudSession(sess); // 更新活跃时间（节流写库）
            req.cloudSessionId = sid;
        } else {
            // 旧版令牌（无会话，升级前登录）：向后兼容，不校验设备
            req.cloudSessionId = null;
        }
        next();
    } catch (e) { res.status(401).json({ success: false, message: '登录已过期，请重新登录' }); }
}

// 公开：云储存功能是否开启
app.get('/api/cloud-storage/enabled', (req, res) => {
    res.json({ success: true, enabled: cloudStorageEnabled() });
});

// 注册云储存账号（用户名 + 密码；无数量上限，仅校验用户名唯一）
app.post('/api/cloud-storage/register', async (req, res) => {
    try {
        if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
        const username = (req.body.username || '').toString().trim();
        const password = (req.body.password || '').toString();
        if (!username || !password) return res.status(400).json({ success: false, message: '用户名和密码不能为空' });
        if (username.length > 64 || password.length < 4) return res.status(400).json({ success: false, message: '用户名过长或密码至少 4 位' });
        const existing = await dbGetCloudAccount(username);
        if (existing) return res.status(409).json({ success: false, message: '该用户名已被注册' });
        const password_hash = bcrypt.hashSync(password, 10);
        const now = new Date().toISOString();
        const clientId = (req.body.clientId || '').toString().trim() || null;
        const acc = { username, password_hash, created_at: now, updated_at: now, client_id: clientId, creator_client_id: clientId };
        await dbSaveCloudAccount(acc);
        const device = (req.body.device || req.headers['user-agent'] || '未知设备').toString().slice(0, 128);
        const ip = getClientIp(req);
        const sess = makeCloudSession(username, device, ip);
        const token = jwt.sign({ username, type: 'cloud', sid: sess.id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ success: true, token, username, sid: sess.id });
    } catch (e) {
        console.error('[云储存] 注册失败:', e);
        res.status(500).json({ success: false, message: '注册失败' });
    }
});

// 云储存登录
app.post('/api/cloud-storage/login', async (req, res) => {
    try {
        if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
        const username = (req.body.username || '').toString().trim();
        const password = (req.body.password || '').toString();
        const acc = await dbGetCloudAccount(username);
        if (!acc || !bcrypt.compareSync(password, acc.password_hash)) {
            return res.status(401).json({ success: false, message: '用户名或密码错误' });
        }
        if (acc.disabled) {
            if (cloudAccountBanExpired(acc)) {
                // 限时封禁已过期 → 自动解封并允许登录
                acc.disabled = 0; acc.banned_until = null; acc.updated_at = new Date().toISOString();
                await dbSaveCloudAccount(acc);
                await dbUpdateBanHistoryUnban('cloud', username, 'system');
            } else {
                return res.status(403).json({ success: false, disabled: true, code: 'ACCOUNT_DISABLED', message: cloudAccountBanMessage(acc), bannedUntil: acc.banned_until || null, banMessage: cloudAccountBanMessage(acc), bannedDays: cloudAccountBanDays(acc) });
            }
        }
        // 二次认证：已开启 2FA 的账号必须在登录时提供正确动态码（管理员关闭该模块 2FA 时跳过，避免锁死）
        if (acc.two_factor_enabled && twofaGlobalEnabledFor(acc)) {
            const code = read2faCode(req);
            if (!code) return res.status(401).json({ success: false, twoFactorRequired: true, message: '该账号已开启二次认证，请输入动态验证码' });
            const deny = assert2faCode(acc, code);
            if (deny) return res.status(401).json({ success: false, twoFactorRequired: true, message: deny });
        }
        // 登录时绑定/更新游戏 clientId（使管理端能用游戏用户定位云账号）
        const clientId = (req.body.clientId || '').toString().trim() || null;
        if (clientId && acc.client_id !== clientId) {
            acc.client_id = clientId;
            acc.updated_at = new Date().toISOString();
            await dbSaveCloudAccount(acc);
        }
        const device = (req.body.device || req.headers['user-agent'] || '未知设备').toString().slice(0, 128);
        const ip = getClientIp(req);
        const sess = makeCloudSession(username, device, ip);
        const token = jwt.sign({ username, type: 'cloud', sid: sess.id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ success: true, token, username, sid: sess.id });
    } catch (e) {
        console.error('[云储存] 登录失败:', e);
        res.status(500).json({ success: false, message: '登录失败' });
    }
});

// ===== 云储存账号自助管理（需登录态）=====
// 自助修改密码：需验证原密码
app.put('/api/cloud-storage/password', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    try {
        const oldPassword = ((req.body && req.body.oldPassword) || '').toString();
        const newPassword = ((req.body && req.body.newPassword) || '').toString();
        if (!oldPassword || !newPassword) return res.status(400).json({ success: false, message: '请输入原密码和新密码' });
        if (newPassword.length < 4) return res.status(400).json({ success: false, message: '新密码至少 4 位' });
        const acc = await dbGetCloudAccount(req.cloudUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        const denyPw = assert2faScope(acc, 'password', read2faCode(req));
        if (denyPw) return res.status(403).json({ success: false, message: denyPw });
        if (!bcrypt.compareSync(oldPassword, acc.password_hash)) {
            return res.status(400).json({ success: false, message: '原密码错误' });
        }
        acc.password_hash = bcrypt.hashSync(newPassword, 10);
        acc.updated_at = new Date().toISOString();
        await dbSaveCloudAccount(acc);
        appendAudit(req.cloudUser || 'cloud', 'cloud-account-password-change', `云储存账号「${req.cloudUser}」修改密码`, req);
        res.json({ success: true, message: '密码已修改' });
    } catch (e) { res.status(500).json({ success: false, message: '修改失败' }); }
});

// 自助注销账号：需验证密码（级联删除全部云端地图、会话与登录态）
app.delete('/api/cloud-storage/account', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    try {
        const password = ((req.body && req.body.password) || '').toString();
        if (!password) return res.status(400).json({ success: false, message: '请输入密码以确认注销' });
        const acc = await dbGetCloudAccount(req.cloudUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        const denyDel = assert2faScope(acc, 'account', read2faCode(req));
        if (denyDel) return res.status(403).json({ success: false, message: denyDel });
        if (!bcrypt.compareSync(password, acc.password_hash)) {
            return res.status(400).json({ success: false, message: '密码错误' });
        }
        await dbDeleteCloudAccount(req.cloudUser);
        appendAudit(req.cloudUser || 'cloud', 'cloud-account-delete', `云储存账号「${req.cloudUser}」自行注销`, req);
        res.json({ success: true, message: '账号已注销' });
    } catch (e) { res.status(500).json({ success: false, message: '注销失败' }); }
});

// ===== 云储存账号「二次认证（2FA）」开关查询与设置 =====
// 查询当前账号是否开启二次认证
app.get('/api/cloud-storage/2fa', requireCloudAuth, async (req, res) => {
    try {
        const acc = await dbGetCloudAccount(req.cloudUser);
        res.json({ success: true, enabled: !!(acc && acc.two_factor_enabled) });
    } catch (e) { res.status(500).json({ success: false, message: '获取失败' }); }
});
// 2FA 作用范围：哪些敏感操作需要动态码（登录始终强制，不在 scope 内）
app.get('/api/cloud-storage/2fa/scopes', requireCloudAuth, async (req, res) => {
    try {
        const acc = await dbGetCloudAccount(req.cloudUser);
        const enabled = !!(acc && acc.two_factor_enabled);
        const scopes = {};
        TOTP_SCOPES.forEach(s => { scopes[s] = enabled && twofaScopeEnabled(acc, s); });
        res.json({ success: true, enabled, login: true, scopes });
    } catch (e) { res.status(500).json({ success: false, message: '获取失败' }); }
});
// 保存 2FA 作用范围：仅 2FA 开启时可修改，且必须提供正确动态码（防止拿到密码就能关掉全部保护）
app.put('/api/cloud-storage/2fa/scopes', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    if (!cloud2faEnabled()) return res.status(403).json({ success: false, message: '管理员已关闭二次认证功能' });
    try {
        const acc = await dbGetCloudAccount(req.cloudUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        if (!acc.two_factor_enabled) return res.status(400).json({ success: false, message: '未开启二次认证，无需配置' });
        const deny = assert2faCode(acc, read2faCode(req));
        if (deny) return res.status(403).json({ success: false, message: deny });
        const reqScopes = (req.body && req.body.scopes) || {};
        const list = TOTP_SCOPES.filter(s => !!reqScopes[s]);
        acc.totp_scopes = (list.length === TOTP_SCOPES.length) ? null : JSON.stringify(list); // 全选 = 默认（全部需要）
        acc.updated_at = new Date().toISOString();
        await dbSaveCloudAccount(acc);
        const scopes = {};
        TOTP_SCOPES.forEach(s => { scopes[s] = twofaScopeEnabled(acc, s); });
        res.json({ success: true, enabled: true, login: true, scopes });
    } catch (e) { res.status(500).json({ success: false, message: '保存失败' }); }
});
// 获取开启二次认证所需信息：生成 TOTP 密钥、otpauth URI 与可扫码二维码。
// 浏览器 2FA 插件（如 Authenticator）扫码或手动填入密钥即可添加该账号。
app.get('/api/cloud-storage/2fa/setup', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    if (!cloud2faEnabled()) return res.status(403).json({ success: false, message: '管理员已关闭二次认证功能' });
    try {
        const secret = totpGenSecret();
        const label = encodeURIComponent('迷宫探险:' + req.cloudUser);
        const issuer = encodeURIComponent('迷宫探险');
        const otpauthUri = 'otpauth://totp/' + label + '?secret=' + secret + '&issuer=' + issuer + '&algorithm=SHA1&digits=6&period=30';
        let qr = '';
        if (QRCode) { try { qr = await QRCode.toDataURL(otpauthUri); } catch (e) { qr = ''; } }
        res.json({ success: true, secret, otpauthUri, qr });
    } catch (e) { res.status(500).json({ success: false, message: '生成失败' }); }
});
// 开启/关闭二次认证：需验证账号密码（敏感操作，防止他人趁账号登录态篡改）。
// 开启时必须同时提供 TOTP 密钥与动态码（来自浏览器插件），服务端校验通过后写入密钥。
app.put('/api/cloud-storage/2fa', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    try {
        const password = ((req.body && req.body.password) || '').toString();
        const enabled = !!((req.body && req.body.enabled));
        if (enabled && !cloud2faEnabled()) return res.status(403).json({ success: false, message: '管理员已关闭二次认证功能' });
        if (!password) return res.status(400).json({ success: false, message: '请输入密码以确认操作' });
        const acc = await dbGetCloudAccount(req.cloudUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        if (!bcrypt.compareSync(password, acc.password_hash)) {
            return res.status(400).json({ success: false, message: '密码错误' });
        }
        if (enabled) {
            // ① 绑定阶段：校验密码 + 插件首个动态码，密钥先进待确认区。
            // **不落库、不改账号状态**——防止误触（账号原本已开启 / 中途放弃 / 确认失败）时把已开启的 2FA 静默关掉。
            const secret = ((req.body && req.body.secret) || '').toString().trim();
            const code = ((req.body && req.body.code) || '').toString().trim();
            if (!secret) return res.status(400).json({ success: false, message: '缺少 TOTP 密钥' });
            if (!totpVerify(secret, code)) return res.status(400).json({ success: false, message: '动态验证码错误，请确认浏览器插件时间已同步' });
            pending2faPut('cloud', req.cloudUser, secret, code);
            return res.json({
                success: true, enabled: false, pendingConfirm: true,
                message: '绑定成功，请等待插件刷新出下一个验证码后再输入一次以完成确认'
            });
        }
        // 关闭：清空密钥并作废任何待确认绑定
        pending2faDrop('cloud', req.cloudUser);
        acc.totp_secret = null;
        acc.two_factor_enabled = 0;
        acc.updated_at = new Date().toISOString();
        await dbSaveCloudAccount(acc);
        appendAudit(req.cloudUser || 'cloud', 'cloud-2fa-change', `云储存账号「${req.cloudUser}」二次认证关闭`, req);
        res.json({ success: true, enabled: false, message: '已关闭二次认证' });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});
// ② 确认阶段：必须再验证一次动态码（且不能复用绑定时那一个），通过才真正开启。
// 一旦验证失败 → 丢弃待确认密钥并强制关闭二次认证，用户需从头重新开启。
app.post('/api/cloud-storage/2fa/confirm', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    if (!cloud2faEnabled()) return res.status(403).json({ success: false, message: '管理员已关闭二次认证功能' });
    try {
        const code = ((req.body && req.body.code) || '').toString().trim();
        const acc = await dbGetCloudAccount(req.cloudUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        const pend = pending2faTake('cloud', req.cloudUser);
        if (!pend) {
            return res.status(400).json({ success: false, expired: true, enabled: false, message: '绑定已超时失效，请重新开启二次认证' });
        }
        // 复用绑定时那一个码不算有效确认：必须等插件刷新出新码，避免"复制粘贴同一个码"糊弄过关
        if (code && code === pend.bindCode) {
            return res.status(400).json({ success: false, sameCode: true, message: '请等待插件刷新出【新的】验证码，不能重复使用刚才那一个' });
        }
        if (!totpVerify(pend.secret, code)) {
            // 确认失败 → 保留待确认密钥，允许在有效期内重试（不强制作废，避免误输一次就前功尽弃）
            appendAudit(req.cloudUser || 'cloud', 'cloud-2fa-confirm-fail', `云储存账号「${req.cloudUser}」二次认证确认失败（动态码错误，密钥保留可重试）`, req);
            return res.status(400).json({ success: false, retryable: true, enabled: false, message: '动态码不正确，请确认你的 2FA 插件显示的验证码后重试（不能重复使用绑定时的那个码，需等插件刷新出新码）' });
        }
        pending2faDrop('cloud', req.cloudUser);
        acc.totp_secret = pend.secret;
        acc.two_factor_enabled = 1;
        acc.updated_at = new Date().toISOString();
        await dbSaveCloudAccount(acc);
        appendAudit(req.cloudUser || 'cloud', 'cloud-2fa-change', `云储存账号「${req.cloudUser}」二次认证开启（已通过二次确认）`, req);
        res.json({ success: true, enabled: true, message: '二次认证已开启' });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});
// 二次认证「升级验证」：敏感操作（打开账号设置/管理设备/踢出设备）前校验账号密码，
// 由注册账号本人输入密码授权后方放行。仅校验，不改任何状态。
app.post('/api/cloud-storage/verify', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    try {
        const password = ((req.body && req.body.password) || '').toString();
        const acc = await dbGetCloudAccount(req.cloudUser);
        if (!acc || !bcrypt.compareSync(password, acc.password_hash)) {
            return res.status(400).json({ success: false, message: '密码错误' });
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: '验证失败' }); }
});

// ===== TOTP（RFC 6238）二次认证：标准动态码，兼容 Authenticator / 2FA 浏览器插件 =====
// 与「创建者设备绑定」不同，TOTP 与设备无关：用户在插件里添加密钥（扫码或手动），
// 敏感操作前输入插件显示的 6 位动态码即可，换设备/换浏览器也不受影响。
const _TOTP_ALGO = 'sha1';   // 浏览器插件默认 SHA1
const _TOTP_DIGITS = 6;
const _TOTP_STEP = 30;       // 秒
const _TOTP_WINDOW = 1;      // 容错前后各 1 个时间窗（克服时钟偏差）

function _base32Encode(buf) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0, value = 0, out = '';
    for (let i = 0; i < buf.length; i++) {
        value = (value << 8) | buf[i];
        bits += 8;
        while (bits >= 5) {
            out += alphabet[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
    return out; // RFC 4648，无填充
}
function _base32Decode(str) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const lookup = {};
    for (let i = 0; i < alphabet.length; i++) lookup[alphabet[i]] = i;
    str = String(str || '').toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
    let bits = 0, value = 0;
    const out = [];
    for (let i = 0; i < str.length; i++) {
        const v = lookup[str[i]];
        if (v === undefined) continue;
        value = (value << 5) | v;
        bits += 5;
        if (bits >= 8) {
            out.push((value >>> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }
    return Buffer.from(out);
}
function totpGenSecret() {
    return _base32Encode(crypto.randomBytes(20)); // 160 bit → 32 字符 base32
}
function totpAt(secret, forTime) {
    const key = _base32Decode(secret);
    const t = Math.floor((forTime != null ? forTime : Date.now()) / 1000 / _TOTP_STEP);
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(Math.floor(t / 0x100000000), 0);
    buf.writeUInt32BE(t & 0xffffffff, 4);
    const hmac = crypto.createHmac(_TOTP_ALGO, key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % Math.pow(10, _TOTP_DIGITS);
    return code.toString().padStart(_TOTP_DIGITS, '0');
}
function totpVerify(secret, code) {
    if (!secret || !code) return false;
    const c = String(code).replace(/\s/g, '');
    if (!/^\d{4,8}$/.test(c)) return false;
    const now = Date.now();
    for (let w = -_TOTP_WINDOW; w <= _TOTP_WINDOW; w++) {
        if (totpAt(secret, now + w * _TOTP_STEP * 1000) === c) return true;
    }
    return false;
}

// ===== 二次认证「两阶段开启」待确认区 =====
// 开启 2FA 分两步：① 绑定（校验密码 + 插件首个动态码）→ 密钥先进入待确认区，**不落库**；
// ② 确认（要求插件刷新后的另一个动态码）→ 校验通过才真正写库开启；校验失败则丢弃密钥并强制关闭 2FA。
// 这样能保证用户确实能持续从 2FA 插件取到动态码，避免绑定了一个自己拿不到码的密钥而把账号锁死。
const pending2fa = new Map();          // key: 'cloud:<user>' / 'clink:<user>' → { secret, bindCode, expiresAt }
const PENDING_2FA_TTL = 10 * 60 * 1000; // 待确认密钥 10 分钟内有效
function pending2faKey(kind, username) { return kind + ':' + username; }
function pending2faPut(kind, username, secret, bindCode) {
    pending2fa.set(pending2faKey(kind, username), { secret, bindCode: String(bindCode || ''), expiresAt: Date.now() + PENDING_2FA_TTL });
}
function pending2faTake(kind, username) {
    const k = pending2faKey(kind, username);
    const v = pending2fa.get(k);
    if (!v) return null;
    if (Date.now() > v.expiresAt) { pending2fa.delete(k); return null; }
    return v;
}
function pending2faDrop(kind, username) { pending2fa.delete(pending2faKey(kind, username)); }

// 从请求中读取动态码：优先 body.code，其次自定义头 X-2FA-Code（用于 GET /sessions，避免把码写进 URL），
// 最后 query.code（兜底）。
function read2faCode(req) {
    if (req.body && req.body.code) return String(req.body.code);
    const h = req.headers && (req.headers['x-2fa-code'] || req.headers['X-2FA-Code']);
    if (h) return String(h);
    if (req.query && req.query.code) return String(req.query.code);
    return '';
}
// 二次认证判定：返回 null 表示放行；返回字符串表示拒绝原因。
// 仅当账号开启二次认证且已登记 TOTP 密钥时，才强制要求动态码正确。
function assert2faCode(acc, code) {
    if (!acc || !acc.two_factor_enabled) return null;
    if (!twofaGlobalEnabledFor(acc)) return null; // 管理员关闭了该模块的 2FA：暂停生效（放行），避免锁死
    const secret = acc.totp_secret || null;
    if (!secret) return null; // 开启但无密钥（旧数据）：放行，待用户重新设置
    if (!totpVerify(secret, code || '')) return '二次认证失败：请输入正确的动态验证码（来自你的 2FA 浏览器插件）';
    return null;
}
// ===== 2FA 作用范围（scope）=====
// 账号可配置哪些敏感操作需要动态码（登录始终强制，不在 scope 列表内）。
// totp_scopes 存储「需要动态码的 scope 数组」的 JSON 字符串；为空（null/undefined/''）表示全部需要（安全默认）。
const TOTP_SCOPES = ['authorize', 'sessions', 'password', 'account'];
function parseTotpScopes(acc) {
    const raw = (acc && acc.totp_scopes != null && acc.totp_scopes !== '') ? String(acc.totp_scopes) : '';
    if (!raw) return null; // 无配置 → 全部需要
    let list = [];
    try { const p = JSON.parse(raw); if (Array.isArray(p)) list = p.map(String); }
    catch (e) { list = raw.split(',').map(s => s.trim()).filter(Boolean); }
    return list.filter(s => TOTP_SCOPES.indexOf(s) >= 0);
}
// 指定操作在当前 2FA 配置下是否要求动态码
function twofaScopeEnabled(acc, scope) {
    if (!acc || !acc.two_factor_enabled) return false;
    const list = parseTotpScopes(acc);
    if (list === null) return true; // 默认全部需要
    return list.indexOf(scope) >= 0;
}
// scope 化守卫：scope 启用则校验动态码，未启用直接放行；返回 null 放行，字符串为拒绝原因
function assert2faScope(acc, scope, code) {
    if (!twofaScopeEnabled(acc, scope)) return null;
    return assert2faCode(acc, code || '');
}
// ===== 2FA 随机抽查（服务端安全抽查）=====
// 每分钟按概率从「正在管理页面（已 checkin 心跳）」的云储存/云链接用户中随机抽一个，
// 要求输入一次当前动态码；**不在管理页面的用户不参与抽查**，未开启 2FA 的用户也不抽。
const _2FA_CHALLENGE_PROB = (process.env.TWOFA_SPOT_PROB != null && !isNaN(parseFloat(process.env.TWOFA_SPOT_PROB))) ? Math.max(0, Math.min(1, parseFloat(process.env.TWOFA_SPOT_PROB))) : 0.05; // 每分钟触发抽查的概率（默认 5%，2026-08-10 由 10% 下调：再降低一点被打扰频率；也可通过环境变量 TWOFA_SPOT_PROB 覆盖）
const _2FA_SPOT_INTERVAL = (process.env.TWOFA_SPOT_INTERVAL != null && !isNaN(parseInt(process.env.TWOFA_SPOT_INTERVAL, 10))) ? Math.max(1000, parseInt(process.env.TWOFA_SPOT_INTERVAL, 10)) : 60000; // 抽查周期（默认 60s，测试可调小）
const _2FA_ACTIVE_TTL = 75 * 1000;       // checkin 心跳有效时长（客户端每 ~30s 上报一次）
const _2faActive = new Map();            // key 'cloud:<u>' | 'clink:<u>' → { kind, username, activeAt, has2fa }
const _2faChallenges = new Map();        // key → { at }（已下发待验证的抽查任务；2026-08-09 起不再设 TTL，长期有效直至验证通过）
const _2faCoolDown = new Map();          // key → cooldownUntil（抽查验证通过后的冷却期：5 分钟内不再抽该用户）
const _2FA_COOLDOWN = 5 * 60 * 1000;     // 抽查冷却期：验证通过后 5 分钟内不抽查
function _2faKey(kind, username) { return kind + ':' + username; }

// 管理页面心跳（进入管理面板后客户端定期上报；active:false 表示离开）
app.post('/api/cloud-storage/2fa/checkin', requireCloudAuth, async (req, res) => {
    try {
        const active = !((req.body && req.body.active === false));
        const key = _2faKey('cloud', req.cloudUser);
        if (active) {
            const acc = await dbGetCloudAccount(req.cloudUser);
            const has2fa = !!(acc && acc.two_factor_enabled && acc.totp_secret && twofaGlobalEnabledFor(acc));
            _2faActive.set(key, { kind: 'cloud', username: req.cloudUser, activeAt: Date.now(), has2fa });
        } else { _2faActive.delete(key); }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: '失败' }); }
});
app.post('/api/cloud-links/2fa/checkin', requireLinkAuth, async (req, res) => {
    try {
        const active = !((req.body && req.body.active === false));
        const key = _2faKey('clink', req.linkUser);
        if (active) {
            const acc = await dbGetLinkAccount(req.linkUser);
            const has2fa = !!(acc && acc.two_factor_enabled && acc.totp_secret && twofaGlobalEnabledFor(acc));
            _2faActive.set(key, { kind: 'clink', username: req.linkUser, activeAt: Date.now(), has2fa });
        } else { _2faActive.delete(key); }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: '失败' }); }
});

// 客户端轮询：当前账号是否有待处理的抽查任务；若任务已超时未完成 → 返回 expired 标记（客户端据此退出登录）
app.get('/api/cloud-storage/2fa/challenge', requireCloudAuth, async (req, res) => {
    try {
        const key = _2faKey('cloud', req.cloudUser);
        const c = _2faChallenges.get(key);
        res.json({ success: true, challenge: !!c, expired: false });
    } catch (e) { res.status(500).json({ success: false, message: '失败' }); }
});
app.get('/api/cloud-links/2fa/challenge', requireLinkAuth, async (req, res) => {
    try {
        const key = _2faKey('clink', req.linkUser);
        const c = _2faChallenges.get(key);
        res.json({ success: true, challenge: !!c, expired: false });
    } catch (e) { res.status(500).json({ success: false, message: '失败' }); }
});

// 提交抽查动态码：正确 → 任务完成；错误 → 403 可重试（写审计）；过期/未开启 → 直接放行
app.post('/api/cloud-storage/2fa/challenge', requireCloudAuth, async (req, res) => {
    try {
        const key = _2faKey('cloud', req.cloudUser);
        const c = _2faChallenges.get(key);
        if (!c) return res.status(400).json({ success: false, message: '没有待验证的抽查任务' });
        const acc = await dbGetCloudAccount(req.cloudUser);
        if (!acc || !acc.two_factor_enabled || !acc.totp_secret) { _2faChallenges.delete(key); return res.json({ success: true, message: '未开启二次认证，跳过抽查' }); }
        if (!totpVerify(acc.totp_secret, read2faCode(req) || '')) {
            appendAudit(req.cloudUser || 'cloud', 'cloud-2fa-spot-check-fail', `云储存账号「${req.cloudUser}」随机抽查验证失败`, req);
            return res.status(403).json({ success: false, message: '动态码错误，请重新输入（来自你的 2FA 浏览器插件）' });
        }
        _2faChallenges.delete(key);
        // 验证通过：进入 5 分钟冷却期，期间不再被随机抽查
        _2faCoolDown.set(key, Date.now() + _2FA_COOLDOWN);
        appendAudit(req.cloudUser || 'cloud', 'cloud-2fa-spot-check', `云储存账号「${req.cloudUser}」随机抽查验证通过（冷却 5 分钟）`, req);
        res.json({ success: true, message: '抽查验证通过' });
    } catch (e) { res.status(500).json({ success: false, message: '失败' }); }
});
app.post('/api/cloud-links/2fa/challenge', requireLinkAuth, async (req, res) => {
    try {
        const key = _2faKey('clink', req.linkUser);
        const c = _2faChallenges.get(key);
        if (!c) return res.status(400).json({ success: false, message: '没有待验证的抽查任务' });
        const acc = await dbGetLinkAccount(req.linkUser);
        if (!acc || !acc.two_factor_enabled || !acc.totp_secret) { _2faChallenges.delete(key); return res.json({ success: true, message: '未开启二次认证，跳过抽查' }); }
        if (!totpVerify(acc.totp_secret, read2faCode(req) || '')) {
            appendAudit(req.linkUser || 'clink', 'cloud-link-2fa-spot-check-fail', `云链接账号「${req.linkUser}」随机抽查验证失败`, req);
            return res.status(403).json({ success: false, message: '动态码错误，请重新输入（来自你的 2FA 浏览器插件）' });
        }
        _2faChallenges.delete(key);
        // 验证通过：进入 5 分钟冷却期，期间不再被随机抽查
        _2faCoolDown.set(key, Date.now() + _2FA_COOLDOWN);
        appendAudit(req.linkUser || 'clink', 'cloud-link-2fa-spot-check', `云链接账号「${req.linkUser}」随机抽查验证通过（冷却 5 分钟）`, req);
        res.json({ success: true, message: '抽查验证通过' });
    } catch (e) { res.status(500).json({ success: false, message: '失败' }); }
});

// 每分钟随机抽查：概率触发 → 从「在管理页面」的已开 2FA 用户中随机抽一个下发抽查任务
setInterval(() => {
    if (Math.random() >= _2FA_CHALLENGE_PROB) return;
    const now = Date.now();
    const candidates = [];
    for (const [key, a] of _2faActive.entries()) {
        if (now - a.activeAt > _2FA_ACTIVE_TTL) { _2faActive.delete(key); continue; } // 心跳过期 = 不在管理页面
        if (!a.has2fa) continue;
        const cd = _2faCoolDown.get(key);
        if (cd && cd > now) continue; // 验证通过后 5 分钟冷却期内不抽
        candidates.push(key);
    }
    // 惰性清理过期冷却记录，避免内存膨胀
    for (const [key, cd] of _2faCoolDown.entries()) { if (cd <= now) _2faCoolDown.delete(key); }
    if (!candidates.length) return;
    const pick = candidates[Math.floor(Math.random() * candidates.length)];
    _2faChallenges.set(pick, { at: now });
    console.log('[2FA抽查] 已向 ' + pick + ' 下发抽查任务（长期有效，验证通过即完成）');
}, _2FA_SPOT_INTERVAL);

// 二次认证「授权」：敏感操作（打开账号设置/管理设备/踢出设备）前的身份校验。
// 必须由创建该账号的人（client_id 匹配）点击授权按钮放行，否则拒绝。
app.post('/api/cloud-storage/authorize', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    try {
        const acc = await dbGetCloudAccount(req.cloudUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        if (!acc.two_factor_enabled) return res.json({ success: true, required: false });
        const provided = (req.body && req.body.clientId) || '';
        const deny = assert2faScope(acc, 'authorize', read2faCode(req));
        if (deny) return res.status(403).json({ success: false, message: deny });
        res.json({ success: true, required: true });
    } catch (e) { res.status(500).json({ success: false, message: '授权校验失败' }); }
});

// 获取当前账号的云地图列表（含网格，用于下载）
app.get('/api/cloud-storage/mazes', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    try {
        const list = await dbGetCloudMazes(req.cloudUser);
        const out = list.map(m => ({
            id: m.id, name: m.name, description: m.description || '', difficulty: m.difficulty || '中等',
            size: (typeof m.size === 'string') ? JSON.parse(m.size) : m.size,
            maze: (typeof m.maze === 'string') ? JSON.parse(m.maze) : m.maze,
            teleporters: (typeof m.teleporters === 'string') ? JSON.parse(m.teleporters) : (m.teleporters || []),
            enemySpeed: m.enemy_speed || 1,
            showShop: m.show_shop !== 0,
            created_at: m.created_at, updated_at: m.updated_at
        }));
        res.json({ success: true, mazes: out, maxMazes: await cloudMaxMazes(req.cloudUser) });
    } catch (e) {
        console.error('[云储存] 获取列表失败:', e);
        res.status(500).json({ success: false, message: '获取失败' });
    }
});

// 上传/更新一张云地图（同 id 则覆盖；超过上限报错）
app.post('/api/cloud-storage/mazes', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    try {
        const b = req.body || {};
        const name = (b.name || '').toString().trim();
        if (!name) return res.status(400).json({ success: false, message: '地图名称不能为空' });
        if (!b.maze || !Array.isArray(b.maze) || b.maze.length === 0) return res.status(400).json({ success: false, message: '地图数据无效' });
        const existingList = await dbGetCloudMazes(req.cloudUser);
        const now = new Date().toISOString();
        let mazeId = b.mazeId || b.id || '';
        let existing = null;
        if (mazeId) existing = existingList.find(m => m.id === mazeId);
        if (existing) {
            // 覆盖同名/同 id 地图
            const m = {
                id: existing.id, username: req.cloudUser, name,
                maze: b.maze, size: b.size || { width: b.maze[0].length, height: b.maze.length },
                teleporters: b.teleporters || [], enemy_speed: b.enemySpeed || 1,
                show_shop: b.showShop !== false, description: b.description || '', difficulty: b.difficulty || '中等',
                created_at: existing.created_at || now, updated_at: now
            };
            await dbUpsertCloudMaze(m);
            return res.json({ success: true, maze: { id: m.id, name: m.name } });
        }
        // 新建：检查上限（受扩容码影响的账号容量）
        const maxMazes = await cloudMaxMazes(req.cloudUser);
        if (existingList.length >= maxMazes) {
            return res.status(403).json({ success: false, message: `每个账号最多保存 ${maxMazes} 个云地图（可删除旧图或兑换扩容码后重试）` });
        }
        // 优先使用客户端提供的稳定 mazeId（使覆盖/跨端引用/管理可追溯）；否则随机生成
        if (!mazeId) mazeId = 'cloud_' + req.cloudUser + '_' + now.toString(36) + '_' + Math.random().toString(36).substr(2, 5);
        const m = {
            id: mazeId, username: req.cloudUser, name,
            maze: b.maze, size: b.size || { width: b.maze[0].length, height: b.maze.length },
            teleporters: b.teleporters || [], enemy_speed: b.enemySpeed || 1,
            show_shop: b.showShop !== false, description: b.description || '', difficulty: b.difficulty || '中等',
            created_at: now, updated_at: now
        };
        await dbUpsertCloudMaze(m);
        res.json({ success: true, maze: { id: m.id, name: m.name } });
    } catch (e) {
        console.error('[云储存] 上传失败:', e);
        res.status(500).json({ success: false, message: '上传失败' });
    }
});

// 删除自己的云地图
app.delete('/api/cloud-storage/mazes/:id', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    try {
        let m = cloudMazes.get(req.params.id);
        if (!m) { const list = await dbGetCloudMazes(req.cloudUser); m = list.find(x => x.id === req.params.id); }
        if (!m || m.username !== req.cloudUser) return res.status(404).json({ success: false, message: '地图不存在' });
        await dbDeleteCloudMaze(req.params.id);
        res.json({ success: true, message: '已删除' });
    } catch (e) {
        console.error('[云储存] 删除失败:', e);
        res.status(500).json({ success: false, message: '删除失败' });
    }
});

// 获取当前账号云端「通关数据」（无则返回 progress:null）
app.get('/api/cloud-storage/progress', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    try {
        const r = await dbGetCloudProgress(req.cloudUser);
        res.json({ success: true, progress: r.progress, updated_at: r.updated_at });
    } catch (e) {
        console.error('[云储存] 读进度失败:', e);
        res.status(500).json({ success: false, message: '读取失败' });
    }
});

// 上传（合并）当前账号「通关数据」到云端；进度只增不减（取最大关卡与并集通关列表）
app.post('/api/cloud-storage/progress', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    try {
        const incoming = (req.body && req.body.progress) ? req.body.progress : req.body;
        if (!incoming || typeof incoming !== 'object') {
            return res.status(400).json({ success: false, message: '进度数据格式不正确' });
        }
        const r = await dbSaveCloudProgress(req.cloudUser, incoming);
        res.json({ success: true, progress: r.progress, updated_at: r.updated_at, message: '已保存到云端' });
    } catch (e) {
        console.error('[云储存] 保存进度失败:', e);
        res.status(500).json({ success: false, message: '保存失败' });
    }
});

// 列出当前账号所有登录设备/会话（标记当前设备）
app.get('/api/cloud-storage/sessions', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    try {
        const acc = await dbGetCloudAccount(req.cloudUser);
        const provided = (req.query && req.query.clientId) || '';
        const deny = assert2faScope(acc, 'sessions', read2faCode(req));
        if (deny) return res.status(403).json({ success: false, message: deny });
        const list = await dbGetCloudSessions(req.cloudUser);
        const out = list.map(s => ({
            id: s.id,
            device: s.device || '未知设备',
            ip: s.ip || '',
            current: s.id === req.cloudSessionId,
            created_at: s.created_at,
            last_active_at: s.last_active_at
        }));
        res.json({ success: true, sessions: out });
    } catch (e) { res.status(500).json({ success: false, message: '获取失败' }); }
});
// 退出指定设备（吊销会话）
app.delete('/api/cloud-storage/sessions/:id', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    try {
        const acc = await dbGetCloudAccount(req.cloudUser);
        const provided = (req.body && req.body.clientId) || '';
        const deny = assert2faScope(acc, 'sessions', read2faCode(req));
        if (deny) return res.status(403).json({ success: false, message: deny });
        const id = req.params.id;
        const list = await dbGetCloudSessions(req.cloudUser);
        const target = list.find(s => s.id === id);
        if (!target) return res.status(404).json({ success: false, message: '会话不存在' });
        await dbDeleteCloudSession(id);
        res.json({ success: true, message: id === req.cloudSessionId ? '已退出当前设备' : '已退出该设备' });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});
// 退出其他所有设备（保留当前）
app.delete('/api/cloud-storage/sessions', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    try {
        const acc = await dbGetCloudAccount(req.cloudUser);
        const provided = (req.body && req.body.clientId) || '';
        const deny = assert2faScope(acc, 'sessions', read2faCode(req));
        if (deny) return res.status(403).json({ success: false, message: deny });
        await dbDeleteCloudSessionsExcept(req.cloudUser, req.cloudSessionId);
        res.json({ success: true, message: '已退出其他所有设备' });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});

// ===================================================================
// 云备份（第三套云端账号体系，与云储存/云链接平行）
// 独立账号（用户名+密码），可备份 成就信息/统计信息/UI设置，三项各自独立上传/下载并应用到本机。
// 复用共享 helper：bcrypt / jwt / totp* / pending2fa* / assert2faCode / parseTotpScopes / twofaScopeEnabled / assert2faScope / twofaGlobalEnabledFor / _healAccountColumn。
// ===================================================================
const CLOUD_BACKUP_FILE = path.join(DATA_DIR, 'cloud-backups.json');
let backupAccounts = new Map();
let backupBackups = new Map(); // username -> { achievements?, statistics?, ui_settings? }  (每项 = { data, updated_at })
function backupEnabled() { return globalFunctions.backup !== false; }
function backup2faEnabled() { return globalFunctions.backup2fa !== false; }
function loadCloudBackups() {
    try {
        if (fs.existsSync(CLOUD_BACKUP_FILE)) {
            const s = JSON.parse(fs.readFileSync(CLOUD_BACKUP_FILE, 'utf8'));
            if (s && s.accounts) s.accounts.forEach(a => { a.__kind = 'backup'; backupAccounts.set(a.username, a); });
            if (s && s.backups) s.backups.forEach(b => backupBackups.set(b.username, b.backups));
        }
        console.log(`[云备份] 已加载 ${backupAccounts.size} 账号`);
    } catch (e) { console.error('[云备份] 加载失败:', e.message); }
}
function saveCloudBackups() {
    try {
        ensureDataDir();
        fs.writeFileSync(CLOUD_BACKUP_FILE, JSON.stringify({
            accounts: Array.from(backupAccounts.values()).map(a => { const c = Object.assign({}, a); delete c.__kind; return c; }),
            backups: Array.from(backupBackups.entries()).map(([username, backups]) => ({ username, backups }))
        }, null, 2));
    } catch (e) { console.error('[云备份] 保存失败:', e.message); }
}
async function dbGetBackupAccount(username) {
    if (DB_AVAILABLE && pool) {
        try { const [rows] = await pool.query('SELECT * FROM cloud_backup_accounts WHERE username=?', [username]); if (rows && rows.length) { const a = rows[0]; a.__kind = 'backup'; return a; } } catch (e) { console.error('[云备份] DB 读账号失败:', e.message); }
    }
    const a = backupAccounts.get(username);
    if (a) a.__kind = 'backup';
    return a || null;
}
async function dbGetBackupAccountByClient(clientId) {
    if (!clientId) return null;
    if (DB_AVAILABLE && pool) {
        try { const [rows] = await pool.query('SELECT * FROM cloud_backup_accounts WHERE client_id=?', [clientId]); if (rows && rows.length) { const a = rows[0]; a.__kind = 'backup'; return a; } } catch (e) { console.error('[云备份] DB 读账号(clientId)失败:', e.message); }
    }
    for (const acc of backupAccounts.values()) { if (acc.client_id === clientId) { acc.__kind = 'backup'; return acc; } }
    return null;
}
async function dbSaveBackupAccount(acc) {
    const clientId = (acc.client_id != null) ? acc.client_id : null;
    const disabled = (acc.disabled != null) ? (acc.disabled ? 1 : 0) : 0;
    const bannedUntil = (acc.banned_until != null && acc.banned_until !== '') ? String(acc.banned_until) : null;
    const twoFactor = (acc.two_factor_enabled != null) ? (acc.two_factor_enabled ? 1 : 0) : 0;
    const creatorClientId = (acc.creator_client_id != null && acc.creator_client_id !== '') ? acc.creator_client_id : null;
    const totpSecret = (acc.totp_secret != null && acc.totp_secret !== '') ? acc.totp_secret : null;
    const totpScopes = (acc.totp_scopes != null && acc.totp_scopes !== '') ? String(acc.totp_scopes) : null;
    const SQL = 'INSERT INTO cloud_backup_accounts (username, password_hash, created_at, updated_at, client_id, disabled, banned_until, two_factor_enabled, creator_client_id, totp_secret, totp_scopes) VALUES (?,?,?,?,?,?,?,?,?,?,?) ' +
        'ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash), updated_at=VALUES(updated_at), client_id=VALUES(client_id), disabled=VALUES(disabled), banned_until=VALUES(banned_until), two_factor_enabled=VALUES(two_factor_enabled), totp_secret=VALUES(totp_secret), totp_scopes=VALUES(totp_scopes)';
    const PARAMS = [acc.username, acc.password_hash, acc.created_at, acc.updated_at, clientId, disabled, bannedUntil, twoFactor, creatorClientId, totpSecret, totpScopes];
    if (DB_AVAILABLE && pool) {
        try { await pool.query(SQL, PARAMS); return; }
        catch (e) {
            const m = String(e.message || '');
            const mm = m.match(/Unknown column ['"]?([a-z_]+)['"]?/i);
            if (mm && CLOUD_ACCOUNT_COLUMNS[mm[1]] && await _healAccountColumn(mm[1], 'cloud_backup_accounts')) {
                try { await pool.query(SQL, PARAMS); return; } catch (e2) { console.error('[云备份] 自愈补列后写入仍失败:', e2.message); }
            }
            console.error('[云备份] DB 写账号失败:', e.message);
        }
    }
    const c = Object.assign({}, acc, { client_id: clientId, disabled, banned_until: bannedUntil, two_factor_enabled: twoFactor, creator_client_id: creatorClientId, totp_secret: totpSecret, totp_scopes: totpScopes });
    c.__kind = 'backup';
    backupAccounts.set(acc.username, c);
    saveCloudBackups();
}
async function dbAllBackupAccounts() {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query('SELECT username, created_at, updated_at, client_id, disabled, banned_until, two_factor_enabled FROM cloud_backup_accounts ORDER BY created_at DESC');
            if (rows) return rows.map(r => ({ username: r.username, created_at: r.created_at, updated_at: r.updated_at, client_id: r.client_id || null, disabled: !!r.disabled, banned_until: (r.banned_until != null && r.banned_until !== '') ? r.banned_until : null, two_factor_enabled: r.two_factor_enabled ? 1 : 0 }));
        } catch (e) { console.error('[云备份] DB 读账号列表失败:', e.message); }
    }
    return Array.from(backupAccounts.values()).map(a => ({ username: a.username, created_at: a.created_at, updated_at: a.updated_at, client_id: a.client_id || null, disabled: !!a.disabled, banned_until: (a.banned_until != null && a.banned_until !== '') ? a.banned_until : null, two_factor_enabled: (a.two_factor_enabled != null ? (a.two_factor_enabled ? 1 : 0) : 0) }));
}
async function dbDeleteBackupAccount(username) {
    if (backupBackups.has(username)) backupBackups.delete(username);
    if (DB_AVAILABLE && pool) {
        try { await pool.query('DELETE FROM cloud_backups WHERE username=?', [username]); } catch (e) { console.error('[云备份] DB 删备份失败:', e.message); }
        try { await pool.query('DELETE FROM cloud_backup_sessions WHERE username=?', [username]); } catch (e) { console.error('[云备份] DB 删会话失败:', e.message); }
        try { await pool.query('DELETE FROM cloud_backup_accounts WHERE username=?', [username]); } catch (e) { console.error('[云备份] DB 删账号失败:', e.message); }
    }
    for (const [k, s] of backupSessions) if (s.username === username) backupSessions.delete(k);
    saveBackupSessions();
    backupAccounts.delete(username);
    saveCloudBackups();
}
const BACKUP_KINDS = ['achievements', 'statistics', 'ui_settings'];
function normalizeBackupData(d) { return (d && typeof d === 'object') ? d : null; }
async function dbGetBackup(username, kind) {
    if (DB_AVAILABLE && pool) {
        try { const [rows] = await pool.query('SELECT data, updated_at FROM cloud_backups WHERE username=? AND kind=?', [username, kind]); if (rows && rows.length) { let data = rows[0].data; if (typeof data === 'string') { try { data = JSON.parse(data); } catch (e) { data = null; } } return { data: normalizeBackupData(data), updated_at: rows[0].updated_at || null }; } } catch (e) { console.error('[云备份] DB 读备份失败:', e.message); }
    }
    const b = backupBackups.get(username);
    const item = b && b[kind];
    return item ? { data: normalizeBackupData(item.data), updated_at: item.updated_at || null } : { data: null, updated_at: null };
}
async function dbUpsertBackup(username, kind, data) {
    const now = new Date().toISOString();
    if (DB_AVAILABLE && pool) {
        try { await pool.query('INSERT INTO cloud_backups (username, kind, data, created_at, updated_at) VALUES (?,?,?,?,?) ON DUPLICATE KEY UPDATE data=VALUES(data), updated_at=VALUES(updated_at)', [username, kind, JSON.stringify(data), now, now]); return { updated_at: now }; }
        catch (e) { console.error('[云备份] DB 写备份失败:', e.message); }
    }
    if (!backupBackups.has(username)) backupBackups.set(username, {});
    backupBackups.get(username)[kind] = { data, updated_at: now };
    saveCloudBackups();
    return { updated_at: now };
}
async function dbDeleteBackup(username, kind) {
    if (DB_AVAILABLE && pool) { try { await pool.query('DELETE FROM cloud_backups WHERE username=? AND kind=?', [username, kind]); } catch (e) { console.error('[云备份] DB 删备份失败:', e.message); } }
    const b = backupBackups.get(username);
    if (b && b[kind]) { delete b[kind]; saveCloudBackups(); }
}
async function dbGetBackupKinds(username) {
    if (DB_AVAILABLE && pool) {
        try { const [rows] = await pool.query('SELECT kind, data, updated_at FROM cloud_backups WHERE username=? ORDER BY updated_at DESC', [username]); if (rows) return rows.map(r => { let data = r.data; if (typeof data === 'string') { try { data = JSON.parse(data); } catch (e) { data = null; } } return { kind: r.kind, updated_at: r.updated_at || null, data: normalizeBackupData(data) }; }); } catch (e) { console.error('[云备份] DB 读备份列表失败:', e.message); }
    }
    const b = backupBackups.get(username);
    if (!b) return [];
    return Object.keys(b).map(k => ({ kind: k, updated_at: (b[k] && b[k].updated_at) || null, data: normalizeBackupData(b[k] && b[k].data) }));
}
// ===== 云备份会话（设备）管理 =====
const BACKUP_SESSIONS_FILE = path.join(DATA_DIR, 'cloud-backup-sessions.json');
let backupSessions = new Map();
async function loadBackupSessions() {
    try {
        if (DB_AVAILABLE && pool) {
            try {
                const [rows] = await pool.query('SELECT * FROM cloud_backup_sessions');
                if (rows) rows.forEach(s => backupSessions.set(s.id, s));
                return; // DB 成功 → 以 DB 为准
            } catch (e) { console.error('[云备份] DB 会话载入失败，回退 JSON:', e.message); }
        }
        if (fs.existsSync(BACKUP_SESSIONS_FILE)) { const arr = JSON.parse(fs.readFileSync(BACKUP_SESSIONS_FILE, 'utf8')); if (Array.isArray(arr)) arr.forEach(s => backupSessions.set(s.id, s)); }
    } catch (e) { console.error('[云备份] 会话载入失败:', e.message); }
}
function saveBackupSessions() { try { ensureDataDir(); fs.writeFileSync(BACKUP_SESSIONS_FILE, JSON.stringify(Array.from(backupSessions.values()), null, 2)); } catch (e) { console.error('[云备份] 会话保存失败:', e.message); } }
async function dbGetBackupSessions(username) {
    if (DB_AVAILABLE && pool) { try { const [rows] = await pool.query('SELECT * FROM cloud_backup_sessions WHERE username=? ORDER BY last_active_at DESC', [username]); if (rows) { rows.forEach(s => backupSessions.set(s.id, s)); return rows; } } catch (e) { console.error('[云备份] DB 读会话失败:', e.message); } }
    return Array.from(backupSessions.values()).filter(s => s.username === username).sort((a, b) => (b.last_active_at || '').localeCompare(a.last_active_at || ''));
}
async function dbUpsertBackupSession(s) { backupSessions.set(s.id, s); if (DB_AVAILABLE && pool) { try { await pool.query('INSERT INTO cloud_backup_sessions (id, username, device, ip, created_at, last_active_at) VALUES (?,?,?,?,?,?) ON DUPLICATE KEY UPDATE device=VALUES(device), ip=VALUES(ip), last_active_at=VALUES(last_active_at)', [s.id, s.username, s.device, s.ip, s.created_at, s.last_active_at]); return; } catch (e) { console.error('[云备份] DB 写会话失败:', e.message); } } saveBackupSessions(); }
async function dbDeleteBackupSession(id) { backupSessions.delete(id); if (DB_AVAILABLE && pool) { try { await pool.query('DELETE FROM cloud_backup_sessions WHERE id=?', [id]); } catch (e) { console.error('[云备份] DB 删会话失败:', e.message); } } saveBackupSessions(); }
async function dbDeleteBackupSessionsExcept(username, exceptId) { if (DB_AVAILABLE && pool) { try { await pool.query('DELETE FROM cloud_backup_sessions WHERE username=? AND id<>?', [username, exceptId]); } catch (e) { console.error('[云备份] DB 删会话失败:', e.message); } } for (const [k, s] of backupSessions) if (s.username === username && k !== exceptId) backupSessions.delete(k); saveBackupSessions(); }
async function dbDeleteBackupSessionsByUser(username) { if (!username) return; if (DB_AVAILABLE && pool) { try { await pool.query('DELETE FROM cloud_backup_sessions WHERE username=?', [username]); } catch (e) { console.error('[云备份] DB 删会话失败:', e.message); } } for (const [k, s] of backupSessions) if (s.username === username) backupSessions.delete(k); saveBackupSessions(); }
function makeBackupSession(username, device, ip) { const id = genSessionId(); const now = new Date().toISOString(); const s = { id, username, device: (device || '未知设备').toString().slice(0, 128), ip: (ip || '').toString().slice(0, 64), created_at: now, last_active_at: now }; dbUpsertBackupSession(s).catch(e => console.error('[云备份] 创建会话失败:', e.message)); return s; }
function touchBackupSession(sess) { sess.last_active_at = new Date().toISOString(); const now = Date.now(); if (!sess._lastTouch || now - sess._lastTouch > 60000) { sess._lastTouch = now; dbUpsertBackupSession(sess).catch(() => {}); } }
loadCloudBackups();
loadBackupSessions().catch(e => console.error('[云备份] 会话载入失败:', e.message));

// 云备份鉴权
async function requireBackupAuth(req, res, next) {
    const h = req.headers.authorization || '';
    if (!h.startsWith('Bearer ')) return res.status(401).json({ success: false, message: '未登录' });
    try {
        const decoded = jwt.verify(h.substring(7), JWT_SECRET);
        if (decoded.type !== 'backup' || !decoded.username) return res.status(401).json({ success: false, message: '无效的登录令牌' });
        req.backupUser = decoded.username;
        const acc = await dbGetBackupAccount(decoded.username);
        if (acc && acc.disabled) {
            if (cloudAccountBanExpired(acc)) { acc.disabled = 0; acc.banned_until = null; acc.updated_at = new Date().toISOString(); await dbSaveBackupAccount(acc); await dbUpdateBanHistoryUnban('backup', decoded.username, 'system'); }
            else { return res.status(403).json({ success: false, disabled: true, code: 'ACCOUNT_DISABLED', message: cloudAccountBanMessage(acc), bannedUntil: acc.banned_until || null, banMessage: cloudAccountBanMessage(acc), bannedDays: cloudAccountBanDays(acc) }); }
        }
        const sid = decoded.sid;
        if (sid) {
            let sess = backupSessions.get(sid);
            if (!sess) {
                // 内存会话丢失（服务端重启 / 冷启动 DB 未就绪）→ 回 DB 重hydrate，避免有效令牌被误判“已退出登录”
                try { await dbGetBackupSessions(decoded.username); sess = backupSessions.get(sid); } catch (e) {}
            }
            if (!sess || sess.username !== decoded.username) return res.status(401).json({ success: false, message: '该设备已被退出登录，请重新登录' });
            touchBackupSession(sess); req.backupSessionId = sid;
        }
        else { req.backupSessionId = null; }
        next();
    } catch (e) { res.status(401).json({ success: false, message: '登录已过期，请重新登录' }); }
}

// 公开：云备份功能是否开启
app.get('/api/cloud-backup/enabled', (req, res) => { res.json({ success: true, enabled: backupEnabled() }); });

// 注册
app.post('/api/cloud-backup/register', async (req, res) => {
    try {
        if (!backupEnabled()) return res.status(403).json({ success: false, message: '云备份功能已关闭' });
        const username = (req.body.username || '').toString().trim();
        const password = (req.body.password || '').toString();
        if (!username || !password) return res.status(400).json({ success: false, message: '用户名和密码不能为空' });
        if (username.length > 64 || password.length < 4) return res.status(400).json({ success: false, message: '用户名过长或密码至少 4 位' });
        const existing = await dbGetBackupAccount(username);
        if (existing) return res.status(409).json({ success: false, message: '该用户名已被注册' });
        const password_hash = bcrypt.hashSync(password, 10);
        const now = new Date().toISOString();
        const clientId = (req.body.clientId || '').toString().trim() || null;
        const acc = { username, password_hash, created_at: now, updated_at: now, client_id: clientId, creator_client_id: clientId };
        await dbSaveBackupAccount(acc);
        const device = (req.body.device || req.headers['user-agent'] || '未知设备').toString().slice(0, 128);
        const ip = getClientIp(req);
        const sess = makeBackupSession(username, device, ip);
        const token = jwt.sign({ username, type: 'backup', sid: sess.id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ success: true, token, username, sid: sess.id });
    } catch (e) { console.error('[云备份] 注册失败:', e); res.status(500).json({ success: false, message: '注册失败' }); }
});

// 登录
app.post('/api/cloud-backup/login', async (req, res) => {
    try {
        if (!backupEnabled()) return res.status(403).json({ success: false, message: '云备份功能已关闭' });
        const username = (req.body.username || '').toString().trim();
        const password = (req.body.password || '').toString();
        const acc = await dbGetBackupAccount(username);
        if (!acc || !bcrypt.compareSync(password, acc.password_hash)) return res.status(401).json({ success: false, message: '用户名或密码错误' });
        if (acc.disabled) {
            if (cloudAccountBanExpired(acc)) { acc.disabled = 0; acc.banned_until = null; acc.updated_at = new Date().toISOString(); await dbSaveBackupAccount(acc); await dbUpdateBanHistoryUnban('backup', username, 'system'); }
            else { return res.status(403).json({ success: false, disabled: true, code: 'ACCOUNT_DISABLED', message: cloudAccountBanMessage(acc), bannedUntil: acc.banned_until || null, banMessage: cloudAccountBanMessage(acc), bannedDays: cloudAccountBanDays(acc) }); }
        }
        if (acc.two_factor_enabled && twofaGlobalEnabledFor(acc)) {
            const code = read2faCode(req);
            if (!code) return res.status(401).json({ success: false, twoFactorRequired: true, message: '该账号已开启二次认证，请输入动态验证码' });
            const deny = assert2faCode(acc, code);
            if (deny) return res.status(401).json({ success: false, twoFactorRequired: true, message: deny });
        }
        const clientId = (req.body.clientId || '').toString().trim() || null;
        if (clientId && acc.client_id !== clientId) { acc.client_id = clientId; acc.updated_at = new Date().toISOString(); await dbSaveBackupAccount(acc); }
        const device = (req.body.device || req.headers['user-agent'] || '未知设备').toString().slice(0, 128);
        const ip = getClientIp(req);
        const sess = makeBackupSession(username, device, ip);
        const token = jwt.sign({ username, type: 'backup', sid: sess.id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ success: true, token, username, sid: sess.id });
    } catch (e) { console.error('[云备份] 登录失败:', e); res.status(500).json({ success: false, message: '登录失败' }); }
});

// 修改密码
app.put('/api/cloud-backup/password', requireBackupAuth, async (req, res) => {
    try {
        const acc = await dbGetBackupAccount(req.backupUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        const deny = assert2faScope(acc, 'account', read2faCode(req));
        if (deny) return res.status(403).json({ success: false, message: deny });
        const oldP = (req.body.oldPassword || '').toString();
        const newP = (req.body.newPassword || '').toString();
        if (!bcrypt.compareSync(oldP, acc.password_hash)) return res.status(400).json({ success: false, message: '原密码错误' });
        if (newP.length < 4) return res.status(400).json({ success: false, message: '新密码至少 4 位' });
        acc.password_hash = bcrypt.hashSync(newP, 10);
        acc.updated_at = new Date().toISOString();
        await dbSaveBackupAccount(acc);
        appendAudit(req.backupUser || 'backup', 'cloud-backup-password', `云备份账号「${req.backupUser}」修改密码`, req);
        res.json({ success: true, message: '密码已修改' });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});

// 注销账号
app.delete('/api/cloud-backup/account', requireBackupAuth, async (req, res) => {
    try {
        const acc = await dbGetBackupAccount(req.backupUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        const deny = assert2faScope(acc, 'account', read2faCode(req));
        if (deny) return res.status(403).json({ success: false, message: deny });
        await dbDeleteBackupAccount(req.backupUser);
        appendAudit(req.backupUser || 'backup', 'cloud-backup-account-delete', `注销云备份账号「${req.backupUser}」`, req);
        res.json({ success: true, message: '账号已注销' });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});

// 当前账号信息
app.get('/api/cloud-backup/me', requireBackupAuth, async (req, res) => {
    try { const acc = await dbGetBackupAccount(req.backupUser); const kinds = await dbGetBackupKinds(req.backupUser); res.json({ success: true, username: req.backupUser, twoFactor: !!acc.two_factor_enabled, backups: kinds }); }
    catch (e) { res.status(500).json({ success: false, message: '获取失败' }); }
});

// 2FA 状态 / 作用范围
app.get('/api/cloud-backup/2fa', requireBackupAuth, async (req, res) => { try { const acc = await dbGetBackupAccount(req.backupUser); res.json({ success: true, enabled: !!(acc && acc.two_factor_enabled) }); } catch (e) { res.status(500).json({ success: false, message: '获取失败' }); } });
app.get('/api/cloud-backup/2fa/scopes', requireBackupAuth, async (req, res) => {
    try { const acc = await dbGetBackupAccount(req.backupUser); const enabled = !!(acc && acc.two_factor_enabled); const scopes = {}; TOTP_SCOPES.forEach(s => { scopes[s] = enabled && twofaScopeEnabled(acc, s); }); res.json({ success: true, enabled, login: true, scopes }); }
    catch (e) { res.status(500).json({ success: false, message: '获取失败' }); }
});
app.put('/api/cloud-backup/2fa/scopes', requireBackupAuth, async (req, res) => {
    if (!backupEnabled()) return res.status(403).json({ success: false, message: '云备份功能已关闭' });
    if (!backup2faEnabled()) return res.status(403).json({ success: false, message: '管理员已关闭二次认证功能' });
    try {
        const acc = await dbGetBackupAccount(req.backupUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        if (!acc.two_factor_enabled) return res.status(400).json({ success: false, message: '未开启二次认证，无需配置' });
        const deny = assert2faCode(acc, read2faCode(req)); if (deny) return res.status(403).json({ success: false, message: deny });
        const reqScopes = (req.body && req.body.scopes) || {}; const list = TOTP_SCOPES.filter(s => !!reqScopes[s]);
        acc.totp_scopes = (list.length === TOTP_SCOPES.length) ? null : JSON.stringify(list); acc.updated_at = new Date().toISOString(); await dbSaveBackupAccount(acc);
        const scopes = {}; TOTP_SCOPES.forEach(s => { scopes[s] = twofaScopeEnabled(acc, s); });
        res.json({ success: true, enabled: true, login: true, scopes });
    } catch (e) { res.status(500).json({ success: false, message: '保存失败' }); }
});
app.get('/api/cloud-backup/2fa/setup', requireBackupAuth, async (req, res) => {
    if (!backupEnabled()) return res.status(403).json({ success: false, message: '云备份功能已关闭' });
    if (!backup2faEnabled()) return res.status(403).json({ success: false, message: '管理员已关闭二次认证功能' });
    try {
        const secret = totpGenSecret(); const label = encodeURIComponent('迷宫探险:' + req.backupUser); const issuer = encodeURIComponent('迷宫探险');
        const otpauthUri = 'otpauth://totp/' + label + '?secret=' + secret + '&issuer=' + issuer + '&algorithm=SHA1&digits=6&period=30';
        let qr = ''; if (typeof QRCode !== 'undefined' && QRCode) { try { qr = await QRCode.toDataURL(otpauthUri); } catch (e) { qr = ''; } }
        res.json({ success: true, secret, otpauthUri, qr });
    } catch (e) { res.status(500).json({ success: false, message: '生成失败' }); }
});
app.put('/api/cloud-backup/2fa', requireBackupAuth, async (req, res) => {
    if (!backupEnabled()) return res.status(403).json({ success: false, message: '云备份功能已关闭' });
    try {
        const password = ((req.body && req.body.password) || '').toString(); const enabled = !!((req.body && req.body.enabled));
        if (enabled && !backup2faEnabled()) return res.status(403).json({ success: false, message: '管理员已关闭二次认证功能' });
        if (!password) return res.status(400).json({ success: false, message: '请输入密码以确认操作' });
        const acc = await dbGetBackupAccount(req.backupUser); if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        if (!bcrypt.compareSync(password, acc.password_hash)) return res.status(400).json({ success: false, message: '密码错误' });
        if (enabled) {
            const secret = ((req.body && req.body.secret) || '').toString().trim(); const code = ((req.body && req.body.code) || '').toString().trim();
            if (!secret) return res.status(400).json({ success: false, message: '缺少 TOTP 密钥' });
            if (!totpVerify(secret, code)) return res.status(400).json({ success: false, message: '动态验证码错误，请确认浏览器插件时间已同步' });
            pending2faPut('backup', req.backupUser, secret, code);
            return res.json({ success: true, enabled: false, pendingConfirm: true, message: '绑定成功，请等待插件刷新出下一个验证码后再输入一次以完成确认' });
        }
        pending2faDrop('backup', req.backupUser); acc.totp_secret = null; acc.two_factor_enabled = 0; acc.updated_at = new Date().toISOString(); await dbSaveBackupAccount(acc);
        appendAudit(req.backupUser || 'backup', 'cloud-backup-2fa-change', `云备份账号「${req.backupUser}」二次认证关闭`, req);
        res.json({ success: true, enabled: false, message: '已关闭二次认证' });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});
app.post('/api/cloud-backup/2fa/confirm', requireBackupAuth, async (req, res) => {
    if (!backupEnabled()) return res.status(403).json({ success: false, message: '云备份功能已关闭' });
    if (!backup2faEnabled()) return res.status(403).json({ success: false, message: '管理员已关闭二次认证功能' });
    try {
        const code = ((req.body && req.body.code) || '').toString().trim(); const acc = await dbGetBackupAccount(req.backupUser); if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        const pend = pending2faTake('backup', req.backupUser); if (!pend) return res.status(400).json({ success: false, expired: true, enabled: false, message: '绑定已超时失效，请重新开启二次认证' });
        if (code && code === pend.bindCode) return res.status(400).json({ success: false, sameCode: true, message: '请等待插件刷新出【新的】验证码，不能重复使用刚才那一个' });
        if (!totpVerify(pend.secret, code)) { appendAudit(req.backupUser || 'backup', 'cloud-backup-2fa-confirm-fail', `云备份账号「${req.backupUser}」二次认证确认失败（动态码错误，密钥保留可重试）`, req); return res.status(400).json({ success: false, retryable: true, enabled: false, message: '动态码不正确，请确认你的 2FA 插件显示的验证码后重试（不能重复使用绑定时的那个码，需等插件刷新出新码）' }); }
        pending2faDrop('backup', req.backupUser); acc.totp_secret = pend.secret; acc.two_factor_enabled = 1; acc.updated_at = new Date().toISOString(); await dbSaveBackupAccount(acc);
        appendAudit(req.backupUser || 'backup', 'cloud-backup-2fa-change', `云备份账号「${req.backupUser}」二次认证开启（已通过二次确认）`, req);
        res.json({ success: true, enabled: true, message: '二次认证已开启' });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});
app.post('/api/cloud-backup/verify', requireBackupAuth, async (req, res) => {
    if (!backupEnabled()) return res.status(403).json({ success: false, message: '云备份功能已关闭' });
    try { const password = ((req.body && req.body.password) || '').toString(); const acc = await dbGetBackupAccount(req.backupUser); if (!acc || !bcrypt.compareSync(password, acc.password_hash)) return res.status(400).json({ success: false, message: '密码错误' }); res.json({ success: true }); }
    catch (e) { res.status(500).json({ success: false, message: '验证失败' }); }
});
// 安全抽查心跳 / 挑战
app.post('/api/cloud-backup/2fa/checkin', requireBackupAuth, async (req, res) => {
    try { const active = !((req.body && req.body.active === false)); const key = _2faKey('backup', req.backupUser);
        if (active) { const acc = await dbGetBackupAccount(req.backupUser); const has2fa = !!(acc && acc.two_factor_enabled && acc.totp_secret && twofaGlobalEnabledFor(acc)); _2faActive.set(key, { kind: 'backup', username: req.backupUser, activeAt: Date.now(), has2fa }); }
        else { _2faActive.delete(key); } res.json({ success: true }); } catch (e) { res.status(500).json({ success: false, message: '失败' }); }
});
app.get('/api/cloud-backup/2fa/challenge', requireBackupAuth, async (req, res) => {
    try { const key = _2faKey('backup', req.backupUser); const c = _2faChallenges.get(key);
        res.json({ success: true, challenge: !!c, expired: false }); } catch (e) { res.status(500).json({ success: false, message: '失败' }); }
});
app.post('/api/cloud-backup/2fa/challenge', requireBackupAuth, async (req, res) => {
    try { const key = _2faKey('backup', req.backupUser); const c = _2faChallenges.get(key);
        if (!c) return res.status(400).json({ success: false, message: '没有待验证的抽查任务' });
        const acc = await dbGetBackupAccount(req.backupUser);
        if (!acc || !acc.two_factor_enabled || !acc.totp_secret) { _2faChallenges.delete(key); return res.json({ success: true, message: '未开启二次认证，跳过抽查' }); }
        if (!totpVerify(acc.totp_secret, read2faCode(req) || '')) { appendAudit(req.backupUser || 'backup', 'cloud-backup-2fa-spot-check-fail', `云备份账号「${req.backupUser}」随机抽查验证失败`, req); return res.status(403).json({ success: false, message: '动态码错误，请重新输入（来自你的 2FA 浏览器插件）' }); }
        _2faChallenges.delete(key); _2faCoolDown.set(key, Date.now() + _2FA_COOLDOWN); appendAudit(req.backupUser || 'backup', 'cloud-backup-2fa-spot-check', `云备份账号「${req.backupUser}」随机抽查验证通过（冷却 5 分钟）`, req);
        res.json({ success: true, message: '抽查验证通过' }); } catch (e) { res.status(500).json({ success: false, message: '失败' }); }
});
app.post('/api/cloud-backup/authorize', requireBackupAuth, async (req, res) => {
    if (!backupEnabled()) return res.status(403).json({ success: false, message: '云备份功能已关闭' });
    try { const acc = await dbGetBackupAccount(req.backupUser); if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        if (!acc.two_factor_enabled) return res.json({ success: true, required: false });
        const deny = assert2faScope(acc, 'authorize', read2faCode(req)); if (deny) return res.status(403).json({ success: false, message: deny });
        res.json({ success: true, required: true }); } catch (e) { res.status(500).json({ success: false, message: '授权校验失败' }); }
});

// 备份数据：三项各自独立（achievements / statistics / ui_settings）
app.get('/api/cloud-backup/backups', requireBackupAuth, async (req, res) => { try { const kinds = await dbGetBackupKinds(req.backupUser); res.json({ success: true, backups: kinds }); } catch (e) { res.status(500).json({ success: false, message: '获取失败' }); } });
app.put('/api/cloud-backup/backup/:kind', requireBackupAuth, async (req, res) => {
    if (!backupEnabled()) return res.status(403).json({ success: false, message: '云备份功能已关闭' });
    try {
        const kind = (req.params.kind || '').toString();
        if (BACKUP_KINDS.indexOf(kind) < 0) return res.status(400).json({ success: false, message: '不支持的备份类型' });
        const data = (req.body && req.body.data); if (data == null) return res.status(400).json({ success: false, message: '缺少备份数据' });
        const r = await dbUpsertBackup(req.backupUser, kind, data);
        appendAudit(req.backupUser || 'backup', 'cloud-backup-upload', `云备份账号「${req.backupUser}」上传备份：${kind}`, req);
        res.json({ success: true, kind, updated_at: r.updated_at, message: '备份已上传' });
    } catch (e) { res.status(500).json({ success: false, message: '上传失败' }); }
});
app.get('/api/cloud-backup/backup/:kind', requireBackupAuth, async (req, res) => {
    try {
        const kind = (req.params.kind || '').toString();
        if (BACKUP_KINDS.indexOf(kind) < 0) return res.status(400).json({ success: false, message: '不支持的备份类型' });
        const r = await dbGetBackup(req.backupUser, kind);
        if (!r.data) return res.status(404).json({ success: false, message: '该备份不存在' });
        res.json({ success: true, kind, data: r.data, updated_at: r.updated_at });
    } catch (e) { res.status(500).json({ success: false, message: '下载失败' }); }
});
app.delete('/api/cloud-backup/backup/:kind', requireBackupAuth, async (req, res) => {
    try { const kind = (req.params.kind || '').toString(); if (BACKUP_KINDS.indexOf(kind) < 0) return res.status(400).json({ success: false, message: '不支持的备份类型' });
        await dbDeleteBackup(req.backupUser, kind); res.json({ success: true, message: '备份已删除' }); } catch (e) { res.status(500).json({ success: false, message: '删除失败' }); }
});

// 会话管理
app.get('/api/cloud-backup/sessions', requireBackupAuth, async (req, res) => {
    try { const acc = await dbGetBackupAccount(req.backupUser); const deny = assert2faScope(acc, 'sessions', read2faCode(req)); if (deny) return res.status(403).json({ success: false, message: deny });
        const list = await dbGetBackupSessions(req.backupUser); const out = list.map(s => ({ id: s.id, device: s.device || '未知设备', ip: s.ip || '', current: s.id === req.backupSessionId, created_at: s.created_at, last_active_at: s.last_active_at }));
        res.json({ success: true, sessions: out }); } catch (e) { res.status(500).json({ success: false, message: '获取失败' }); }
});
app.delete('/api/cloud-backup/sessions/:id', requireBackupAuth, async (req, res) => {
    try { const acc = await dbGetBackupAccount(req.backupUser); const deny = assert2faScope(acc, 'sessions', read2faCode(req)); if (deny) return res.status(403).json({ success: false, message: deny });
        const id = req.params.id; const list = await dbGetBackupSessions(req.backupUser); const target = list.find(s => s.id === id); if (!target) return res.status(404).json({ success: false, message: '会话不存在' });
        await dbDeleteBackupSession(id); res.json({ success: true, message: id === req.backupSessionId ? '已退出当前设备' : '已退出该设备' }); } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});
app.delete('/api/cloud-backup/sessions', requireBackupAuth, async (req, res) => {
    try { const acc = await dbGetBackupAccount(req.backupUser); const deny = assert2faScope(acc, 'sessions', read2faCode(req)); if (deny) return res.status(403).json({ success: false, message: deny });
        await dbDeleteBackupSessionsExcept(req.backupUser, req.backupSessionId); res.json({ success: true, message: '已退出其他所有设备' }); } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});

// ===== 云备份管理（管理员）=====
app.get('/api/admin/cloud-backup/accounts', requireAdminAuth, async (req, res) => {
    try {
        const accounts = await dbAllBackupAccounts(); const q = ((req.query.q || '').toString().trim()).toLowerCase(); let list = accounts;
        if (q) list = list.filter(a => (a.username || '').toLowerCase().includes(q) || (a.client_id || '').toLowerCase().includes(q));
        const out = await Promise.all(list.map(async a => { let backupCount = 0; let lastIps = []; try { backupCount = (await dbGetBackupKinds(a.username)).length; } catch (e) {} try { const sessions = await dbGetBackupSessions(a.username); const seen = new Set(); for (const s of sessions) { const ip = s.ip && typeof s.ip === 'string' ? s.ip.trim() : ''; if (ip && !seen.has(ip)) { seen.add(ip); lastIps.push(ip); } } } catch (e) {} return { username: a.username, created_at: a.created_at, updated_at: a.updated_at, client_id: a.client_id || null, disabled: !!a.disabled, bannedUntil: (a.banned_until != null && a.banned_until !== '') ? a.banned_until : null, twoFactor: !!a.two_factor_enabled, backupCount, lastIps }; }));
        res.json({ success: true, accounts: out });
    } catch (e) { res.status(500).json({ success: false, message: '获取账号列表失败' }); }
});
app.delete('/api/admin/cloud-backup/accounts/:username', requireAdminAuth, async (req, res) => {
    try { const username = decodeURIComponent(req.params.username || ''); if (!username) return res.status(400).json({ success: false, message: '缺少用户名' }); const acc = await dbGetBackupAccount(username); if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        await dbDeleteBackupAccount(username); appendAudit('admin', 'cloud-backup-account-delete', `删除云备份账号「${username}」及其全部备份/会话`, req); res.json({ success: true, message: '已删除账号及其备份/会话' }); } catch (e) { res.status(500).json({ success: false, message: '删除失败' }); }
});
app.put('/api/admin/cloud-backup/accounts/:username/ban', requireAdminAuth, async (req, res) => {
    try { const username = decodeURIComponent(req.params.username || ''); if (!username) return res.status(400).json({ success: false, message: '缺少用户名' }); const acc = await dbGetBackupAccount(username); if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        const disabled = !!(req.body && req.body.disabled); acc.disabled = disabled; acc.updated_at = new Date().toISOString();
        if (disabled) { const bu = (req.body && req.body.bannedUntil); acc.banned_until = (bu && String(bu).trim() !== '') ? String(bu) : null; await dbDeleteBackupSessionsByUser(username); }
        else { acc.banned_until = null; }
        await dbSaveBackupAccount(acc); const actorName = (req.admin && req.admin.name) || 'admin';
        if (disabled) { await dbSaveBanHistory({ id: 'bh_backup_' + username + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2,6), type: 'backup', target: username, username: username, clientId: acc.client_id || null, reason: acc.banned_until ? ('限时封禁至 ' + acc.banned_until) : '永久封禁', bannedAt: acc.updated_at, expiresAt: acc.banned_until || null, unbannedAt: null, unbannedBy: null, bannedBy: actorName }); }
        else { await dbUpdateBanHistoryUnban('backup', username, actorName); }
        appendAudit('admin', 'cloud-backup-account-ban', `云备份账号「${username}」${disabled ? (acc.banned_until ? '限时封禁至 ' + acc.banned_until : '永久封禁') : '解封'}，并已退登其全部设备`, req);
        res.json({ success: true, disabled, bannedUntil: acc.banned_until || null, message: disabled ? (acc.banned_until ? ('已封禁该账号（至 ' + acc.banned_until + '），并已退登其全部设备') : '已永久封禁该账号，并已退登其全部设备') : '已解封该账号' });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});
app.put('/api/admin/cloud-backup/accounts/:username/password', requireAdminAuth, async (req, res) => {
    try { const username = decodeURIComponent(req.params.username || ''); if (!username) return res.status(400).json({ success: false, message: '缺少用户名' }); const acc = await dbGetBackupAccount(username); if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        const password = (req.body && req.body.password || '').toString(); if (password.length < 4) return res.status(400).json({ success: false, message: '密码至少 4 位' });
        acc.password_hash = bcrypt.hashSync(password, 10); acc.updated_at = new Date().toISOString(); await dbSaveBackupAccount(acc); appendAudit('admin', 'cloud-backup-account-password', `重置云备份账号「${username}」的密码`, req); res.json({ success: true, message: '密码已修改' }); } catch (e) { res.status(500).json({ success: false, message: '修改失败' }); }
});
app.put('/api/admin/cloud-backup/accounts/:username/2fa', requireAdminAuth, async (req, res) => {
    try { const username = decodeURIComponent(req.params.username || ''); if (!username) return res.status(400).json({ success: false, message: '缺少用户名' }); const acc = await dbGetBackupAccount(username); if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        if (req.body && req.body.enabled === true) return res.status(400).json({ success: false, message: '开启二次认证必须由用户本人操作' });
        acc.two_factor_enabled = 0; acc.totp_secret = null; acc.totp_scopes = null; acc.updated_at = new Date().toISOString(); await dbSaveBackupAccount(acc);
        appendAudit('admin', 'cloud-backup-2fa-admin-disable', `管理员关闭云备份账号「${username}」的二次认证`, req); res.json({ success: true, enabled: false, message: '已关闭该账号的二次认证' }); } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});

// ===== 云储存管理（管理员专用）=====
// 列出所有云储存账号
app.get('/api/admin/cloud-storage/users', requireAdminAuth, async (req, res) => {
    try {
        const accounts = await dbGetAllCloudAccounts();
        res.json({ success: true, accounts });
    } catch (e) { res.status(500).json({ success: false, message: '获取失败' }); }
});
// 列出某账号的云地图（含网格，供管理/下载）
app.get('/api/admin/cloud-storage/mazes', requireAdminAuth, async (req, res) => {
    try {
        const username = (req.query.username || '').toString().trim();
        if (!username) return res.status(400).json({ success: false, message: '缺少 username' });
        // 兼容：前端可能传 clientId，这里只支持云 username
        const list = await dbGetCloudMazes(username);
        const out = list.map(m => ({
            id: m.id, name: m.name, description: m.description || '', difficulty: m.difficulty || '中等',
            size: (typeof m.size === 'string') ? JSON.parse(m.size) : m.size,
            maze: (typeof m.maze === 'string') ? JSON.parse(m.maze) : m.maze,
            teleporters: (typeof m.teleporters === 'string') ? JSON.parse(m.teleporters) : (m.teleporters || []),
            enemySpeed: m.enemy_speed || 1, showShop: m.show_shop !== 0,
            created_at: m.created_at, updated_at: m.updated_at
        }));
        res.json({ success: true, mazes: out });
    } catch (e) { res.status(500).json({ success: false, message: '获取失败' }); }
});

// ===== 云储存账号管理（管理员）=====
// 列出所有云储存账号（含封禁状态、地图数、关联游戏 clientId）
// 管理员直接创建云储存账号（不受全局云储存开关限制；可设无限量或自定义容量）
app.post('/api/admin/cloud-storage/accounts', requireAdminAuth, async (req, res) => {
    try {
        const b = req.body || {};
        const username = (b.username || '').toString().trim();
        const password = (b.password || '').toString();
        if (!username || !password) return res.status(400).json({ success: false, message: '用户名和密码不能为空' });
        if (username.length > 64 || password.length < 4) return res.status(400).json({ success: false, message: '用户名过长或密码至少 4 位' });
        const existing = await dbGetCloudAccount(username);
        if (existing) return res.status(409).json({ success: false, message: '该用户名已被注册' });
        // 容量：显式给出合法正整数则采用，否则默认无限量
        const maxRaw = Number(b.maxMazes);
        const maxMazes = (b.maxMazes != null && isFinite(maxRaw) && maxRaw > 0)
            ? Math.min(Math.floor(maxRaw), CLOUD_UNLIMITED_MAZES)
            : CLOUD_UNLIMITED_MAZES;
        const password_hash = bcrypt.hashSync(password, 10);
        const now = new Date().toISOString();
        const acc = {
            username, password_hash, created_at: now, updated_at: now,
            max_mazes: maxMazes, client_id: null, disabled: 0
        };
        await dbSaveCloudAccount(acc);
        appendAudit('admin', 'cloud-account-create', `创建云储存账号「${username}」（容量 ${maxMazes >= CLOUD_UNLIMITED_THRESHOLD ? '无限' : maxMazes}）`, req);
        res.json({
            success: true,
            message: '云储存账号已创建',
            account: { username, maxMazes, unlimited: maxMazes >= CLOUD_UNLIMITED_THRESHOLD }
        });
    } catch (e) {
        console.error('[云储存] 管理员创建账号失败:', e);
        res.status(500).json({ success: false, message: '创建失败' });
    }
});

app.get('/api/admin/cloud-storage/accounts', requireAdminAuth, async (req, res) => {
    try {
        const accounts = await dbGetAllCloudAccounts();
        const q = ((req.query.q || '').toString().trim()).toLowerCase();
        let list = accounts;
        if (q) list = list.filter(a => (a.username || '').toLowerCase().includes(q) || (a.client_id || '').toLowerCase().includes(q));
        const out = await Promise.all(list.map(async a => {
            let mazeCount = 0;
            let lastIps = [];
            try { mazeCount = (await dbGetCloudMazes(a.username)).length; } catch (e) {}
            try {
                const sessions = await dbGetCloudSessions(a.username);
                const seen = new Set();
                for (const s of sessions) {
                    const ip = s.ip && typeof s.ip === 'string' ? s.ip.trim() : '';
                    if (ip && !seen.has(ip)) { seen.add(ip); lastIps.push(ip); }
                }
            } catch (e) {}
            return {
                username: a.username,
                created_at: a.created_at,
                updated_at: a.updated_at,
                client_id: a.client_id || null,
                disabled: !!a.disabled,
                bannedUntil: (a.banned_until != null && a.banned_until !== '') ? a.banned_until : null,
                maxMazes: (a.max_mazes != null) ? Number(a.max_mazes) : CLOUD_MAX_MAZES,
                unlimited: (a.max_mazes != null) ? (Number(a.max_mazes) >= CLOUD_UNLIMITED_THRESHOLD) : false,
                twoFactor: !!a.two_factor_enabled,
                mazeCount,
                lastIps
            };
        }));
        res.json({ success: true, accounts: out });
    } catch (e) { res.status(500).json({ success: false, message: '获取账号列表失败' }); }
});

// 删除云储存账号（级联删除其地图与会话）
app.delete('/api/admin/cloud-storage/accounts/:username', requireAdminAuth, async (req, res) => {
    try {
        const username = decodeURIComponent(req.params.username || '');
        if (!username) return res.status(400).json({ success: false, message: '缺少用户名' });
        const acc = await dbGetCloudAccount(username);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        await dbDeleteCloudAccount(username);
        appendAudit('admin', 'cloud-account-delete', `删除云储存账号「${username}」及其全部地图/会话`, req);
        res.json({ success: true, message: '已删除账号及其地图/会话' });
    } catch (e) { res.status(500).json({ success: false, message: '删除失败' }); }
});

// 封禁 / 解封云储存账号（支持限时封禁：bannedUntil 为 ISO 时间串，null/空=永久；封禁即退登全部设备）
app.put('/api/admin/cloud-storage/accounts/:username/ban', requireAdminAuth, async (req, res) => {
    try {
        const username = decodeURIComponent(req.params.username || '');
        if (!username) return res.status(400).json({ success: false, message: '缺少用户名' });
        const acc = await dbGetCloudAccount(username);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        const disabled = !!(req.body && req.body.disabled);
        acc.disabled = disabled;
        acc.updated_at = new Date().toISOString();
        if (disabled) {
            // bannedUntil 为 ISO 时间字符串；null/空 = 永久封禁
            const bu = (req.body && req.body.bannedUntil);
            acc.banned_until = (bu && String(bu).trim() !== '') ? String(bu) : null;
            // 封禁即退登该账号所有已登录设备（强制下线）
            await dbDeleteCloudSessionsByUser(username);
        } else {
            acc.banned_until = null;
        }
        await dbSaveCloudAccount(acc);
        const actorName = (req.admin && req.admin.name) || 'admin';
        if (disabled) {
            // 写入封禁历史（供反作弊标签页展示）
            await dbSaveBanHistory({
                id: 'bh_cloud_' + username + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
                type: 'cloud',
                target: username,
                username: username,
                clientId: acc.client_id || null,
                reason: acc.banned_until ? ('限时封禁至 ' + acc.banned_until) : '永久封禁',
                bannedAt: acc.updated_at,
                expiresAt: acc.banned_until || null,
                unbannedAt: null,
                unbannedBy: null,
                bannedBy: actorName
            });
        } else {
            // 解封：标记历史为已解封
            await dbUpdateBanHistoryUnban('cloud', username, actorName);
        }
        appendAudit('admin', 'cloud-account-ban', `云储存账号「${username}」${disabled ? (acc.banned_until ? '限时封禁至 ' + acc.banned_until : '永久封禁') : '解封'}，并已退登其全部设备`, req);
        res.json({
            success: true, disabled,
            bannedUntil: acc.banned_until || null,
            message: disabled
                ? (acc.banned_until ? ('已封禁该账号（至 ' + acc.banned_until + '），并已退登其全部设备') : '已永久封禁该账号，并已退登其全部设备')
                : '已解封该账号'
        });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});

// 修改云储存账号密码
app.put('/api/admin/cloud-storage/accounts/:username/password', requireAdminAuth, async (req, res) => {
    try {
        const username = decodeURIComponent(req.params.username || '');
        if (!username) return res.status(400).json({ success: false, message: '缺少用户名' });
        const acc = await dbGetCloudAccount(username);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        const password = (req.body && req.body.password || '').toString();
        if (password.length < 4) return res.status(400).json({ success: false, message: '密码至少 4 位' });
        acc.password_hash = bcrypt.hashSync(password, 10);
        acc.updated_at = new Date().toISOString();
        await dbSaveCloudAccount(acc);
        appendAudit('admin', 'cloud-account-password', `重置云储存账号「${username}」的密码`, req);
        res.json({ success: true, message: '密码已修改' });
    } catch (e) { res.status(500).json({ success: false, message: '修改失败' }); }
});

// 管理员强制关闭某云储存账号的二次认证（用户换手机/丢失 2FA 插件时的救援通道）。
// 只支持「关闭」：开启必须由用户本人在客户端绑定密钥并完成二次确认，管理员无法代为开启。
app.put('/api/admin/cloud-storage/accounts/:username/2fa', requireAdminAuth, async (req, res) => {
    try {
        const username = decodeURIComponent(req.params.username || '');
        if (!username) return res.status(400).json({ success: false, message: '缺少用户名' });
        const enabled = !!(req.body && req.body.enabled);
        if (enabled) return res.status(400).json({ success: false, message: '管理员只能关闭二次认证；开启需用户本人绑定 2FA 插件并完成确认' });
        const acc = await dbGetCloudAccount(username);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        pending2faDrop('cloud', username);
        acc.totp_secret = null;
        acc.two_factor_enabled = 0;
        acc.updated_at = new Date().toISOString();
        await dbSaveCloudAccount(acc);
        appendAudit('admin', 'cloud-2fa-admin-disable', `管理员强制关闭云储存账号「${username}」的二次认证`, req);
        res.json({ success: true, enabled: false, message: '已强制关闭该账号的二次认证' });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});

// 管理员改名云地图
app.put('/api/admin/cloud-storage/mazes/:id', requireAdminAuth, async (req, res) => {
    try {
        // 统一读取：DB 优先 + JSON 兜底（避免 DB 模式下 cloudMazes Map 为空导致查不到）
        let m = cloudMazes.get(req.params.id);
        if (!m && DB_AVAILABLE && pool) {
            try {
                const [rows] = await pool.query('SELECT * FROM cloud_storage_mazes WHERE id=?', [req.params.id]);
                if (rows && rows.length) m = rows[0];
            } catch (e) { console.error('[云储存] admin 改名查图失败:', e.message); }
        }
        if (!m) return res.status(404).json({ success: false, message: '地图不存在' });
        const name = (req.body.name || '').toString().trim();
        if (!name) return res.status(400).json({ success: false, message: '名称不能为空' });
        m.name = name;
        m.updated_at = new Date().toISOString();
        await dbUpsertCloudMaze(m);
        appendAudit('admin', 'cloud-maze-rename', `将云地图 ${m.id} 改名为「${name}」`, req);
        res.json({ success: true, maze: { id: m.id, name: m.name } });
    } catch (e) { res.status(500).json({ success: false, message: '改名失败' }); }
});
// 管理员删除云地图
app.delete('/api/admin/cloud-storage/mazes/:id', requireAdminAuth, async (req, res) => {
    try {
        let exists = cloudMazes.has(req.params.id);
        if (!exists && DB_AVAILABLE && pool) {
            try {
                const [rows] = await pool.query('SELECT id FROM cloud_storage_mazes WHERE id=?', [req.params.id]);
                if (rows && rows.length) exists = true;
            } catch (e) { console.error('[云储存] admin 删除查图失败:', e.message); }
        }
        if (!exists) return res.status(404).json({ success: false, message: '地图不存在' });
        await dbDeleteCloudMaze(req.params.id);
        appendAudit('admin', 'cloud-maze-delete', `删除云地图 ${req.params.id}`, req);
        res.json({ success: true, message: '已删除' });
    } catch (e) { res.status(500).json({ success: false, message: '删除失败' }); }
});

// 客户端兑换扩容码：校验使用次数 / IP / 是否已用，写回账号容量
app.post('/api/cloud-storage/redeem', requireCloudAuth, async (req, res) => {
    if (!cloudStorageEnabled()) return res.status(403).json({ success: false, message: '云储存功能已关闭' });
    try {
        const raw = (req.body && req.body.code || '').toString().toUpperCase().replace(/[\s-]/g, '');
        if (!raw) return res.status(400).json({ success: false, message: '请输入扩容码' });
        const c = await dbGetCloudCode(raw);
        if (!c) return res.status(404).json({ success: false, message: '扩容码无效' });
        if (c.active === 0 || c.active === false) return res.status(410).json({ success: false, message: '该扩容码已作废' });
        if (c.used >= c.max_uses) return res.status(403).json({ success: false, message: '该扩容码已达到使用上限' });
        const redeemedBy = Array.isArray(c.redeemed_by) ? c.redeemed_by : [];
        const alreadyRedeemed = redeemedBy.includes(req.cloudUser);
        if (alreadyRedeemed) {
            // 兼容历史 bug：若账号当前容量仍低于码容量，说明上次兑换因缺 max_mazes 列未真正持久化，
            // 允许重新生效且不重复计次（used/redeemed_by 不再累加）；只有容量确实已达标才拦截。
            const curMax = await cloudMaxMazes(req.cloudUser);
            if (curMax >= c.capacity) {
                return res.status(403).json({ success: false, message: '本账号已使用过该扩容码' });
            }
        }
        // IP 限制
        const clientIp = getClientIp(req);
        if (c.allowed_ips !== '*' && Array.isArray(c.allowed_ips)) {
            const ok = c.allowed_ips.some(ip => {
                const t = ip.trim();
                if (!t) return false;
                return clientIp === t || clientIp.startsWith(t.replace(/\.\*$/, '.')) || clientIp === t.replace(/\.\*$/, '');
            });
            if (!ok) return res.status(403).json({ success: false, message: `该扩容码不允许当前 IP（${clientIp}）使用` });
        }
        // 写回账号容量（取较大值，避免缩小）
        const acc = await dbGetCloudAccount(req.cloudUser);
        if (!acc) return res.status(404).json({ success: false, message: '账号不存在' });
        const newMax = Math.max(Number(acc.max_mazes != null ? acc.max_mazes : CLOUD_MAX_MAZES), Number(c.capacity));
        acc.max_mazes = newMax;
        acc.updated_at = new Date().toISOString();
        await dbSaveCloudAccount(acc);
        // 更新码状态（仅当本次是"首次真正生效"才计次，避免历史未生效的重复兑换消耗使用次数）
        if (!alreadyRedeemed) {
            c.used = (c.used || 0) + 1;
            redeemedBy.push(req.cloudUser);
            c.redeemed_by = redeemedBy;
        }
        await dbUpsertCloudCode(c);
        res.json({ success: true, maxMazes: newMax, capacity: c.capacity, message: `云空间已扩容至 ${newMax} 个` });
    } catch (e) {
        console.error('[云储存] 兑换失败:', e);
        res.status(500).json({ success: false, message: '兑换失败' });
    }
});

// 管理员生成扩容码（自定义使用次数 / 允许 IP / 扩容容量）
app.post('/api/admin/cloud-codes', requireAdminAuth, async (req, res) => {
    try {
        const b = req.body || {};
        let maxUses = parseInt(b.maxUses, 10);
        if (!maxUses || maxUses < 1) maxUses = 1;
        if (maxUses > 1000) maxUses = 1000;
        let capacity = parseInt(b.capacity, 10);
        if (!capacity || capacity < 1) capacity = 10;
        if (capacity > 10000) capacity = 10000;
        let allowedIps = '*';
        if (b.allowedIps && String(b.allowedIps).trim() && String(b.allowedIps).trim() !== '*') {
            allowedIps = String(b.allowedIps).split(',').map(s => s.trim()).filter(Boolean);
            if (allowedIps.length === 0) allowedIps = '*';
        }
        const code = genExpansionCode();
        const now = new Date().toISOString();
        const obj = {
            code, max_uses: maxUses, used: 0, allowed_ips: allowedIps, capacity,
            created_at: now, created_by: (req.adminUser || 'admin'), note: (b.note || '').toString().slice(0, 255),
            active: 1, redeemed_by: []
        };
        await dbUpsertCloudCode(obj);
        appendAudit('admin', 'cloud-code-create', `生成扩容码 ${code}（容量 ${capacity}，可用 ${maxUses} 次）`, req);
        res.json({ success: true, code, maxUses, capacity, allowedIps, message: '生成成功' });
    } catch (e) {
        console.error('[云储存] 生成扩容码失败:', e);
        res.status(500).json({ success: false, message: '生成失败' });
    }
});

// 管理员列出所有扩容码
app.get('/api/admin/cloud-codes', requireAdminAuth, async (req, res) => {
    try {
        const list = await dbAllCloudCodes();
        const out = list.map(c => ({
            code: c.code, maxUses: c.max_uses, used: c.used,
            allowedIps: c.allowed_ips, capacity: c.capacity,
            created_at: c.created_at, created_by: c.created_by, note: c.note,
            active: c.active !== 0 && c.active !== false
        }));
        res.json({ success: true, codes: out });
    } catch (e) { res.status(500).json({ success: false, message: '获取失败' }); }
});

// 管理员作废某个扩容码
app.delete('/api/admin/cloud-codes/:code', requireAdminAuth, async (req, res) => {
    try {
        const code = (req.params.code || '').toUpperCase();
        const c = await dbGetCloudCode(code);
        if (!c) return res.status(404).json({ success: false, message: '扩容码不存在' });
        await dbDeleteCloudCode(code);
        appendAudit('admin', 'cloud-code-void', `作废扩容码 ${code}`, req);
        res.json({ success: true, message: '已作废' });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});

// 管理员查看某云账号占用空间（容量 / 地图数 / 占用字节 / 设备列表）
app.get('/api/admin/cloud-storage/usage', requireAdminAuth, async (req, res) => {
    try {
        const username = (req.query.username || '').toString().trim();
        const clientId = (req.query.clientId || '').toString().trim();
        let acc = username ? await dbGetCloudAccount(username) : null;
        if (!acc && clientId) acc = await dbGetCloudAccountByClient(clientId);
        if (!acc) return res.status(404).json({ success: false, message: '该游戏账号尚未注册/绑定云储存账号' });
        const max = (acc.max_mazes != null) ? acc.max_mazes : CLOUD_MAX_MAZES;
        // 注意：按 clientId 反查时本地 username 变量为空，必须统一用 acc.username 查询
        const uname = acc.username;
        const list = await dbGetCloudMazes(uname);
        const mazes = list.map(m => {
            const bytes = Buffer.byteLength(JSON.stringify({
                name: m.name, maze: m.maze, size: m.size, teleporters: m.teleporters,
                description: m.description, difficulty: m.difficulty
            }), 'utf8');
            return { id: m.id, name: m.name, bytes, updated_at: m.updated_at };
        });
        const totalBytes = mazes.reduce((s, m) => s + m.bytes, 0);
        const devices = (await dbGetCloudSessions(uname)).map(s => ({
            id: s.id, device: s.device || '未知设备', ip: s.ip || '',
            created_at: s.created_at, last_active_at: s.last_active_at
        }));
        res.json({
            success: true, username: uname, maxMazes: max, count: list.length,
            totalBytes, mazes, devices
        });
    } catch (e) { res.status(500).json({ success: false, message: '获取失败' }); }
});

// 管理员查看某云账号的登录设备
app.get('/api/admin/cloud-storage/devices', requireAdminAuth, async (req, res) => {
    try {
        const username = (req.query.username || '').toString().trim();
        const clientId = (req.query.clientId || '').toString().trim();
        let acc = username ? await dbGetCloudAccount(username) : null;
        if (!acc && clientId) acc = await dbGetCloudAccountByClient(clientId);
        const uname = acc ? acc.username : username;
        const devices = (await dbGetCloudSessions(uname)).map(s => ({
            id: s.id, device: s.device || '未知设备', ip: s.ip || '',
            created_at: s.created_at, last_active_at: s.last_active_at
        }));
        res.json({ success: true, devices });
    } catch (e) { res.status(500).json({ success: false, message: '获取失败' }); }
});

// 管理员退登某云账号的指定设备
app.delete('/api/admin/cloud-storage/devices', requireAdminAuth, async (req, res) => {
    try {
        const username = (req.query.username || '').toString().trim();
        const clientId = (req.query.clientId || '').toString().trim();
        const id = (req.query.id || '').toString().trim();
        if (!id) return res.status(400).json({ success: false, message: '缺少 id' });
        let acc = username ? await dbGetCloudAccount(username) : null;
        if (!acc && clientId) acc = await dbGetCloudAccountByClient(clientId);
        const uname = acc ? acc.username : username;
        if (!uname) return res.status(400).json({ success: false, message: '缺少 username 或 clientId' });
        await dbDeleteCloudSession(id);
        appendAudit('admin', 'cloud-device-logout', `退登云储存账号「${uname}」的设备 ${id}`, req);
        res.json({ success: true, message: '已退登该设备' });
    } catch (e) { res.status(500).json({ success: false, message: '操作失败' }); }
});

// 玩家上报/保存自己的地图（公开，需 clientId 归属）
app.post('/api/player-mazes', async (req, res) => {
    try {
        const b = req.body || {};
        const clientId = b.clientId || (req.headers['x-client-id'] || '').toString() || '';
        if (!clientId) return res.status(400).json({ success: false, message: '缺少 clientId，无法归属地图' });
        const name = (b.name || '').toString().trim();
        if (!name) return res.status(400).json({ success: false, message: '地图名称不能为空' });
        let maze = null;
        let resolvedId = null;
        // 客户端可携带稳定 mazeId（编辑器 serverMazeId 或本地图 local_xxx），用于幂等更新：
        // 1) 该 id 已存在且作者一致 → 原地更新；
        // 2) 该 id 从未出现过（客户端首次自建）→ 直接采用该 id 作为地图 id，避免重复进入游戏时生成多份。
        if (b.mazeId) {
            if (playerMazes.has(b.mazeId)) {
                const existing = playerMazes.get(b.mazeId);
                if (existing.author === clientId) { maze = existing; resolvedId = b.mazeId; }
            } else {
                resolvedId = b.mazeId; // 新 id，由客户端提供，直接采用
            }
        }
        const now = Date.now();
        if (!maze) {
            maze = { id: resolvedId || ('pmaze_' + now.toString(36) + '_' + Math.random().toString(36).substr(2, 5)), createdAt: now, noShare: false, disabled: false, playCount: 0 };
        }
        maze.name = name;
        maze.description = b.description || '';
        maze.difficulty = b.difficulty || '中等';
        maze.size = b.size || (b.maze && b.maze[0] ? { width: b.maze[0].length, height: b.maze.length } : { width: 10, height: 10 });
        maze.maze = b.maze || null;
        maze.teleporters = b.teleporters || [];
        maze.enemySpeed = b.enemySpeed || 1;
        maze.showShop = b.showShop !== false;
        maze.author = clientId;
        maze.authorName = b.authorName || '玩家';
        maze.accountId = b.accountId || null;
        maze.isShared = b.isShared === true;
        // isPublic：玩家自己控制的"是否公开"（默认私密=false）。玩家更新时覆盖；noShare / disabled 由 admin 控制不覆盖
        if (b.mazeId && playerMazes.has(b.mazeId)) {
            // 更新已有图：以客户端本次传入为准（明确传 false/true 都尊重）
            maze.isPublic = b.isPublic === true;
        } else {
            // 新建图：默认私密
            maze.isPublic = b.isPublic === true;
        }
        // noShare / disabled 由 admin 控制，玩家更新时不覆盖
        maze.updatedAt = now;
        playerMazes.set(maze.id, maze);
        savePlayerMazes();
        console.log(`[工坊] 玩家 ${clientId} ${b.mazeId ? '更新' : '保存'}地图: ${maze.name} (${maze.id})`);
        res.json({ success: true, message: '地图已保存', maze: { id: maze.id, name: maze.name, isShared: maze.isShared } });
    } catch (e) {
        console.error('[工坊] 保存玩家地图失败:', e);
        res.status(500).json({ success: false, message: '保存失败' });
    }
});

// 公开：浏览玩家分享的地图（过滤禁分享/禁用）
app.get('/api/browse-mazes', (req, res) => {
    try {
        const list = Array.from(playerMazes.values())
            .filter(m => m.isShared && !m.noShare && !m.disabled)
            .sort((a, b) => (b.playCount || 0) - (a.playCount || 0) || (b.createdAt || 0) - (a.createdAt || 0))
            .map(m => ({
                id: m.id, name: m.name, description: m.description, difficulty: m.difficulty,
                size: m.size, maze: m.maze, teleporters: m.teleporters || [], enemySpeed: m.enemySpeed || 1,
                showShop: m.showShop !== false, authorName: m.authorName, author: m.author, playCount: m.playCount || 0,
                createdAt: m.createdAt, updatedAt: m.updatedAt
            }));
        res.json({ success: true, mazes: list });
    } catch (e) {
        res.status(500).json({ success: false, message: '获取失败' });
    }
});

// 管理员：获取某玩家的全部地图（按 clientId 或 accountId）
app.get('/api/admin/users/:userId/mazes', requireAdminAuth, (req, res) => {
    try {
        const uid = req.params.userId;
        const list = Array.from(playerMazes.values())
            .filter(m => m.author === uid || m.accountId === uid)
            .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0))
            .map(m => {
                let popularId = null;
                for (const pm of mazes.values()) { if (pm.sourceMazeId === m.id) { popularId = pm.id; break; } }
                return {
                    id: m.id, name: m.name, description: m.description, difficulty: m.difficulty,
                    size: m.size, isShared: m.isShared, noShare: !!m.noShare, disabled: !!m.disabled,
                    isPublic: !!m.isPublic, popularId, playCount: m.playCount || 0, createdAt: m.createdAt, updatedAt: m.updatedAt
                };
            });
        res.json({ success: true, mazes: list });
    } catch (e) {
        res.status(500).json({ success: false, message: '获取失败' });
    }
});

// 公开：获取某玩家的「公开地图」（个人主页展示用，默认私密，仅 isPublic 的可见；避免暴露私密图）
app.get('/api/users/:clientId/public-mazes', (req, res) => {
    try {
        const cid = req.params.clientId;
        const list = Array.from(playerMazes.values())
            .filter(m => m.author === cid && m.isPublic === true && !m.disabled)
            .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0))
            .map(m => ({
                id: m.id, name: m.name, description: m.description, difficulty: m.difficulty,
                size: m.size, maze: m.maze, teleporters: m.teleporters || [], enemySpeed: m.enemySpeed || 1,
                showShop: m.showShop !== false, authorName: m.authorName, playCount: m.playCount || 0,
                createdAt: m.createdAt, updatedAt: m.updatedAt
            }));
        res.json({ success: true, mazes: list });
    } catch (e) {
        res.status(500).json({ success: false, message: '获取失败' });
    }
});

// 管理员：更新玩家地图标志（禁用/禁止分享/改名）
app.put('/api/admin/player-mazes/:mazeId', requireAdminAuth, async (req, res) => {
    try {
        const mazeId = req.params.mazeId;
        const maze = playerMazes.get(mazeId);
        if (!maze) return res.status(404).json({ success: false, message: '地图不存在' });
        const b = req.body || {};
        if (b.disabled !== undefined) maze.disabled = !!b.disabled;
        if (b.noShare !== undefined) maze.noShare = !!b.noShare;
        if (b.isPublic !== undefined) maze.isPublic = !!b.isPublic;
        if (b.name !== undefined) maze.name = String(b.name).trim() || maze.name;
        maze.updatedAt = Date.now();
        playerMazes.set(mazeId, maze);
        savePlayerMazes();
        appendAudit('admin', 'player-maze-edit', `编辑玩家地图 ${maze.name} (${mazeId}) disabled=${maze.disabled} noShare=${maze.noShare}`);
        console.log(`[Admin] 编辑玩家地图: ${maze.name} (${mazeId})`);
        res.json({ success: true, message: '已更新', maze: { id: maze.id, disabled: maze.disabled, noShare: maze.noShare } });
    } catch (e) {
        console.error('[API] 编辑玩家地图失败:', e);
        res.status(500).json({ success: false, message: '更新失败' });
    }
});

// 玩家本人：列出自己的全部地图（含服务端 isPublic 状态）。需 clientId 头。
app.get('/api/player-mazes/self', (req, res) => {
    try {
        const clientId = (req.headers['x-client-id'] || '').toString();
        if (!clientId) return res.status(400).json({ success: false, message: '缺少 clientId' });
        const list = Array.from(playerMazes.values())
            .filter(m => m.author === clientId)
            .map(m => ({ id: m.id, name: m.name, isPublic: !!m.isPublic, isShared: !!m.isShared, disabled: !!m.disabled }));
        res.json({ success: true, mazes: list });
    } catch (e) {
        res.status(500).json({ success: false, message: '获取失败' });
    }
});

// 玩家本人：设置自己地图是否公开（默认私密）。需 clientId 头，仅本人可改。
app.put('/api/player-mazes/:mazeId/public', async (req, res) => {
    try {
        const mazeId = req.params.mazeId;
        const clientId = (req.headers['x-client-id'] || (req.body && req.body.clientId) || '').toString();
        const maze = playerMazes.get(mazeId);
        if (!maze) return res.status(404).json({ success: false, message: '地图不存在' });
        if (!clientId || maze.author !== clientId) return res.status(403).json({ success: false, message: '只能修改自己的地图' });
        const b = req.body || {};
        maze.isPublic = b.isPublic === true;
        maze.updatedAt = Date.now();
        playerMazes.set(mazeId, maze);
        savePlayerMazes();
        res.json({ success: true, isPublic: maze.isPublic, message: maze.isPublic ? '已设为公开' : '已设为私密' });
    } catch (e) {
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 管理员：删除玩家地图
app.delete('/api/admin/player-mazes/:mazeId', requireAdminAuth, async (req, res) => {
    try {
        const mazeId = req.params.mazeId;
        if (!playerMazes.has(mazeId)) return res.status(404).json({ success: false, message: '地图不存在' });
        const m = playerMazes.get(mazeId);
        playerMazes.delete(mazeId);
        savePlayerMazes();
        appendAudit('admin', 'player-maze-delete', `删除玩家地图 ${m.name} (${mazeId})`);
        console.log(`[Admin] 删除玩家地图: ${mazeId}`);
        res.json({ success: true, message: '地图删除成功' });
    } catch (e) {
        console.error('[API] 删除玩家地图失败:', e);
        res.status(500).json({ success: false, message: '删除失败' });
    }
});

// 管理员：将某玩家地图设为热门地图（复制到热门迷宫列表，按 sourceMazeId 去重）
app.post('/api/admin/player-mazes/:mazeId/promote', requireAdminAuth, async (req, res) => {
    try {
        const mazeId = req.params.mazeId;
        const maze = playerMazes.get(mazeId);
        if (!maze) return res.status(404).json({ success: false, message: '玩家地图不存在' });
        if (!maze.maze || (Array.isArray(maze.maze) && maze.maze.length === 0)) {
            return res.status(400).json({ success: false, message: '该地图没有可游玩的迷宫数据，无法设为热门' });
        }
        const grid = maze.maze;
        let sz;
        if (maze.size && typeof maze.size.width === 'number') sz = maze.size.width;
        else if (typeof maze.size === 'number') sz = maze.size;
        else if (grid && grid[0]) sz = grid[0].length;
        else sz = 10;
        // 去重：若该玩家地图已被设为热门，则原地更新而非重复新增
        let existing = null;
        for (const pm of mazes.values()) { if (pm.sourceMazeId === maze.id) { existing = pm; break; } }
        const pm = existing || { id: generateMazeId(), createdAt: Date.now() };
        pm.name = String(maze.name || '未命名地图').trim();
        pm.description = maze.description || '';
        pm.difficulty = maze.difficulty || '中等';
        pm.size = sz;
        pm.data = grid;
        pm.teleporters = maze.teleporters || [];
        pm.enemySpeed = maze.enemySpeed || 1;
        pm.showShop = maze.showShop !== false;
        pm.sourceMazeId = maze.id;
        pm.author = maze.author;
        pm.authorName = maze.authorName || '玩家';
        pm.updatedAt = Date.now();
        mazes.set(pm.id, pm);
        await saveMazes();
        // 设为热门时，自动将该玩家地图转为可公开游玩状态（避免出现“热门却已被禁用/禁分享”的矛盾）
        maze.disabled = false;
        maze.noShare = false;
        maze.isShared = true;
        maze.updatedAt = Date.now();
        playerMazes.set(maze.id, maze);
        savePlayerMazes();
        appendAudit('admin', 'player-maze-promote', `将玩家地图 ${maze.name} (${maze.id}) 设为热门 (${pm.id})`);
        console.log(`[Admin] 玩家地图设为热门: ${maze.name} -> ${pm.id} (${existing ? '更新' : '新增'})`);
        res.json({ success: true, message: existing ? '已更新热门地图' : '已设为热门地图', popularId: pm.id, alreadyPromoted: !!existing });
    } catch (e) {
        console.error('[API] 设为热门地图失败:', e);
        res.status(500).json({ success: false, message: '设为热门失败' });
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
app.put('/api/admin/global-functions', requireAdminAuth, async (req, res) => {
    try {
        const body = req.body || {};
        const validKeys = Object.keys(GLOBAL_FUNCTIONS_DEFAULT);
        const next = Object.assign({}, GLOBAL_FUNCTIONS_DEFAULT);
        for (const k of validKeys) {
            if (typeof body[k] === 'boolean') next[k] = body[k];
        }
        // 新增：处理「使用新UI」策略（对象，非布尔）
        if (body.newUi && typeof body.newUi === 'object') {
            const m = body.newUi.mode;
            if (m === 'always' || m === 'never' || m === 'probability') {
                let prob = parseInt(body.newUi.prob, 10);
                if (isNaN(prob)) prob = (m === 'probability') ? 100 : (GLOBAL_FUNCTIONS_DEFAULT.newUi ? GLOBAL_FUNCTIONS_DEFAULT.newUi.prob : 100);
                prob = Math.max(0, Math.min(100, prob));
                next.newUi = { mode: m, prob: prob };
            }
        }
        globalFunctions = next;
        await saveGlobalFunctions();
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

// ===== 每日挑战自定义配置（admin 可编辑并设持续天数，默认1天）=====
const VALID_DAILY_TYPES = ['speed', 'steps', 'no_traps', 'collection'];

// 公开接口：游戏客户端拉取当前生效的每日挑战配置（含过期判断）。无需鉴权。
app.get('/api/daily-challenge-config', (req, res) => {
    const cfg = dailyChallengeConfig || {};
    if (!cfg.enabled) return res.json({ enabled: false });
    const today = serverTodayString();
    const start = cfg.startDate || today;
    const dur = Math.max(1, parseInt(cfg.durationDays, 10) || 1);
    const expire = addDaysToDateString(start, dur); // 生效区间 [start, expire)
    if (today < start || today >= expire) {
        return res.json({ enabled: false, expired: true });
    }
    res.json({
        enabled: true,
        type: VALID_DAILY_TYPES.includes(cfg.type) ? cfg.type : 'speed',
        level: parseInt(cfg.level, 10) || 0, // 0 = 客户端按日期自动
        durationDays: dur,
        startDate: start,
        expiresOn: expire,
        rewards: (cfg.rewards && (cfg.rewards.coins > 0 || cfg.rewards.stars > 0))
            ? { coins: parseInt(cfg.rewards.coins, 10) || 0, stars: parseInt(cfg.rewards.stars, 10) || 0 }
            : null
    });
});

// 管理接口：保存每日挑战自定义配置（需管理员令牌）
app.put('/api/admin/daily-challenge', requireAdminAuth, async (req, res) => {
    try {
        const b = req.body || {};
        const enabled = b.enabled === true;
        const type = VALID_DAILY_TYPES.includes(b.type) ? b.type : (dailyChallengeConfig.type || 'speed');
        const level = Math.max(0, parseInt(b.level, 10) || 0);
        const durationDays = Math.max(1, Math.min(365, parseInt(b.durationDays, 10) || 1));
        const startDate = (typeof b.startDate === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(b.startDate))
            ? b.startDate
            : serverTodayString();
        let rewards = null;
        if (b.rewards && (parseInt(b.rewards.coins, 10) > 0 || parseInt(b.rewards.stars, 10) > 0)) {
            rewards = {
                coins: Math.max(0, parseInt(b.rewards.coins, 10) || 0),
                stars: Math.max(0, parseInt(b.rewards.stars, 10) || 0)
            };
        }
        dailyChallengeConfig = {
            enabled: enabled,
            type: type,
            level: level,
            durationDays: durationDays,
            startDate: startDate,
            rewards: rewards,
            createdAt: new Date().toISOString(),
            createdBy: (req.admin && (req.admin.name || req.admin.role)) || 'admin'
        };
        await saveDailyChallengeConfig();
        appendAudit('admin', 'daily-challenge-edit', `编辑每日挑战: type=${type}, level=${level}, duration=${durationDays}天, enabled=${enabled}`);
        console.log('[Admin] 每日挑战配置已保存:', dailyChallengeConfig);
        res.json({ success: true, message: '每日挑战配置已保存', config: Object.assign({}, dailyChallengeConfig) });
    } catch (error) {
        console.error('[API] 保存每日挑战配置失败:', error);
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

// 公开接口：被封禁的账户列表，供游戏客户端「反作弊」标签页展示
// 数据源统一为 ban_history：包含已解封与未解封的全部记录，按「封禁时间」过滤最近 10 天，
// 状态字段 status: 'unbanned'（已解封）| 'active'（未解封·生效中）| 'expired'（未解封·已到期）
app.get('/api/public/recent-bans', async (req, res) => {
    try {
        if (!antiCheatEnabled()) return res.status(403).json({ success: false, message: '反作弊功能已关闭' });
        const TEN_DAYS = 10 * 24 * 3600 * 1000;
        const cutoff = Date.now() - TEN_DAYS;
        const list = await dbGetBanHistory();
        const bans = [];
        for (const rec of list) {
            const bannedT = rec.bannedAt ? Date.parse(rec.bannedAt) : 0;
            if (isNaN(bannedT) || bannedT < cutoff) continue; // 仅展示最近 10 天内的封禁
            const unbanned = !!(rec.unbannedAt && !isNaN(Date.parse(rec.unbannedAt)));
            let status;
            if (unbanned) status = 'unbanned';
            else if (rec.expiresAt && !isNaN(Date.parse(rec.expiresAt)) && Date.parse(rec.expiresAt) <= Date.now()) status = 'expired';
            else status = 'active';
            const isIp = rec.type === 'ip';
            bans.push({
                type: rec.type,
                target: isIp ? maskIP(rec.target) : rec.target,
                // 注意：公开接口只返回脱敏后的 target，绝不返回未脱敏的原始 IP（rawTarget 已移除）
                username: rec.username || null,
                clientId: rec.clientId || null,
                reason: rec.reason || '',
                bannedAt: rec.bannedAt || '',
                expiresAt: rec.expiresAt || null,
                unbannedAt: rec.unbannedAt || null,
                unbannedBy: rec.unbannedBy || null,
                permanent: !rec.expiresAt,
                status: status,
                term: status === 'unbanned' ? '已解封' : (status === 'expired' ? '已到期' : describeIPBan({ expiresAt: rec.expiresAt }))
            });
        }
        // 按封禁时间倒序（最新在前）
        bans.sort((x, y) => String(y.bannedAt).localeCompare(String(x.bannedAt)));
        res.json({ success: true, bans });
    } catch (e) {
        console.error('[recent-bans] 失败:', e);
        res.status(500).json({ success: false, message: '查询失败' });
    }
});

// ===== 封禁申诉（玩家从客户端反作弊标签页提交，管理员在后台查看并一键解封）=====
const BAN_APPEALS_FILE = path.join(DATA_DIR, 'ban-appeals.json');
const banAppeals = new Map(); // id -> { id, clientId, username, banType, target, message, status, createdAt, handledBy, handledAt }

function loadBanAppeals() {
    try {
        if (fs.existsSync(BAN_APPEALS_FILE)) {
            const arr = JSON.parse(fs.readFileSync(BAN_APPEALS_FILE, 'utf8'));
            if (Array.isArray(arr)) arr.forEach(a => { if (a && a.id) banAppeals.set(a.id, a); });
        }
    } catch (e) { console.error('[申诉] 载入失败:', e.message); }
}
function saveBanAppealsJson() {
    try { fs.writeFileSync(BAN_APPEALS_FILE, JSON.stringify(Array.from(banAppeals.values()), null, 2)); }
    catch (e) { console.error('[申诉] 写入失败:', e.message); }
}
async function dbSaveAppeal(rec) {
    if (!rec || !rec.id) return;
    banAppeals.set(rec.id, rec);
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query(
                'INSERT INTO ban_appeals (id, client_id, username, ban_type, target, message, status, created_at) VALUES (?,?,?,?,?,?,?,?) ' +
                'ON DUPLICATE KEY UPDATE status=VALUES(status), message=VALUES(message)',
                [rec.id, rec.clientId || null, rec.username || null, rec.banType, rec.target, rec.message || '', rec.status || 'pending', rec.createdAt || '']
            );
            return;
        } catch (e) { console.error('[申诉] DB 写入失败:', e.message); }
    }
    saveBanAppealsJson();
}
async function dbGetAppeals() {
    if (DB_AVAILABLE && pool) {
        try {
            const [rows] = await pool.query(
                "SELECT * FROM ban_appeals ORDER BY (status='pending') DESC, created_at DESC"
            );
            if (rows && rows.length) return rows.map(r => ({
                id: r.id, clientId: r.client_id || null, username: r.username || null,
                banType: r.ban_type, target: r.target, message: r.message || '', status: r.status || 'pending',
                createdAt: r.created_at, handledBy: r.handled_by || null, handledAt: r.handled_at || null
            }));
        } catch (e) { console.error('[申诉] DB 读取失败:', e.message); }
    }
    return Array.from(banAppeals.values())
        .sort((a, b) => {
            if ((a.status === 'pending') !== (b.status === 'pending')) return a.status === 'pending' ? -1 : 1;
            return String(b.createdAt).localeCompare(String(a.createdAt));
        });
}
async function dbResolveAppeal(id, handledBy) {
    const rec = banAppeals.get(String(id));
    if (rec) { rec.status = 'resolved'; rec.handledBy = handledBy || 'admin'; rec.handledAt = new Date().toISOString(); }
    if (DB_AVAILABLE && pool) {
        try {
            await pool.query(
                "UPDATE ban_appeals SET status='resolved', handled_by=?, handled_at=? WHERE id=?",
                [handledBy || 'admin', new Date().toISOString(), String(id)]
            );
        } catch (e) { console.error('[申诉] DB 更新失败:', e.message); }
    }
    saveBanAppealsJson();
    return rec;
}

// 公开接口：玩家提交封禁申诉（无需鉴权）。banType: 'ip' | 'cloud'；target: IP 或云账号用户名
app.post('/api/public/ban-appeal', async (req, res) => {
    try {
        const b = req.body || {};
        const banType = String(b.banType || '').slice(0, 16);
        let target = String(b.target || '').slice(0, 128);
        const message = String(b.message || '').trim().slice(0, 1000);
        const clientId = String(b.clientId || '').slice(0, 64);
        const username = String(b.username || '').slice(0, 128) || null;
        if (banType !== 'ip' && banType !== 'cloud') return res.status(400).json({ success: false, message: '申诉类型无效' });
        // IP 申诉：客户端未携带封禁对象时，回退到请求方自身 IP（与 banned_ips 记录一致），
        // 避免「缺少封禁对象」报错导致玩家无法申诉自己的 IP 封禁。
        if (banType === 'ip' && !target) {
            const reqIp = getClientIp(req);
            if (reqIp) { target = reqIp; console.log(`[申诉] 客户端未传 target，回退使用请求 IP ${reqIp}`); }
        }
        if (!target) return res.status(400).json({ success: false, message: '缺少封禁对象' });
        if (message.length < 3) return res.status(400).json({ success: false, message: '申诉说明至少 3 个字' });
        const id = 'ap_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
        await dbSaveAppeal({
            id, clientId, username, banType, target, message,
            status: 'pending', createdAt: new Date().toISOString()
        });
        console.log(`[申诉] 收到 ${banType} 申诉：target=${target}，clientId=${clientId || '未知'}`);
        res.json({ success: true, message: '申诉已提交，管理员审核通过后可解封' });
    } catch (e) {
        console.error('[申诉] 提交失败:', e);
        res.status(500).json({ success: false, message: '提交失败' });
    }
});

// 管理端接口：查看全部申诉（待处理在前）
app.get('/api/admin/ban-appeals', requireAdminAuth, async (req, res) => {
    try {
        const list = await dbGetAppeals();
        res.json({ success: true, appeals: list });
    } catch (e) {
        res.status(500).json({ success: false, message: '查询失败' });
    }
});

// 管理端接口：处理申诉并一键解封（解封对应封禁，写入 SQL，标记申诉为已处理）
app.post('/api/admin/ban-appeals/:id/resolve', requireAdminAuth, async (req, res) => {
    try {
        const id = req.params.id;
        const rec = await dbGetAppeals().then(list => list.find(a => a.id === String(id)));
        if (!rec) return res.status(404).json({ success: false, message: '申诉记录不存在' });
        if (rec.status === 'resolved') return res.json({ success: true, alreadyResolved: true, message: '该申诉已处理' });
        // 一键解封：依据类型解除对应封禁
        let unbanMsg = '';
        if (rec.banType === 'ip') {
            await removeIPBan(rec.target, 'appeal');
            unbanMsg = `已解封 IP ${rec.target}`;
        } else if (rec.banType === 'cloud') {
            const acc = await dbGetCloudAccount(rec.target);
            if (acc) {
                acc.disabled = 0; acc.banned_until = null; acc.updated_at = new Date().toISOString();
                await dbSaveCloudAccount(acc);
                await dbUpdateBanHistoryUnban('cloud', rec.target, handler);
                // 退登其全部已登录设备
                try { await dbDeleteCloudSessionsByUser(rec.target); } catch (e) {}
                unbanMsg = `已解封云储存账号 ${rec.target}`;
            } else {
                unbanMsg = '云账号不存在（可能已删除）';
            }
        }
        const handler = (req.admin && req.admin.name) ? req.admin.name : 'admin';
        await dbResolveAppeal(id, handler);
        appendAudit('admin', 'appeal-resolve', `处理封禁申诉（${rec.banType}：${rec.target}）${unbanMsg}，${handler}`, req);
        res.json({ success: true, message: unbanMsg + '，申诉已标记为已处理' });
    } catch (e) {
        console.error('[申诉] 处理失败:', e);
        res.status(500).json({ success: false, message: '处理失败' });
    }
});

loadBanAppeals();

// IP 简单脱敏：IPv4 保留前两位，后两位替换为 x.x；IPv6 保留前 4 段
function maskIP(ip) {
    if (!ip || typeof ip !== 'string') return '';
    if (ip.indexOf(':') !== -1) {
        const parts = ip.split(':');
        if (parts.length > 4) return parts.slice(0, 4).join(':') + ':xxxx:xxxx';
        return ip;
    }
    const parts = ip.split('.');
    if (parts.length === 4) return parts[0] + '.' + parts[1] + '.x.x';
    return ip.replace(/\d+\.\d+$/, 'x.x');
}

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
            // 先通知被踢玩家（事件名 kicked-by-admin，客户端收到后会自行停止重连并清理多人状态）
            playerSocket.emit('kicked-by-admin', { message: '你已被管理员踢出。' });
            // 延迟断开，确保上面这条事件已送达客户端后再关连接；
            // 否则 disconnect(true) 会立即销毁 socket，事件可能来不及 flush，客户端永远收不到、也就不会停止重连。
            setTimeout(() => { try { playerSocket.disconnect(true); } catch (_) {} }, 500);
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
// 服务端迷宫生成（递归回溯，生成完美迷宫；编码：0通路 1墙 2起点 3终点）
function generateServerMaze(size) {
    size = parseInt(size);
    if (isNaN(size)) size = 15;
    size = Math.max(7, Math.min(41, size));
    if (size % 2 === 0) size += 1; // 必须为奇数，保证网格对齐
    const grid = Array.from({ length: size }, () => Array(size).fill(1)); // 初始全为墙
    const stack = [[1, 1]];
    grid[1][1] = 0;
    const dirs = [[0, -2], [0, 2], [-2, 0], [2, 0]];
    while (stack.length) {
        const [y, x] = stack[stack.length - 1];
        const nbrs = [];
        for (const [dy, dx] of dirs) {
            const ny = y + dy, nx = x + dx;
            if (ny > 0 && ny < size - 1 && nx > 0 && nx < size - 1 && grid[ny][nx] === 1) nbrs.push([ny, nx, dy, dx]);
        }
        if (nbrs.length === 0) { stack.pop(); continue; }
        const [ny, nx, dy, dx] = nbrs[Math.floor(Math.random() * nbrs.length)];
        grid[y + dy / 2][x + dx / 2] = 0; // 打通中间墙
        grid[ny][nx] = 0;
        stack.push([ny, nx]);
    }
    grid[1][1] = 2;                 // 起点
    grid[size - 2][size - 2] = 3;   // 终点
    return grid;
}

// 校验 admin 传入的自定义迷宫 JSON（2D 数字数组，编码同 multiplayer 迷宫）
function validateCustomMaze(maze) {
    if (!Array.isArray(maze) || maze.length < 3) return '迷宫必须是至少 3 行的二维数组';
    const h = maze.length;
    const w = Array.isArray(maze[0]) ? maze[0].length : 0;
    if (!w || w < 3) return '迷宫每一行必须是至少 3 列的数字数组';
    let hasStart = false, hasEnd = false;
    for (let y = 0; y < h; y++) {
        if (!Array.isArray(maze[y]) || maze[y].length !== w) return `第 ${y + 1} 行长度不一致（应为 ${w} 列）`;
        for (let x = 0; x < w; x++) {
            const v = maze[y][x];
            if (typeof v !== 'number' || !Number.isFinite(v) || v < 0 || v > 15) return `位置 (${y},${x}) 的值 ${v} 非法（需为 0~15 的整数）`;
            if (v === 2) hasStart = true;
            if (v === 3) hasEnd = true;
        }
    }
    if (!hasStart) return '迷宫缺少起点（编码 2）';
    if (!hasEnd) return '迷宫缺少终点（编码 3）';
    return null; // 校验通过
}

app.post('/api/admin/rooms/:roomId/change-map', requireAdminAuth, (req, res) => {
    try {
        const room = rooms.get(req.params.roomId);
        if (!room) return res.status(404).json({ success: false, message: '房间不存在' });
        const mode = (req.body && req.body.mode) || 'random';
        let newMaze;
        if (mode === 'json') {
            const raw = req.body.maze;
            const maze = Array.isArray(raw) ? raw : (raw && typeof raw === 'string' ? safeParseMaze(raw) : null);
            if (!maze) return res.status(400).json({ success: false, message: '缺少或无法解析 maze 字段（需为二维数字数组）' });
            const err = validateCustomMaze(maze);
            if (err) return res.status(400).json({ success: false, message: err });
            newMaze = maze;
        } else {
            // random：服务端直接生成完美迷宫，无需房主在线
            const size = req.body && req.body.size ? req.body.size : 15;
            newMaze = generateServerMaze(size);
        }
        room.maze = newMaze;
        room.lastActivity = Date.now();
        // 直接广播给房间内所有玩家（与房主 maze-generated 后广播的通道一致）
        io.to(room.id).emit('maze-updated', { maze: newMaze });
        console.log(`[Admin] 已为房间 ${room.id} 应用新地图（mode=${mode}，尺寸 ${newMaze.length}x${newMaze[0].length}）`);
        appendAudit('admin', 'change-map', `房间 ${room.id} 更换地图（mode=${mode}）`);
        res.json({ success: true, message: '已应用新地图并下发至房间内所有玩家', size: { w: newMaze[0].length, h: newMaze.length } });
    } catch (error) {
        console.error('[API] 更改地图失败:', error);
        res.status(500).json({ success: false, message: '操作失败' });
    }
});

// 安全解析迷宫 JSON 字符串（容错：提取数组）
function safeParseMaze(str) {
    try {
        const obj = JSON.parse(str);
        if (Array.isArray(obj)) return obj;
        if (obj && Array.isArray(obj.maze)) return obj.maze;
        return null;
    } catch (e) { return null; }
}

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
        const p = reportedProgress.get(userId) || { unlockedLevel: 1, completedLevels: [], puzzleCompletedLevels: [], customCompletedLevels: [], lastReportedAt: null };
        res.json({
            success: true,
            userId: userId,
            unlockedLevel: p.unlockedLevel || 1,
            completedLevels: Array.isArray(p.completedLevels) ? p.completedLevels : [],
            puzzleCompletedLevels: Array.isArray(p.puzzleCompletedLevels) ? p.puzzleCompletedLevels : [],
            customCompletedLevels: Array.isArray(p.customCompletedLevels) ? p.customCompletedLevels : [],
            lastReportedAt: p.lastReportedAt || null,
            maxSingle: 80,
            maxPuzzle: 60,
            maxCustom: 60
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
        if (!/^(single|puzzle|custom):\d+$/.test(key || '')) {
            return res.status(400).json({ success: false, message: 'key 格式应为 single:N / puzzle:N / custom:N' });
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
        // 自定义关卡 1..MAX_PUZZLE_LEVEL 全部完成
        const customCompletedLevels = [];
        for (let i = 1; i <= MAX_PUZZLE_LEVEL; i++) customCompletedLevels.push(i);

        mergeProgress(userId, { unlockedLevel: MAX_SINGLE_LEVEL, completedLevels, puzzleCompletedLevels, customCompletedLevels });

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
            puzzleCompletedLevels: puzzleCompletedLevels,
            customCompletedLevels: customCompletedLevels
        });
        console.log(`[Admin] 已将 ${userId} 单人 / 解密 / 自定义全部通关，并授予 迷宫大师 + 解密高手`);
        appendAudit('admin', 'complete-all', `将 ${userId} 单人/解密/自定义全部通关`);
        res.json({ success: true, message: `已将 ${userId} 单人、解密、自定义全部通关`, achievements: cur });
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


// ===== 服务器异常与运行日志查看（admin 后台）=====
app.get('/api/admin/server-errors', requireAdminAuth, (req, res) => {
    res.json({
        success: true,
        errors: serverErrors.slice().reverse(),   // 新 -> 旧
        recentLogs: recentLogs.slice().reverse(), // 新 -> 旧
        dbAvailable: DB_AVAILABLE,
        uptime: process.uptime(),
        serverTime: new Date().toISOString()
    });
});
app.delete('/api/admin/server-errors', requireAdminAuth, (req, res) => {
    serverErrors = [];
    recentLogs = [];
    try { if (fs.existsSync(SERVER_ERRORS_FILE)) fs.writeFileSync(SERVER_ERRORS_FILE, ''); } catch (_) {}
    appendAudit('admin', 'clear-server-errors', '清空了全部服务端报错与运行日志', req);
    res.json({ success: true, message: '已清空服务器报错与日志' });
});
// 全局请求级错误兜底：捕获路由内未处理的异常，避免进程崩溃并记入日志
app.use((err, req, res, next) => {
    recordServerError('request', err);
    if (!res.headersSent) res.status(500).json({ success: false, message: '服务器内部错误，已记录' });
});

// 在服务器启动时初始化管理员密码
console.log('🚀 正在初始化服务器...');
initializeAdminPassword();
initializeSuperAdminPassword();

const PORT = process.env.PORT || 234;
// 先监听，保证 onrender 等平台的健康检查能立即通过；数据库初始化与数据加载放到后台异步进行，
// 避免 MySQL 不可达/缓慢时阻塞启动（否则 onrender 会因启动超时判定为“运行报错”）。
server.listen(PORT, () => {
    console.log(`\n✅ 服务器运行在 http://localhost:${PORT}`);
    console.log(`📊 服务器状态: http://localhost:${PORT}/api/server-status`);
    console.log(`🏠 房间列表: http://localhost:${PORT}/api/rooms`);
    console.log(`👤 创建房间: http://localhost:${PORT}/api/create-room`);
    console.log(`Socket.IO 服务已启动\n`);
});

(async () => {
    loadServerErrorsFromFile();   // 恢复重启前记录的异常
    await initDatabase();
    loadAdminState();
    await loadUserRoles();
    await loadUserSettings();
    await loadGlobalFunctions();
    await loadDailyChallengeConfig();
    await loadAccounts();
    await loadHomeProfiles();
    loadFriends();             // 好友请求 / 好友关系 / 私聊记录（JSON 文件持久化）
    await loadMazes();         // DB 模式下从 popular_mazes 表载入热门迷宫到内存（与全局配置同模式）
})().catch(e => console.error('[Init] 后台初始化失败:', e));
