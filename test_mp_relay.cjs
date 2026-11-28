// test_mp_relay.cjs —— WebSocket 联机中继端到端冒烟测试（不依赖真实 HTTP 服务）
// 用内存 stub 模拟 server.cjs 传给 mountMpRelay 的依赖，验证建房/加入/走位/聊天/踢人/断线交接。
const assert = require('assert');
const http = require('http');
const WebSocket = require('ws');
const mount = require('./server-mp-relay.cjs');

const rooms = new Map();
const roomChats = new Map();
const onlinePlayers = new Map();
const userBans = new Map();
const globalFunctions = { multiplayer: true, multiplayerChat: true };
let roomListBroadcasts = 0;
const sentSocketEvents = [];

const io = {
  on() {},
  to(roomId) { return { emit(ev, data) { sentSocketEvents.push({ roomId, ev, data }); } }; }
};
function generateRoomId() { return String(10000 + Math.floor(Math.random() * 90000)); }
function getRandomColor() { return '#4CAF50'; }
function getAllRoomsList() {
  return Array.from(rooms.values()).map(r => ({
    id: r.id, name: r.name, hostName: r.hostName,
    players: r.players.size, maxPlayers: r.maxPlayers,
    status: r.status, private: !!r.private, hasPassword: !!r.password
  }));
}
function broadcastRoomList() { roomListBroadcasts++; }

const server = http.createServer();
mount({
  app: {}, server, io, rooms, roomChats, players: new Map(), onlinePlayers,
  globalFunctions, userBans, clientIp: () => null, isIPBanned: () => false,
  generateRoomId, getRandomColor, getAllRoomsList, broadcastRoomList, WebSocket
});

function connect() {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket('ws://127.0.0.1:' + server.address().port + '/mp-relay');
    ws.messages = [];
    ws.on('message', d => ws.messages.push(JSON.parse(String(d))));
    ws.on('open', () => resolve(ws));
    ws.on('error', reject);
  });
}
function send(ws, msg) { ws.send(JSON.stringify(msg)); }
function wait(ms) { return new Promise(r => setTimeout(r, ms)); }
function last(ws, t) {
  const arr = ws.messages.filter(m => m.t === t);
  return arr[arr.length - 1];
}

(async () => {
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const host = await connect();
  send(host, { t: 'hello', clientId: 'client_A', name: '房主' });
  await wait(40);
  assert.ok(last(host, 'welcome'), 'welcome received');
  send(host, { t: 'create', rid: 'c1', name: '冒烟房', roomCode: 'smoke_room', maxPlayers: 4 });
  await wait(50);
  const created = last(host, 'joined');
  assert.ok(created && created.roomId === 'smoke_room', 'room created with custom code');
  assert.ok(created.isHost === true, 'creator is host');

  const guest = await connect();
  send(guest, { t: 'hello', clientId: 'client_B', name: '访客' });
  await wait(40);
  send(guest, { t: 'join', rid: 'j1', roomId: 'smoke_room' });
  await wait(60);
  const joined = last(guest, 'joined');
  assert.ok(joined && joined.roomId === 'smoke_room' && !joined.isHost, 'guest joined');
  assert.ok(last(host, 'player-joined'), 'host notified of join');

  const maze = Array.from({ length: 5 }, (_, y) =>
    Array.from({ length: 5 }, (_, x) => (x === 0 || y === 0 || x === 4 || y === 4 ? 1 : 0)));
  maze[1][1] = 2; maze[3][3] = 3;
  send(host, { t: 'maze', maze });
  await wait(50);
  assert.ok(last(guest, 'maze-updated') && last(guest, 'maze-updated').maze.length === 5, 'maze relayed');

  send(host, { t: 'start' });
  await wait(50);
  assert.ok(last(guest, 'game-started'), 'game start relayed');

  send(host, { t: 'move', x: 1, y: 2 });
  await wait(50);
  const mv = last(guest, 'player-move');
  assert.ok(mv && mv.x === 1 && mv.y === 2, 'move relayed');

  send(guest, { t: 'chat', rid: 'm1', messageId: 'msg_1', text: '你好房主' });
  await wait(50);
  assert.ok(last(host, 'chat') && last(host, 'chat').text === '你好房主', 'chat relayed');
  assert.ok(roomChats.get('smoke_room').length === 1, 'chat mirrored for admin');
  const tinyPng = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8AAAwAB/wF6WQAAAABJRU5ErkJggg==';
  send(guest, { t: 'image', rid: 'i1', messageId: 'img_1', image: tinyPng });
  await wait(50);
  assert.ok(last(host, 'image') && last(host, 'image').messageId === 'img_1', 'image relayed');
  assert.ok(roomChats.get('smoke_room').some(x => x.messageId === 'img_1' && x.image), 'image mirrored for admin');

  const tinyVoice = 'data:audio/mpeg;base64,SUQzBAAAAAAAI1RTU0UAAAAPAAADTGF2ZjU2LjQwLjEwMAAAAAAAAAAAAAAA//tQxAADBw';
  send(guest, { t: 'voice', rid: 'v1', messageId: 'voice_1', voice: tinyVoice, duration: 3 });
  await wait(50);
  assert.ok(last(host, 'voice') && last(host, 'voice').duration === 3, 'voice relayed');
  assert.ok(roomChats.get('smoke_room').some(x => x.messageId === 'voice_1'), 'voice mirrored for admin');


  send(guest, { t: 'pm', to: created.playerId, text: '私聊内容' });
  await wait(50);
  assert.ok(last(host, 'pm') && last(host, 'pm').text === '私聊内容', 'private message relayed');

  send(host, { t: 'kick', playerId: joined.playerId });
  await wait(80);
  assert.ok(last(guest, 'kicked'), 'guest kicked by host');
  assert.ok(!rooms.get('smoke_room').players.has(joined.playerId), 'kicked player removed from room');

  // 房主断线 → 房间里还有玩家则交接（当前没有，验证清理不报错）
  host.close(); guest.close();
  await wait(80);
  assert.ok(rooms.size >= 1, 'server still alive after disconnect');
  server.close();
  console.log('MP-RELAY SMOKE: ALL PASS');
})().catch(e => { console.error('MP-RELAY SMOKE FAILED:', e); process.exit(1); });
