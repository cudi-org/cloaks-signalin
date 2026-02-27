const WebSocket = require('ws');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

const PORT = process.env.PORT || 8080;
const wss = new WebSocket.Server({ port: PORT });

const appClients = new Map();
const cloakRooms = new Map();
const connectionsPerIP = new Map();
const pendingMatches = new Map();

const MAX_MESSAGE_SIZE = 64 * 1024; 
const HEARTBEAT_INTERVAL = 30000;

function heartbeat() { this.isAlive = true; }

wss.on('connection', (ws, req) => {
    const ip = req.socket.remoteAddress;
    const currentIPCount = (connectionsPerIP.get(ip) || 0) + 1;
    if (currentIPCount > 20) return ws.terminate();
    connectionsPerIP.set(ip, currentIPCount);

    ws.isAlive = true;
    ws.id = crypto.randomBytes(4).toString('hex');
    ws.msgCount = 0;
    ws.msgTs = Date.now();
    ws.on('pong', heartbeat);

    ws.on('message', async message => {
        const now = Date.now();
        if (now - ws.msgTs > 1000) { 
            ws.msgTs = now; 
            ws.msgCount = 0; 
        }
        if (++ws.msgCount > 50) return ws.close(1011);

        try {
            const messageString = message.toString();
            if (messageString.length > MAX_MESSAGE_SIZE) return ws.close(1009);
            const data = JSON.parse(messageString);

            if (data.appType === 'cloaks' || data.appType === 'cudi-sync') {
                await handleCloakLogic(ws, data, messageString);
            } else if (data.appType === 'cudi-messenger') {
                handleMessengerLogic(ws, data, messageString);
            }
        } catch (e) { return; }
    });

    ws.on('close', () => {
        const count = connectionsPerIP.get(ip) - 1;
        if (count <= 0) connectionsPerIP.delete(ip);
        else connectionsPerIP.set(ip, count);
        limpiarRecursos(ws);
    });
});

async function handleCloakLogic(ws, data, messageString) {
    switch (data.type) {
        case 'join':
            if (!data.room) return;
            if (!cloakRooms.has(data.room)) {
                let passwordHash = data.password ? await bcrypt.hash(data.password, 8) : null;
                cloakRooms.set(data.room, {
                    clients: new Set(),
                    password: passwordHash,
                    createdAt: Date.now()
                });
            }
            const room = cloakRooms.get(data.room);
            if (room.password) {
                if (!data.password) return ws.send(JSON.stringify({ type: 'error', message: 'Password required' }));
                const match = await bcrypt.compare(data.password, room.password);
                if (!match) return ws.send(JSON.stringify({ type: 'error', message: 'Wrong password' }));
            }
            ws.room = data.room;
            ws.alias = data.alias || 'Cloaker';
            room.clients.add(ws);
            const peersInRoom = Array.from(room.clients)
                .filter(c => c !== ws)
                .map(c => ({ id: c.id, alias: c.alias }));
            ws.send(JSON.stringify({ 
                type: 'joined', 
                room: data.room, 
                yourId: ws.id,
                peers: peersInRoom 
            }));
            broadcastToRoom(data.room, { 
                type: 'peer_joined', 
                peerId: ws.id, 
                alias: ws.alias 
            }, ws);
            break;

        case 'signal':
            if (!ws.room) return;
            broadcastToRoom(ws.room, {
                ...data,
                fromPeerId: ws.id
            }, ws, data.targetPeerId);
            break;
    }
}

function broadcastToRoom(roomId, messageObj, sender, targetId = null) {
    const room = cloakRooms.get(roomId);
    if (!room) return;
    const msg = JSON.stringify(messageObj);
    room.clients.forEach(client => {
        if (client !== sender && client.readyState === WebSocket.OPEN) {
            if (targetId && client.id !== targetId) return;
            client.send(msg);
        }
    });
}

function handleMessengerLogic(ws, data, messageString) {
    if (!appClients.has('cudi-messenger')) appClients.set('cudi-messenger', new Map());
    const clients = appClients.get('cudi-messenger');
    
    switch (data.type) {
        case 'register':
            if (data.peerId) {
                clients.set(data.peerId, ws);
                ws.peerId = data.peerId;
                ws.send(JSON.stringify({ type: 'registered', peerId: data.peerId }));
                if (pendingMatches.has(data.peerId)) {
                    const requesterWs = pendingMatches.get(data.peerId);
                    if (requesterWs.readyState === WebSocket.OPEN) {
                        requesterWs.send(JSON.stringify({ type: 'peer_found', peerId: data.peerId }));
                        ws.send(JSON.stringify({ type: 'peer_found', peerId: requesterWs.peerId }));
                    }
                    pendingMatches.delete(data.peerId);
                }
            }
            break;

        case 'find_peer':
            if (data.targetPeerId) {
                if (clients.has(data.targetPeerId)) {
                    ws.send(JSON.stringify({ type: 'peer_found', peerId: data.targetPeerId }));
                } else {
                    pendingMatches.set(data.targetPeerId, ws);
                    setTimeout(() => {
                        if (pendingMatches.get(data.targetPeerId) === ws) pendingMatches.delete(data.targetPeerId);
                    }, 300000);
                }
            }
            break;

        case 'offer':
        case 'answer':
        case 'candidate':
            if (data.targetPeerId && clients.has(data.targetPeerId)) {
                const targetWs = clients.get(data.targetPeerId);
                if (targetWs.readyState === WebSocket.OPEN) {
                    const forwardData = JSON.parse(messageString);
                    forwardData.fromPeerId = ws.peerId;
                    targetWs.send(JSON.stringify(forwardData));
                }
            }
            break;
    }
}

function limpiarRecursos(ws) {
    if (ws.room && cloakRooms.has(ws.room)) {
        const room = cloakRooms.get(ws.room);
        room.clients.delete(ws);
        broadcastToRoom(ws.room, { type: 'peer_left', peerId: ws.id });
        if (room.clients.size === 0) cloakRooms.delete(ws.room);
    }
    if (ws.peerId && appClients.has('cudi-messenger')) {
        appClients.get('cudi-messenger').delete(ws.peerId);
        for (let [targetId, requesterWs] of pendingMatches) {
            if (requesterWs === ws) pendingMatches.delete(targetId);
        }
    }
}

const interval = setInterval(() => {
    wss.clients.forEach(ws => {
        if (!ws.isAlive) return ws.terminate();
        ws.isAlive = false;
        ws.ping();
    });
}, HEARTBEAT_INTERVAL);

wss.on('close', () => clearInterval(interval));
