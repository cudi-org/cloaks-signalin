const WebSocket = require('ws');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const { URL } = require('url');

const PORT = process.env.PORT || 8080;
const MAX_CONNECTIONS_PER_IP = parseInt(process.env.MAX_CONNECTIONS_PER_IP, 10) || 20;
const MAX_MESSAGES_PER_SECOND = parseInt(process.env.MAX_MESSAGES_PER_SECOND, 10) || 50;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_for_dev_only';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 12;
const MAX_MESSAGE_SIZE = 64 * 1024; 
const HEARTBEAT_INTERVAL = 30000;

const wss = new WebSocket.Server({ port: PORT });

const appClients = new Map();
const cloakRooms = new Map();
const connectionsPerIP = new Map();
const pendingMatches = new Map();

const messageSchema = Joi.object({
    type: Joi.string().required(),
    appType: Joi.string().required()
}).unknown(true);

function heartbeat() { this.isAlive = true; }

function generateSecureId() {
    return crypto.randomBytes(16).toString('hex');
}

function generatePeerToken(peerId) {
    return jwt.sign(
        { peerId, iat: Math.floor(Date.now() / 1000) },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
}

async function validateMessage(data) {
    try {
        const { error, value } = await messageSchema.validateAsync(data);
        return error ? null : value;
    } catch (e) {
        return null;
    }
}

wss.on('connection', (ws, req) => {
    const ip = req.socket.remoteAddress;
    const currentIPCount = (connectionsPerIP.get(ip) || 0) + 1;
    
    if (currentIPCount > MAX_CONNECTIONS_PER_IP) return ws.terminate();
    connectionsPerIP.set(ip, currentIPCount);

    ws.isAlive = true;
    ws.id = generateSecureId();
    ws.msgCount = 0;
    ws.msgTs = Date.now();
    ws.on('pong', heartbeat);

    ws.on('message', async message => {
        const now = Date.now();
        if (now - ws.msgTs > 1000) { 
            ws.msgTs = now; 
            ws.msgCount = 0; 
        }
        if (++ws.msgCount > MAX_MESSAGES_PER_SECOND) return ws.close(1011);

        try {
            const messageString = message.toString();
            if (messageString.length > MAX_MESSAGE_SIZE) return ws.close(1009);
            
            const rawData = JSON.parse(messageString);
            
            if (rawData.type === 'ping') return;

            const data = await validateMessage(rawData);

            if (!data) {
                return ws.send(JSON.stringify({ 
                    type: 'error', 
                    message: 'DEBUG: Joi rejected this message' 
                }));
            }

            if (data.appType === 'cloaks' || data.appType === 'cudi-sync') {
                await handleCloakLogic(ws, data, messageString);
            } else if (data.appType === 'cudi-messenger') {
                handleMessengerLogic(ws, data, messageString);
            }
        } catch (e) {
            return;
        }
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
            ws.id = data.permanentId || data.peerId || ws.id;
            
            const sanitizedAlias = (data.alias || 'Cloaker')
                .slice(0, 32)
                .replace(/[<>\"'`]/g, '');

            if (!cloakRooms.has(data.room)) {
                let passwordHash = data.password ? await bcrypt.hash(data.password, BCRYPT_ROUNDS) : null;
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
            ws.alias = sanitizedAlias;
            ws.peerToken = generatePeerToken(ws.id);
            room.clients.add(ws);

            const peersInRoom = Array.from(room.clients)
                .filter(c => c !== ws)
                .map(c => ({ id: c.id, alias: c.alias }));

            ws.send(JSON.stringify({ 
                type: 'joined', 
                room: data.room, 
                yourId: ws.id,
                token: ws.peerToken,
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
                ws.id = data.peerId;
                ws.peerToken = generatePeerToken(data.peerId);
                
                ws.send(JSON.stringify({ 
                    type: 'registered', 
                    peerId: data.peerId,
                    token: ws.peerToken
                }));
                
                wss.clients.forEach(client => {
                    if (client.searchingFor === data.peerId) {
                        client.send(JSON.stringify({ type: 'peer_found', peerId: data.peerId }));
                        ws.send(JSON.stringify({ type: 'peer_found', peerId: client.peerId || client.id }));
                        client.searchingFor = null;
                    }
                });

                if (pendingMatches.has(data.peerId)) {
                    const requesterWs = pendingMatches.get(data.peerId);
                    if (requesterWs.readyState === WebSocket.OPEN) {
                        requesterWs.send(JSON.stringify({ type: 'peer_found', peerId: data.peerId }));
                        ws.send(JSON.stringify({ type: 'peer_found', peerId: requesterWs.peerId || requesterWs.id }));
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
                    ws.searchingFor = data.targetPeerId;
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
                    forwardData.fromPeerId = ws.peerId || ws.id;
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
    const currentId = ws.peerId || ws.id;
    if (currentId && appClients.has('cudi-messenger')) {
        appClients.get('cudi-messenger').delete(currentId);
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
