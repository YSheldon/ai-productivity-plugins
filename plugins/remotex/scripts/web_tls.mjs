import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import {createHash, timingSafeEqual, X509Certificate} from 'node:crypto';

const HOP_HEADERS = new Set(['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade']);
const MAX_BODY = 32 * 1024 * 1024;

function verifyPeer(socket, pin) {
  const raw = socket.getPeerCertificate()?.raw;
  if (!raw || !timingSafeEqual(createHash('sha256').update(raw).digest(), Buffer.from(pin,'hex'))) {
    throw new Error('certificate-pin-mismatch');
  }
  const certificate = new X509Certificate(raw), now = Date.now();
  const start = Date.parse(certificate.validFrom), end = Date.parse(certificate.validTo);
  if (!Number.isFinite(start) || !Number.isFinite(end) || now < start || now > end) {
    throw new Error('certificate-validity-failed');
  }
}

class PinnedAgent extends https.Agent {
  constructor(url, pin) {
    super({keepAlive:false,maxCachedSessions:0});
    this.endpoint = url;
    this.pin = pin;
    this.ownedSockets = new Set();
  }

  createConnection(_options, callback) {
    const host = this.endpoint.hostname.replace(/^\[|\]$/g,''), port = Number(this.endpoint.port || 443);
    const socket = tls.connect({host,port,servername:net.isIP(host)?undefined:host,
      rejectUnauthorized:false,minVersion:'TLSv1.2',ALPNProtocols:['http/1.1']});
    this.ownedSockets.add(socket);
    let completed = false;
    const finish = (error) => {
      if (completed) return;
      completed = true;
      if (error) socket.destroy();
      callback(error, error ? undefined : socket);
    };
    socket.once('close',()=>{this.ownedSockets.delete(socket);finish(new Error('tls-or-navigation-failed'));});
    socket.once('error',()=>finish(new Error('tls-or-navigation-failed')));
    socket.once('secureConnect',()=>{
      try {verifyPeer(socket,this.pin);finish(null);}
      catch(error) {finish(error);}
    });
    // Do not return the socket: HTTP may attach only after pin/validity verification.
  }

  destroy() {
    for (const socket of this.ownedSockets) socket.destroy();
    super.destroy();
  }
}

export async function pinnedResponse(request, origin, pin, signal) {
  const url = new URL(request.url());
  if (url.protocol !== 'https:' || url.origin !== origin || url.username || url.password) throw new Error('origin-blocked');
  if (typeof pin !== 'string' || !/^[a-f0-9]{64}$/.test(pin)) throw new Error('invalid-job');
  const body = request.postDataBuffer();
  if (body && body.length > 1024 * 1024) throw new Error('request-too-large');
  const headers = Object.fromEntries(Object.entries(await request.allHeaders()).filter(([key])=>!HOP_HEADERS.has(key.toLowerCase())));
  if (signal?.aborted) throw new Error('tls-or-navigation-failed');
  headers.host = url.host;
  headers['accept-encoding'] = 'identity';
  if (body) headers['content-length'] = String(body.length);
  else delete headers['content-length'];
  const agent = new PinnedAgent(url,pin);
  const abort = () => agent.destroy();
  signal?.addEventListener('abort',abort,{once:true});
  let timer;
  try {
    return await new Promise((resolve,reject)=>{
      const outgoing = https.request(url,{agent,method:request.method(),headers,signal},response=>{
        const chunks = [];let bytes = 0;
        response.on('data',chunk=>{
          bytes += chunk.length;
          if (bytes > MAX_BODY) {outgoing.destroy(new Error('response-too-large'));return;}
          chunks.push(chunk);
        });
        response.once('error',()=>reject(new Error('tls-or-navigation-failed')));
        response.once('end',()=>{
          const blocked = new Set([...HOP_HEADERS,...String(response.headers.connection||'').toLowerCase().split(',').map(s=>s.trim())]);
          const resultHeaders = {};
          for (const [key,value] of Object.entries(response.headers)) {
            if (blocked.has(key) || value === undefined) continue;
            resultHeaders[key] = Array.isArray(value) ? value.join(key==='set-cookie'?'\n':', ') : value;
          }
          resultHeaders['content-length'] = String(bytes);
          resolve({status:response.statusCode,headers:resultHeaders,body:Buffer.concat(chunks)});
        });
      });
      outgoing.once('error',reject);
      timer = setTimeout(()=>{agent.destroy();outgoing.destroy(new Error('tls-or-navigation-failed'));},20000);
      outgoing.end(body || undefined);
    });
  } finally {clearTimeout(timer);signal?.removeEventListener('abort',abort);agent.destroy();}
}
