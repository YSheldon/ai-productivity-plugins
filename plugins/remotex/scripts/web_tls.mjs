import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import {createHash, timingSafeEqual, X509Certificate} from 'node:crypto';
import {privateIntentFrame,withInitializationIntent,verifyInitializationCookieContext} from './web_outgoing_intent.mjs';

const HOP_HEADERS = new Set(['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade']);
const MAX_BODY = 32 * 1024 * 1024;

function verifyPeer(socket, pin) {
  if(pin===undefined){
    if(!socket.authorized)throw new Error('tls-or-navigation-failed');
    return;
  }
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

class GuardedAgent extends https.Agent {
  constructor(url, pin, beforeSend) {
    super({keepAlive:false,maxCachedSessions:0});
    this.endpoint = url;
    this.pin = pin;
    this.beforeSend=beforeSend;
    this.ownedSockets = new Set();
  }

  createConnection(_options, callback) {
    const host = this.endpoint.hostname.replace(/^\[|\]$/g,''), port = Number(this.endpoint.port || 443);
    const socket = tls.connect({host,port,servername:net.isIP(host)?undefined:host,
      rejectUnauthorized:this.pin===undefined,minVersion:'TLSv1.2',ALPNProtocols:['http/1.1'],
      ...(this.pin===undefined?{checkServerIdentity:(_name,cert)=>tls.checkServerIdentity(host,cert)}:{})});
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
    socket.once('secureConnect',async()=>{
      try {
        verifyPeer(socket,this.pin);
        await this.beforeSend?.();
        if(socket.destroyed)throw new Error('tls-or-navigation-failed');
        finish(null);
      }
      catch(error) {finish(error);}
    });
    // Do not return the socket: HTTP may attach only after pin/validity verification.
  }

  destroy() {
    for (const socket of this.ownedSockets) socket.destroy();
    super.destroy();
  }
}

export function pinnedResponse(request, origin, pin, signal, options={}) {
  if(typeof pin!=='string'||!/^[a-f0-9]{64}$/.test(pin))throw new Error('invalid-job');
  return guardedResponse(request,origin,pin,signal,options);
}

export function initializationResponse(request,origin,pin,signal,deadline,beforeSend){
  return guardedResponse(request,origin,pin,signal,{deadline,beforeSend,maxBody:65536,initialization:true});
}

export async function initializationIntentResponse(intent,origin,pin,signal,deadline,beforeSend){
  return withInitializationIntent(intent,frozen=>{
    const url=new URL(frozen.url);
    if(url.origin!==origin||url.protocol!=='https:'||url.username||url.password)throw new Error('origin-blocked');
    const check=async()=>{
      await verifyInitializationCookieContext(intent);
      await beforeSend?.();
      const frame=privateIntentFrame(intent);
      if(frame.body_b64!==frozen.body.toString('base64'))throw new Error('scope-mismatch');
    };
    return sendSnapshot(url,frozen.method,frozen.headers,frozen.body,pin,signal,
      {deadline,beforeSend:check,maxBody:65536,initialization:true});
  });
}

export async function guardedResponse(request, origin, pin, signal, options={}) {
  const url = new URL(request.url());
  if (url.protocol !== 'https:' || url.origin !== origin || url.username || url.password) throw new Error('origin-blocked');
  if (pin!==undefined&&(typeof pin !== 'string' || !/^[a-f0-9]{64}$/.test(pin))) throw new Error('invalid-job');
  const body = request.postDataBuffer();
  if (body && body.length > 1024 * 1024) throw new Error('request-too-large');
  const headers = Object.fromEntries(Object.entries(await request.allHeaders()).filter(([key])=>!HOP_HEADERS.has(key.toLowerCase())));
  if (signal?.aborted) throw new Error('tls-or-navigation-failed');
  headers.host = url.host;
  headers['accept-encoding'] = 'identity';
  if (body) headers['content-length'] = String(body.length);
  else delete headers['content-length'];
  return sendSnapshot(url,request.method(),headers,body,pin,signal,options);
}

async function sendSnapshot(url,method,headers,body,pin,signal,options){
  if(pin!==undefined&&(typeof pin!=='string'||!/^[a-f0-9]{64}$/.test(pin)))throw new Error('invalid-job');
  if(signal?.aborted)throw new Error('tls-or-navigation-failed');
  const maxBody=Math.min(MAX_BODY,options.maxBody??MAX_BODY);
  if(!Number.isSafeInteger(maxBody)||maxBody<1)throw new Error('invalid-job');
  const remaining=options.deadline===undefined?20000:Math.min(20000,options.deadline-Date.now());
  if(!Number.isFinite(remaining)||remaining<=0)throw new Error('scope-mismatch');
  const agent = new GuardedAgent(url,pin,options.beforeSend);
  const abort = () => agent.destroy();
  signal?.addEventListener('abort',abort,{once:true});
  let timer;
  try {
    return await new Promise((resolve,reject)=>{
      const outgoing = https.request(url,{agent,method,headers,signal},response=>{
        if(options.initialization){
          const rawNames=response.rawHeaders.filter((_,index)=>index%2===0).map(name=>name.toLowerCase());
          const critical=['content-type','content-length','set-cookie','www-authenticate','proxy-authenticate'];
          const rejected=response.statusCode<200||response.statusCode>=300||
            critical.some(name=>rawNames.filter(value=>value===name).length>1)||
            ['set-cookie','www-authenticate','proxy-authenticate','authentication-info','proxy-authentication-info','location','upgrade']
              .some(name=>Object.hasOwn(response.headers,name))||
            (response.headers['content-encoding']&&response.headers['content-encoding'].toLowerCase()!=='identity');
          if(rejected){const error=new Error('initialization-response-rejected');reject(error);outgoing.destroy(error);return;}
        }
        const chunks = [];let bytes = 0;
        response.on('data',chunk=>{
          bytes += chunk.length;
          if (bytes > maxBody) {const error=new Error('response-too-large');reject(error);outgoing.destroy(error);return;}
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
      timer = setTimeout(()=>{agent.destroy();outgoing.destroy(new Error('tls-or-navigation-failed'));},remaining);
      outgoing.end(body || undefined);
    });
  } finally {clearTimeout(timer);signal?.removeEventListener('abort',abort);agent.destroy();}
}
