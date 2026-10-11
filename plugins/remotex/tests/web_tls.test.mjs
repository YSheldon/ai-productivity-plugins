import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import tls from 'node:tls';
import {once} from 'node:events';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {X509Certificate} from 'node:crypto';
import {createRequire} from 'node:module';
import {guardRoute, launchEdge} from '../scripts/web_login_worker.mjs';
import * as worker from '../scripts/web_login_worker.mjs';

async function fixture(t, handler, handshakeGate) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'remotex-tls-test-'));
  const keyPath = path.join(directory, 'key.pem'), certPath = path.join(directory, 'cert.pem');
  t.after(() => fs.rm(directory, {recursive:true,force:true}));
  const configPath = path.join(directory, 'openssl.cnf');
  await fs.writeFile(configPath, '[req]\ndistinguished_name=dn\n[dn]\n');
  execFileSync(process.env.REMOTEX_TEST_OPENSSL || 'openssl', [
    'req','-x509','-newkey','rsa:2048','-nodes','-keyout',keyPath,'-out',certPath,
    '-days','2','-subj','/CN=remotex-test.invalid','-config',configPath,
  ], {stdio:['ignore','pipe','pipe'],timeout:15000});
  const key = await fs.readFile(keyPath), cert = await fs.readFile(certPath);
  const fingerprint = new X509Certificate(cert).fingerprint256.replaceAll(':','').toLowerCase();
  const evidence = {applicationBytes:0,requests:0,bodies:[]};
  const server = https.createServer({key,cert,...(handshakeGate ? {SNICallback(_name,callback){handshakeGate(()=>callback(null,tls.createSecureContext({key,cert})));}} : {})}, async(req,res) => {
    evidence.requests++;
    const chunks=[];for await(const c of req) chunks.push(c);
    evidence.bodies.push(Buffer.concat(chunks).toString());
    if(handler) return handler(req,res);
    res.writeHead(200, {'content-type':'text/plain','set-cookie':['a=1; Secure; Path=/','b=2; Secure; Path=/']});
    res.end('trusted-response');
  });
  const sockets=new Set();
  server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});
  server.on('secureConnection',s=>s.on('data',chunk=>evidence.applicationBytes+=chunk.length));
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  t.after(async()=>{for(const s of sockets)s.destroy();await new Promise(resolve=>server.close(resolve));});
  return {origin:`https://127.0.0.1:${server.address().port}`,fingerprint,evidence,sockets};
}

function routeFor(url, body='synthetic-secret-canary') {
  const state = {fulfilled:null,aborted:false,code:null};
  const route = {
    request:()=>({url:()=>url,method:()=> 'POST',allHeaders:async()=>({'content-type':'application/x-www-form-urlencoded'}),postDataBuffer:()=>Buffer.from(body)}),
    fetch:async()=>{throw new Error('strict TLS rejects this self-signed fixture');},
    fulfill:async value=>{state.fulfilled=value;},abort:async()=>{state.aborted=true;},
  };
  return {route,state,failed:code=>{state.code=code;}};
}

test('matching explicit pin admits the exact self-signed endpoint and preserves response cookies', async t=>{
  const f=await fixture(t);const r=routeFor(f.origin+'/login');
  await guardRoute(r.route,f.origin,r.failed,f.fingerprint);
  assert.equal(r.state.code,null);assert.equal(r.state.aborted,false);
  assert.equal(r.state.fulfilled?.body.toString(),'trusted-response');
  assert.equal(f.evidence.requests,1);
  assert.deepEqual(f.evidence.bodies,['synthetic-secret-canary']);
  assert.match(r.state.fulfilled.headers['set-cookie'],/a=1/);
  assert.match(r.state.fulfilled.headers['set-cookie'],/b=2/);
});

test('wrong pin blocks all HTTP headers and credential body bytes before transmission', async t=>{
  const f=await fixture(t);const r=routeFor(f.origin+'/login');
  await guardRoute(r.route,f.origin,r.failed,'0'.repeat(64));
  assert.equal(r.state.code,'certificate-pin-mismatch');assert.equal(r.state.aborted,true);
  assert.equal(f.evidence.requests,0);assert.equal(f.evidence.applicationBytes,0);
});

test('pinned trust still rejects expired and not-yet-valid certificates before HTTP', async t=>{
  const f=await fixture(t);const now=Date.now();
  for(const shift of [-3,3]) {
    const r=routeFor(f.origin+'/login');
    t.mock.timers.enable({apis:['Date'],now:now+shift*86400000});
    try {await guardRoute(r.route,f.origin,r.failed,f.fingerprint);}
    finally {t.mock.timers.reset();}
    assert.equal(r.state.code,'certificate-validity-failed');
    assert.equal(f.evidence.requests,0);assert.equal(f.evidence.applicationBytes,0);
  }
});

test('a pin cannot authorize another host or port', async t=>{
  const f=await fixture(t);const r=routeFor(f.origin+'/login');
  await guardRoute(r.route,'https://different.invalid',r.failed,f.fingerprint);
  assert.equal(r.state.code,'origin-blocked');assert.equal(f.evidence.applicationBytes,0);
});

test('pinned redirect response is not followed or delivered to the browser', async t=>{
  const f=await fixture(t,(_req,res)=>{res.writeHead(307,{location:'https://foreign.invalid/'});res.end();});
  const r=routeFor(f.origin+'/login');await guardRoute(r.route,f.origin,r.failed,f.fingerprint);
  assert.equal(r.state.code,'redirect-blocked');assert.equal(r.state.fulfilled,null);
  assert.equal(f.evidence.requests,1);
});

test('real isolated Edge accepts only the pinned transport and round-trips multiple secure cookies', {timeout:30000}, async t=>{
  const f=await fixture(t,(req,res)=>{
    if(req.url==='/cookie-check') {res.end(req.headers.cookie||'');return;}
    res.writeHead(200,{'content-type':'text/html','set-cookie':['a=1; Secure; Path=/','b=2; Secure; Path=/']});
    res.end('<div id="result">ready</div>');
  });
  const require=createRequire(import.meta.url);const pw=require('../scripts/web-runtime/node_modules/playwright-core');
  const {browser,deny}=await launchEdge(pw,true);
  try {
    const context=await browser.newContext({ignoreHTTPSErrors:false,serviceWorkers:'block'});
    await context.setOffline(true);
    let failure=null;
    await context.route('**/*',r=>guardRoute(r,f.origin,code=>failure=code,f.fingerprint));
    const page=await context.newPage();await page.goto(f.origin);
    assert.equal(await page.locator('#result').innerText(),'ready');
    await page.goto(f.origin+'/cookie-check');
    const body=await page.locator('body').innerText();
    assert.match(body,/a=1/);assert.match(body,/b=2/);assert.equal(failure,null);
  } finally {await browser.close();deny.close();}
});

test('session cancellation destroys a pending TLS connection before any HTTP can be sent', {timeout:30000}, async t=>{
  let releaseHandshake, signalHandshake;
  const enteredHandshake = new Promise(resolve=>signalHandshake=resolve);
  const f=await fixture(t,undefined,next=>{releaseHandshake=next;signalHandshake();});
  const origin=f.origin.replace('127.0.0.1','localhost');
  const r=routeFor(origin+'/pending');const controller=new AbortController();
  const pending=guardRoute(r.route,origin,r.failed,f.fingerprint,controller.signal);
  await enteredHandshake;
  const closed=Promise.all([...f.sockets].map(socket=>once(socket,'close')));
  controller.abort();releaseHandshake();
  await pending;await closed;
  assert.equal(r.state.fulfilled,null);assert.equal(r.state.aborted,true);
  assert.equal(f.evidence.requests,0);assert.equal(f.evidence.applicationBytes,0);
});

test('real browser closure cancels pending pinned credential transmission', {timeout:30000}, async t=>{
  assert.equal(typeof worker.browserCancellation,'function');
  let releaseHandshake, signalHandshake;
  const enteredHandshake=new Promise(resolve=>signalHandshake=resolve);
  const f=await fixture(t,undefined,next=>{releaseHandshake=next;signalHandshake();});
  const origin=f.origin.replace('127.0.0.1','localhost');
  const require=createRequire(import.meta.url);const pw=require('../scripts/web-runtime/node_modules/playwright-core');
  const {browser,deny}=await launchEdge(pw,true);
  try {
    const context=await browser.newContext();await context.setOffline(true);
    const cancellation=worker.browserCancellation(context);
    await context.route('**/*',r=>r.request().url().endsWith('/pending')
      ? guardRoute(r,origin,()=>{},f.fingerprint,cancellation.signal)
      : r.fulfill({contentType:'text/html',body:'<title>Cancellation fixture</title>'}));
    const page=await context.newPage();await page.goto(origin);
    const pending=page.evaluate(()=>fetch('/pending',{method:'POST',body:'synthetic-secret-canary'}).catch(()=>null)).catch(()=>{});
    await enteredHandshake;
    const closed=Promise.all([...f.sockets].map(socket=>once(socket,'close')));
    await context.close();releaseHandshake();
    await pending;await closed;
    assert.equal(cancellation.signal.aborted,true);
    assert.equal(f.evidence.requests,0);assert.equal(f.evidence.applicationBytes,0);
  } finally {releaseHandshake?.();await browser.close();deny.close();}
});
