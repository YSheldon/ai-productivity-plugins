import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import tls from 'node:tls';
import {once} from 'node:events';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {execFileSync,spawn} from 'node:child_process';
import {X509Certificate} from 'node:crypto';
import {createRequire} from 'node:module';
import {guardRoute, launchEdge} from '../scripts/web_login_worker.mjs';
import * as worker from '../scripts/web_login_worker.mjs';
import {readFrames} from '../scripts/web_control.mjs';

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

async function workerControlFixture(t, rejectTransport=false) {
  let loginCount=0,businessCount=0;
  const f=await fixture(t,(req,res)=>{
    if(req.url==='/login'){
      loginCount++;res.writeHead(200,{'content-type':'application/json','set-cookie':'auth=fixture-only; Secure; HttpOnly; Path=/'});res.end('{"ok":true}');return;
    }
    if(req.url.startsWith('/api')){
      assert.match(req.headers.cookie||'',/auth=fixture-only/);businessCount++;
      res.writeHead(200,{'content-type':'application/json'});res.end('{"nResult":0,"token":"not-for-export","total":2}');return;
    }
    res.writeHead(200,{'content-type':'text/html'});
    res.end(`<input id="user"><input id="pass"><button id="login">Login</button><main id="main" hidden><h1>Fixture Center</h1><a href="#/assets">Assets</a></main><script>
      document.getElementById('login').onclick=async()=>{await fetch('/login',{method:'POST',body:document.getElementById('pass').value});document.getElementById('pass').hidden=true;document.getElementById('main').hidden=false;setInterval(()=>fetch('/api?cmd=get_status'),300);};
      ${rejectTransport ? "window.addEventListener('hashchange',()=>fetch('https://foreign.invalid/blocked').catch(()=>{}));" : ''}
    </script>`);
  });
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),'remotex-control-test-'));
  const child=spawn(process.execPath,['--use-system-ca',path.resolve('scripts/web_login_worker.mjs'),directory,path.resolve('scripts/web-runtime/node_modules/playwright-core')],{stdio:['pipe','pipe','ignore'],windowsHide:true});
  const exited=once(child,'exit');
  t.after(async()=>{child.stdin.end();await Promise.race([exited,new Promise(r=>setTimeout(r,5000))]);if(child.exitCode===null)child.kill();await fs.rm(directory,{recursive:true,force:true});});
  child.stdin.write(JSON.stringify({config:{origin:f.origin,url:f.origin+'/#/home',account:'operator',username_selector:'#user',password_selector:'#pass',submit_selector:'#login',success_selector:'#main',certificate_sha256:f.fingerprint},username:'operator',password:'synthetic-session-secret',deadline:Date.now()+30000})+'\n');
  let state;
  for(let n=0;n<150;n++){
    try{state=JSON.parse(await fs.readFile(path.join(directory,'state.json'),'utf8'));}catch{}
    if(state?.state==='verified'||state?.state==='failed')break;
    await new Promise(r=>setTimeout(r,100));
  }
  assert.equal(state?.state,'verified');
  const frames=readFrames(child.stdout);
  const call=async(operation,args={})=>{
    child.stdin.write(JSON.stringify({id:'a'.repeat(32),operation,arguments:args})+'\n');
    const response=(await frames.next()).value;assert.equal(response.id,'a'.repeat(32));return response.result;
  };
  const observation=await call('observe');
  assert.match(observation.text,/Fixture Center/);
  assert.equal(observation.geometry.mode,'window','the actual login worker must not restore a fixed viewport');
  await new Promise(r=>setTimeout(r,700));
  const business=await call('read-result');
  assert.equal(business.newRequestSent,false);
  assert.ok(business.results.some(row=>row.command==='get_status'&&row.result.nResult===0));
  const navigation={observation_id:observation.observationId,element_ref:observation.links[0].ref,confirm:true};
  if(rejectTransport){
    child.stdin.write(JSON.stringify({id:'b'.repeat(32),operation:'navigate',arguments:navigation})+'\n');
    await exited;
    const failed=JSON.parse(await fs.readFile(path.join(directory,'state.json'),'utf8'));
    assert.equal(failed.state,'failed');assert.equal(failed.failureCode,'origin-blocked');
    assert.equal(loginCount,1);return;
  }
  const navigated=await call('navigate',navigation);
  assert.equal(navigated.page.route,'#/assets');assert.equal(loginCount,1);assert.ok(businessCount>0);
  for(const content of [JSON.stringify(observation),JSON.stringify(business),await fs.readFile(path.join(directory,'state.json'),'utf8')]){
    for(const forbidden of ['synthetic-session-secret','auth=fixture-only','not-for-export'])assert.ok(!content.includes(forbidden));
  }
  assert.deepEqual((await fs.readdir(directory)).filter(name=>!name.endsWith('.tmp')),['state.json']);
  child.stdin.end();await exited;
  assert.equal(child.exitCode,0);
}

test('worker pipe reuses authenticated Edge for page and passive business readback without content files', {timeout:45000},t=>workerControlFixture(t));
test('post-login origin rejection closes the same worker and preserves a failed receipt', {timeout:45000},t=>workerControlFixture(t,true));
