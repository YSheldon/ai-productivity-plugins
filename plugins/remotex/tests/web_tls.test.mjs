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
import {fileURLToPath} from 'node:url';
import {setTimeout as sleep} from 'node:timers/promises';
import {guardRoute, launchEdge} from '../scripts/web_login_worker.mjs';
import * as worker from '../scripts/web_login_worker.mjs';
import {readFrames} from '../scripts/web_control.mjs';
import * as transport from '../scripts/web_tls.mjs';
import {captureInitializationIntent,privateIntentFrame,disposeInitializationIntent,createOwnedCookieContext} from '../scripts/web_outgoing_intent.mjs';

async function fixture(t, handler, handshakeGate, {san=false}={}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'remotex-tls-test-'));
  const keyPath = path.join(directory, 'key.pem'), certPath = path.join(directory, 'cert.pem');
  t.after(() => fs.rm(directory, {recursive:true,force:true}));
  const configPath = path.join(directory, 'openssl.cnf');
  await fs.writeFile(configPath, '[req]\ndistinguished_name=dn\n[dn]\n');
  execFileSync(process.env.REMOTEX_TEST_OPENSSL || 'openssl', [
    'req','-x509','-newkey','rsa:2048','-nodes','-keyout',keyPath,'-out',certPath,
    '-days','2','-subj','/CN=remotex-test.invalid','-config',configPath,
    ...(san?['-addext','subjectAltName=IP:127.0.0.1']:[]),
  ], {stdio:['ignore','pipe','pipe'],timeout:60000});
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
  return {origin:`https://127.0.0.1:${server.address().port}`,fingerprint,evidence,sockets,certPath};
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

async function v3Intent(origin,body='{"mode":"public"}'){
  let reads=0;
  const request={url:()=>origin+'/bootstrap',method:()=> 'POST',resourceType:()=> 'xhr',
    postDataBuffer:()=>{reads++;return Buffer.from(body);},
    headersArray:async()=>[{name:'Content-Type',value:'application/json'}]};
  const intent=await captureInitializationIntent(request,{origin,cookie_context:null,protection_refs:[],secrets:[]});
  request.postDataBuffer=()=>{throw new Error('The transport must not reread the browser');};
  return {intent,reads:()=>reads};
}

test('v3 transport sends the committed owned bytes without rebuilding from Request',async t=>{
  assert.equal(typeof transport.initializationIntentResponse,'function');
  const f=await fixture(t,(_req,res)=>{res.writeHead(200,{'content-type':'application/json'});res.end('{"ready":true}');});
  const c=await v3Intent(f.origin);
  t.after(()=>disposeInitializationIntent(c.intent));
  const original=privateIntentFrame(c.intent);
  const result=await transport.initializationIntentResponse(c.intent,f.origin,f.fingerprint,undefined,Date.now()+10000,()=>{});
  assert.equal(result.status,200);assert.equal(c.reads(),1);
  assert.equal(Buffer.from(original.body_b64,'base64').toString(),f.evidence.bodies[0]);
  assert.equal(f.evidence.requests,1);
});

test('v3 pin rejection and post-certificate revocation send no HTTP',async t=>{
  assert.equal(typeof transport.initializationIntentResponse,'function');
  const f=await fixture(t);const c=await v3Intent(f.origin);
  t.after(()=>disposeInitializationIntent(c.intent));
  await assert.rejects(()=>transport.initializationIntentResponse(c.intent,f.origin,'0'.repeat(64),undefined,Date.now()+10000,()=>{}),/certificate-pin-mismatch/);
  await assert.rejects(()=>transport.initializationIntentResponse(c.intent,f.origin,f.fingerprint,undefined,Date.now()+10000,()=>{throw new Error('scope-mismatch');}),/scope-mismatch/);
  assert.equal(f.evidence.applicationBytes,0);assert.equal(f.evidence.requests,0);
});

test('v3 post-certificate asynchronous guard completes before any HTTP attachment',async t=>{
  const f=await fixture(t,(_req,res)=>{res.writeHead(200,{'content-type':'application/json'});res.end('{"ready":true}');});
  const c=await v3Intent(f.origin);t.after(()=>disposeInitializationIntent(c.intent));
  let entered,release;const started=new Promise(resolve=>{entered=resolve;}),gate=new Promise(resolve=>{release=resolve;});
  t.after(()=>release());
  const guarded=gate.then(()=>{throw new Error('scope-mismatch');});guarded.catch(()=>{});
  const pending=transport.initializationIntentResponse(c.intent,f.origin,f.fingerprint,undefined,Date.now()+10000,()=>{entered();return guarded;});
  pending.catch(()=>{});
  await started;await sleep(30);
  const before=f.evidence.requests;release();
  assert.equal(before,0,'A pending private guard must not send HTTP');
  await assert.rejects(pending,/scope-mismatch/);
  assert.equal(f.evidence.applicationBytes,0);
});

test('v3 cookie attribute changes are rechecked after TLS without rewriting the frozen Cookie',async t=>{
  const f=await fixture(t,(_req,res)=>{res.writeHead(200,{'content-type':'application/json'});res.end('{"ready":true}');});
  let sameSite='Strict';
  const resolver=createOwnedCookieContext({cookies:async()=>[{name:'preauth',value:'private-cookie-fixture',
    domain:'127.0.0.1',path:'/',expires:-1,httpOnly:true,secure:true,sameSite}]},f.origin);
  const request={url:()=>f.origin+'/bootstrap',method:()=> 'POST',resourceType:()=> 'xhr',
    postDataBuffer:()=>Buffer.from('{"mode":"public"}'),headersArray:async()=>[
      {name:'Content-Type',value:'application/json'},{name:'Cookie',value:'preauth=private-cookie-fixture'}]};
  const intent=await captureInitializationIntent(request,{origin:f.origin,cookie_context:resolver,protection_refs:[],secrets:[]});
  t.after(()=>{disposeInitializationIntent(intent);resolver.dispose();});
  sameSite='Lax';
  await assert.rejects(()=>transport.initializationIntentResponse(intent,f.origin,f.fingerprint,undefined,Date.now()+10000,()=>{}),/scope-mismatch/);
  assert.equal(f.evidence.requests,0);assert.equal(f.evidence.applicationBytes,0);
});

test('the production route dispatches v3 through its frozen intent without another browser body read',async t=>{
  const f=await fixture(t,(_req,res)=>{res.writeHead(200,{'content-type':'application/json'});res.end('{"ready":true}');});
  const original={url:()=>f.origin+'/bootstrap',method:()=> 'POST',resourceType:()=> 'xhr',
    postDataBuffer:()=>Buffer.from('{"mode":"public"}'),headersArray:async()=>[{name:'Content-Type',value:'application/json'}]};
  const intent=await captureInitializationIntent(original,{origin:f.origin,cookie_context:null,protection_refs:[],secrets:[]});
  original.postDataBuffer=()=>{throw new Error('No repeated body read');};
  const ready=[];let fulfilled=null;
  const completed=()=>disposeInitializationIntent(intent);
  completed.intent=intent;completed.checkDispatch=()=>{};completed.startupDeadline=Date.now()+45000;
  completed.initialization={kind:'initialization-permit-v3',expires_at_ms:Date.now()+9000,dispatch_deadline:performance.now()+9000,
    response_checks:[{pointer:'/ready',test:'equals-boolean',expected:true}]};
  const require=createRequire(import.meta.url),{parseTree}=require('../scripts/web-runtime/node_modules/jsonc-parser');
  const policy={authorize:async()=>true,beginForwarding:()=>completed,parseTree,
    startupState:{forward(){},check(){},response(_receipt,result){ready.push(result.ready);}}};
  const route={request:()=>original,abort:async()=>{},fulfill:async response=>{fulfilled=response;}};
  await guardRoute(route,f.origin,()=>{},f.fingerprint,undefined,undefined,policy);
  assert.equal(fulfilled?.status,200);assert.deepEqual(ready,[true]);assert.equal(f.evidence.requests,1);
  assert.throws(()=>privateIntentFrame(intent));
});

test('initialization transport enforces a streaming64KiB response ceiling',async t=>{
  assert.equal(typeof transport.initializationResponse,'function','Bounded initialization transport is missing');
  const f=await fixture(t,(_req,res)=>{res.writeHead(200,{'content-type':'application/json'});res.end(' '.repeat(65537));});
  const r=routeFor(f.origin+'/init','cmd=info');
  await assert.rejects(()=>transport.initializationResponse(r.route.request(),f.origin,f.fingerprint,
    new AbortController().signal,Date.now()+45000),/response-too-large/);
});

test('a phase seal during TLS prevents old startup permission from sending HTTP',async t=>{
  let release,entered;const handshake=new Promise(resolve=>{entered=resolve;});
  const f=await fixture(t,undefined,next=>{release=next;entered();});
  const origin=f.origin.replace('127.0.0.1','localhost'),r=routeFor(origin+'/startup','cmd=info');
  let sealed=false;
  const completed=()=>{};completed.privateStartup=true;
  completed.checkDispatch=()=>{if(sealed)throw new Error('scope-mismatch');};
  const pending=guardRoute(r.route,origin,r.failed,f.fingerprint,undefined,undefined,
    {authorize:async()=>true,beginForwarding:()=>completed});
  await handshake;sealed=true;release();await pending;
  assert.equal(f.evidence.requests,0);assert.equal(f.evidence.applicationBytes,0);
});

test('an init Set-Cookie is rejected before it enters the real browser cookie jar',{timeout:30000},async t=>{
  const f=await fixture(t,(_req,res)=>{res.writeHead(200,{'content-type':'application/json',
    'set-cookie':'init_auth=not-permitted; Secure; Path=/'});res.end('{"exist":true}');});
  const require=createRequire(import.meta.url),pw=require('../scripts/web-runtime/node_modules/playwright-core');
  const {parseTree}=require('../scripts/web-runtime/node_modules/jsonc-parser');
  const {browser,deny}=await launchEdge(pw,true);
  try{
    const context=await browser.newContext({ignoreHTTPSErrors:false,serviceWorkers:'block'});await context.setOffline(true);
    const completed=()=>{};completed.initialization={response_checks:[{pointer:'/exist',test:'equals-boolean',expected:true}]};
    completed.checkDispatch=()=>{};
    const policy={authorize:async()=>true,beginForwarding:()=>completed,parseTree,
      startupState:{check(){},forward(){},response(){}}};
    await context.route('**/*',r=>r.request().url().endsWith('/init')?
      guardRoute(r,f.origin,()=>{},f.fingerprint,undefined,undefined,policy):
      r.fulfill({contentType:'text/html',body:'<title>Initialization cookie fixture</title>'}));
    const page=await context.newPage();await page.goto(f.origin);
    await page.evaluate(()=>fetch('/init',{method:'POST',headers:{'content-type':'application/json'},
      body:'{"cmd":"info"}'}).then(r=>r.text()).catch(()=>null));
    assert.equal((await context.cookies()).some(c=>c.name==='init_auth'),false);
    assert.equal(f.evidence.requests,1);
  }finally{await browser.close();deny.close();}
});

test('non-pinned initialization uses verified CA and hostname without a browser cookie transport',{timeout:30000},async t=>{
  const f=await fixture(t,(req,res)=>{
    res.writeHead(200,{'content-type':'application/json',...(req.url==='/cookie'?{'set-cookie':'auth=not-init'}:{})});
    res.end('{"exist":true}');
  },undefined,{san:true});
  const read=async(origin,path)=>{
    const source=`import {initializationResponse} from ${JSON.stringify(new URL('../scripts/web_tls.mjs',import.meta.url).href)};
      const origin=${JSON.stringify(origin)};
      const request={url:()=>origin+${JSON.stringify(path)},method:()=> 'POST',
        postDataBuffer:()=>Buffer.from('{"cmd":"info"}'),allHeaders:async()=>({'content-type':'application/json'})};
      try{const response=await initializationResponse(request,origin,undefined,undefined,Date.now()+10000);
        process.stdout.write(JSON.stringify({status:response.status}));}
      catch{process.stdout.write(JSON.stringify({blocked:true}));}`;
    const child=spawn(process.execPath,['--use-system-ca','--input-type=module','-e',source],
      {env:{...process.env,NODE_EXTRA_CA_CERTS:f.certPath},stdio:['ignore','pipe','ignore'],windowsHide:true});
    const exited=once(child,'exit');let output='';for await(const data of child.stdout)output+=data;
    assert.equal((await exited)[0],0);return JSON.parse(output);
  };
  assert.deepEqual(await read(f.origin,'/init'),{status:200});
  assert.deepEqual(await read(f.origin,'/cookie'),{blocked:true});
  const sent=f.evidence.requests;
  assert.deepEqual(await read(f.origin.replace('127.0.0.1','localhost'),'/init'),{blocked:true});
  assert.equal(f.evidence.requests,sent,'A trusted certificate with the wrong name must send no HTTP');
});

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

async function workerControlFixture(t, rejectTransport=false, {slowStatic=false,competing=0,bootstrapOnly=false,initialization=false}={}) {
  let loginCount=0,businessCount=0,unapprovedStaticCount=0,initCount=0;
  const markup='<input id="user"><input id="pass"><button id="login">Login</button><main id="main" hidden><h1>Fixture Center</h1><a href="#/assets">Assets</a><button id="refresh">Refresh</button></main>';
  const behavior=`
    document.getElementById('login').onclick=async()=>{try{await fetch('/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:document.getElementById('pass').value})});document.getElementById('pass').hidden=true;document.getElementById('main').hidden=false;setInterval(()=>fetch('/api?cmd=get_status').catch(()=>{}),300);}catch{}};
    document.getElementById('refresh').onclick=()=>fetch('/api?cmd=get_status');
    ${rejectTransport ? "window.addEventListener('hashchange',()=>{if(location.hash==='#/assets')fetch('https://foreign.invalid/blocked').catch(()=>{});});" : ''}`;
  const f=await fixture(t,(req,res)=>{
    if(req.url==='/init'){
      initCount++;res.writeHead(200,{'content-type':'application/json'});res.end('{"exist":true,"guid":"fixture-private-guid"}');return;
    }
    if(req.url.startsWith('/unapproved/')){unapprovedStaticCount++;res.end('');return;}
    if(/^\/assets\/[0-9]+\.js$/.test(req.url)){
      res.writeHead(200,{'content-type':'application/javascript'});
      res.end('window.assetCount++;if(window.assetCount===15)window.mountFixture();');return;
    }
    if(req.url==='/login'){
      loginCount++;res.writeHead(200,{'content-type':'application/json','set-cookie':'auth=fixture-only; Secure; HttpOnly; Path=/'});res.end('{"ok":true}');return;
    }
    if(req.url.startsWith('/api')){
      assert.match(req.headers.cookie||'',/auth=fixture-only/);businessCount++;
      res.writeHead(200,{'content-type':'application/json'});res.end('{"nResult":0,"token":"not-for-export","total":2}');return;
    }
    res.writeHead(200,{'content-type':'text/html'});
    if(initialization){
      res.end(`<script>window.mountFixture=()=>{document.body.innerHTML=${JSON.stringify(markup)};${behavior}};
        fetch('/init',{method:'POST',headers:{'content-type':'application/json'},body:'{"cmd":"info"}'})
        .then(r=>r.json()).then(v=>{if(v.exist)window.mountFixture();}).catch(()=>{});</script>`);return;
    }
    if(!slowStatic){res.end(markup+`<script>${behavior}</script>`);return;}
    res.end(`<script>window.assetCount=0;window.mountFixture=()=>{document.body.innerHTML=${JSON.stringify(markup)};${behavior}};</script>`+
      Array.from({length:competing},(_,index)=>`<script defer src="/unapproved/${index}.js"></script>`).join('')+
      Array.from({length:15},(_,index)=>`<script defer src="/assets/${index}.js"></script>`).join(''));
  });
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),'remotex-control-test-'));
  const child=spawn(process.execPath,['--use-system-ca',fileURLToPath(new URL('../scripts/web_login_worker.mjs',import.meta.url)),directory,
    fileURLToPath(new URL('../scripts/web-runtime/node_modules/playwright-core',import.meta.url))],{stdio:['pipe','pipe','ignore'],windowsHide:true});
  const exited=once(child,'exit');
  const stopped=new AbortController();
  t.after(async()=>{stopped.abort();child.stdin.end();await Promise.race([exited,new Promise(r=>setTimeout(r,5000))]);if(child.exitCode===null)child.kill();await fs.rm(directory,{recursive:true,force:true});});
  const pending=new Map(),approvedActions=new Set(),trace=[];
  let rootApproved=false,loginApproved=false,allowBusiness=false,coreApproved=!slowStatic;
  let loginRootApproved=!slowStatic,loginCoreApproved=!slowStatic,staticOutstanding=0,maxStaticOutstanding=0;
  let decisions=Promise.resolve(),transportFailure=null;
  let initApproved=false,initContext=null;
  const fail=error=>{if(stopped.signal.aborted)return;transportFailure=error;for(const entry of pending.values())entry.reject(error);};
  child.stdin.on('error',fail);
  const transport=(async()=>{
    for await(const frame of readFrames(child.stdout)){
      if(frame.event==='startup-state'){
        if(trace.length<64)trace.push({event:frame.state.kind,phase:frame.state.phase,generation:frame.state.generation});
        continue;
      }
      if(frame.event==='authorization-check'||frame.event==='authorization-check-batch'){
        const checks=frame.event==='authorization-check'?[{id:frame.id,request:frame.request}]:frame.checks;
        if(frame.event==='authorization-check-batch'){
          assert.ok(checks.length>=2&&checks.length<=16);
          assert.ok(Buffer.byteLength(JSON.stringify(frame)+'\n')<=32768);
        }
        const staticCount=checks.filter(({request:value})=>value.kind==='network'&&
          value.descriptor.method==='GET'&&/\.(js|css)$/.test(value.descriptor.path)).length;
        staticOutstanding+=staticCount;maxStaticOutstanding=Math.max(maxStaticOutstanding,staticOutstanding);
        decisions=decisions.then(async()=>{
          if(stopped.signal.aborted)return;
          const replies=checks.map(check=>{
            const value=check.request,descriptor=value.descriptor;
            let allowed=value.kind==='action'&&approvedActions.has(value.attempt_id);
            if(value.kind==='network'){
            if(initApproved&&descriptor.method==='POST'&&descriptor.path==='/init'&&descriptor.body?.cmd==='info'&&value.startup){
              return {authorization_reply:check.id,allowed:true,permit:{kind:'initialization-read',check_id:check.id,
                descriptor_digest:value.digest,binding_digest:'1'.repeat(64),...value.startup,
                expires_at_ms:Date.now()+9000,prerequisite_id:initContext.prerequisite_id,
                response_checks:initContext.response_checks}};
            }
            const root=value.phase==='bootstrap'?rootApproved:value.phase==='login-once'&&loginRootApproved;
            const core=value.phase==='bootstrap'?coreApproved:value.phase==='login-once'&&loginCoreApproved;
            allowed=!!(root&&descriptor.method==='GET'&&descriptor.path==='/'&&descriptor.body===null)||
              !!(core&&descriptor.method==='GET'&&/^\/assets\/(?:[0-9]|1[0-4])\.js$/.test(descriptor.path)&&descriptor.body===null&&Object.keys(descriptor.query).length===0)||
              !!(loginApproved&&value.phase==='login-once'&&descriptor.method==='POST'&&descriptor.path==='/login'&&descriptor.body?.password?.internalAuth===true)||
              !!(allowBusiness&&value.phase==='grant-active'&&approvedActions.has(value.attempt_id)&&descriptor.method==='GET'&&descriptor.path==='/api'&&descriptor.query.cmd==='get_status');
            }
            if(trace.length<(slowStatic?256:64))trace.push({kind:value.kind,phase:value.phase,path:descriptor?.path,allowed});
            return {authorization_reply:check.id,allowed};
          });
          // One durable transaction delay, whether it contains one or16 static checks.
          if(slowStatic&&staticCount&&replies.some(row=>row.allowed))await sleep(1400,undefined,{signal:stopped.signal});
          if(!stopped.signal.aborted)child.stdin.write(JSON.stringify(frame.event==='authorization-check'?replies[0]:
            {authorization_batch_reply:replies})+'\n');
          staticOutstanding-=staticCount;
        }).catch(fail);
      }else{
        const entry=pending.get(frame.id);assert.ok(entry,'Unexpected worker response');pending.delete(frame.id);entry.resolve(frame.result);
      }
    }
    await decisions;
  })().catch(fail);
  const sessionDeadline=Date.now()+(slowStatic?150000:60000);
  child.stdin.write(JSON.stringify({config:{origin:f.origin,url:f.origin+'/#/home',account:'operator',username_selector:'#user',password_selector:'#pass',submit_selector:'#login',success_selector:'#main',certificate_sha256:f.fingerprint},username:'operator',password:'synthetic-session-secret',deadline:sessionDeadline})+'\n');
  let sequence=0;
  const call=async(operation,args={})=>{
    if(transportFailure)throw transportFailure;
    const id=(++sequence).toString(16).padStart(32,'0');
    const result=new Promise((resolve,reject)=>pending.set(id,{resolve,reject}));
    child.stdin.write(JSON.stringify({id,operation,arguments:args})+'\n');
    let timeout;
    try {return await Promise.race([result,new Promise((_,reject)=>{
      timeout=setTimeout(async()=>{
        let state='unavailable';try{state=await fs.readFile(path.join(directory,'state.json'),'utf8');}catch{}
        reject(new Error(`Worker ${operation} timed out; receipt: ${state}; exit: ${child.exitCode}`));
      },slowStatic?60000:18000);
    }),exited.then(()=>{throw new Error(`Worker exited during ${operation}`);})]);}finally{clearTimeout(timeout);}
  };
  const blocked=await call('network-status');
  assert.equal(f.evidence.requests,0,'Unknown startup traffic must be blocked before any request is sent');
  assert.ok(blocked.descriptors.some(row=>row.path==='/'));
  rootApproved=true;
  const firstResume=await call('resume-login');
  assert.equal(firstResume.authenticationVerified,false);
  assert.equal(loginCount,0,'An unapproved authentication request must not leave the worker');
  let resumeSequence=0;
  const resume=()=>call('resume-login',initContext?{startup:{resume_id:(++resumeSequence).toString(16).padStart(32,'0'),
    preauth_lifecycle:initContext.preauth_lifecycle,binding_digest:'1'.repeat(64),deadline_ms:Math.min(sessionDeadline,Date.now()+45000)}}:{});
  if(initialization){
    assert.equal(initCount,0,'Unapproved initialization must not reach the server');
    const network=await call('network-status'),ref=network.descriptors.find(d=>d.path==='/init')?.ref;
    assert.ok(ref,'The hidden controls require an observed initialization descriptor');
    const proposal=await call('resolve-setup',{setup:{revision:2,phase:network.phase,requests:[{
      network_ref:ref,purpose:'initialization-read',evidence:[{kind:'source-review',reference:'Synthetic no-write handler'}],
      response_checks:[{pointer:'/exist',test:'equals-boolean',expected:true}]}]}});
    assert.equal(proposal.ok,true,JSON.stringify(proposal));initContext=Object.values(proposal.contracts)[0];
    assert.equal((await call('register-initialization',{contracts:proposal.contracts})).ok,true);
    assert.equal(initCount,0,'Registration and approval alone cannot transmit a request');
    initApproved=true;const initResume=await resume();
    assert.equal(initCount,1,JSON.stringify({initResume,trace,network:await call('network-status')}));
    assert.equal(loginCount,0,'Initialization approval is not Login approval');
  }
  if(slowStatic){
    const assets=await call('network-status');
    assert.equal(assets.phase,'bootstrap');
    assert.equal(assets.descriptors.filter(row=>/^\/assets\/[0-9]+\.js$/.test(row.path)).length,15);
    coreApproved=true;
    await call('resume-login');
    const ready=await call('network-status');
    assert.equal(ready.phase,'login-once','15 granted assets must commit the login controls despite serial broker latency');
    assert.ok(maxStaticOutstanding>=2&&maxStaticOutstanding<=16,'the real worker must wire bounded startup transactions');
    assert.equal(unapprovedStaticCount,0,'competing unknown assets must never reach the server');
    if(bootstrapOnly){
      assert.equal(loginCount,0);assert.equal(child.exitCode,null);
      child.stdin.end();await exited;await transport;assert.equal(child.exitCode,0);return;
    }
  }
  let authenticationBlocked=false;
  for(let attempt=0;attempt<50;attempt++){
    const network=await call('network-status');
    if(network.descriptors.some(row=>row.path==='/login')){authenticationBlocked=true;break;}
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  assert.ok(authenticationBlocked,JSON.stringify({message:'Authentication descriptor not captured',firstResume,trace,
    receipt:JSON.parse(await fs.readFile(path.join(directory,'state.json'),'utf8')),loginCount,requestCount:f.evidence.requests}));
  loginApproved=true;
  if(slowStatic){
    await call('resume-login');
    const deniedRoot=await call('network-status');
    assert.ok(deniedRoot.descriptors.some(row=>row.path==='/'));
    assert.equal(loginCount,0,'bootstrap grants must not authorize login-phase documents');
    loginRootApproved=true;await call('resume-login');
    const deniedAssets=await call('network-status');
    assert.equal(deniedAssets.descriptors.filter(row=>/^\/assets\/[0-9]+\.js$/.test(row.path)).length,15);
    assert.equal(loginCount,0);loginCoreApproved=true;
  }
  const resumed=await resume();
  const receipt=JSON.parse(await fs.readFile(path.join(directory,'state.json'),'utf8'));
  assert.equal(resumed.authenticationVerified,true,JSON.stringify({resumed,receipt,loginCount}));
  if(initialization)assert.equal(initCount,2,'A new pre-credential document needs a fresh readiness response');
  if(slowStatic){assert.ok(maxStaticOutstanding>=2&&maxStaticOutstanding<=16);assert.equal(unapprovedStaticCount,0);}
  assert.equal((await call('observe')).failureCode,'approval-required');
  assert.equal(businessCount,0,'Post-login polling must not inherit login permission');
  const view=await call('components');
  assert.equal(view.geometry.mode,'window','The production worker must retain a window-sized viewport');
  const main=view.components.find(row=>row.id==='main'),refresh=view.components.find(row=>row.id==='refresh'),link=view.components.find(row=>row.href==='#/assets');
  const resolve=async(item_id,capability,component)=>{
    const response=await call('resolve-items',{items:[{item_id,capability,observation_id:view.observationId,component_ref:component.ref}]});
    assert.equal(response.ok,true);return response.items[0];
  };
  const execute=async(scope,component)=>{
    const attempt=(++sequence).toString(16).padStart(32,'0');approvedActions.add(attempt);
    return call('execute',{attempt_id:attempt,scope,observation_id:view.observationId,component_ref:component.ref});
  };
  const observation=await execute(await resolve('read','web.read_region',main),main);
  assert.match(observation.result.text,/Fixture Center/);
  allowBusiness=true;
  await execute(await resolve('refresh','web.page_step',refresh),refresh);
  const business=(await execute(await resolve('results','web.read_result',main),main)).result;
  assert.ok(business.results.some(row=>row.command==='get_status'&&row.result.nResult===0));
  const navigation=await resolve('assets','web.navigate',link);
  if(rejectTransport){
    void execute(navigation,link).catch(()=>{});
    await exited;
    const failed=JSON.parse(await fs.readFile(path.join(directory,'state.json'),'utf8'));
    assert.equal(failed.state,'failed');assert.equal(failed.failureCode,'origin-blocked');
    assert.equal(loginCount,1);return;
  }
  const navigated=await execute(navigation,link);
  assert.equal(navigated.result.page.route,'#/assets');assert.equal(loginCount,1);assert.ok(businessCount>0);
  for(const content of [JSON.stringify(observation),JSON.stringify(business),await fs.readFile(path.join(directory,'state.json'),'utf8')]){
    for(const forbidden of ['synthetic-session-secret','auth=fixture-only','not-for-export'])assert.ok(!content.includes(forbidden));
  }
  assert.deepEqual((await fs.readdir(directory)).filter(name=>!name.endsWith('.tmp')),['state.json']);
  child.stdin.end();await exited;await transport;
  assert.equal(child.exitCode,0);
}

test('worker pipe reuses authenticated Edge for approved page and business readback without content files', {timeout:65000},t=>workerControlFixture(t));
test('post-login origin rejection closes the same approved worker and preserves a failed receipt', {timeout:65000},t=>workerControlFixture(t,true));
test('owned worker initializes hidden controls then uses separate Login and Read permissions',
  {timeout:65000},t=>workerControlFixture(t,false,{initialization:true}));

test('slow serial startup loads 15 approved assets then logs in and reads in the same worker',
  {timeout:150000},t=>workerControlFixture(t,false,{slowStatic:true}));
test('slow serial startup admits its 15 core assets among 47 competing checks without leaking unknown requests',
  {timeout:100000},t=>workerControlFixture(t,false,{slowStatic:true,competing:32,bootstrapOnly:true}));

test('bootstrap diagnosis distinguishes an allowed HTML response from committed page readiness', {timeout:40000},async t=>{
  const f=await fixture(t,(_req,res)=>{res.writeHead(200,{'content-type':'text/html'});res.end('<input id="user"><input id="pass"><button id="login">Login</button>');});
  const require=createRequire(import.meta.url),pw=require('../scripts/web-runtime/node_modules/playwright-core');
  const {browser,deny}=await launchEdge(pw,true);
  try {
    for(let iteration=0;iteration<5;iteration++){
      const context=await worker.createWebContext(browser);await context.setOffline(true);
      let allowed=false;const failures=[];
      await context.route('**/*',route=>guardRoute(route,f.origin,code=>failures.push(code),f.fingerprint,undefined,undefined,{authorize:async()=>allowed}));
      const page=await context.newPage(),url=f.origin+'/#/home';
      try{await page.goto(url,{waitUntil:'domcontentloaded',timeout:5000});}catch{}
      allowed=true;
      let navigationError=null;
      try{await worker.loadConfiguredDocument(page,{url,origin:f.origin});}
      catch(error){navigationError=String(error.message).split('\n')[0];}
      const document=await page.evaluate(()=>({uri:document.documentURI,state:document.readyState,
        title:document.title,user:!!document.getElementById('user')}));
      assert.equal(document.user,true,JSON.stringify({iteration,navigationError,document,failures,requests:f.evidence.requests}));
      await context.close();
    }
  }finally{await browser.close();deny.close();}
});
