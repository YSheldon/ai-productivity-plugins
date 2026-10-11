import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {sameOrigin,guardRoute,validateJob,submitLogin,launchEdge,verifyNetworkGuard} from '../scripts/web_login_worker.mjs';

const cfg = {url:'https://console.example:6868/#/',origin:'https://console.example:6868',account:'security',username_selector:'#user',password_selector:'#pass',submit_selector:'#login',success_selector:null};
test('origin matching rejects scheme, port, userinfo and sibling-host changes',()=>{
  assert.equal(sameOrigin(cfg.url,cfg.origin),true);
  for(const url of ['http://console.example:6868/','https://console.example/','https://console.example.evil:6868/','https://u:p@console.example:6868/'])assert.equal(sameOrigin(url,cfg.origin),false);
});
test('redirect response cannot replay credentials to another destination',async()=>{
  let sent=0,aborted=0,fulfilled=0,code;
  await guardRoute({request:()=>({url:()=>cfg.url}),fetch:async options=>{assert.equal(options.maxRedirects,0);sent++;return {status:()=>307};},abort:async()=>aborted++,fulfill:async()=>fulfilled++},cfg.origin,x=>code=x);
  assert.deepEqual({sent,aborted,fulfilled,code},{sent:1,aborted:1,fulfilled:0,code:'redirect-blocked'});
});
test('foreign destination is blocked before network transmission',async()=>{
  let aborted=false;
  await guardRoute({request:()=>({url:()=> 'https://evil.example/'}),fetch:()=>{throw Error('must-not-fetch');},abort:async()=>{aborted=true;}},cfg.origin,()=>{});
  assert.equal(aborted,true);
});
test('TLS errors are sanitized and never fulfilled',async()=>{
  let code;
  await guardRoute({request:()=>({url:()=>cfg.url}),fetch:async()=>{throw Error('SECRET-CANARY');},abort:async()=>{}},cfg.origin,c=>code=c);
  assert.equal(code,'tls-or-navigation-failed');
});
test('job cannot change stored account or supply broad selectors',()=>{
  const job={config:cfg,username:'security',password:'synthetic-test-only',deadline:Date.now()+60000};
  assert.equal(validateJob(job),cfg);
  assert.throws(()=>validateJob({...job,username:'other'}));
  assert.throws(()=>validateJob({...job,config:{...cfg,password_selector:'body'}}));
});
test('masking precedes typing and submit happens once',async()=>{
  const actions=[];
  const page={url:()=>cfg.url,locator:id=>({count:async()=>1,fill:async()=>actions.push('user'),click:async()=>actions.push(id==='\x23login'?'submit':'focus'),evaluate:async fn=>{const e={tagName:'INPUT',type:'text'};fn(e);assert.equal(e.type,'password');actions.push('mask');},getAttribute:async()=> 'password',pressSequentially:async()=>actions.push('type')})};
  await submitLogin(page,cfg,'security','synthetic-test-only',()=>{});
  assert.deepEqual(actions,['user','focus','mask','type','submit']);
});

test('probe validates configuration without requiring credential material',()=>{
  assert.equal(validateJob({config:cfg,mode:'probe',deadline:Date.now()+60000}),cfg);
  assert.throws(()=>validateJob({config:cfg,mode:'other',username:'security',password:'test',deadline:Date.now()+60000}));
});

test('real Edge fixture sends exact keyboard input and masks legacy text field', {timeout:30000}, async()=>{
  const require=createRequire(import.meta.url);
  const {chromium}=require('../scripts/web-runtime/node_modules/playwright-core');
  const {browser,deny}=await launchEdge({chromium},true);
  try {
    assert.deepEqual(await verifyNetworkGuard(browser),{udpPackets:0,tcpConnections:0});
    const context=await browser.newContext();
    await context.setOffline(true);
    await context.route('**/*',r=>r.fulfill({contentType:'text/html',body:`<input id="user"><input id="pass" type="text"><button id="login">Log in</button><div id="success" hidden>Logged in</div><script>document.getElementById('login').onclick=()=>{window.received={user:document.getElementById('user').value,pass:document.getElementById('pass').value,type:document.getElementById('pass').type};document.getElementById('pass').hidden=true;document.getElementById('success').hidden=false;};</script>`}));
    const page=await context.newPage();await page.goto(cfg.url);
    await submitLogin(page,cfg,'security','synthetic-pass!42',()=>{});
    assert.deepEqual(await page.evaluate(()=>window.received),{user:'security',pass:'synthetic-pass!42',type:'password'});
    assert.equal(await page.locator('#success').isVisible(),true);
  } finally { await browser.close();deny.close(); }
});
