import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {sameOrigin,guardRoute,validateJob,submitLogin,launchEdge,verifyNetworkGuard} from '../scripts/web_login_worker.mjs';
import * as worker from '../scripts/web_login_worker.mjs';
import {SessionControl} from '../scripts/web_control.mjs';

const cfg = {url:'https://console.example:6868/#/',origin:'https://console.example:6868',account:'security',username_selector:'#user',password_selector:'#pass',submit_selector:'#login',success_selector:null};

function assertViewportTracksWindow(view) {
  // CSS rectangles can be fractional while innerWidth/innerHeight are integers.
  for(const [content,viewport] of [[view.contentWidth,view.width],[view.contentHeight,view.height]]) {
    assert.ok(Number.isFinite(content) && Number.isFinite(viewport) && content>0 && viewport>0,'viewport dimensions must be positive finite numbers');
    assert.ok(Math.abs(content-viewport)<=1,`${content} vs ${viewport}: content must follow the viewport within one CSS pixel`);
  }
}

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

test('long task job accepts thirteen hours but not a longer or expired lifetime',t=>{
  t.mock.method(Date,'now',()=>1000);
  const job={config:cfg,username:'security',password:'synthetic-long-job',deadline:1000+46800000};
  assert.equal(validateJob(job),cfg);
  for(const deadline of [1000,1000+46800001,Infinity,'46800000'])assert.throws(()=>validateJob({...job,deadline}),/invalid-job/);
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

test('viewport comparison accepts at most one CSS pixel of rounding on each axis',()=>{
  assert.equal(typeof assertViewportTracksWindow,'function');
  assert.doesNotThrow(()=>assertViewportTracksWindow({width:578,height:369,contentWidth:578,contentHeight:369.3333435058594}));
  assert.doesNotThrow(()=>assertViewportTracksWindow({width:578,height:369,contentWidth:579,contentHeight:368}));
});

test('viewport comparison rejects differences over one pixel and fixed-size content',()=>{
  assert.equal(typeof assertViewportTracksWindow,'function');
  for(const [contentWidth,contentHeight] of [[579.01,369],[578,370.01],[576.99,369],[578,367.99],[1280,720]]) {
    assert.throws(()=>assertViewportTracksWindow({width:578,height:369,contentWidth,contentHeight}));
  }
});

test('viewport comparison rejects missing nonfinite and zero dimensions',()=>{
  assert.equal(typeof assertViewportTracksWindow,'function');
  for(const key of ['width','height','contentWidth','contentHeight']) {
    for(const value of [undefined,NaN,Infinity,0,-1]) {
      assert.throws(()=>assertViewportTracksWindow({...{width:578,height:369,contentWidth:578,contentHeight:369},[key]:value}));
    }
  }
});

test('visible Edge content follows actual window enlargement and shrinking', {timeout:30000},async()=>{
  assert.equal(typeof worker.createWebContext,'function');
  const require=createRequire(import.meta.url);
  const pw=require('../scripts/web-runtime/node_modules/playwright-core');
  const {browser,deny}=await launchEdge(pw,false);
  try {
    const context=await worker.createWebContext(browser);
    await context.setOffline(true);
    await context.route('**/*',r=>r.fulfill({contentType:'text/html',body:'<style>html,body{margin:0;overflow:hidden}#main{width:100vw;height:100vh}</style><input id="pass" hidden><main id="main">Responsive console fixture</main>'}));
    const page=await context.newPage();await page.goto(cfg.url);
    const pageCDP=await context.newCDPSession(page),browserCDP=await browser.newBrowserCDPSession();
    const {targetInfo}=await pageCDP.send('Target.getTargetInfo');
    const {windowId}=await browserCDP.send('Browser.getWindowForTarget',{targetId:targetInfo.targetId});
    const resize=async(width,height,previous)=>{
      await browserCDP.send('Browser.setWindowBounds',{windowId,bounds:{windowState:'normal'}});
      await browserCDP.send('Browser.setWindowBounds',{windowId,bounds:{left:40,top:40,width,height}});
      let view,bounds;
      for(let attempt=0;attempt<30;attempt++){
        ({bounds}=await browserCDP.send('Browser.getWindowBounds',{windowId}));
        view=await page.evaluate(()=>({width:innerWidth,height:innerHeight,contentWidth:document.getElementById('main').getBoundingClientRect().width,contentHeight:document.getElementById('main').getBoundingClientRect().height}));
        if(bounds.width===width && bounds.height===height && (!previous || (view.width!==previous.width && view.height!==previous.height)))break;
        await new Promise(resolve=>setTimeout(resolve,100));
      }
      assert.equal(bounds.width,width);assert.equal(bounds.height,height);
      assertViewportTracksWindow(view);
      return view;
    };
    // Keep the test windows within the small desktop available on hosted runners.
    const narrow=await resize(600,460),wide=await resize(900,680,narrow),shrunk=await resize(700,500,wide);
    assert.ok(wide.width>narrow.width+200,`${narrow.width} -> ${wide.width}: viewport must grow with the window`);
    assert.ok(wide.height>narrow.height+100,`${narrow.height} -> ${wide.height}: viewport height must grow`);
    assert.ok(shrunk.width<wide.width-100 && shrunk.height<wide.height-100,'viewport must shrink with the window');
    assert.equal(page.viewportSize(),null,'the visible window must not use an emulated fixed viewport');
    const control=new SessionControl(page,{...cfg,success_selector:'#main'},{deadline:Date.now()+60000,secret:'fixture-secret',check:()=>{}});
    try {
      const observation=await control.observe();
      assert.equal(observation.geometry.mode,'window');
      assert.deepEqual(observation.geometry.viewport,{width:shrunk.width,height:shrunk.height});
      // The public geometry contract rounds dimensions to bounded integer pixels.
      assert.deepEqual(observation.geometry.content,{width:Math.round(shrunk.contentWidth),height:Math.round(shrunk.contentHeight)});
      assert.ok(observation.geometry.window.width>=observation.geometry.viewport.width);
    } finally {await control.dispose();}
  } finally {await browser.close();deny.close();}
});
