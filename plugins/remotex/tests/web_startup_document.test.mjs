import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {createRequire} from 'node:module';
import * as worker from '../scripts/web_login_worker.mjs';
import {StartupState} from '../scripts/web_startup_state.mjs';

test('owned Edge keeps BFCache disabled so fresh HTTPS documents produce navigation requests',async()=>{
  let options;
  const {deny}=await worker.launchEdge({chromium:{launch:async value=>{options=value;return {};}}});
  try{assert.ok(options.args.includes('--disable-back-forward-cache'));}
  finally{await new Promise(resolve=>deny.close(resolve));}
});

function fixture(){
  assert.equal(typeof worker.watchStartupDocument,'function');
  const page=new EventEmitter(),frame={url:()=> 'https://fixture.invalid/#/'};
  page.mainFrame=()=>frame;
  const abort=new AbortController(),state=new StartupState({lifecycle:'a'.repeat(32)});
  const context={preauth_lifecycle:'a'.repeat(32),resume_id:'b'.repeat(32),document_id:'c'.repeat(32),
    generation:1,phase:'bootstrap',deadline:Date.now()+45000,signal:abort.signal};
  state.open(context);let replaced=0,committed=0,authentication=0;
  const guard=worker.watchStartupDocument(page,{origin:'https://fixture.invalid',
    authenticating:()=>authentication>0,onCommit:()=>committed++,onReplace:()=>{replaced++;abort.abort();}});
  const request=()=>({isNavigationRequest:()=>true,frame:()=>frame});
  return {page,frame,state,context,guard,request,abort,counts:()=>({replaced,committed}),authenticate:()=>authentication++};
}

test('same-URL full document request invalidates prior readiness, not only its next commit',()=>{
  const f=fixture();
  f.page.emit('request',f.request());f.page.emit('framenavigated',f.frame);
  assert.equal(f.state.canInsertCredentials(),true);assert.equal(f.guard.committed(),true);
  f.page.emit('request',f.request());
  assert.equal(f.state.canInsertCredentials(),false);assert.equal(f.guard.committed(),false);
  f.page.emit('framenavigated',f.frame);assert.deepEqual(f.counts(),{replaced:1,committed:1});f.guard.dispose();
});

test('fragment-only navigation and subframes do not replace a startup document',()=>{
  const f=fixture();f.page.emit('request',f.request());f.page.emit('framenavigated',f.frame);
  f.frame.url=()=> 'https://fixture.invalid/#/login';f.page.emit('framenavigated',f.frame);
  f.page.emit('request',{isNavigationRequest:()=>true,frame:()=>({})});
  f.page.emit('request',{isNavigationRequest:()=>false});f.page.emit('framenavigated',{});
  assert.equal(f.guard.committed(),true);assert.equal(f.state.canInsertCredentials(),true);
  assert.deepEqual(f.counts(),{replaced:0,committed:1});f.guard.dispose();
});

test('a delayed old-document response cannot become ready after replacement',()=>{
  const f=fixture(),id='d'.repeat(64);
  f.state.required.set(id,{prerequisite_id:id});
  const receipt=f.state.begin({...f.context,kind:'initialization-read',prerequisite_id:id,
    check_id:'e'.repeat(32),expires_at_ms:Date.now()+10000});
  f.state.forward(receipt);f.page.emit('request',f.request());f.page.emit('framenavigated',f.frame);
  f.page.emit('request',f.request());
  assert.throws(()=>f.state.response(receipt,{ready:true}),/scope-mismatch/);
  assert.equal(f.state.ready.size,0);assert.equal(f.state.canInsertCredentials(),false);f.guard.dispose();
});

test('out-of-origin local documents fail closed; verified exchange navigation is not a second login',()=>{
  const f=fixture();f.page.emit('request',f.request());f.page.emit('framenavigated',f.frame);
  f.frame.url=()=> 'about:blank';f.page.emit('framenavigated',f.frame);
  assert.equal(f.guard.committed(),false);assert.equal(f.counts().replaced,1);f.guard.dispose();
  const next=fixture();next.page.emit('request',next.request());next.page.emit('framenavigated',next.frame);
  next.authenticate();next.page.emit('request',next.request());next.page.emit('framenavigated',next.frame);
  assert.equal(next.counts().replaced,0);next.guard.dispose();
  assert.equal(next.page.listenerCount('request'),0);assert.equal(next.page.listenerCount('framenavigated'),0);
});

test('the final trusted Login form submit is not a pre-credential replacement', {timeout:30000},async()=>{
  const require=createRequire(import.meta.url),pw=require('../scripts/web-runtime/node_modules/playwright-core');
  const {browser,deny}=await worker.launchEdge(pw,true);let guard;
  try{
    const context=await worker.createWebContext(browser);await context.setOffline(true);
    await context.route('**/*',route=>route.fulfill({contentType:'text/html',body:route.request().method()==='POST'?
      '<main id="success">Synthetic form accepted</main>':
      '<form action="/login" method="post"><input id="user"><input id="pass" name="password"><button id="login">Login</button></form>'}));
    const page=await context.newPage();let submitting=false,replaced=0;
    guard=worker.watchStartupDocument(page,{origin:'https://fixture.invalid',authenticating:()=>submitting,
      onCommit:()=>{},onReplace:()=>replaced++});
    const cfg={url:'https://fixture.invalid/#/',origin:'https://fixture.invalid',username_selector:'#user',
      password_selector:'#pass',submit_selector:'#login'};
    await page.goto(cfg.url);
    await worker.submitLogin(page,cfg,'operator','synthetic-form-only',()=>{
      assert.equal(guard.committed(),true);
    },()=>{submitting=true;});
    await page.locator('#success').waitFor({state:'visible',timeout:5000});
    assert.equal(replaced,0);assert.equal(submitting,true);
  }finally{guard?.dispose();await browser.close();deny.close();}
});
