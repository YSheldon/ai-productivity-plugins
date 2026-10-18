import test from 'node:test';
import assert from 'node:assert/strict';
import {loadConfiguredDocument,guardRoute} from '../scripts/web_login_worker.mjs';

const cfg={origin:'https://console.example',url:'https://console.example/#/login'};

test('startup navigation shares one 45-second budget across document and fragment steps',async t=>{
  t.mock.timers.enable({apis:['Date','setTimeout'],now:1000});
  const calls=[];
  const page={url:()=>cfg.origin+'/',goto:async(url,options)=>{
    calls.push({url,timeout:options.timeout});if(calls.length===1)t.mock.timers.tick(20000);
  }};
  await loadConfiguredDocument(page,cfg);
  assert.deepEqual(calls,[{url:'https://console.example/',timeout:45000},
    {url:'https://console.example/#/login',timeout:25000}]);
});

test('an expired startup deadline cannot begin a document request',async t=>{
  t.mock.timers.enable({apis:['Date','setTimeout'],now:1000});let sent=0;
  const page={url:()=>cfg.origin+'/',goto:async()=>{sent++;}};
  await assert.rejects(()=>loadConfiguredDocument(page,cfg,{deadline:999}),/startup-deadline-exceeded/);
  assert.equal(sent,0);
});

test('remaining session time caps both startup navigation steps without resetting the clock',async t=>{
  t.mock.timers.enable({apis:['Date','setTimeout'],now:1000});const timeouts=[];
  const page={url:()=>cfg.origin+'/',goto:async(_url,options)=>{
    timeouts.push(options.timeout);if(timeouts.length===1)t.mock.timers.tick(1000);
  }};
  await loadConfiguredDocument(page,cfg,{deadline:5000});
  assert.deepEqual(timeouts,[4000,3000]);
});

test('wall-clock rollback cannot extend the remaining startup session budget',async t=>{
  let now=1000;
  t.mock.method(Date,'now',()=>now);
  const timeouts=[];
  const page={url:()=>cfg.origin+'/',goto:async(_url,options)=>{
    timeouts.push(options.timeout);
    if(timeouts.length===1){now=0;await new Promise(resolve=>setTimeout(resolve,10));}
  }};
  await loadConfiguredDocument(page,cfg,{deadline:5000});
  assert.equal(timeouts[0],4000);
  assert.ok(timeouts[1]<timeouts[0],`remaining timeout increased to ${timeouts[1]}`);
});

test('a cancelled queued route is denied before entering either TLS transport',async()=>{
  let cancelled=false,sent=0,aborted=0,began=0,failed=0;
  const request={url:()=>cfg.origin+'/app.js',failure:()=>cancelled?{errorText:'net::ERR_ABORTED'}:null};
  const route={request:()=>request,fetch:async()=>{sent++;return {status:()=>200};},
    fulfill:async()=>{},abort:async()=>{aborted++;}};
  const policy={authorize:async()=>{cancelled=true;return true;},beginForwarding:()=>{began++;}};
  await guardRoute(route,cfg.origin,()=>{failed++;},undefined,undefined,undefined,policy);
  assert.deepEqual({sent,aborted,began,failed},{sent:0,aborted:1,began:0,failed:0});
});
