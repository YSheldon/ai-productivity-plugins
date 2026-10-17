import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {Readable} from 'node:stream';
import {launchEdge} from '../scripts/web_login_worker.mjs';
import {SessionControl, projectResponse, readFrames, boundResult} from '../scripts/web_control.mjs';

const cfg = {origin:'https://console.example:6868',password_selector:'#pass',success_selector:'#main'};
const request = (url, body = '', method = 'POST') => ({url:()=>url,method:()=>method,postData:()=>body,resourceType:()=> 'xhr'});

test('passive response projection never returns payloads, headers, query values or tokens',()=>{
  const result = projectResponse(request(cfg.origin+'/api?cmd=get_status&token=secret'),200,
    Buffer.from(JSON.stringify({nResult:0,total:3,password:'secret',token:'secret',rows:[{secret:'private'}]})));
  assert.deepEqual(result,{path:'/api',method:'POST',command:'get_status',httpStatus:200,result:{nResult:0,total:3}});
  assert.equal(projectResponse(request(cfg.origin+'/login'),200,Buffer.from('{"token":"secret"}')),null);
  assert.equal(projectResponse(request(cfg.origin+'/api'),200,Buffer.alloc(262145)),null);
  assert.equal(projectResponse(request(cfg.origin+'/api'),200,Buffer.from('{"nResult":"secret"}')),null);
  assert.equal(projectResponse(request(cfg.origin+'/api'),200,Buffer.from('not json')),null);
});

test('framing is bounded and supports a credential-free EOF probe',async()=>{
  const messages=[];
  for await(const frame of readFrames(Readable.from([Buffer.from('{"a":1}\n{"b":2}')]))){messages.push(frame);}
  assert.deepEqual(messages,[{a:1},{b:2}]);
  await assert.rejects(async()=>{for await(const frame of readFrames(Readable.from([Buffer.alloc(65537,65)])))void frame;},/invalid-job/);
});

test('serialized UTF-8 and post-redaction expansion stay below the pipe bound',()=>{
  for(const text of ['\u4e2d'.repeat(16000),'[redacted]'.repeat(16000),'\x01'.repeat(16000)]){
    const result=boundResult({ok:true,text,links:Array.from({length:100},()=>({label:'\u4e2d'.repeat(160),route:'#/'+ 'a'.repeat(500)}))});
    assert.ok(Buffer.byteLength(JSON.stringify(result),'utf8')<=98304);
    assert.equal(result.truncated,true);assert.equal(result.ok,true);
  }
});

test('real Edge keeps one page, redacts fields, rejects stale refs and reads passive results', {timeout:30000},async()=>{
  const require=createRequire(import.meta.url);
  const {chromium}=require('../scripts/web-runtime/node_modules/playwright-core');
  const {browser,deny}=await launchEdge({chromium},true);
  try {
    const context=await browser.newContext();await context.setOffline(true);
    await context.route('**/*',r=>r.fulfill({contentType:'text/html',body:`<input id="pass" hidden><main id="main"><h1>Console</h1><p>secret-canary</p><input value="private-field"><textarea>private-area</textarea><div contenteditable>private-edit</div><p hidden>private-hidden</p><a href="#/assets">Assets<textarea>private-link-area</textarea><span contenteditable>private-link-edit</span><span hidden>private-link-hidden</span></a><a href="https://other.example/#/">Foreign</a><button onclick="window.mutated=true">Delete</button></main>`}));
    const page=await context.newPage();await page.goto(cfg.origin+'/#/home');
    const control=new SessionControl(page,cfg,{deadline:Date.now()+60000,secret:'secret-canary',check:()=>{}});
    const observed=await control.observe();
    assert.equal(observed.authenticationVerified,true);
    assert.equal(observed.geometry.mode,'emulated');
    assert.equal(observed.controlScope,'same-session');
    assert.match(observed.text,/Console/);
    for(const value of ['secret-canary','private-field','private-area','private-edit','private-hidden','private-link-area','private-link-edit','private-link-hidden'])assert.ok(!JSON.stringify(observed).includes(value),value);
    assert.equal(observed.links.length,1);
    const link=observed.links[0];
    const preview=await control.navigate({observation_id:observed.observationId,element_ref:link.ref,confirm:false});
    assert.equal(preview.preview,true);
    assert.ok(page.url().endsWith('/#/home'));
    await control.navigate({observation_id:observed.observationId,element_ref:link.ref,confirm:true});
    assert.ok(page.url().endsWith('/#/assets'));
    assert.equal(await page.evaluate(()=>window.mutated),undefined);
    await assert.rejects(()=>control.navigate({observation_id:observed.observationId,element_ref:link.ref,confirm:true}),/stale-observation/);
    control.record({path:'/api',method:'POST',command:'get_status',httpStatus:200,result:{nResult:0}});
    const evidence=await control.readResult();
    assert.equal(evidence.newRequestSent,false);
    assert.equal(evidence.results[0].result.nResult,0);
    assert.equal(evidence.businessSuccessVerified,false);
    const shortSecret=new SessionControl(page,cfg,{deadline:Date.now()+60000,secret:'a',check:()=>{}});
    const shortObserved=await shortSecret.observe();
    assert.match(shortObserved.observationId,/^[a-f0-9]{32}$/);
    assert.equal(shortObserved.controlScope,'same-session');
    assert.match(shortObserved.links[0].ref,/^[a-f0-9]{32}$/);
    const shortPreview=await shortSecret.navigate({observation_id:shortObserved.observationId,element_ref:shortObserved.links[0].ref,confirm:false});
    assert.equal(shortPreview.preview,true);await shortSecret.dispose();
    await page.locator('#main').evaluate(el=>{el.innerHTML='<p>'+'A'.repeat(16001)+'</p>';});
    const clipped=await control.observe();assert.equal(clipped.text.length,16000);assert.equal(clipped.truncated,true);
    await page.locator('#pass').evaluate(el=>{el.hidden=false;});
    await assert.rejects(()=>control.observe(),/authentication-required/);
    await context.close();
    await assert.rejects(()=>control.readResult(),/session-unavailable/);
  } finally {await browser.close();deny.close();}
});

test('session checks run before every operation',async()=>{
  const control=new SessionControl({isClosed:()=>false},cfg,{deadline:Date.now()+60000,secret:'x',check:()=>{throw Error('lease-invalid');}});
  for(const call of [()=>control.observe(),()=>control.readResult(),()=>control.navigate({})])await assert.rejects(call,/lease-invalid/);
});
