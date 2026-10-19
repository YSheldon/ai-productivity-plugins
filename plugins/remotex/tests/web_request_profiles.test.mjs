import test from 'node:test';
import assert from 'node:assert/strict';
import {parseV3Profile,validatePublicReference,safeV3Observation} from '../scripts/web_request_profiles.mjs';
import {vectors,sampleCapture,publicReference,parseTree,b64,header} from './fixtures/v3_test_support.mjs';
import {createRequire} from 'node:module';
import {launchEdge} from '../scripts/web_login_worker.mjs';
import {captureInitializationIntent,privateIntentFrame,disposeInitializationIntent} from '../scripts/web_outgoing_intent.mjs';

for(const row of vectors)test(`strict v3 profile: ${row.id}`,()=>{
  const capture=sampleCapture({bodyText:row.body,contentType:row.content_type});
  if(row.error){assert.throws(()=>parseV3Profile(capture,row.profile,parseTree),new RegExp(row.error));return;}
  const view=parseV3Profile(capture,row.profile,parseTree);
  assert.equal(view.unit_count,row.units);
  assert.deepEqual(validatePublicReference(capture,view,publicReference(row.id)),
    {matched:true,complete:true,unit_count:row.units});
});
test('complete public wire coverage rejects decoded-equivalent mutations',()=>{
  const source=publicReference();
  for(const change of [{bodyText:'{ "mode":"public"}'},{bodyText:'{"mode":"publ\\u0069c"}'},
    {target:'/bootstrap?mode=p%75blic'},{contentType:'application/json; charset=utf-8'}]){
    const capture=sampleCapture(change),view=parseV3Profile(capture,'json-utf8-v1',parseTree);
    assert.equal(validatePublicReference(capture,view,source).matched,false);
  }
});
test('JSON-looking values stay strings',()=>{
  const a=parseV3Profile(sampleCapture({bodyText:'{"x":"{\\"a\\":1}"}'}),'json-utf8-v1',parseTree);
  const b=parseV3Profile(sampleCapture({bodyText:'{"x":{"a":1}}'}),'json-utf8-v1',parseTree);
  assert.notDeepEqual(a.ordered_tree,b.ordered_tree);
});

test('structured query names cannot bypass a body-only profile or hide hard authentication slots',()=>{
  for(const name of ['{"token":"PRIVATE_SESSION_CANARY"}',' {"userSession":"PUBLIC_MARKER"}',
    '\ufeff{"token":"PRIVATE_SESSION_CANARY"}']){
    const capture=sampleCapture({target:'/bootstrap?'+encodeURIComponent(name)+'='});
    assert.throws(()=>parseV3Profile(capture,'json-utf8-v1',parseTree),/request-contract-unavailable/);
  }
});
test('capture schema, transport headers and private markers fail closed',()=>{
  for(const capture of [sampleCapture({extra:true}),sampleCapture({body_b64:'e30'}),
    sampleCapture({protection_refs:['1'.repeat(32)]}),sampleCapture({headers:[['Authorization','public']]}),
    sampleCapture({headers:[['X-Api-Key','public']]}),sampleCapture({headers:[['Cookie','pre=one']]}),
    sampleCapture({original_headers:[header('content-type','application/json'),header('Content-Type','application/json')]}),
    sampleCapture({effective_headers:[]}),sampleCapture({target:'/bootstrap?x=%ZZ'}),
    sampleCapture({body_b64:'/w=='})])assert.throws(()=>parseV3Profile(capture,'json-utf8-v1',parseTree));
});
test('unknown material never enters the safe public projection',()=>{
  const canary='private-low-entropy-canary';
  const capture=sampleCapture({target:`/${canary}`,bodyText:`{"${canary}":true}`,headers:[['x-public',canary]]});
  const view=parseV3Profile(capture,'json-utf8-v1',parseTree);
  const safe=safeV3Observation({network_ref:'1'.repeat(32),representation_ref:'2'.repeat(32),
    literal_review_refs:view.locations.map((_,i)=>(i+3).toString(16).padStart(32,'0'))},
    {origin:'https://fixture.example',account:'operator'});
  assert.equal(JSON.stringify(safe).includes(canary),false);
  assert.equal(JSON.stringify(safe).includes('body_b64'),false);
});
test('reference matching cannot accept partial or extra public fields',()=>{
  const capture=sampleCapture(),view=parseV3Profile(capture,'json-utf8-v1',parseTree);
  for(const ref of [{...publicReference(),body_text:'{}'}, {...publicReference(),extra:true},
    {...publicReference(),public_headers:[{name:'x-extra',value:'public'}]}])
    assert.equal(validatePublicReference(capture,view,ref).complete,false);
});
test('strict parser exact limits and one above are independent of reference caps',()=>{
  const parse=(body,extra={})=>parseV3Profile(sampleCapture({bodyText:body,...extra}),'json-utf8-v1',parseTree);
  assert.doesNotThrow(()=>parse('{}'+' '.repeat(16382)));
  assert.throws(()=>parse('{}'+' '.repeat(16383)));
  assert.doesNotThrow(()=>parse(JSON.stringify({['k'.repeat(128)]:true})));
  assert.throws(()=>parse(JSON.stringify({['k'.repeat(129)]:true})));
  assert.doesNotThrow(()=>parse(JSON.stringify({x:Array(31).fill(true)}),{target:'/'}));
  assert.throws(()=>parse(JSON.stringify({x:Array(32).fill(true)}),{target:'/'}),/setup-plan-capacity-required/);
  for(const body of ['{"a":"\\u0000"}','{"a":"\\ud800"}','{"a":1,}','[]','{"a":NaN}'])assert.throws(()=>parse(body));
  for(const body of ['{"a":1.0}','{"a":1e0}','{"a":-0}'])assert.doesNotThrow(()=>parse(body));
});
test('profile ceilings cover UTF-8, depth, collections, query and protected literals',()=>{
  const parse=(body,overrides={})=>parseV3Profile(sampleCapture({bodyText:body,...overrides}),'json-utf8-v1',parseTree);
  assert.doesNotThrow(()=>parse(JSON.stringify({x:'\u00e9'.repeat(128)})));
  assert.throws(()=>parse(JSON.stringify({x:'\u00e9'.repeat(129)})),/setup-plan-capacity-required/);
  assert.doesNotThrow(()=>parse(JSON.stringify({['\u00e9'.repeat(64)]:true})));
  assert.throws(()=>parse(JSON.stringify({['\u00e9'.repeat(65)]:true})),/request-contract-unavailable/);
  let value=true;for(let i=0;i<7;i++)value=[value];
  assert.doesNotThrow(()=>parse(JSON.stringify({x:value})));
  assert.throws(()=>parse(JSON.stringify({x:[value]})),/request-contract-unavailable/);
  assert.throws(()=>parse(JSON.stringify({x:Array(100).fill(true)})),/setup-plan-capacity-required/);
  assert.throws(()=>parse(JSON.stringify({x:Array(101).fill(true)})),/request-contract-unavailable/);
  assert.throws(()=>parse('{}',{target:'/bootstrap?x='+'a'.repeat(8190)}),/setup-plan-capacity-required/);
  assert.throws(()=>parse('{}',{target:'/bootstrap?x='+'a'.repeat(8191)}),/request-contract-unavailable/);
  for(const value of ['-----BEGIN PRIVATE KEY-----','ghp_synthetic','glpat-synthetic','sk-proj-synthetic'])
    assert.throws(()=>parse(JSON.stringify({x:value})),/request-contract-unavailable/);
});
test('forms decode once and pair spelling/order cannot inherit a reference',()=>{
  const profile='form-utf8-v1',ct='application/x-www-form-urlencoded';
  const a=parseV3Profile(sampleCapture({contentType:ct,bodyText:'x=%2520'}),profile,parseTree);
  assert.equal(a.ordered_tree.body.pairs[0][1],'%20');
  const b=parseV3Profile(sampleCapture({contentType:ct,bodyText:'x=a+b'}),profile,parseTree);
  assert.equal(b.ordered_tree.body.pairs[0][1],'a b');
  const c=parseV3Profile(sampleCapture({contentType:ct,bodyText:'x=a%2Bb'}),profile,parseTree);
  assert.equal(c.ordered_tree.body.pairs[0][1],'a+b');
  for(const raw of ['x=1&','&x=1','x=1&&y=2','=x','x=%00','x=%ED%A0%80'])
    assert.throws(()=>parseV3Profile(sampleCapture({contentType:ct,bodyText:raw}),profile,parseTree));
});

test('actual isolated Edge headers fit the approved complete 32-unit profile without exemptions',{timeout:30000},async()=>{
  const require=createRequire(import.meta.url),pw=require('../scripts/web-runtime/node_modules/playwright-core');
  const {browser,deny}=await launchEdge(pw,true);
  let unitCount=0;
  try{
    const context=await browser.newContext({ignoreHTTPSErrors:false,serviceWorkers:'block'});await context.setOffline(true);
    await context.route('**/*',async route=>{
      if(route.request().url()==='https://fixture.example/'){
        await route.fulfill({contentType:'text/html',body:'<!doctype html><title>Synthetic header admission</title>'});return;
      }
      if(route.request().url()!=='https://fixture.example/bootstrap'||route.request().method()!=='POST'){await route.abort();return;}
      let intent;
      try{
        intent=await captureInitializationIntent(route.request(),{origin:'https://fixture.example',cookie_context:null,protection_refs:[],secrets:[]});
        const frame=privateIntentFrame(intent),view=parseV3Profile(frame,'json-utf8-v1',parseTree);
        const nonfixed=frame.effective_headers.filter(row=>!['host','content-length','accept-encoding','content-type','cookie']
          .includes(Buffer.from(row.name_b64,'base64').toString()));
        unitCount=view.unit_count;
        assert.equal(unitCount,nonfixed.length*2+3,'Every non-fixed header name and value must still count');
        assert.ok(unitCount>8&&unitCount<=32);
        assert.equal(validatePublicReference(frame,view,publicReference()).matched,false,'Parsing alone cannot replace a complete independent wire reference');
      }finally{if(intent)disposeInitializationIntent(intent);await route.abort();}
    });
    const page=await context.newPage();await page.goto('https://fixture.example/');
    await page.evaluate(()=>fetch('/bootstrap',{method:'POST',headers:{'content-type':'application/json'},body:'{"mode":"public"}'}).catch(()=>null));
    assert.ok(unitCount>0);
  }finally{await browser.close();deny.close();}
});
