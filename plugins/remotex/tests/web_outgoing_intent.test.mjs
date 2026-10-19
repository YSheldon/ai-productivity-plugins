import test from 'node:test';
import assert from 'node:assert/strict';
import {captureInitializationIntent,privateIntentFrame,withInitializationIntent,disposeInitializationIntent,
  createOwnedCookieContext,verifyInitializationCookieContext,privateIntentProfile} from '../scripts/web_outgoing_intent.mjs';
import {fakeRequest,capturePolicy,parseTree} from './fixtures/v3_test_support.mjs';

test('commitment and dispatch use one privately owned request snapshot',async()=>{
  const req=fakeRequest(),intent=await captureInitializationIntent(req,capturePolicy());
  req.replaceBody('{"mode":"changed"}');req.headers[0].value='text/plain';
  const frame=privateIntentFrame(intent);frame.body_b64='changed';frame.original_headers=[];
  const sent=await withInitializationIntent(intent,frozen=>({body:frozen.body.toString('utf8'),headers:frozen.headers,url:frozen.url}));
  assert.equal(sent.body,'{"mode":"public"}');
  assert.equal(sent.headers['content-type'],'application/json');
  assert.equal(privateIntentFrame(intent).body_b64,Buffer.from(sent.body).toString('base64'));
  assert.equal(req.calls.postDataBuffer,1);assert.equal(req.calls.headersArray,1);assert.equal(req.calls.url,1);
  assert.equal(JSON.stringify(intent),'{}');assert.equal(Object.keys(intent).length,0);
  disposeInitializationIntent(intent);
  assert.throws(()=>privateIntentFrame(intent),/request-contract-unavailable/);
  assert.throws(()=>withInitializationIntent(intent,()=>true),/request-contract-unavailable/);
});
test('capture rejects ambiguous, protected or unavailable header views',async()=>{
  for(const req of [fakeRequest({headers:[{name:'Content-Type',value:'application/json'},{name:'content-type',value:'application/json'}]}),
    fakeRequest({headers:[{name:'Content-Type',value:'application/json'},{name:'Authorization',value:'public'}]}),
    {...fakeRequest(),headersArray:undefined},fakeRequest({bodyText:'{"x":"synthetic-private"}'})]){
    await assert.rejects(captureInitializationIntent(req,capturePolicy({secrets:['synthetic-private']})),/request-contract-unavailable/);
  }
  await assert.rejects(captureInitializationIntent(fakeRequest(),capturePolicy({protection_refs:['1'.repeat(32)]})),/request-contract-unavailable/);
});
test('fixed egress is derived once and no caller exclusions are accepted',async()=>{
  const req=fakeRequest({headers:[{name:'Content-Type',value:'application/json'},{name:'Host',value:'fixture.example'},
    {name:'Accept-Encoding',value:'gzip'},{name:'Content-Length',value:'999'},{name:'Connection',value:'keep-alive'}]});
  const intent=await captureInitializationIntent(req,capturePolicy());
  await withInitializationIntent(intent,frozen=>{
    assert.equal(frozen.headers['accept-encoding'],'identity');assert.equal(frozen.headers['content-length'],'17');
    assert.equal(frozen.headers.connection,undefined);
    assert.equal(Object.isFrozen(frozen.headers),true);
  });
  await assert.rejects(captureInitializationIntent(fakeRequest(),capturePolicy({exclude_headers:['x-auth']})),/request-contract-unavailable/);
});

function cookieCase(){
  let cookies=[{name:'fixture_preauth',value:'private-cookie-canary',domain:'fixture.example',path:'/',
    expires:-1,httpOnly:true,secure:true,sameSite:'Strict'}];
  const context={cookies:async()=>structuredClone(cookies)};
  const resolver=createOwnedCookieContext(context,'https://fixture.example',()=>false);
  return {resolver,set:change=>{cookies=change(cookies);}};
}
test('cookie intent belongs to one original jar and its complete available attribute epoch',async()=>{
  const c=cookieCase();
  const req=fakeRequest({headers:[{name:'Content-Type',value:'application/json'},
    {name:'Cookie',value:'fixture_preauth=private-cookie-canary'}]});
  const intent=await captureInitializationIntent(req,capturePolicy({cookie_context:c.resolver}));
  assert.match(privateIntentFrame(intent).cookie_context.jar_ref,/^[a-f0-9]{32}$/);
  await verifyInitializationCookieContext(intent);
  c.set(rows=>rows.map(row=>({...row,sameSite:'Lax'})));
  await assert.rejects(()=>verifyInitializationCookieContext(intent),/scope-mismatch/);
  c.resolver.dispose();disposeInitializationIntent(intent);
});
test('foreign cookie bytes and private cookie/credential values outside their carrier stay ineligible',async()=>{
  const c=cookieCase();
  await assert.rejects(captureInitializationIntent(fakeRequest({headers:[{name:'Content-Type',value:'application/json'},
    {name:'Cookie',value:'foreign=not-in-original-jar'}]}),capturePolicy({cookie_context:c.resolver})),/request-contract-unavailable/);
  await assert.rejects(captureInitializationIntent(fakeRequest({bodyText:'{"x":"private-cookie-canary"}'}),
    capturePolicy({cookie_context:c.resolver})),/request-contract-unavailable/);
  await assert.rejects(captureInitializationIntent(fakeRequest({bodyText:'x=pr%69vate-cookie-canary',
    headers:[{name:'Content-Type',value:'application/x-www-form-urlencoded'}]}),capturePolicy({cookie_context:c.resolver})),/request-contract-unavailable/);
  await assert.rejects(captureInitializationIntent(fakeRequest({headers:[{name:'Content-Type',value:'application/json'},
    {name:'Cookie',value:'fixture_preauth=private-cookie-canary'}]}),capturePolicy({cookie_context:c.resolver,secrets:['private-cookie-canary']})),/request-contract-unavailable/);
  c.resolver.dispose();
});
test('decoded JSON private material cannot hide behind a different public wire spelling',async()=>{
  const intent=await captureInitializationIntent(fakeRequest({bodyText:'{"x":"pri\\u0076ate-password"}'}),
    capturePolicy({secrets:['private-password']}));
  assert.throws(()=>privateIntentProfile(intent,'json-utf8-v1',parseTree),/credential-in-unsupported-field/);
  disposeInitializationIntent(intent);
});
test('fixed parser type labels are not mistaken for private request data',async()=>{
  const intent=await captureInitializationIntent(fakeRequest(),capturePolicy({secrets:['object']}));
  assert.doesNotThrow(()=>privateIntentProfile(intent,'json-utf8-v1',parseTree));
  disposeInitializationIntent(intent);
});
