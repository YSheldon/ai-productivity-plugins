import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {NetworkPolicy} from '../scripts/web_network_authorization.mjs';
import {WorkerAuthority} from '../scripts/web_authorization_ipc.mjs';
import {StartupState} from '../scripts/web_startup_state.mjs';
import {setupContracts} from '../scripts/web_task_contracts.mjs';
import {privateIntentFrame,withInitializationIntent} from '../scripts/web_outgoing_intent.mjs';
import {fakeRequest,parseTree} from './fixtures/v3_test_support.mjs';

const origin='https://fixture.example';
function request(body='{"userSession":"PUBLIC_MARKER"}',target='/bootstrap',extra=[]){
  const headers=[{name:'Content-Type',value:'application/json'},...extra];
  const req=fakeRequest({bodyText:body,target,headers});
  req.headers=()=>Object.fromEntries(headers.map(row=>[row.name.toLowerCase(),row.value]));req.postData=()=>body;
  return req;
}
function policyCase(){
  const calls=[];
  const policy=new NetworkPolicy({origin,secret:'synthetic-password-only',requestPermit:async frame=>{calls.push(frame);return false;}});
  policy.parseTree=parseTree;
  return {policy,calls};
}
function setup(row){
  const representation=row.representations.find(value=>value.profile_id==='json-utf8-v1');
  return {revision:3,phase:'bootstrap',requests:[{network_ref:row.ref,purpose:'initialization-read',
    representation_ref:representation.representation_ref,literal_review_refs:representation.literal_review_refs,
    max_uses:2,response_checks:[{pointer:'/ready',test:'equals-boolean',expected:true}],
    evidence:[{kind:'verified-record',reference:'independent-synthetic-source'}]}]};
}

test('preauth v3 discovery exposes opaque refs only and cannot downgrade a sensitive request',async()=>{
  const {policy,calls}=policyCase();
  const req=request(undefined,'/private-path-canary',[{name:'X-Private-Header',value:'private-header-canary'}]);
  assert.equal(await policy.authorize(req),false);
  const rows=policy.list();assert.equal(rows.length,1);
  const safe=JSON.stringify(rows);
  for(const canary of ['userSession','PUBLIC_MARKER','private-path-canary','private-header-canary','x-private-header'])assert.equal(safe.includes(canary),false);
  assert.equal(calls.length,0,'A v3-only denied observation is not a legacy permit attempt');
  assert.ok(rows[0].representations.length);assert.deepEqual(rows[0].setup_revisions,[3]);
  const declaration=setup(rows[0]),resolved=setupContracts(declaration,policy);
  const capture=resolved.private_initialization['setup.network.1'];
  const privateHash=createHash('sha256').update(JSON.stringify(capture)).digest('hex');
  assert.equal(safe.includes(privateHash),false);
  assert.throws(()=>policy.resolve(rows[0].ref),/request-contract-unavailable/);
  assert.throws(()=>policy.resolveV3(rows[0].ref,'0'.repeat(32),declaration.requests[0].literal_review_refs));
  assert.throws(()=>policy.resolveV3(rows[0].ref,declaration.requests[0].representation_ref,[]));
  assert.equal(req.calls.postDataBuffer,1);assert.equal(req.calls.headersArray,1);
  policy.fence();
});

test('known original auth slots and decoded password material never acquire v3 representations',async()=>{
  for(const body of ['{"token":"public"}','{"x":"synthetic-pass\\u0077ord-only"}']){
    const {policy}=policyCase();await policy.authorize(request(body));
    for(const row of policy.list())assert.deepEqual(row.representations??[],[]);
    policy.fence();
  }
});

test('an escaped known password in a structured query key never acquires a representation',async()=>{
  const {policy}=policyCase();
  const key='{"token":"synthetic-pass\\u0077ord-only"}';
  await policy.authorize(request('{"mode":"public"}','/bootstrap?'+encodeURIComponent(key)+'='));
  assert.deepEqual(policy.list(),[]);
  policy.fence();
});

test('v3 observations retain the unchanged 120-second TTL and do not refresh on listing',async t=>{
  let now=1000;t.mock.method(Date,'now',()=>now);
  const {policy}=policyCase();await policy.authorize(request());const original=policy.list()[0].ref;
  now+=119999;assert.equal(policy.list()[0].ref,original);
  now+=2;assert.deepEqual(policy.list(),[]);
  policy.fence();
});

test('legacy-safe denied requests retain a live private v3 snapshot after the permit await',async()=>{
  const {policy}=policyCase();
  try{
    await policy.authorize(request('{"mode":"public"}'));
    const row=policy.list()[0];assert.ok(row.representations.length);
    assert.equal(row.path,'/bootstrap','Legacy-safe discovery retains its existing descriptor fields');
    assert.doesNotThrow(()=>setupContracts(setup(row),policy));
  }finally{policy.fence();}
});

test('expired private observations dispose their owned bytes on ordinary cache eviction',async t=>{
  let now=1000;t.mock.method(Date,'now',()=>now);
  const {policy}=policyCase();await policy.authorize(request());
  const handle=[...policy.pending.values()][0].intent;
  now+=120001;
  await policy.authorize({url:()=>origin+'/asset.js',method:()=> 'GET',postData:()=>'',headers:()=>({}),resourceType:()=> 'script'});
  assert.throws(()=>privateIntentFrame(handle),/request-contract-unavailable/);
  policy.fence();
});

test('an expired startup cannot start another private body or cookie capture',async()=>{
  const policy=new NetworkPolicy({origin,startup:()=>({deadline:Date.now()-1}),requestPermit:async()=>false});
  policy.parseTree=parseTree;const req=request();
  assert.equal(await policy.authorize(req),false);
  assert.equal(req.calls.postDataBuffer,0);assert.equal(req.calls.headersArray,0);
  policy.fence();
});

test('approved v3 forwarding consumes an original typed receipt and uses the new frozen request',async()=>{
  let context=null,contract;
  const frames=[];
  const authority=new WorkerAuthority({startup:()=>context,onRevoke:()=>{},emit:frame=>{
    frames.push(frame);
    if(!context){queueMicrotask(()=>authority.handle({authorization_reply:frame.id,allowed:false}));return;}
    queueMicrotask(()=>authority.handle({authorization_reply:frame.id,allowed:true,permit:{
      kind:'initialization-permit-v3',version:3,check_id:frame.id,binding_digest:context.binding_digest,
      grant_id:'1'.repeat(32),item_id:'setup.network.1',intent_ref:contract.intent_ref,intent_commitment:'2'.repeat(64),
      receipt_id:'3'.repeat(32),permit_commitment:'4'.repeat(64),prerequisite_id:contract.prerequisite_id,
      preauth_lifecycle:context.preauth_lifecycle,resume_id:context.resume_id,document_id:context.document_id,
      generation:context.generation,expires_at_ms:Date.now()+9000,response_checks:contract.response_checks}}));
  }});
  const policy=new NetworkPolicy({origin,secret:'synthetic-password-only',startup:()=>context,
    requestPermit:(value,options)=>authority.checkNetwork({kind:'network',...value},options),
    consumeReceipt:(receipt,expected)=>authority.consumeNetworkReceipt(receipt,expected)});
  policy.parseTree=parseTree;policy.startupState=new StartupState({lifecycle:policy.preauthLifecycle});
  try{
    await policy.authorize(request());const plan=setupContracts(setup(policy.list()[0]),policy);
    contract=plan.contracts['setup.network.1'];
    policy.holdSetup(3);policy.registerV3Contracts(plan.contracts);policy.startupState.register(plan.contracts);policy.releaseSetup();
    const controller=new AbortController();
    context={policy,phase:policy.phase,generation:policy.generation,preauth_lifecycle:policy.preauthLifecycle,
      resume_id:'a'.repeat(32),document_id:'b'.repeat(32),binding_digest:'c'.repeat(64),deadline:Date.now()+45000,signal:controller.signal};
    policy.startupState.open(context);
    const current=request();assert.equal(await policy.authorize(current),true);
    current.postDataBuffer=()=>{throw new Error('No browser reread');};current.postData=()=>{throw new Error('No browser reread');};
    const completed=policy.beginForwarding(current);
    assert.equal(completed.initialization.kind,'initialization-permit-v3');assert.ok(completed.intent);
    assert.equal(policy.authenticationForwarded,0);assert.equal(policy.initializationForwarded,1);
    await withInitializationIntent(completed.intent,frozen=>assert.equal(frozen.body.toString(),'{"userSession":"PUBLIC_MARKER"}'));
    assert.equal(privateIntentFrame(completed.intent).method,'POST');
    completed();assert.equal(current.calls.postDataBuffer,1);
    assert.throws(()=>policy.beginForwarding(current));
  }finally{policy.fence();authority.dispose();}
});
