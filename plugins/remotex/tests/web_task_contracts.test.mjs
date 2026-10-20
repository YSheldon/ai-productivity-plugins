import test from 'node:test';
import assert from 'node:assert/strict';
import {setupContracts,taskContracts} from '../scripts/web_task_contracts.mjs';
import * as contracts from '../scripts/web_task_contracts.mjs';
import {guardRoute} from '../scripts/web_login_worker.mjs';
import {sampleCapture,parseTree} from './fixtures/v3_test_support.mjs';

const descriptor={method:'POST',path:'/dispatch',query:{},contentType:'application/json',
  body:{cmd:'move',ids:['host-one'],group:'New Group'},resourceType:'xhr'};
const proof=[{kind:'operator-inspected',reference:'Reviewed synthetic handler only'}];

function v3SetupCase(){
  const refs=Array.from({length:5},(_,i)=>(i+3).toString(16).padStart(32,'0'));
  const capture=sampleCapture({bodyText:'{"private-low-entropy-canary":true}'});
  const network={phase:'bootstrap',preauthLifecycle:'a'.repeat(32),parseTree,
    resolveV3:(ref,representation,fields)=>{
      assert.equal(ref,'b'.repeat(32));assert.equal(representation,'c'.repeat(32));assert.deepEqual(fields,refs);
      return {capture,profile_id:'json-utf8-v1',representation_ref:representation,literal_review_refs:refs};
    }};
  const setup={revision:3,phase:'bootstrap',requests:[{network_ref:'b'.repeat(32),representation_ref:'c'.repeat(32),
    literal_review_refs:refs,purpose:'initialization-read',max_uses:2,evidence:proof,
    response_checks:[{pointer:'/ready',test:'equals-boolean',expected:true}]}]};
  return {setup,network,capture};
}

test('revision3 exposes safe exact-ref contracts and sends private captures only on private resolution',()=>{
  const {setup,network,capture}=v3SetupCase();
  const result=setupContracts(setup,network),contract=result.contracts['setup.network.1'];
  assert.equal(result.setup_revision,3);assert.equal(contract.revision,3);assert.equal(contract.required,true);
  assert.equal(contract.intent_ref,'c'.repeat(32));assert.equal(contract.profile_id,'json-utf8-v1');
  assert.deepEqual(result.private_initialization['setup.network.1'],capture);
  const publicScope=JSON.stringify({items:result.items,contracts:result.contracts,prerequisites:result.prerequisites});
  assert.equal(publicScope.includes('private-low-entropy-canary'),false);
  assert.equal(publicScope.includes(capture.body_b64),false);
  assert.equal(publicScope.includes('target_b64'),false);
  assert.deepEqual(setupContracts(setup,network),result,'Idempotent resolution must not invent new scope IDs');
});
test('revision3 public declarations cannot supply raw values, verdicts, replacements or partial coverage',()=>{
  const {setup,network}=v3SetupCase();
  for(const change of [{...setup,replace_grant_ids:[]},{...setup,resources:[]},{...setup,revision:4},
    {...setup,requests:[{...setup.requests[0],body:'public'}]},
    {...setup,requests:[{...setup.requests[0],public_invariant:true}]},
    {...setup,requests:[{...setup.requests[0],profile_id:'json-utf8-v1'}]},
    {...setup,requests:[{...setup.requests[0],purpose:'bootstrap-resource'}]},
    {...setup,requests:[{...setup.requests[0],literal_review_refs:[]}]},
    {...setup,requests:[setup.requests[0],setup.requests[0]]}])assert.throws(()=>setupContracts(change,network));
});

test('revision2 exact init purpose keeps legacy Bootstrap POST denied',()=>{
  const post={...descriptor,body:{cmd:'database_info'}};
  const network={phase:'bootstrap',preauthLifecycle:'a'.repeat(32),resolve:()=>post};
  const setup={revision:2,phase:'bootstrap',requests:[{network_ref:'b'.repeat(32),
    purpose:'initialization-read',max_uses:2,evidence:proof,
    response_checks:[{pointer:'/exist',test:'equals-boolean',expected:true}]}],replace_grant_ids:[]};
  const result=setupContracts(setup,network),contract=result.contracts['setup.network.1'];
  assert.equal(result.setup_revision,2);assert.equal(contract.semantics,'initialization-read');
  assert.deepEqual(contract.phase_applicability,['bootstrap','login-once']);
  assert.equal(contract.required,true);assert.equal(contract.preauth_lifecycle,'a'.repeat(32));
  assert.equal(result.items[0].parameters.review_kind,'initialization-read');
  assert.throws(()=>setupContracts({phase:'bootstrap',network_refs:['a'],evidence:proof},network));
  for(const changed of [{...setup,network_refs:['a']},{...setup,revision:3},
    {...setup,phase_applicability:['grant-active']},
    {...setup,requests:[{...setup.requests[0],purpose:'bootstrap-resource'}]},
    {...setup,requests:[setup.requests[0],setup.requests[0]]},
    {...setup,replace_grant_ids:['c'.repeat(32),'c'.repeat(32)]}])
    assert.throws(()=>setupContracts(changed,network));
});

test('revision2 static resources cannot carry internal authentication slots',()=>{
  const descriptor={method:'GET',path:'/app.js',query:{token:{internalAuth:true}},
    contentType:'',body:null,resourceType:'script'};
  assert.throws(()=>setupContracts({revision:2,phase:'bootstrap',requests:[{network_ref:'b'.repeat(32),
    purpose:'bootstrap-resource',evidence:proof}]},{phase:'bootstrap',preauthLifecycle:'a'.repeat(32),resolve:()=>descriptor}));
});

test('equivalent readiness check key ordering keeps the prerequisite identity stable',()=>{
  const descriptor={method:'POST',path:'/init',query:{},contentType:'application/json',body:{cmd:'info'},resourceType:'xhr'};
  const network={phase:'bootstrap',preauthLifecycle:'a'.repeat(32),resolve:()=>descriptor};
  const setup=check=>({revision:2,phase:'bootstrap',requests:[{network_ref:'b'.repeat(32),purpose:'initialization-read',
    evidence:proof,response_checks:[check]}]});
  const first=setupContracts(setup({pointer:'/exist',test:'equals-boolean',expected:true}),network);
  const second=setupContracts(setup({expected:true,test:'equals-boolean',pointer:'/exist'}),network);
  assert.deepEqual(first.prerequisites,second.prerequisites);
});

test('bootstrap contracts never authorize business requests or credential submission',()=>{
  const network={phase:'bootstrap',resolve:()=>descriptor};
  assert.throws(()=>setupContracts({phase:'bootstrap',network_refs:['a'],evidence:proof},network),/request-contract-unavailable/);
  const root={...descriptor,method:'GET',body:null,path:'/',contentType:'',resourceType:'document'};
  const result=setupContracts({phase:'bootstrap',network_refs:['a'],evidence:proof},{...network,resolve:()=>root});
  assert.equal(result.items.length,1);
  assert.equal(result.contracts['setup.network.1'].phase,'bootstrap');
  assert.throws(()=>setupContracts({phase:'login-once',network_refs:['a'],evidence:proof},network),/request-invalid/);
});

test('network sub-items are independently approved with actual target scope and evidence',()=>{
  const scope={item_id:'move',capability:'web.business_action',targets:['host-one'],max_uses:1,
    parameters:{action_draft_ref:'draft',network_refs:['request']}};
  const result=taskContracts([scope],[{}],{resolve:()=>descriptor},new Map([['draft',{effect:{evidence:proof},
    changes:[{field:'group',after:'New Group'}],network_bindings:[{network_ref:'request',target_path:['body','ids'],change_paths:{group:['body','group']}}]}]]));
  assert.equal(result.items.length,2);
  assert.deepEqual(result.contracts['move.network.1'].targets,['host-one']);
  assert.equal(result.contracts['move.network.1'].semantics,'write');
  assert.equal(result.items[1].max_uses,1);
  assert.match(result.items[1].display.preview,/New Group/);
  assert.throws(()=>taskContracts([{...scope,capability:'web.page_step'}],[{}],{resolve:()=>descriptor},new Map()),/request-contract-unavailable/);
});

test('request permit denial aborts before the route can send headers or a body',async()=>{
  let sent=0,aborted=0;
  const route={request:()=>({url:()=> 'https://console.example/dispatch'}),
    fetch:async()=>{sent++;throw new Error('must-not-send');},abort:async()=>aborted++};
  await guardRoute(route,'https://console.example',()=>{},undefined,undefined,undefined,
    {authorize:async()=>false});
  assert.equal(sent,0);assert.equal(aborted,1);
});

test('a denied top-level document receives only an inert local 403 without remote transmission',async()=>{
  let sent=0,aborted=0,fulfilled;
  const owner={},frame={page:()=>owner,parentFrame:()=>null};
  const route={request:()=>({url:()=> 'https://console.example/',isNavigationRequest:()=>true,frame:()=>frame}),
    fetch:async()=>{sent++;throw new Error('must-not-send');},abort:async()=>aborted++,
    fulfill:async value=>{fulfilled=value;}};
  await guardRoute(route,'https://console.example',()=>{},undefined,undefined,undefined,
    {authorize:async()=>false},owner);
  assert.equal(sent,0);assert.equal(aborted,0);assert.equal(fulfilled?.status,403);
  assert.equal(fulfilled.headers['cache-control'],'no-store');
  assert.match(fulfilled.headers['content-security-policy'],/default-src 'none'/);
  assert.ok(!fulfilled.body.includes('<script'));
});

test('a popup cannot borrow the owned page request permit or its local document response',async()=>{
  let sent=0,aborted=0,checked=0;
  const owner={},frame={page:()=>({}),parentFrame:()=>null};
  const route={request:()=>({url:()=> 'https://console.example/',isNavigationRequest:()=>true,frame:()=>frame}),
    fetch:async()=>sent++,abort:async()=>aborted++,fulfill:async()=>sent++};
  await guardRoute(route,'https://console.example',()=>{},undefined,undefined,undefined,
    {authorize:async()=>{checked++;return true;}},owner);
  assert.deepEqual({sent,aborted,checked},{sent:0,aborted:1,checked:0});
});

test('a cancellation after a permit reply still prevents forwarding',async()=>{
  let sent=0;
  const abort=new AbortController();
  const route={request:()=>({url:()=> 'https://console.example/dispatch'}),
    fetch:async()=>{sent++;throw new Error('must-not-send');},abort:async()=>{}};
  await guardRoute(route,'https://console.example',()=>{},undefined,abort.signal,undefined,
    {authorize:async()=>{abort.abort();return true;}});
  assert.equal(sent,0);
});

test('write bindings must bind every target and approved changed value without hidden extra targets',()=>{
  assert.equal(typeof contracts.bindWriteContract,'function');
  const targets=['host-one','host-two'];
  const body={...descriptor,body:{cmd:'move',ids:targets,group:'New Group'}};
  const binding={target_path:['body','ids'],change_paths:{group:['body','group']}};
  const resolved=contracts.bindWriteContract(body,{targets,changes:{group:'New Group'}},binding);
  assert.deepEqual(resolved.target_path,['body','ids']);
  assert.throws(()=>contracts.bindWriteContract({...body,body:{...body.body,group:'Another Group'}},
    {targets,changes:{group:'New Group'}},binding),/scope-mismatch/);
  assert.throws(()=>contracts.bindWriteContract({...body,body:{...body.body,extra_ids:targets}},
    {targets,changes:{group:'New Group'}},binding),/scope-mismatch/);
  assert.throws(()=>contracts.bindWriteContract(body,{targets,changes:{group:'New Group'}},
    {target_path:['body','ids'],change_paths:{}}),/scope-mismatch/);
});
