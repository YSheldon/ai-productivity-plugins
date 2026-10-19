import test from 'node:test';
import assert from 'node:assert/strict';

test('the production dispatcher refuses old content and navigation bypasses',async()=>{
  const {WorkerRuntime}=await import('../scripts/web_worker_runtime.mjs');
  const runtime=new WorkerRuntime({control:{admit:async()=>{}},registry:{},task:{},network:{},resume:async()=>{}});
  for(const operation of ['observe','read-result','navigate']){
    await assert.rejects(()=>runtime.dispatch({operation,arguments:{}}),/approval-required/);
  }
});

test('startup metadata and contracts never require an authenticated content read',async()=>{
  const {WorkerRuntime}=await import('../scripts/web_worker_runtime.mjs');
  const runtime=new WorkerRuntime({control:{admit:async()=>{throw new Error('authentication-required');}},registry:{},task:{},
    network:{phase:'bootstrap',list:()=>[{ref:'a'}]},resume:async()=>({ok:true,authenticationVerified:false})});
  assert.deepEqual(await runtime.dispatch({operation:'network-status',arguments:{}}),{ok:true,descriptors:[{ref:'a'}],phase:'bootstrap'});
  assert.equal((await runtime.dispatch({operation:'resume-login',arguments:{}})).authenticationVerified,false);
  await assert.rejects(()=>runtime.dispatch({operation:'components',arguments:{}}),/authentication-required/);
});

test('only private setup registration and original resume tickets reach the worker',async()=>{
  const {WorkerRuntime}=await import('../scripts/web_worker_runtime.mjs');
  let registered=null,ticket=null;
  const runtime=new WorkerRuntime({control:{admit:async()=>{throw new Error('authentication-required');}},registry:{},task:{},
    network:{preauthLifecycle:'b'.repeat(32),startupState:{register:value=>{registered=value;}}},resume:async value=>{ticket=value;return {ok:true};}});
  const request={resume_id:'a'.repeat(32),preauth_lifecycle:'b'.repeat(32),binding_digest:'c'.repeat(64),deadline_ms:Date.now()+45000};
  await runtime.dispatch({operation:'register-initialization',arguments:{contracts:{}}});assert.deepEqual(registered,{});
  await runtime.dispatch({operation:'resume-login',arguments:{startup:request}});assert.deepEqual(ticket,request);
  await assert.rejects(()=>runtime.dispatch({operation:'resume-login',arguments:{startup:request,script:'bad'}}));
  await assert.rejects(()=>runtime.dispatch({operation:'resume-login',arguments:{startup:{...request,script:'bad'}}}));
  await assert.rejects(()=>runtime.dispatch({operation:'resume-login',arguments:{startup:{...request,deadline_ms:Date.now()-1}}}));
});

test('a supervisor clock one millisecond ahead is narrowed rather than extending startup',async t=>{
  t.mock.method(Date,'now',()=>1000);
  const {WorkerRuntime}=await import('../scripts/web_worker_runtime.mjs');let received;
  const runtime=new WorkerRuntime({network:{preauthLifecycle:'b'.repeat(32)},
    resume:async ticket=>{received=ticket;return {ok:true};}});
  const ticket={resume_id:'a'.repeat(32),preauth_lifecycle:'b'.repeat(32),binding_digest:'c'.repeat(64),deadline_ms:46001};
  await runtime.dispatch({operation:'resume-login',arguments:{startup:ticket}});
  assert.equal(received.deadline_ms,46000);
  assert.equal(ticket.deadline_ms,46001,'The original supervisor ticket remains immutable');
});
