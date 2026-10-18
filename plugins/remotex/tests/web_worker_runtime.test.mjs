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
