import test from 'node:test';
import assert from 'node:assert/strict';

let ipc;
try {ipc=await import('../scripts/web_authorization_ipc.mjs');}catch(error){if(error.code!=='ERR_MODULE_NOT_FOUND')throw error;}

test('worker permits need a matching private reply and are consumed once',async()=>{
  assert.ok(ipc,'The private worker authorization pump is not implemented');
  const frames=[];const authority=new ipc.WorkerAuthority({emit:frame=>frames.push(frame),onRevoke:()=>{}});
  const pending=authority.check({phase:'discovery-only'});
  assert.equal(frames[0].event,'authorization-check');
  assert.equal(authority.handle({authorization_reply:'0'.repeat(32),allowed:true}),false);
  assert.equal(authority.handle({authorization_reply:frames[0].id,allowed:true}),true);
  assert.equal(await pending,true);
  assert.equal(authority.handle({authorization_reply:frames[0].id,allowed:true}),false);
  authority.dispose();
});

test('revocation independently resolves pending requests to deny',async()=>{
  assert.ok(ipc);
  const frames=[],revocations=[];
  const authority=new ipc.WorkerAuthority({emit:frame=>frames.push(frame),onRevoke:generation=>revocations.push(generation)});
  const pending=authority.check({phase:'grant-active'});
  assert.equal(authority.handle({control_event:'revoke',generation:1}),true);
  assert.equal(await pending,false);
  assert.deepEqual(revocations,[1]);
  assert.equal(authority.handle({authorization_reply:frames[0].id,allowed:true}),false);
  assert.equal(authority.handle({control_event:'revoke',generation:0}),false);
  authority.dispose();
});

test('closing the worker denies authority without a replay',async()=>{
  assert.ok(ipc);
  const frames=[];const authority=new ipc.WorkerAuthority({emit:frame=>frames.push(frame),onRevoke:()=>{}});
  const pending=authority.check({phase:'bootstrap'});authority.dispose();
  assert.equal(await pending,false);
  assert.equal(await authority.check({phase:'bootstrap'}),false);
  assert.equal(frames.length,1);
});
