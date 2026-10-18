import test from 'node:test';
import assert from 'node:assert/strict';
import {NetworkPolicy} from '../scripts/web_network_authorization.mjs';

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
  assert.equal(authority.handle({authorization_reply:frames[0].id,allowed:true}),true);
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

const flush=()=>new Promise(resolve=>setImmediate(resolve));

function startupFixture(t){
  t.mock.timers.enable({apis:['Date','setTimeout'],now:1000});
  const frames=[],controller=new AbortController();
  const policy=new NetworkPolicy({origin:'https://console.example',requestPermit:async()=>false});
  let context={policy,phase:'bootstrap',generation:0,deadline:46000,signal:controller.signal};
  const authority=new ipc.WorkerAuthority({emit:frame=>frames.push(frame),
    onRevoke:()=>policy.fence(),startup:()=>context});
  t.after(()=>authority.dispose());
  const request=(index,updates={})=>({kind:'network',phase:'bootstrap',attempt_id:null,
    descriptor:{method:'GET',path:`/assets/${index}.js`,query:{},contentType:'',body:null,resourceType:'script'},
    digest:'d'.repeat(64),...updates});
  return {authority,frames,controller,policy,request,get context(){return context;},replace:value=>{context=value;}};
}

test('a timed-out own reply is consumed once without reviving its denied check',async t=>{
  t.mock.timers.enable({apis:['Date','setTimeout'],now:1000});
  const frames=[],authority=new ipc.WorkerAuthority({emit:frame=>frames.push(frame),onRevoke:()=>{}});
  t.after(()=>authority.dispose());
  const pending=authority.check({phase:'discovery-only'});
  t.mock.timers.tick(10001);
  assert.equal(await pending,false);
  assert.equal(authority.handle({authorization_reply:frames[0].id,allowed:true}),true);
  assert.equal(authority.handle({authorization_reply:frames[0].id,allowed:true}),false);
  assert.equal(frames.length,1,'a late permit must not emit a command or retry');
});

test('cancelled emitted checks consume their late reply but never grant permission',async t=>{
  const frames=[],controller=new AbortController();
  const authority=new ipc.WorkerAuthority({emit:frame=>frames.push(frame),onRevoke:()=>{}});
  t.after(()=>authority.dispose());
  let verdict;
  const pending=authority.check({phase:'discovery-only'},{signal:controller.signal}).then(value=>{verdict=value;});
  controller.abort();await flush();
  assert.equal(verdict,false);
  assert.equal(authority.handle({authorization_reply:frames[0].id,allowed:true}),true);
  await pending;
});

test('malformed and unknown replies cannot consume a known expired check',async t=>{
  t.mock.timers.enable({apis:['Date','setTimeout'],now:1000});
  const frames=[],authority=new ipc.WorkerAuthority({emit:frame=>frames.push(frame),onRevoke:()=>{}});
  t.after(()=>authority.dispose());
  const pending=authority.check({phase:'discovery-only'});t.mock.timers.tick(10001);await pending;
  assert.equal(authority.handle({authorization_reply:frames[0].id,allowed:'true'}),false);
  assert.equal(authority.handle({authorization_reply:'0'.repeat(32),allowed:true}),false);
  assert.equal(authority.handle({authorization_reply:frames[0].id,allowed:true,extra:1}),false);
  assert.equal(authority.handle({authorization_reply:frames[0].id,allowed:false}),true);
});

test('expired reply metadata has a bounded 64-entry capacity and 60-second lifetime',async t=>{
  t.mock.timers.enable({apis:['Date','setTimeout'],now:1000});
  const frames=[],authority=new ipc.WorkerAuthority({emit:frame=>frames.push(frame),onRevoke:()=>{}});
  t.after(()=>authority.dispose());
  for(let batch=0;batch<4;batch++){
    const pending=Array.from({length:16},()=>authority.check({phase:'discovery-only'}));
    t.mock.timers.tick(10001);assert.deepEqual(await Promise.all(pending),Array(16).fill(false));
  }
  const controller=new AbortController();
  let lastVerdict;
  const last=authority.check({phase:'discovery-only'},{signal:controller.signal}).then(value=>{lastVerdict=value;});
  controller.abort();await flush();assert.equal(lastVerdict,false);await last;
  assert.equal(authority.handle({authorization_reply:frames[0].id,allowed:true}),false,'oldest metadata must be evicted');
  assert.equal(authority.handle({authorization_reply:frames[1].id,allowed:true}),true);
  t.mock.timers.tick(60001);
  assert.equal(authority.handle({authorization_reply:frames.at(-1).id,allowed:true}),false,'metadata must not renew authority');
});

test('ordinary checks retain the 16-emitted-check limit',async t=>{
  const frames=[],authority=new ipc.WorkerAuthority({emit:frame=>frames.push(frame),onRevoke:()=>{}});
  t.after(()=>authority.dispose());
  const pending=Array.from({length:16},()=>authority.check({phase:'grant-active'}));
  assert.equal(await authority.check({phase:'grant-active'}),false);
  assert.equal(frames.length,16);
  for(const frame of frames)authority.handle({authorization_reply:frame.id,allowed:false});
  assert.deepEqual(await Promise.all(pending),Array(16).fill(false));
});

test('15 pre-auth static checks retain FIFO order across the initial check and queued batch',async t=>{
  const f=startupFixture(t);
  const pending=Array.from({length:15},(_,index)=>f.authority.check(f.request(index)));
  assert.equal(f.frames.length,1,'startup fan-in must not create 15 simultaneous reply deadlines');
  assert.equal(f.frames[0].request.descriptor.path,'/assets/0.js');
  t.mock.timers.tick(1500);
  f.authority.handle({authorization_reply:f.frames[0].id,allowed:true});await flush();
  assert.deepEqual(f.frames[1].checks.map(row=>row.request.descriptor.path),
    Array.from({length:14},(_,index)=>`/assets/${index+1}.js`));
  t.mock.timers.tick(1500);f.authority.handle(batchReply(f.frames[1]));await flush();
  assert.deepEqual(await Promise.all(pending),Array(15).fill(true));
});

test('47 competing static checks cannot starve the 15 approved core assets',async t=>{
  const f=startupFixture(t);
  const pending=Array.from({length:47},(_,index)=>f.authority.check(f.request(index)));
  assert.equal(f.frames.length,1);
  f.authority.handle({authorization_reply:f.frames[0].id,allowed:false});await flush();
  const paths=['/assets/0.js'];
  for(let group=1;group<=3;group++){
    const frame=f.frames[group];paths.push(...frame.checks.map(row=>row.request.descriptor.path));
    t.mock.timers.tick(1500);
    f.authority.handle(batchReply(frame,index=>Number(frame.checks[index].request.descriptor.path.match(/(\d+)\.js$/)[1])>=32));await flush();
  }
  assert.deepEqual(paths,Array.from({length:47},(_,index)=>`/assets/${index}.js`));
  assert.deepEqual(await Promise.all(pending),[...Array(32).fill(false),...Array(15).fill(true)]);
});

test('startup queue overflow denies the 65th check and cancellation clears queued work',async t=>{
  const f=startupFixture(t);
  const pending=Array.from({length:64},(_,index)=>f.authority.check(f.request(index)));
  assert.equal(f.frames.length,1);
  assert.equal(await f.authority.check(f.request(64)),false);
  f.controller.abort();await flush();
  assert.deepEqual(await Promise.all(pending),Array(64).fill(false));
  assert.equal(f.frames.length,1);
  assert.equal(f.authority.handle({authorization_reply:f.frames[0].id,allowed:true}),true);
});

test('one absolute startup deadline cannot be extended by mutating its context',async t=>{
  const f=startupFixture(t);
  const pending=[f.authority.check(f.request(0)),f.authority.check(f.request(1))];
  f.context.deadline=900000;
  t.mock.timers.tick(45001);await flush();
  assert.deepEqual(await Promise.all(pending),[false,false]);
  assert.equal(f.frames.length,1);
  assert.equal(f.authority.handle({authorization_reply:f.frames[0].id,allowed:true}),true);
});

test('an expired startup context stays closed after the wall clock moves backwards',async t=>{
  const f=startupFixture(t);
  const expired=f.authority.check(f.request(0));
  t.mock.timers.tick(45001);assert.equal(await expired,false);
  t.mock.method(Date,'now',()=>1000);
  let verdict;
  const later=f.authority.check(f.request(1)).then(value=>{verdict=value;});
  await flush();assert.equal(verdict,false);await later;
  assert.equal(f.frames.length,1);
});

test('a replacement startup context cancels old checks instead of rebasing them',async t=>{
  const f=startupFixture(t);
  const results=[];
  const old=[0,1].map(index=>f.authority.check(f.request(index)).then(value=>{results[index]=value;}));
  t.mock.timers.tick(1000);
  f.replace({...f.context,deadline:47000,signal:new AbortController().signal});
  const fresh=f.authority.check(f.request(2));await flush();
  assert.deepEqual(results,[false,false]);await Promise.all(old);
  assert.equal(f.frames.length,2);
  assert.equal(f.frames[1].request.descriptor.path,'/assets/2.js');
  assert.equal(f.authority.handle({authorization_reply:f.frames[0].id,allowed:true}),true);
  f.authority.handle({authorization_reply:f.frames[1].id,allowed:true});assert.equal(await fresh,true);
});

test('phase changes deny both the in-flight static check and its queued successor',async t=>{
  const f=startupFixture(t);
  const results=[];
  const pending=[0,1].map(index=>f.authority.check(f.request(index)).then(value=>{results[index]=value;}));
  f.policy.setPhase('login-once');
  f.authority.handle({authorization_reply:f.frames[0].id,allowed:true});await flush();
  assert.deepEqual(results,[false,false]);await Promise.all(pending);assert.equal(f.frames.length,1);
});

test('revocation stops queued startup work without waiting for broker replies',async t=>{
  const f=startupFixture(t);let results=[];
  const pending=[0,1,2].map(index=>f.authority.check(f.request(index)).then(value=>results.push(value)));
  f.authority.handle({control_event:'revoke',generation:1});await flush();
  assert.deepEqual(results,[false,false,false]);assert.equal(f.frames.length,1);
  assert.equal(f.authority.handle({authorization_reply:f.frames[0].id,allowed:true}),true);
  await Promise.all(pending);
});

test('login POST and business checks do not inherit the static queue waiting budget',async t=>{
  const f=startupFixture(t);
  const statics=[f.authority.check(f.request(0)),f.authority.check(f.request(1))];
  const post=f.authority.check(f.request(2,{phase:'login-once',descriptor:{method:'POST',path:'/login',query:{},contentType:'application/json',body:{password:{internalAuth:true}},resourceType:'xhr'}}));
  assert.equal(f.frames.length,2);assert.equal(f.frames[1].request.descriptor.method,'POST');
  t.mock.timers.tick(10001);assert.equal(await post,false);
  assert.equal(f.authority.handle({authorization_reply:f.frames[1].id,allowed:true}),true);
  f.authority.dispose();await Promise.all(statics);
});

test('static checks outside an explicit startup context cannot forward in the background',async t=>{
  const f=startupFixture(t);f.replace(null);
  let result;
  const pending=f.authority.check(f.request(0)).then(value=>{result=value;});await flush();
  assert.equal(result,false);await pending;assert.equal(f.frames.length,0);
});

test('a static request cannot borrow a startup context from another phase',async t=>{
  const f=startupFixture(t);let result;
  const pending=f.authority.check(f.request(0,{phase:'login-once'})).then(value=>{result=value;});
  await flush();assert.equal(result,false);await pending;assert.equal(f.frames.length,0);
});

test('cancelling one queued static request does not cancel its independent sibling',async t=>{
  const f=startupFixture(t),controller=new AbortController();let cancelled;
  const first=f.authority.check(f.request(0));
  const second=f.authority.check(f.request(1),{signal:controller.signal}).then(value=>{cancelled=value;});
  const third=f.authority.check(f.request(2));controller.abort();await flush();
  assert.equal(cancelled,false);assert.equal(f.frames.length,1);
  f.authority.handle({authorization_reply:f.frames[0].id,allowed:true});await flush();
  assert.equal(f.frames[1].request.descriptor.path,'/assets/2.js');
  f.authority.handle({authorization_reply:f.frames[1].id,allowed:true});
  assert.equal(await first,true);assert.equal(await third,true);await second;
});

test('the production policy drops a cancelled FIFO request before broker emission',async t=>{
  const f=startupFixture(t);let cancelled=false;
  f.policy.requestPermit=(value,options)=>f.authority.check({kind:'network',...value},options);
  const asset=(path,failure=()=>null)=>({url:()=>f.policy.origin+path,method:()=>'GET',
    postData:()=>null,headers:()=>({}),resourceType:()=>'script',failure});
  const first=f.policy.authorize(asset('/first.js'));
  const stale=f.policy.authorize(asset('/cancelled.js',()=>cancelled?{errorText:'net::ERR_ABORTED'}:null));
  const live=f.policy.authorize(asset('/live.js'));
  cancelled=true;
  f.authority.handle({authorization_reply:f.frames[0].id,allowed:true});await flush();
  assert.deepEqual(f.frames.map(frame=>frame.request.descriptor.path),['/first.js','/live.js']);
  f.authority.handle({authorization_reply:f.frames[1].id,allowed:true});
  assert.deepEqual(await Promise.all([first,stale,live]),[true,false,true]);
  assert.equal(f.policy.list().length,0);
});

test('a queued cancellation predicate that throws is denied without blocking a live sibling',async t=>{
  const f=startupFixture(t);let failed=false;
  const first=f.authority.check(f.request(0));
  const stale=f.authority.check(f.request(1),{isCancelled:()=>{if(failed)throw new Error('request-unavailable');return false;}});
  const live=f.authority.check(f.request(2));failed=true;
  f.authority.handle({authorization_reply:f.frames[0].id,allowed:true});await flush();
  assert.deepEqual(f.frames.map(frame=>frame.request.descriptor.path),['/assets/0.js','/assets/2.js']);
  f.authority.handle({authorization_reply:f.frames[1].id,allowed:true});
  assert.deepEqual(await Promise.all([first,stale,live]),[true,false,true]);
});

async function issuedBatch(t,count=5,options=()=>({})){
  const f=startupFixture(t);
  const pending=Array.from({length:count},(_,index)=>f.authority.check(f.request(index),options(index)));
  f.authority.handle({authorization_reply:f.frames[0].id,allowed:true});await flush();
  assert.equal(f.frames[1].event,'authorization-check-batch','queued static checks must share a bounded transaction');
  return {...f,pending,batch:f.frames[1]};
}

const batchReply=(frame,allow=()=>true)=>({authorization_batch_reply:frame.checks.map((check,index)=>({
  authorization_reply:check.id,allowed:allow(index)}))});

test('queued static checks share at most16 issued deadlines and retain FIFO order',async t=>{
  const f=await issuedBatch(t,48);
  for(let group=1;group<=3;group++){
    const frame=f.frames[group];
    assert.equal(frame.event,'authorization-check-batch');
    assert.equal(frame.checks.length,group===3?15:16);
    assert.ok(Buffer.byteLength(JSON.stringify(frame)+'\n')<=32768);
    assert.deepEqual(frame.checks.map(row=>row.request.descriptor.path),
      Array.from({length:frame.checks.length},(_,index)=>`/assets/${1+(group-1)*16+index}.js`));
    f.authority.handle(batchReply(frame));await flush();
  }
  assert.deepEqual(await Promise.all(f.pending),Array(48).fill(true));
  assert.equal(f.frames.length,4);
});

test('a batch reply must contain every unique member before any permission resolves',async t=>{
  const f=await issuedBatch(t),results=[];
  f.pending[1].then(value=>results.push(value));
  const reply=batchReply(f.batch);
  assert.equal(f.authority.handle({authorization_batch_reply:reply.authorization_batch_reply.slice(1)}),false);
  assert.equal(f.authority.handle({authorization_batch_reply:[reply.authorization_batch_reply[0],...reply.authorization_batch_reply.slice(0,-1)]}),false);
  assert.equal(f.authority.handle({...reply,extra:true}),false);
  assert.equal(f.authority.handle({authorization_reply:f.batch.checks[0].id,allowed:true}),false);
  await flush();assert.deepEqual(results,[]);
  assert.equal(f.authority.handle(reply),true);
  assert.deepEqual(await Promise.all(f.pending),Array(5).fill(true));
  assert.equal(f.authority.handle(reply),false);
});

test('one cancelled emitted batch member cannot revoke or authorize its siblings',async t=>{
  const controller=new AbortController();
  const f=await issuedBatch(t,5,index=>index===2?{signal:controller.signal}:{});
  controller.abort();await flush();
  assert.equal(f.authority.handle(batchReply(f.batch)),true);
  assert.deepEqual(await Promise.all(f.pending),[true,true,false,true,true]);
});

test('each issued batch member still expires after10 seconds and one late frame is diagnostic only',async t=>{
  const f=await issuedBatch(t);
  t.mock.timers.tick(10001);await flush();
  assert.deepEqual(await Promise.all(f.pending),[true,false,false,false,false]);
  assert.equal(f.authority.handle(batchReply(f.batch)),true);
  assert.equal(f.authority.handle(batchReply(f.batch)),false);
});

test('revocation denies an entire active batch and its queued work before late permission',async t=>{
  const f=await issuedBatch(t,30);
  f.authority.handle({control_event:'revoke',generation:1});await flush();
  assert.deepEqual(await Promise.all(f.pending),[true,...Array(29).fill(false)]);
  assert.equal(f.frames.length,2);
  assert.equal(f.authority.handle(batchReply(f.batch)),true);
});

test('a phase change invalidates an active batch even when every broker result is true',async t=>{
  const f=await issuedBatch(t);
  f.policy.setPhase('login-once');
  f.authority.handle(batchReply(f.batch));await flush();
  assert.deepEqual(await Promise.all(f.pending),[true,false,false,false,false]);
});

test('oversized static descriptors use the single-check path without truncation',async t=>{
  const f=startupFixture(t);
  const large=f.request(1);large.descriptor.contentType='x'.repeat(32768);
  const pending=[f.authority.check(f.request(0)),f.authority.check(large),f.authority.check(f.request(2))];
  f.authority.handle({authorization_reply:f.frames[0].id,allowed:true});await flush();
  assert.equal(f.frames[1].event,'authorization-check');
  assert.equal(f.frames[1].request.descriptor.contentType.length,32768);
  f.authority.handle({authorization_reply:f.frames[1].id,allowed:true});await flush();
  f.authority.handle({authorization_reply:f.frames[2].id,allowed:true});
  assert.deepEqual(await Promise.all(pending),[true,true,true]);
});

test('an overdue batch reply cannot beat a delayed10-second timer callback',async t=>{
  const f=await issuedBatch(t);
  t.mock.method(Date,'now',()=>11001);
  assert.equal(f.authority.handle(batchReply(f.batch)),true);
  assert.deepEqual(await Promise.all(f.pending),[true,false,false,false,false]);
});
