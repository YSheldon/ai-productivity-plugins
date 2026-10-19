import test from 'node:test';
import assert from 'node:assert/strict';
import {WorkerAuthority} from '../scripts/web_authorization_ipc.mjs';
import {sampleCapture} from './fixtures/v3_test_support.mjs';

const descriptor={method:'POST',path:'/init',query:{},contentType:'application/json',body:{cmd:'info'},resourceType:'xhr'};
function prepared(){
  const controller=new AbortController(),frames=[];
  const context={policy:{origin:'https://console.example',phase:'bootstrap',generation:0},
    phase:'bootstrap',generation:0,signal:controller.signal,deadline:Date.now()+45000,
    preauth_lifecycle:'a'.repeat(32),resume_id:'b'.repeat(32),document_id:'c'.repeat(32),binding_digest:'d'.repeat(64)};
  const request={kind:'network',phase:'bootstrap',attempt_id:null,descriptor,digest:'e'.repeat(64),startup:{
    preauth_lifecycle:context.preauth_lifecycle,resume_id:context.resume_id,document_id:context.document_id,generation:0}};
  const value=new WorkerAuthority({emit:frame=>frames.push(frame),onRevoke:()=>{},startup:()=>context});
  assert.equal(typeof value.checkNetwork,'function','Typed network IPC is missing');
  return {value,context,request,frames,controller};
}
function reply(frame,context){return {authorization_reply:frame.id,allowed:true,permit:{
  kind:'initialization-read',check_id:frame.id,descriptor_digest:'e'.repeat(64),binding_digest:context.binding_digest,
  preauth_lifecycle:context.preauth_lifecycle,resume_id:context.resume_id,document_id:context.document_id,
  generation:0,expires_at_ms:Date.now()+9000,prerequisite_id:'f'.repeat(64),
  response_checks:[{pointer:'/exist',test:'equals-boolean',expected:true}]}};}
function expected(context){return {descriptor_digest:'e'.repeat(64),binding_digest:context.binding_digest,
  preauth_lifecycle:context.preauth_lifecycle,resume_id:context.resume_id,document_id:context.document_id,generation:0};}
test('typed network receipt belongs to its outstanding check and is consumed once',async()=>{
  const {value,context,request,frames}=prepared();
  try{
    const pending=value.checkNetwork(request),frame=reply(frames[0],context);
    assert.equal(value.handle(frame),true);
    const permit=await pending;
    assert.equal(value.consumeNetworkReceipt(permit,expected(context)).kind,'initialization-read');
    assert.throws(()=>value.consumeNetworkReceipt(permit,expected(context)));
    assert.throws(()=>value.consumeNetworkReceipt(structuredClone(frame.permit),expected(context)));
  }finally{value.dispose();}
});
test('substituted descriptors and cancelled contexts cannot produce forwarding receipts',async()=>{
  const {value,context,request,frames,controller}=prepared();
  try{
    const pending=value.checkNetwork(request),frame=reply(frames[0],context);
    assert.equal(value.handle({...frame,permit:{...frame.permit,descriptor_digest:'0'.repeat(64)}}),false);
    assert.equal(value.handle(frame),true);const permit=await pending;
    controller.abort();assert.throws(()=>value.consumeNetworkReceipt(permit,expected(context)));
  }finally{value.dispose();}
});
test('an expired typed permit does not grant and never becomes an ordinary boolean',async()=>{
  const {value,context,request,frames}=prepared();
  try{
    const pending=value.checkNetwork(request),frame=reply(frames[0],context);
    assert.equal(value.handle({...frame,permit:{...frame.permit,expires_at_ms:Date.now()-1}}),false);
    value.dispose();assert.equal(await pending,false);
  }finally{value.dispose();}
});

test('supervisor expiry is narrowed to the original emitted ten-second deadline',async t=>{
  let now=1000;t.mock.method(Date,'now',()=>now);
  const {value,context,request,frames}=prepared();
  try{
    const pending=value.checkNetwork(request);now++;
    const frame=reply(frames[0],context);frame.permit.expires_at_ms=11001;
    assert.equal(value.handle(frame),true);
    const permit=await pending;
    assert.equal(value.consumeNetworkReceipt(permit,expected(context)).expires_at_ms,11000);
  }finally{value.dispose();}
});

test('moving the wall clock backwards cannot extend a typed forwarding permit',async t=>{
  let wall=1000,mono=1000;t.mock.method(Date,'now',()=>wall);t.mock.method(performance,'now',()=>mono);
  const {value,context,request,frames}=prepared();
  try{
    const pending=value.checkNetwork(request);value.handle(reply(frames[0],context));const permit=await pending;
    wall=0;mono=11001;assert.throws(()=>value.consumeNetworkReceipt(permit,expected(context)));
  }finally{value.dispose();}
});

function preparedV3(){
  const c=prepared();delete c.request.descriptor;delete c.request.digest;
  c.request.version=3;c.request.capture=sampleCapture();c.context.policy.origin='https://fixture.example';return c;
}
function replyV3(frame,context){return {authorization_reply:frame.id,allowed:true,permit:{
  kind:'initialization-permit-v3',version:3,check_id:frame.id,binding_digest:context.binding_digest,
  preauth_lifecycle:context.preauth_lifecycle,resume_id:context.resume_id,document_id:context.document_id,generation:0,
  expires_at_ms:Date.now()+9000,prerequisite_id:'f'.repeat(64),intent_ref:'1'.repeat(32),
  grant_id:'5'.repeat(32),item_id:'setup.network.1',
  intent_commitment:'2'.repeat(64),receipt_id:'3'.repeat(32),permit_commitment:'4'.repeat(64),
  response_checks:[{pointer:'/exist',test:'equals-boolean',expected:true}]}};}
function expectedV3(context,capture){const value=expected(context);delete value.descriptor_digest;return {...value,capture};}

test('v3 receipts bind the private exact capture and current document, never a boolean',async()=>{
  const {value,context,request,frames}=preparedV3();
  try{
    const pending=value.checkNetwork(request);assert.equal(frames.length,1);
    assert.equal(value.handle({authorization_reply:frames[0].id,allowed:true}),false);
    const frame=replyV3(frames[0],context);
    assert.equal(value.handle({...frame,permit:{...frame.permit,version:2}}),false);
    assert.equal(value.handle(frame),true);
    const permit=await pending;
    assert.equal(permit.kind,'initialization-permit-v3');
    assert.throws(()=>value.consumeNetworkReceipt(permit,expectedV3(context,sampleCapture({bodyText:'{ "mode":"public"}'}))));
    assert.throws(()=>value.consumeNetworkReceipt(permit,expectedV3(context,request.capture)));
  }finally{value.dispose();}
});
test('v3 receipts consume once and a new document cannot reuse one',async()=>{
  for(const changedDocument of [false,true]){
    const {value,context,request,frames}=preparedV3();
    try{
      const pending=value.checkNetwork(request);assert.equal(value.handle(replyV3(frames[0],context)),true);
      const permit=await pending;
      if(changedDocument)context.document_id='9'.repeat(32);
      if(changedDocument)assert.throws(()=>value.consumeNetworkReceipt(permit,expectedV3(context,request.capture)));
      else assert.equal(value.consumeNetworkReceipt(permit,expectedV3(context,request.capture)).kind,'initialization-permit-v3');
      assert.throws(()=>value.consumeNetworkReceipt(permit,expectedV3(context,request.capture)));
    }finally{value.dispose();}
  }
});

test('ending a startup retires its single pending check before a late known typed reply',async()=>{
  for(const version of [2,3])for(const abortSource of ['startup','caller']){
    const c=version===3?preparedV3():prepared(),caller=new AbortController();
    try{
      const pending=c.value.checkNetwork(c.request,{signal:caller.signal});
      const frame=(version===3?replyV3:reply)(c.frames[0],c.context);
      (abortSource==='startup'?c.controller:caller).abort();
      assert.equal(c.value.pending.size,0,'Every single check must be bound to its original startup, not only caller cancellation');
      assert.equal(await pending,false);
      assert.equal(c.value.handle(frame),true,'Discard exactly the known retired reply; it is never a UI command');
      assert.throws(()=>c.value.consumeNetworkReceipt(frame.permit,version===3?expectedV3(c.context,c.request.capture):expected(c.context)));
      assert.equal(c.value.handle({...frame,authorization_reply:'0'.repeat(32)}),false,'An unknown reply is not silently retired');
    }finally{c.value.dispose();}
  }
});
