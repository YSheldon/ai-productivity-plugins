import test from 'node:test';
import assert from 'node:assert/strict';
import {WorkerAuthority} from '../scripts/web_authorization_ipc.mjs';

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
