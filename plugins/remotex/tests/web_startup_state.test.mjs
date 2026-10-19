import test from 'node:test';
import assert from 'node:assert/strict';
const api=await import('../scripts/web_startup_state.mjs').catch(()=>({}));
const descriptor={method:'POST',path:'/init',query:{},contentType:'application/json',body:{cmd:'info'},resourceType:'xhr'};
const contract={revision:2,purpose:'initialization-read',required:true,prerequisite_id:'a'.repeat(64),
  descriptor,response_checks:[{pointer:'/exist',test:'equals-boolean',expected:true}]};
function prepared(){
  assert.equal(typeof api.StartupState,'function','Private worker readiness must be implemented');
  const events=[],state=new api.StartupState({lifecycle:'b'.repeat(32),clock:()=>1000,emit:event=>events.push(event)});
  const context={resume_id:'c'.repeat(32),document_id:'d'.repeat(32),preauth_lifecycle:'b'.repeat(32),
    phase:'bootstrap',generation:0,deadline:46000,signal:new AbortController().signal};
  state.register({init:contract});state.open(context);return {state,context,events};
}
function permit(context,id='e'.repeat(32)){return {kind:'initialization-read',check_id:id,
  prerequisite_id:contract.prerequisite_id,preauth_lifecycle:context.preauth_lifecycle,
  resume_id:context.resume_id,document_id:context.document_id,generation:context.generation,
  expires_at_ms:11000,response_checks:contract.response_checks};}
test('unsettled missing and failed prerequisites block credential insertion',()=>{
  const {state,context}=prepared();assert.equal(state.canInsertCredentials(),false);
  state.register({});assert.equal(state.status().required,1);
  const receipt=state.begin(permit(context));assert.equal(state.canInsertCredentials(),false);
  state.forward(receipt);state.response(receipt,{ready:true});
  assert.equal(state.canInsertCredentials(),true);state.armCredentials();
  assert.throws(()=>state.begin(permit(context,'f'.repeat(32))));
});
test('a receipt belongs to one context and cannot survive document replacement',()=>{
  const {state,context}=prepared(),receipt=state.begin(permit(context));state.forward(receipt);
  state.end(context);state.open({...context,resume_id:'f'.repeat(32),document_id:'0'.repeat(32)});
  assert.throws(()=>state.response(receipt,{ready:true}));assert.equal(state.status().ready,0);
  assert.equal(state.canInsertCredentials(),false);
});
test('a required descriptor cannot be silently redefined or removed',()=>{
  const {state}=prepared();
  assert.throws(()=>state.register({changed:{...contract,prerequisite_id:'f'.repeat(64),
    response_checks:[{pointer:'/exist',test:'equals-boolean',expected:false}]}}));
  state.register({});assert.equal(state.status().required,1);
});
test('no private response values are included in readiness events or status',()=>{
  const {state,context,events}=prepared(),receipt=state.begin(permit(context));
  state.forward(receipt);state.response(receipt,{ready:true});
  assert.deepEqual(state.status(),{required:1,ready:1,pending:0,blocked:0,state:'ready'});
  assert.ok(!JSON.stringify(events).includes('response_checks'));
});

test('credential sealing advances only the same owned document generation',()=>{
  const {state,context}=prepared(),receipt=state.begin(permit(context));
  state.forward(receipt);state.response(receipt,{ready:true});
  assert.equal(typeof state.updateContext,'function');
  state.updateContext({...context,phase:'login-once',generation:1});state.armCredentials();
  assert.throws(()=>state.check(receipt));assert.equal(state.status().state,'sealed');
});

test('a wall clock rollback cannot extend initialization dispatch',()=>{
  assert.equal(typeof api.StartupState,'function');let wall=1000,mono=1000;
  const state=new api.StartupState({lifecycle:'b'.repeat(32),clock:()=>wall,monotonic:()=>mono});
  const context={resume_id:'c'.repeat(32),document_id:'d'.repeat(32),preauth_lifecycle:'b'.repeat(32),
    phase:'bootstrap',generation:0,deadline:46000,signal:new AbortController().signal};
  state.register({init:contract});state.open(context);const receipt=state.begin(permit(context));
  wall=0;mono=11001;assert.throws(()=>state.forward(receipt));
});
