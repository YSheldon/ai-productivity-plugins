import test from 'node:test';
import assert from 'node:assert/strict';
import {SiteNetworkPolicy,SiteControl} from '../scripts/web_site_control.mjs';

test('site network allows ordinary POST only after a current exact-origin permit',async()=>{
  let active=false,calls=0;
  const policy=new SiteNetworkPolicy({origin:'https://console.example',check:async row=>{calls++;return active&&row.origin==='https://console.example';}});
  const req={url:()=> 'https://console.example/init',method:()=> 'POST'};
  assert.equal(await policy.authorize(req),false);
  active=true; assert.equal(await policy.authorize(req),true);
  for(const url of ['http://console.example/','https://console.example:8443/','https://other.example/','https://user:pass@console.example/'])
    assert.equal(await policy.authorize({...req,url:()=>url}),false);
  assert.equal(calls,2);
  const finish=policy.beginForwarding(req);
  active=false;
  await assert.rejects(()=>finish.checkDispatch(),/grant-revoked/);
  policy.fence(); active=true;
  assert.equal(await policy.authorize(req),false);
});

test('network permit backpressure bounds IPC concurrency without dropping authorized assets',async()=>{
  let current=0,maximum=0;
  const policy=new SiteNetworkPolicy({origin:'https://console.example',check:async()=>{
    current++;maximum=Math.max(current,maximum);await new Promise(resolve=>setTimeout(resolve,1));current--;return true;
  }});
  const result=await Promise.all(Array.from({length:48},()=>policy.authorize({url:()=> 'https://console.example/a.js',method:()=> 'GET'})));
  assert.equal(result.every(Boolean),true);assert.ok(maximum<=4);
});

function control(meta={kind:'action',name:'Save',id:'save'}){
  const entry={meta,fingerprint:'fingerprint',url:'https://console.example/'};
  let clicks=0;
  entry.node={evaluate:async()=>({target:'Example record',state:'same'})};
  const registry={page:{url:()=>entry.url},resolve:async()=>entry,check:async()=>{},redact:value=>value,
    perform:async(e,action,value,permit)=>{assert.equal(await permit(),true);clicks++;return {ok:true,businessSuccessVerified:false};},
    project:async()=>({ok:true,text:'Example record'})};
  const runtime=new SiteControl({registry,authorize:async()=>true});
  return {runtime,registry,entry,clicks:()=>clicks};
}

test('ordinary controls use observed references and do not need per-request permissions',async()=>{
  const h=control();
  const proposal=await h.runtime.preview({observation_id:'a'.repeat(32),component_ref:'b'.repeat(32),action:'click',risk:'ordinary'});
  assert.equal(proposal.sensitive,false);assert.equal(h.clicks(),0);
  const result=await h.runtime.execute({action_ref:proposal.action_ref,attempt_id:'c'.repeat(32)});
  assert.equal(result.businessSuccessVerified,false);assert.equal(h.clicks(),1);
  await assert.rejects(()=>h.runtime.execute({action_ref:proposal.action_ref,attempt_id:'c'.repeat(32)}),/component-stale/);
});

test('sensitive labels cannot be downgraded by the ordinary hint',async()=>{
  const h=control({kind:'action',name:'Delete permanently',id:'remove'});
  const result=await h.runtime.preview({observation_id:'a'.repeat(32),component_ref:'b'.repeat(32),action:'click',risk:'ordinary'});
  assert.equal(result.sensitive,true);
});

test('changed sensitive target prevents dispatch and caller cannot supply raw selectors',async()=>{
  const h=control({kind:'action',name:'Delete permanently',id:'remove'});
  const args={observation_id:'a'.repeat(32),component_ref:'b'.repeat(32),action:'click',risk:'sensitive'};
  await assert.rejects(()=>h.runtime.preview({...args,selector:'#delete'}),/request-invalid/);
  const result=await h.runtime.preview(args);
  h.entry.node.evaluate=async()=>({target:'Different record',state:'changed'});
  await assert.rejects(()=>h.runtime.execute({action_ref:result.action_ref,attempt_id:'c'.repeat(32)}),/target-state-changed/);
  assert.equal(h.clicks(),0);
});

test('credential or payment controls require manual handling',async()=>{
  for(const name of ['Change password','Confirm payment','Solve CAPTCHA']){
    const h=control({kind:'action',name,id:'control'});
    await assert.rejects(()=>h.runtime.preview({observation_id:'a'.repeat(32),component_ref:'b'.repeat(32),action:'click',risk:'ordinary'}),/manual-operation-required/);
  }
});

test('generic confirmation inherits sensitive or manual effects from its logical target',async()=>{
  const args={observation_id:'a'.repeat(32),component_ref:'b'.repeat(32),action:'click',risk:'ordinary'};
  const h=control({kind:'action',name:'Confirm',id:'confirm'});
  h.entry.node.evaluate=async()=>({target:'Delete all hosts permanently',state:'unchanged'});
  assert.equal((await h.runtime.preview(args)).sensitive,true);
  for(const target of ['Confirm payment of USD 500','Change account password']){
    const value=control({kind:'action',name:'Confirm',id:'confirm'});
    value.entry.node.evaluate=async()=>({target,state:'unchanged'});
    await assert.rejects(()=>value.runtime.preview(args),/manual-operation-required/);
  }
});

test('full private destination changes invalidate a confirmation even with identical labels',async()=>{
  const h=control({kind:'action',name:'Delete',id:'remove'});
  let destination='https://console.example/delete?id=A';
  h.entry.node.evaluate=async()=>({target:'Confirm deletion',state:'same',destination});
  const proposal=await h.runtime.preview({observation_id:'a'.repeat(32),component_ref:'b'.repeat(32),action:'click',risk:'sensitive'});
  destination='https://console.example/delete?id=B';
  await assert.rejects(()=>h.runtime.execute({action_ref:proposal.action_ref,attempt_id:'c'.repeat(32)}),/target-state-changed/);
  assert.equal(h.clicks(),0);
});

test('request completion is private, paired once and distinguishes unknown transport outcome',async()=>{
  const checks=[],completed=[];
  const policy=new SiteNetworkPolicy({origin:'https://console.example',check:async row=>{checks.push(row);return true;},onComplete:row=>completed.push(row)});
  const request={url:()=> 'https://console.example/save?private=not-exported',method:()=> 'POST'};
  assert.equal(await policy.authorize(request),true);
  const finish=policy.beginForwarding(request);
  await finish.checkDispatch();finish.received();finish();finish();
  assert.equal(checks[0].request_id,checks[1].request_id);
  assert.deepEqual(completed,[{kind:'site-network-complete',request_id:checks[0].request_id,known:true}]);
  assert.equal(JSON.stringify({checks,completed}).includes('private='),false);
  assert.equal(await policy.authorize(request),false);
  const other={url:()=> 'https://console.example/save',method:()=> 'POST'};
  assert.equal(await policy.authorize(other),true);policy.beginForwarding(other)();
  assert.equal(completed[1].known,false);
});

test('valid late native approval still has time for its separate execution ticket',async t=>{
  let now=1000;t.mock.method(Date,'now',()=>now);
  const h=control();
  const proposal=await h.runtime.preview({observation_id:'a'.repeat(32),component_ref:'b'.repeat(32),action:'click',risk:'sensitive'});
  now+=200000;
  assert.equal((await h.runtime.execute({action_ref:proposal.action_ref,attempt_id:'c'.repeat(32)})).ok,true);
});
