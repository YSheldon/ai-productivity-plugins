import test from 'node:test';
import assert from 'node:assert/strict';

let network;
try {network=await import('../scripts/web_network_authorization.mjs');}catch(error){if(error.code!=='ERR_MODULE_NOT_FOUND')throw error;}
const origin='https://console.example:6868';
const request=(body,url=origin+'/inter',type='application/json')=>({url:()=>url,method:()=> 'POST',
  postData:()=>body,headers:()=>({'content-type':type,'cookie':'never-export'}),resourceType:()=> 'xhr'});

test('request contracts use structured exact payloads and internal auth slots',()=>{
  assert.ok(network,'The network authorization gate has not been implemented');
  const value=network.describeRequest(request('{"cmd":"set_group","args":{"id":"host-1","group":"test","token":"private-token"}}'),origin,[]);
  assert.deepEqual(value.body.args,{id:'host-1',group:'test',token:{internalAuth:true}});
  assert.ok(!JSON.stringify(value).includes('private-token'));
  assert.ok(!JSON.stringify(value).includes('never-export'));
});

test('duplicate or ambiguous JSON/form fields cannot match a reviewed request',()=>{
  assert.ok(network);
  for(const body of ['{"cmd":"get_status","cmd":"delete"}','{"args":{"id":"a","id":"b"}}'])
    assert.throws(()=>network.describeRequest(request(body),origin,[]),/request-contract-unavailable/);
  assert.throws(()=>network.describeRequest(request('cmd=read&cmd=delete',undefined,'application/x-www-form-urlencoded'),origin,[]),/request-contract-unavailable/);
  assert.throws(()=>network.describeRequest(request('{bad'),origin,[]),/request-contract-unavailable/);
});

test('cross-origin, query duplication and oversized requests are blocked before forwarding',()=>{
  assert.ok(network);
  assert.throws(()=>network.describeRequest(request('{}','https://other.example/inter'),origin,[]),/origin-blocked/);
  assert.throws(()=>network.describeRequest(request('{}',origin+'/inter?a=1&a=2'),origin,[]),/request-contract-unavailable/);
  assert.throws(()=>network.describeRequest(request('A'.repeat(16385)),origin,[]),/request-too-large/);
});

test('unknown requests remain blocked until an exact permit and current phase allow them',async()=>{
  assert.ok(network);
  const checks=[];let permitted=false;
  const policy=new network.NetworkPolicy({origin,secret:'private-pass',requestPermit:async value=>{checks.push(value);return permitted;}});
  assert.equal(await policy.authorize(request('{"cmd":"get_status"}')),false);
  assert.equal(policy.list().length,1);
  assert.ok(!JSON.stringify(policy.list()).includes('get_status'));
  permitted=true;
  assert.equal(await policy.authorize(request('{"cmd":"get_status"}')),true);
  policy.fence();
  assert.equal(await policy.authorize(request('{"cmd":"get_status"}')),false);
  assert.equal(checks.length,2);
});

test('permit handshake does not cache authority across requests or leak unknown-field credentials',async()=>{
  assert.ok(network);
  const events=[];
  const policy=new network.NetworkPolicy({origin,secret:'private-pass',requestPermit:async value=>{events.push(value);return true;}});
  assert.equal(await policy.authorize(request('{"cmd":"login","data":"private-pass"}')),false);
  assert.equal(events.length,0);
  assert.equal(await policy.authorize(request('{"cmd":"get_status"}')),true);
  assert.equal(await policy.authorize(request('{"cmd":"get_status"}')),true);
  assert.equal(events.length,2);
});

test('an authenticated session cannot return to login authority',()=>{
  assert.ok(network);
  const policy=new network.NetworkPolicy({origin,secret:'canary',requestPermit:async()=>true});
  policy.setPhase('login-once');policy.setPhase('discovery-only');
  assert.throws(()=>policy.setPhase('login-once'),/session-unavailable/);
  policy.setPhase('grant-active');policy.setPhase('discovery-only');
  assert.throws(()=>policy.setPhase('bootstrap'),/session-unavailable/);
});

test('task traffic is denied before arming and after the short dispatch window',async()=>{
  let now=1000;
  const policy=new network.NetworkPolicy({origin,secret:'canary',requestPermit:async()=>true,clock:()=>now});
  policy.setPhase('login-once');policy.setPhase('discovery-only');policy.setPhase('grant-active');
  assert.equal(await policy.authorize(request('{"cmd":"set_group"}')),false);
  policy.arm('a'.repeat(32));
  assert.equal(await policy.authorize(request('{"cmd":"set_group"}')),true);
  now+=5001;
  assert.equal(await policy.authorize(request('{"cmd":"set_group"}')),false);
});

test('loading a login document is not evidence that credentials were transmitted',()=>{
  const policy=new network.NetworkPolicy({origin,secret:'canary',requestPermit:async()=>true});
  policy.setPhase('login-once');
  const document={url:()=>origin+'/',method:()=> 'GET',postData:()=>null,headers:()=>({}),resourceType:()=> 'document'};
  policy.beginForwarding(document)();
  assert.equal(policy.authenticationForwarded,0);
  policy.beginForwarding(request('{"password":"canary"}'))();
  assert.equal(policy.authenticationForwarded,1);
});
