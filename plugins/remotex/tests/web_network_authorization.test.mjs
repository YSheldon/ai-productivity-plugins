import test from 'node:test';
import assert from 'node:assert/strict';

let network;
try {network=await import('../scripts/web_network_authorization.mjs');}catch(error){if(error.code!=='ERR_MODULE_NOT_FOUND')throw error;}
const origin='https://console.example:6868';
const request=(body,url=origin+'/inter',type='application/json')=>({url:()=>url,method:()=> 'POST',
  postData:()=>body,headers:()=>({'content-type':type,'cookie':'never-export'}),resourceType:()=> 'xhr'});
const asset=(path='/assets/app.js')=>({url:()=>origin+path,method:()=> 'GET',
  postData:()=>null,headers:()=>({}),resourceType:()=> 'script'});
async function withTime(run){
  let now=1000;const actual=Date.now;Date.now=()=>now;
  try {await run(delta=>{now+=delta;});}finally{Date.now=actual;}
}

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

test('a newly denied request replaces its expired reference without authorizing traffic',()=>withTime(async advance=>{
  const policy=new network.NetworkPolicy({origin,requestPermit:async()=>false});
  assert.equal(await policy.authorize(asset()),false);
  const original=policy.list()[0].ref;
  advance(120001);
  assert.deepEqual(policy.list(),[]);
  assert.throws(()=>policy.resolve(original),/request-contract-unavailable/);
  assert.equal(await policy.authorize(asset()),false);
  const current=policy.list();
  assert.equal(current.length,1);
  assert.notEqual(current[0].ref,original);
  assert.deepEqual(policy.resolve(current[0].ref),{method:'GET',path:'/assets/app.js',query:{},contentType:'',body:null,resourceType:'script'});
  assert.throws(()=>policy.resolve(original),/request-contract-unavailable/);
  assert.equal(policy.authenticationForwarded,0);
}));

test('unexpired repeated denials keep the same reference and the original expiry',()=>withTime(async advance=>{
  const policy=new network.NetworkPolicy({origin,requestPermit:async()=>false});
  await policy.authorize(asset());const original=policy.list()[0].ref;
  advance(60000);assert.equal(await policy.authorize(asset()),false);
  assert.equal(policy.list()[0].ref,original);
  advance(60000);assert.equal(policy.list()[0].ref,original);
  advance(1);assert.deepEqual(policy.list(),[]);
  assert.throws(()=>policy.resolve(original),/request-contract-unavailable/);
}));

test('listing expired metadata neither refreshes a reference nor requests a permit',()=>withTime(async advance=>{
  let calls=0;
  const policy=new network.NetworkPolicy({origin,requestPermit:async()=>{calls++;return false;}});
  await policy.authorize(asset());const original=policy.list()[0].ref;
  advance(120001);
  for(let at=0;at<3;at++)assert.deepEqual(policy.list(),[]);
  assert.throws(()=>policy.resolve(original),/request-contract-unavailable/);
  assert.equal(calls,1);
}));

test('expired cache entries cannot exhaust the unchanged 100-reference capacity',()=>withTime(async advance=>{
  const policy=new network.NetworkPolicy({origin,requestPermit:async()=>false});
  for(let at=0;at<101;at++)assert.equal(await policy.authorize(asset(`/assets/${at}.js`)),false);
  assert.equal(policy.list().length,100);
  const original=policy.list()[0].ref;
  advance(120001);
  assert.equal(await policy.authorize(asset('/assets/100.js')),false);
  assert.equal(policy.list().length,1);
  assert.equal(policy.resolve(policy.list()[0].ref).path,'/assets/100.js');
  assert.throws(()=>policy.resolve(original),/request-contract-unavailable/);
}));

test('refreshed descriptors retain internal auth slots and never export credential values',()=>withTime(async advance=>{
  const policy=new network.NetworkPolicy({origin,secret:'private-pass',requestPermit:async()=>false});
  const login=request('{"password":"private-pass","token":"token-value"}');
  await policy.authorize(login);advance(120001);
  assert.equal(await policy.authorize(login),false);
  assert.equal(policy.list().length,1);
  const value=policy.resolve(policy.list()[0].ref);
  assert.deepEqual(value.body,{password:{internalAuth:true},token:{internalAuth:true}});
  assert.ok(!JSON.stringify([policy.list(),value]).includes('private-pass'));
  assert.ok(!JSON.stringify([policy.list(),value]).includes('token-value'));
}));

test('reference recovery does not mint metadata for invalid requests or fenced sessions',()=>withTime(async advance=>{
  let calls=0;
  const policy=new network.NetworkPolicy({origin,secret:'private-pass',requestPermit:async()=>{calls++;return false;}});
  await policy.authorize(asset());advance(120001);
  assert.equal(await policy.authorize(request('{}','https://other.example/inter')),false);
  assert.equal(await policy.authorize(request('{"unknown":"private-pass"}')),false);
  assert.deepEqual(policy.list(),[]);assert.equal(calls,1);
  policy.fence();assert.equal(await policy.authorize(asset()),false);
  assert.deepEqual(policy.list(),[]);assert.equal(calls,1);
}));

test('permitted traffic does not receive a new denied-request reference',()=>withTime(async advance=>{
  let allowed=false;
  const policy=new network.NetworkPolicy({origin,requestPermit:async()=>allowed});
  await policy.authorize(asset());advance(120001);allowed=true;
  assert.equal(await policy.authorize(asset()),true);
  assert.deepEqual(policy.list(),[]);
}));
