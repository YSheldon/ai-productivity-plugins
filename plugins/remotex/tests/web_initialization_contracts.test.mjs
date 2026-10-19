import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const api=await import('../scripts/web_initialization_contracts.mjs').catch(()=>({}));
const require=createRequire(import.meta.url);
const descriptor={method:'POST',path:'/init',query:{},contentType:'application/json',
  body:{cmd:'database_info'},resourceType:'xhr'};
const check={pointer:'/exist',test:'equals-boolean',expected:true};
function functions(){
  for(const name of ['normalizeResponseChecks','validateInitializationDescriptor','evaluateInitializationResponse'])
    assert.equal(typeof api[name],'function',`${name} must enforce the initialization contract`);
}
function response(body,headers={'content-type':'application/json'},status=200){return {status,headers,body:Buffer.from(body)};}
function evaluate(value,checks=[check]){
  functions();
  const {parseTree}=require('../scripts/web-runtime/node_modules/jsonc-parser');
  return api.evaluateInitializationResponse(value,api.normalizeResponseChecks(checks),parseTree);
}
test('initialization descriptor is an exact non-authentication POST only',()=>{
  functions();assert.deepEqual(api.validateInitializationDescriptor(descriptor),descriptor);
  for(const changed of [
    {...descriptor,method:'GET'}, {...descriptor,resourceType:'document'},
    {...descriptor,contentType:'text/plain'}, {...descriptor,body:{password:{internalAuth:true}}},
    {...descriptor,query:{sessionid:'opaque'}}, {...descriptor,body:{deep:{credential:'hidden'}}},
    {...descriptor,headers:{cookie:'injected'}}, {...descriptor,path:'/any/*'}])
    assert.throws(()=>api.validateInitializationDescriptor(changed));
});
test('readiness supports only bounded fixed tests and never a secret oracle',()=>{
  functions();assert.deepEqual(api.normalizeResponseChecks([check]),[check]);
  const invalid=[[],Array(9).fill(check),
    [{...check,pointer:'/a/b/c/d/e/f/g/h/i'}],[{...check,pointer:''}],
    [{...check,pointer:'/token'}],[{...check,pointer:'/auth/access_token'}],
    [{...check,pointer:'/session/value'}],[{...check,pointer:'/__proto__/a'}],
    [{...check,pointer:'/bad~2escape'}],[{...check,test:'equals-string',expected:'guess'}],
    [{...check,test:'equals-integer',expected:true}],
    [{...check,test:'equals-integer',expected:9007199254740992}],
    [{...check,extra:true}]];
  for(const value of invalid)assert.throws(()=>api.normalizeResponseChecks(value));
});
test('strict pretty JSON readiness returns only a fixed result',()=>{
  assert.deepEqual(evaluate(response('{\n "exist": true, "guid":"private-test-value"\n}')),{ready:true});
  assert.deepEqual(evaluate(response('{"a/b":{"~name":"present"}}'),
    [{pointer:'/a~1b/~0name',test:'nonempty-string'}]),{ready:true});
});
test('ambiguous JSON and failed predicates cannot become readiness',()=>{
  functions();
  for(const raw of ['{"exist":false,"exist":true}','{"exist":false,"ex\\u0069st":true}',
    '{"exist":true,}','{/*comment*/"exist":true}','{"exist":false}','{}',
    '{"exist":"true"}','{"exist":NaN}','{"a":{"b":1,"b":2},"exist":true}'])
    assert.throws(()=>evaluate(response(raw)));
  assert.throws(()=>evaluate(response('{"n":9007199254740992}'),
    [{pointer:'/n',test:'type',expected:'integer'}]));
});
test('initialization response headers and size are checked before release',()=>{
  functions();
  for(const headers of [ {'content-type':'text/html'},
    {'content-type':'application/json','set-cookie':'auth=not-applied'},
    {'content-type':'application/json','www-authenticate':'Basic'},
    {'content-type':'application/json','proxy-authenticate':'Basic'},
    {'content-type':'application/json','location':'/login'},
    {'content-type':'application/json','content-encoding':'gzip'}])
    assert.throws(()=>evaluate(response('{"exist":true}',headers)));
  for(const status of [301,304,400,401,407,500])assert.throws(()=>evaluate(response('{"exist":true}',undefined,status)));
  assert.throws(()=>evaluate(response(' '.repeat(65537))));
  assert.throws(()=>evaluate({...response('{}'),body:Buffer.from([0xff])}));
});
