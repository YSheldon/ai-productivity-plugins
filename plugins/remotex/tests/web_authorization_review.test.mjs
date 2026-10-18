import test from 'node:test';
import assert from 'node:assert/strict';
import {NetworkPolicy,describeRequest} from '../scripts/web_network_authorization.mjs';
import {taskContracts} from '../scripts/web_task_contracts.mjs';

const origin='https://console.example';
const secret='review-canary-password';
const request=(path,body=null,contentType='application/json')=>({url:()=>origin+path,
  method:()=>body?'POST':'GET',postData:()=>body,headers:()=>({'content-type':contentType}),resourceType:()=> 'xhr'});

test('a page-step request is unclassified, never automatically a task-bounded read',()=>{
  const scope={item_id:'delete',capability:'web.page_step',targets:[],max_uses:2,parameters:{network_refs:['request']}};
  const descriptor=describeRequest(request('/delete','{"cmd":"delete","ids":["host-one"]}'),origin,[]);
  const result=taskContracts([scope],[{network_evidence:[{kind:'operator-inspected',reference:'Unreviewed proposal'}]}],
    {resolve:()=>descriptor},new Map());
  assert.equal(result.contracts['delete.network.1'].semantics,'unclassified');
  assert.equal(result.items[1].parameters.review_kind,'unclassified');
});

test('known credentials in paths, dynamic field names and content types never enter blocked metadata',async()=>{
  const policy=new NetworkPolicy({origin,secret,requestPermit:async()=>false});
  for(const pending of [request('/'+secret),request('/query?'+secret+'=1'),
    request('/query',JSON.stringify({[secret]:1})),request('/query','{}','application/'+secret)]){
    assert.equal(await policy.authorize(pending),false);
  }
  assert.equal(policy.list().length,0);
  assert.ok(!JSON.stringify(policy.list()).includes(secret));
});
