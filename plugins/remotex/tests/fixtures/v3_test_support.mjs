import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
export const {parseTree}=createRequire(import.meta.url)('../../scripts/web-runtime/node_modules/jsonc-parser');
export const vectors=JSON.parse(readFileSync(new URL('./v3_profile_vectors.json',import.meta.url),'utf8'));
export const b64=value=>Buffer.from(value,'utf8').toString('base64');
export const header=(name,value)=>({name_b64:b64(name),value_b64:b64(value)});
export function sampleCapture({bodyText='{"mode":"public"}',contentType='application/json',
  target='/bootstrap?mode=public',origin='https://fixture.example',headers=[],...overrides}={}){
  const original=[header('content-type',contentType),...headers.map(([name,value])=>header(name,value))];
  const effective=[...original,header('host',new URL(origin).host),header('accept-encoding','identity'),
    header('content-length',String(Buffer.byteLength(bodyText)))].sort((a,b)=>
      Buffer.from(a.name_b64,'base64').toString().localeCompare(Buffer.from(b.name_b64,'base64').toString(),'en'));
  return {version:3,method:'POST',origin,resource_type:'xhr',
    target_b64:b64(target),body_b64:b64(bodyText),content_type_b64:b64(contentType),
    original_headers:original,effective_headers:effective,transport_policy:'fixed-egress-v1',
    cookie_context:null,protection_refs:[],...overrides};
}
// Independently declared source records, never derived from a captured request.
export function publicReference(id='json-public'){
  const row=vectors.find(value=>value.id===id);
  if(!row||row.error)throw new Error('unknown synthetic public source');
  return {profile_id:row.profile,target_text:'/bootstrap?mode=public',content_type:row.content_type,
    body_text:row.body,public_headers:[]};
}
export function fakeRequest({bodyText='{"mode":"public"}',headers=[{name:'Content-Type',value:'application/json'}],
  target='/bootstrap?mode=public'}={}){
  let body=Buffer.from(bodyText);const calls={postDataBuffer:0,headersArray:0,url:0};
  return {calls,headers,url:()=>{calls.url++;return 'https://fixture.example'+target;},method:()=> 'POST',
    resourceType:()=> 'xhr',postDataBuffer:()=>{calls.postDataBuffer++;return body;},
    headersArray:async()=>{calls.headersArray++;return headers;},
    replaceBody:value=>{body=Buffer.from(value);}};
}
export const capturePolicy=overrides=>({origin:'https://fixture.example',cookie_context:null,protection_refs:[],secrets:[],...overrides});
