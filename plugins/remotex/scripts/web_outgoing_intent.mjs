import {decodeV3Capture,effectiveV3Headers,parseV3Profile} from './web_request_profiles.mjs';
import {randomBytes} from 'node:crypto';

const owned=new WeakMap();
const invalid=()=>{throw new Error('request-contract-unavailable');};
const encode=value=>Buffer.from(value,'utf8').toString('base64');
const headersFrame=rows=>rows.map(([name,value])=>({name_b64:encode(name),value_b64:encode(value)}));
const variants=value=>[value,encodeURIComponent(value),Buffer.from(value).toString('base64')];
const candidates=value=>{
  const result=[value];
  if(/%[0-9a-f]{2}/i.test(value)&&!/%(?![0-9a-f]{2})/i.test(value)){
    try{result.push(decodeURIComponent(value.replaceAll('+',' ')));}catch{}
  }
  return result;
};
const containsPrivate=(values,secrets)=>values.some(value=>candidates(value).some(part=>secrets.some(secret=>secret&&part.includes(secret))));

export function createOwnedCookieContext(context,origin,isSealed=()=>false){
  if(!context||typeof context.cookies!=='function'||typeof isSealed!=='function')invalid();
  let jarRef=randomBytes(16).toString('hex'),epochRef=null,lastSnapshot=null,closed=false;
  const snapshot=rows=>{
    const keys=['name','value','domain','path','expires','httpOnly','secure','sameSite','partitionKey','_crHasCrossSiteAncestor'];
    if(!Array.isArray(rows)||rows.length>100)invalid();
    const result=rows.map(row=>{
      if(!row||typeof row!=='object'||Array.isArray(row)||Object.keys(row).some(key=>!keys.includes(key))||
        !['name','value','domain','path'].every(key=>typeof row[key]==='string')||
        !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(row.name)||row.value.length>4096||
        !/^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*$/.test(row.value)||
        !Number.isFinite(row.expires)||typeof row.httpOnly!=='boolean'||typeof row.secure!=='boolean'||
        !['Strict','Lax','None'].includes(row.sameSite)||
        (row.partitionKey!==undefined&&typeof row.partitionKey!=='string')||
        (row._crHasCrossSiteAncestor!==undefined&&typeof row._crHasCrossSiteAncestor!=='boolean'))invalid();
      return Object.fromEntries(Object.keys(row).sort().map(key=>[key,key==='expires'?String(row[key]):row[key]]));
    }).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b),'en'));
    const text=JSON.stringify(result);if(Buffer.byteLength(text)>32768)invalid();
    return {text,rows:result};
  };
  const resolve=async(urlText,original)=>{
    if(closed||isSealed()||new URL(urlText).origin!==origin)invalid();
    const full=snapshot(await context.cookies());
    const applicable=snapshot(await context.cookies([urlText]));
    const confirm=snapshot(await context.cookies());
    if(closed||isSealed()||full.text!==confirm.text||applicable.rows.some(row=>!full.rows.some(part=>JSON.stringify(part)===JSON.stringify(row))))invalid();
    if(full.text!==lastSnapshot){lastSnapshot=full.text;epochRef=randomBytes(16).toString('hex');}
    const cookie=original.find(([name])=>name.toLowerCase()==='cookie');
    if(cookie){
      const actual=cookie[1].split(';').map(part=>part.trim()),available=applicable.rows.map(row=>`${row.name}=${row.value}`);
      if(!actual.length||actual.length>100)invalid();
      for(const pair of actual){const at=available.indexOf(pair);if(at<0)invalid();available.splice(at,1);}
    }
    return {context:cookie?{jar_ref:jarRef,epoch_ref:epochRef}:null,private_values:full.rows.map(row=>row.value).filter(Boolean)};
  };
  resolve.dispose=()=>{closed=true;lastSnapshot=null;jarRef=null;epochRef=null;};
  return resolve;
}

export async function captureInitializationIntent(request,policy){
  let body;
  try{
    if(!policy||Object.keys(policy).sort().join(',')!=='cookie_context,origin,protection_refs,secrets'||
      !Array.isArray(policy.secrets)||policy.secrets.some(v=>typeof v!=='string'||v.length>16384)||
      policy.secrets.length>32||!Array.isArray(policy.protection_refs)||policy.protection_refs.length||
      typeof request?.headersArray!=='function')invalid();
    const url=new URL(request.url()),method=request.method(),resourceType=request.resourceType();
    if(url.origin!==policy.origin||url.protocol!=='https:'||url.username||url.password||url.hash)invalid();
    const browserBody=request.postDataBuffer();
    if(!Buffer.isBuffer(browserBody)||browserBody.length>16384)invalid();
    body=Buffer.from(browserBody);
    const rawHeaders=await request.headersArray();
    if(!Array.isArray(rawHeaders)||rawHeaders.length>100)invalid();
    const original=rawHeaders.map(row=>{
      if(!row||Object.keys(row).sort().join(',')!=='name,value'||typeof row.name!=='string'||typeof row.value!=='string')invalid();
      return [row.name,row.value];
    });
    const target=url.pathname+url.search;
    const secretForms=policy.secrets.filter(Boolean).flatMap(variants);
    const observed=[target,body.toString('utf8'),...original.flat()];
    if(containsPrivate(observed,secretForms))invalid();
    const cookieResolver=typeof policy.cookie_context==='function'?policy.cookie_context:null;
    const cookieData=cookieResolver?await cookieResolver(url.href,structuredClone(original)):{context:policy.cookie_context,private_values:[]};
    if(!cookieData||Object.keys(cookieData).sort().join(',')!=='context,private_values'||!Array.isArray(cookieData.private_values)||
      cookieData.private_values.length>100||cookieData.private_values.some(value=>typeof value!=='string'||value.length>4096))invalid();
    const cookieSecrets=cookieData.private_values.filter(Boolean).flatMap(variants);
    const nonCookie=[target,body.toString('utf8'),...original.filter(([name])=>name.toLowerCase()!=='cookie').flat()];
    if(containsPrivate(nonCookie,cookieSecrets))invalid();
    const effective=effectiveV3Headers(original,policy.origin,body.length);
    const frame={version:3,method,origin:policy.origin,resource_type:resourceType,target_b64:encode(target),
      body_b64:body.toString('base64'),content_type_b64:encode(original.find(([name])=>name.toLowerCase()==='content-type')?.[1]??''),
      original_headers:headersFrame(original),effective_headers:headersFrame(effective),transport_policy:'fixed-egress-v1',
      cookie_context:structuredClone(cookieData.context),protection_refs:[]};
    decodeV3Capture(frame);
    const handle=Object.freeze(Object.create(null));
    const frozen=Object.freeze({url:url.href,origin:policy.origin,method,body,headers:Object.freeze(Object.fromEntries(effective))});
    owned.set(handle,{frame,frozen,body,original:structuredClone(original),cookieResolver,
      knownPrivate:[...secretForms,...cookieSecrets],borrows:0,disposed:false});
    return handle;
  }catch{body?.fill(0);invalid();}
}

function requireOwned(handle){
  const state=owned.get(handle);if(!state||state.disposed)invalid();return state;
}

export function privateIntentFrame(handle){
  return structuredClone(requireOwned(handle).frame);
}

function clear(state){
  if(state.disposed&&!state.borrows){state.body.fill(0);state.frame=null;state.frozen=null;state.original=null;state.cookieResolver=null;state.knownPrivate=[];}
}

export function privateIntentProfile(handle,profileId,parseTree){
  const state=requireOwned(handle),view=parseV3Profile(state.frame,profileId,parseTree);
  const strings=[...view.ordered_tree.path,...view.ordered_tree.query.flat()];
  const visit=node=>{
    if(node.type==='object')for(const [name,part] of node.entries){strings.push(name);visit(part);}
    else if(node.type==='array')for(const part of node.items)visit(part);
    else if(node.type==='form')strings.push(...node.pairs.flat());
    else if(node.type==='string')strings.push(node.value);
  };
  visit(view.ordered_tree.body);
  if(containsPrivate(strings,state.knownPrivate))throw new Error('credential-in-unsupported-field');
  return view;
}

export async function verifyInitializationCookieContext(handle){
  const state=requireOwned(handle);
  try{
    if(state.cookieResolver){
      const current=await state.cookieResolver(state.frozen.url,structuredClone(state.original));
      requireOwned(handle);
      if(JSON.stringify(current.context)!==JSON.stringify(state.frame.cookie_context))throw new Error();
    }
  }catch{throw new Error('scope-mismatch');}
}

export function withInitializationIntent(handle,sendFrozen){
  const state=requireOwned(handle);if(typeof sendFrozen!=='function')invalid();
  // Only the trusted transport borrows these owned bytes. No Request getter is used again.
  state.borrows++;
  const release=()=>{state.borrows--;clear(state);};
  try{
    const result=sendFrozen(state.frozen);
    if(result&&typeof result.then==='function')return Promise.resolve(result).finally(release);
    release();return result;
  }catch(error){release();throw error;}
}

export function disposeInitializationIntent(handle){
  const state=owned.get(handle);if(!state)return;
  state.disposed=true;clear(state);
}
