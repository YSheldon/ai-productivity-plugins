export const PROFILES=Object.freeze(['json-utf8-v1','form-utf8-v1','form-json-name-view-v1']);
export const MAX_REFERENCE_UNITS=32;
export const MAX_PROPOSAL_UNITS=96;
const CAPTURE_KEYS=['version','method','origin','resource_type','target_b64','body_b64','content_type_b64',
  'original_headers','effective_headers','transport_policy','cookie_context','protection_refs'];
const HOP=new Set(['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade']);
const FIXED=new Set(['host','content-length','accept-encoding','content-type','cookie']);
const HARD_NAME=/^(?:internalAuth|password|passwd|pwd|token|access_token|refresh_token|session_id|sessionid|csrf|csrf_token|nonce|signature|ticket)$/i;
const AUTH_HEADER=/authorization|(?:^|[-_])(?:auth|token|session|csrf|nonce|signature|credential|api[-_]?key)(?:$|[-_])/i;
const bad=()=>{throw new Error('request-contract-unavailable');};
const capacity=()=>{throw new Error('setup-plan-capacity-required');};
const object=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const exact=(v,keys)=>object(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const bytes=v=>Buffer.byteLength(v,'utf8');
const text=v=>{
  if(typeof v!=='string'||/[\p{Cc}\p{Cs}]/u.test(v)||/-----BEGIN |\b(?:ghp_|glpat-|sk-proj-)/.test(v))bad();
  return v;
};
const decode=b=>new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(b);
const unbase64=v=>{
  if(typeof v!=='string'||! /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(v))bad();
  const b=Buffer.from(v,'base64');if(b.toString('base64')!==v)bad();return b;
};
const key=v=>{
  text(v);if(!v||bytes(v)>128||['__proto__','prototype','constructor'].includes(v)||HARD_NAME.test(v))bad();return v;
};

function headerRows(rows){
  if(!Array.isArray(rows)||rows.length>100)bad();
  const seen=new Set();
  return rows.map(row=>{
    if(!exact(row,['name_b64','value_b64']))bad();
    const name=decode(unbase64(row.name_b64)),value=decode(unbase64(row.value_b64));
    text(name);text(value);
    if(!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)||!/^[\x20-\x7e]*$/.test(value)||seen.has(name.toLowerCase()))bad();
    seen.add(name.toLowerCase());if(AUTH_HEADER.test(name))bad();
    return [name,value];
  });
}

export function effectiveV3Headers(original,origin,bodyLength){
  const result=new Map();
  for(const [name,value] of original){if(!HOP.has(name.toLowerCase()))result.set(name.toLowerCase(),value);}
  result.set('host',new URL(origin).host);result.set('accept-encoding','identity');
  result.set('content-length',String(bodyLength));
  return [...result].sort(([a],[b])=>a<b?-1:a>b?1:0);
}

export function decodeV3Capture(capture){
  try{
    if(!exact(capture,CAPTURE_KEYS)||capture.version!==3||capture.method!=='POST'||
      !['xhr','fetch'].includes(capture.resource_type)||capture.transport_policy!=='fixed-egress-v1'||
      !Array.isArray(capture.protection_refs)||capture.protection_refs.length)bad();
    if(bytes(JSON.stringify(capture))>32768)capacity();
    const origin=new URL(capture.origin);
    if(origin.protocol!=='https:'||origin.origin!==capture.origin||origin.username||origin.password)bad();
    const body=unbase64(capture.body_b64),target=decode(unbase64(capture.target_b64)),contentType=decode(unbase64(capture.content_type_b64));
    if(body.length>16384||!/^\/(?!\/)[\x21-\x7e]*$/.test(target)||target.includes('#'))bad();
    const url=new URL(target,capture.origin);
    if(url.origin!==capture.origin||url.pathname+url.search!==target||bytes(url.search.slice(1))>8192)bad();
    if(!/^application\/(?:json|x-www-form-urlencoded)(?:; *charset=(?:utf-8|"utf-8"))?$/i.test(contentType))bad();
    const original=headerRows(capture.original_headers),effective=headerRows(capture.effective_headers);
    if(original.find(([n])=>n.toLowerCase()==='content-type')?.[1]!==contentType||
      JSON.stringify(effective)!==JSON.stringify(effectiveV3Headers(original,capture.origin,body.length)))bad();
    const hasCookie=original.some(([name])=>name.toLowerCase()==='cookie');
    const cookie=capture.cookie_context;
    if(hasCookie){
      if(!exact(cookie,['jar_ref','epoch_ref'])||Object.values(cookie).some(v=>typeof v!=='string'||!/^[a-f0-9]{32}$/.test(v)))bad();
    }else if(cookie!==null)bad();
    return {body,target,contentType,original,effective,url};
  }catch(error){if(error.message==='setup-plan-capacity-required')throw error;bad();}
}

function component(raw){
  if(/%(?![0-9a-fA-F]{2})/.test(raw))bad();
  try{return text(decodeURIComponent(raw.replaceAll('+',' ')));}catch{bad();}
}

function form(raw,{carrier=false}={}){
  if(!raw)return [];
  const seen=new Set(),parts=raw.split('&');if(parts.length>100)bad();
  return parts.map(part=>{
    const at=part.indexOf('='),name=component(at<0?part:part.slice(0,at)),value=component(at<0?'':part.slice(at+1));
    if(!name||seen.has(name))bad();seen.add(name);
    if(!carrier){
      // Structured names are supported only by the explicit body carrier view.
      if(/^\s*[\[{]/.test(name))bad();
      key(name);
    }
    return [name,value];
  });
}

function jsonTree(raw,parseTree){
  if(typeof parseTree!=='function')bad();
  const errors=[],root=parseTree(raw,errors,{disallowComments:true,allowTrailingComma:false,allowEmptyContent:false});
  if(errors.length||root?.type!=='object')bad();
  const visit=(node,depth=0)=>{
    if(depth>8)bad();
    if(node.type==='object'){
      const entries=[],seen=new Set();if((node.children||[]).length>100)bad();
      for(const prop of node.children||[]){
        const name=key(prop.children?.[0]?.value);if(seen.has(name))bad();seen.add(name);
        entries.push([name,visit(prop.children[1],depth+1)]);
      }
      return {type:'object',entries};
    }
    if(node.type==='array'){
      if((node.children||[]).length>100)bad();return {type:'array',items:(node.children||[]).map(n=>visit(n,depth+1))};
    }
    if(node.type==='string')return {type:'string',value:text(node.value)};
    if(node.type==='number'){if(!Number.isSafeInteger(node.value))bad();return {type:'integer',value:node.value===0?0:node.value};}
    if(node.type==='boolean'||node.type==='null')return {type:node.type,value:node.value};
    bad();
  };
  return visit(root);
}

export function parseV3Profile(capture,profileId,parseTree){
  try{
    if(!PROFILES.includes(profileId))bad();
    const c=decodeV3Capture(capture),json=profileId==='json-utf8-v1';
    if(c.contentType.split(';')[0].toLowerCase()!==(json?'application/json':'application/x-www-form-urlencoded'))bad();
    const path=c.url.pathname.split('/').filter(Boolean).map(part=>{
      // A path does not use the form '+' convention.
      const value=component(part.replaceAll('+','%2B'));if(bytes(value)>256)capacity();return value;
    });
    const query=form(c.url.search.slice(1));
    const raw=decode(c.body);
    let body,carrier=false;
    if(json)body=jsonTree(raw,parseTree);
    else{
      const pairs=form(raw,{carrier:profileId==='form-json-name-view-v1'});
      if(profileId==='form-json-name-view-v1'){
        if(pairs.length!==1||pairs[0][1]!=='')bad();
        body=jsonTree(pairs[0][0],parseTree);carrier=true;
      }else body={type:'form',pairs};
    }
    const locations=[];
    const add=(id,type,value,sensitive=false)=>{
      if(typeof value==='string'&&bytes(value)>256)capacity();
      locations.push({id,type,sensitive});
    };
    path.forEach((part,i)=>add(`path.${i}`,'string',part));
    const pairs=(rows,prefix)=>rows.forEach(([name,value],i)=>{
      key(name);add(`${prefix}.${i}.key`,'key',name,/session|auth|token|key|credential|challenge/i.test(name));
      add(`${prefix}.${i}.value`,'string',value);
    });
    pairs(query,'query');
    pairs(c.effective.filter(([name])=>!FIXED.has(name)),'header');
    const walk=(node,id)=>{
      if(node.type==='object'){
        if(!node.entries.length)add(id,'empty-object',null);
        node.entries.forEach(([name,child],i)=>{
          add(`${id}.${i}.key`,'key',name,/session|auth|token|key|credential|challenge/i.test(name));walk(child,`${id}.${i}.value`);
        });
      }else if(node.type==='array'){
        if(!node.items.length)add(id,'empty-array',null);node.items.forEach((child,i)=>walk(child,`${id}.${i}`));
      }else if(node.type==='form')pairs(node.pairs,id);
      else add(id,node.type,node.value);
    };
    if(carrier){add('body.carrier','structured-carrier',null);add('body.outer-value','string','');}
    walk(body,'body');if(locations.length>MAX_REFERENCE_UNITS)capacity();
    return {profile_id:profileId,ordered_tree:{path,query,body},locations,unit_count:locations.length,
      byte_count:bytes(JSON.stringify(capture))};
  }catch(error){if(error.message==='setup-plan-capacity-required')throw error;bad();}
}

export function validatePublicReference(capture,view,reference){
  const result={matched:false,complete:false,unit_count:view.unit_count};
  try{
    if(!exact(reference,['profile_id','target_text','content_type','body_text','public_headers'])||
      reference.profile_id!==view.profile_id||!Array.isArray(reference.public_headers)||reference.public_headers.length>100)return result;
    const c=decodeV3Capture(capture),headers=reference.public_headers.map(row=>{
      if(!exact(row,['name','value'])||typeof row.name!=='string'||row.name!==row.name.toLowerCase()||
        typeof row.value!=='string'||bytes(row.name)>256||bytes(row.value)>256)bad();
      return [row.name,row.value];
    });
    const expected=c.effective.filter(([name])=>!FIXED.has(name));
    const matched=reference.target_text===c.target&&reference.content_type===c.contentType&&
      reference.body_text===decode(c.body)&&JSON.stringify(headers)===JSON.stringify(expected);
    return {matched,complete:matched,unit_count:view.unit_count};
  }catch{return result;}
}

export function safeV3Observation(refs,publicIdentity){
  if(!exact(refs,['network_ref','representation_ref','literal_review_refs'])||
    !exact(publicIdentity,['origin','account'])||!Array.isArray(refs.literal_review_refs)||
    refs.literal_review_refs.length>MAX_REFERENCE_UNITS||[refs.network_ref,refs.representation_ref,...refs.literal_review_refs]
      .some(v=>typeof v!=='string'||!/^[a-f0-9]{32}$/.test(v)))bad();
  return {...structuredClone(refs),method:'POST',purpose:'initialization-read',profiles:[...PROFILES],
    origin:publicIdentity.origin,account:publicIdentity.account};
}
