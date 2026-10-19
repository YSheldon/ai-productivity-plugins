const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const exact=(value,keys)=>object(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const forbidden=/password|passwd|credential|private.?key|cookie|authorization|token|session|csrf|nonce|signature|ticket|challenge|username|account|(?:^|[_-])auth(?:$|[_-])/i;
const invalid=()=>{throw new Error('request-contract-unavailable');};
const freeze=value=>{if(value&&typeof value==='object'){for(const part of Object.values(value))freeze(part);Object.freeze(value);}return value;};

function pointerParts(pointer){
  if(typeof pointer!=='string'||!pointer.startsWith('/')||pointer.length>512||/~(?![01])/.test(pointer))invalid();
  const parts=pointer.slice(1).split('/').map(part=>part.replaceAll('~1','/').replaceAll('~0','~'));
  if(parts.length>8||parts.some(part=>!part||forbidden.test(part)||['__proto__','constructor','prototype'].includes(part)||/[\x00-\x1f]/.test(part)))invalid();
  return parts;
}

export function normalizeResponseChecks(value){
  if(!Array.isArray(value)||!value.length||value.length>8)invalid();
  const seen=new Set();
  for(const row of value){
    if(!object(row))invalid();
    pointerParts(row.pointer);
    const key=JSON.stringify(row);
    if(seen.has(key))invalid();seen.add(key);
    if(row.test==='nonempty-string'){
      if(!exact(row,['pointer','test']))invalid();
    }else{
      if(!exact(row,['pointer','test','expected']))invalid();
      if(row.test==='type'){
        if(!['object','array','string','boolean','integer','null'].includes(row.expected))invalid();
      }else if(row.test==='equals-boolean'){
        if(typeof row.expected!=='boolean')invalid();
      }else if(row.test==='equals-integer'){
        if(!Number.isSafeInteger(row.expected))invalid();
      }else invalid();
    }
  }
  return freeze(structuredClone(value));
}

function literals(value,depth=0){
  if(depth>8)invalid();
  if(value===null||typeof value==='boolean'||Number.isSafeInteger(value))return;
  if(typeof value==='string'){
    if(value.length>16384||/[\x00-\x1f]/.test(value)||/-----BEGIN |\b(?:ghp_|glpat-|sk-proj-)/.test(value))invalid();
    return;
  }
  if(Array.isArray(value)){
    if(value.length>100)invalid();for(const part of value)literals(part,depth+1);return;
  }
  if(!object(value)||Object.keys(value).length>100)invalid();
  for(const [key,part] of Object.entries(value)){
    if(key.length>128||forbidden.test(key)||['internalAuth','__proto__','constructor','prototype'].includes(key))invalid();
    literals(part,depth+1);
  }
}

export function validateInitializationDescriptor(descriptor){
  if(!exact(descriptor,['method','path','query','contentType','body','resourceType'])||
    descriptor.method!=='POST'||!/^\/[A-Za-z0-9/_.~-]{0,511}$/.test(descriptor.path)||
    !['xhr','fetch'].includes(descriptor.resourceType)||
    !['application/json','application/x-www-form-urlencoded'].includes(descriptor.contentType)||
    !object(descriptor.query)||!object(descriptor.body))invalid();
  literals(descriptor.query);literals(descriptor.body);
  if(Buffer.byteLength(JSON.stringify(descriptor))>32768)invalid();
  return structuredClone(descriptor);
}

export function evaluateInitializationResponse(response,checks,parseTree){
  const fail=()=>{throw new Error('initialization-response-rejected');};
  try{
    normalizeResponseChecks(checks);
    if(!object(response)||!Number.isInteger(response.status)||response.status<200||response.status>=300||
      !object(response.headers)||!Buffer.isBuffer(response.body)||response.body.length>65536||typeof parseTree!=='function')fail();
    const headers={};
    for(const [key,value] of Object.entries(response.headers)){
      const name=key.toLowerCase();if(Object.hasOwn(headers,name)||typeof value!=='string')fail();headers[name]=value;
    }
    if(Object.keys(headers).some(key=>['set-cookie','www-authenticate','proxy-authenticate','authentication-info',
      'proxy-authentication-info','location','upgrade'].includes(key))||
      (headers['content-encoding']&&headers['content-encoding'].toLowerCase()!=='identity')||
      (headers['content-type']||'').split(';')[0].trim().toLowerCase()!=='application/json')fail();
    const text=new TextDecoder('utf-8',{fatal:true}).decode(response.body),errors=[];
    const root=parseTree(text,errors,{disallowComments:true,allowTrailingComma:false,allowEmptyContent:false});
    if(errors.length||!root)fail();
    const visit=(node,depth=0)=>{
      if(depth>64)fail();
      if(node.type==='object'){
        const seen=new Set();
        for(const prop of node.children||[]){
          const key=prop.children?.[0]?.value;
          if(typeof key!=='string'||seen.has(key)||['__proto__','constructor','prototype'].includes(key))fail();
          seen.add(key);visit(prop.children[1],depth+1);
        }
      }else if(node.type==='array')for(const child of node.children||[])visit(child,depth+1);
      else if(node.type==='number'&&!Number.isFinite(node.value))fail();
    };
    visit(root);
    for(const check of checks){
      let node=root;
      for(const part of pointerParts(check.pointer)){
        if(node.type==='object')node=node.children?.find(prop=>prop.children[0].value===part)?.children[1];
        else if(node.type==='array'&&/^(0|[1-9][0-9]*)$/.test(part))node=node.children?.[Number(part)];
        else node=undefined;
        if(!node)fail();
      }
      const type=node.type==='number'?(Number.isSafeInteger(node.value)?'integer':'number'):node.type;
      if(check.test==='type'&&type!==check.expected)fail();
      if(check.test==='nonempty-string'&&(type!=='string'||!node.value.length))fail();
      if(check.test==='equals-boolean'&&(type!=='boolean'||node.value!==check.expected))fail();
      if(check.test==='equals-integer'&&(type!=='integer'||node.value!==check.expected))fail();
    }
    return {ready:true};
  }catch{fail();}
}
