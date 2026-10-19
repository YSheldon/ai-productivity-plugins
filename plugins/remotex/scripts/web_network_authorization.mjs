import {createHash,randomUUID} from 'node:crypto';

const authName=/^(?:password|passwd|pwd|token|access_token|refresh_token|session_id|sessionid|csrf|csrf_token|nonce|signature|ticket)$/i;
const signature=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');

export function requestCancelled(request){
  try {return !!request.failure?.();}catch{return true;}
}

function parseJson(raw){
  try {
    const value=JSON.parse(raw);
    // Browser JSON.stringify payloads have one unambiguous representation. Reject
    // duplicate keys and noncanonical encodings instead of guessing their meaning.
    if(JSON.stringify(value)!==raw.trim())throw new Error();
    return value;
  }catch{throw new Error('request-contract-unavailable');}
}

function pairs(params){
  const entries=[...params.entries()],keys=new Set(entries.map(([key])=>key));
  if(entries.length!==keys.size||entries.length>100||entries.some(([key,value])=>!key||key.includes('\uFFFD')||value.includes('\uFFFD')))throw new Error('request-contract-unavailable');
  return Object.fromEntries(entries);
}

function safeValue(value,secrets,key='',depth=0){
  if(depth>8)throw new Error('request-contract-unavailable');
  if(authName.test(key)){
    if(typeof value!=='string'||value.length>4096)throw new Error('request-contract-unavailable');
    return {internalAuth:true};
  }
  if(typeof value==='string'){
    if(value.length>16384||secrets.some(secret=>secret&&value.includes(secret)))throw new Error('credential-in-unsupported-field');
    if(value.startsWith('{')||value.startsWith('['))return safeValue(parseJson(value),secrets,key,depth+1);
    return value;
  }
  if(Array.isArray(value)){
    if(value.length>100)throw new Error('request-contract-unavailable');
    return value.map(part=>safeValue(part,secrets,'',depth+1));
  }
  if(value&&typeof value==='object'){
    const entries=Object.entries(value);
    if(entries.length>100||entries.some(([name])=>name.length>128||['__proto__','constructor','prototype'].includes(name)))throw new Error('request-contract-unavailable');
    if(entries.some(([name])=>secrets.some(secret=>secret&&name.includes(secret))))throw new Error('credential-in-unsupported-field');
    return Object.fromEntries(entries.map(([name,part])=>[name,safeValue(part,secrets,name,depth+1)]));
  }
  if(value===null||typeof value==='boolean'||Number.isSafeInteger(value))return value;
  throw new Error('request-contract-unavailable');
}

export function describeRequest(request,origin,secrets){
  const url=new URL(request.url());
  if(url.protocol!=='https:'||url.origin!==origin||url.username||url.password)throw new Error('origin-blocked');
  if(!/^\/[A-Za-z0-9/_.~-]{0,511}$/.test(url.pathname))throw new Error('request-contract-unavailable');
  const raw=request.postData()||'';
  if(Buffer.byteLength(raw,'utf8')>16384||url.search.length>8192)throw new Error('request-too-large');
  const method=request.method();
  if(!['GET','HEAD','POST','PUT','PATCH','DELETE'].includes(method))throw new Error('request-contract-unavailable');
  const contentType=(request.headers()['content-type']||'').split(';')[0].trim().toLowerCase();
  let body=null;
  if(raw){
    if(contentType==='application/json')body=parseJson(raw);
    else if(contentType==='application/x-www-form-urlencoded'){
      if(/%(?![A-Fa-f0-9]{2})/.test(raw))throw new Error('request-contract-unavailable');
      body=pairs(new URLSearchParams(raw));
    }else throw new Error('request-contract-unavailable');
  }
  const result={method,path:url.pathname,query:safeValue(pairs(url.searchParams),secrets),
    contentType,body:safeValue(body,secrets),resourceType:request.resourceType()};
  const exportedStrings=value=>typeof value==='string'?[value]:value&&typeof value==='object'?Object.values(value).flatMap(exportedStrings):[];
  if(exportedStrings(result).some(value=>secrets.some(secret=>secret&&value.includes(secret))))throw new Error('credential-in-unsupported-field');
  if(!['document','stylesheet','script','image','font','xhr','fetch','other'].includes(result.resourceType))throw new Error('request-contract-unavailable');
  if(Buffer.byteLength(JSON.stringify(result),'utf8')>32768)throw new Error('request-too-large');
  return result;
}

export class NetworkPolicy {
  constructor({origin,secret,requestPermit,clock=Date.now,startup,consumeReceipt}){
    if(typeof requestPermit!=='function')throw new Error('invalid-job');
    this.origin=origin;this.requestPermit=requestPermit;this.phase='bootstrap';this.generation=0;
    this.activeAttempt=null;this.pending=new Map();
    this.forwarded=new Map();this.inFlight=new Map();this.loginForwarded=0;this.authenticationForwarded=0;
    this.clock=clock;this.dispatchDeadline=0;
    this.startup=startup;this.consumeReceipt=consumeReceipt;this.forwardingReceipts=new WeakMap();
    this.preauthLifecycle=randomUUID().replaceAll('-','');this.initializationForwarded=0;
    this.setupHold=false;this.activeChecks=0;this.activeForwarding=0;
    this.secrets=secret?[secret,encodeURIComponent(secret),Buffer.from(secret).toString('base64')]:[];
  }

  setPhase(phase){
    if(!['bootstrap','login-once','discovery-only','grant-active'].includes(phase)||this.phase==='fenced')throw new Error('session-unavailable');
    const allowed={bootstrap:['bootstrap','login-once'], 'login-once':['login-once','discovery-only'],
      'discovery-only':['discovery-only','grant-active'], 'grant-active':['grant-active','discovery-only']};
    if(!allowed[this.phase].includes(phase))throw new Error('session-unavailable');
    this.phase=phase;this.generation++;
  }

  fence(){this.phase='fenced';this.activeAttempt=null;this.generation++;}

  arm(attempt){
    if(this.phase!=='grant-active'||this.activeAttempt||typeof attempt!=='string'||!/^[a-f0-9]{32}$/.test(attempt))throw new Error('session-unavailable');
    this.activeAttempt=attempt;this.dispatchDeadline=this.clock()+5000;this.generation++;
  }

  beginForwarding(request){
    if(this.phase==='fenced')throw new Error('grant-revoked');
    if(this.setupHold)throw new Error('replacement-pending');
    const permit=this.takeForwardingReceipt(request);
    const attempt=this.activeAttempt;
    let initialization;
    if(permit.kind==='initialization-read'){
      if(!this.startupState||this.authenticationForwarded)throw new Error('scope-mismatch');
      initialization=this.startupState.begin(permit);this.initializationForwarded++;
    }else if(attempt){
      this.forwarded.set(attempt,(this.forwarded.get(attempt)||0)+1);
      this.inFlight.set(attempt,(this.inFlight.get(attempt)||0)+1);
    }else if(this.phase==='login-once'){
      this.loginForwarded++;
      const descriptor=describeRequest(request,this.origin,this.secrets);
      const internalAuth=value=>!!(value&&typeof value==='object'&&
        (value.internalAuth===true||Object.values(value).some(internalAuth)));
      if(!['GET','HEAD'].includes(descriptor.method)||internalAuth(descriptor.body)||internalAuth(descriptor.query)){
        this.authenticationForwarded++;
        if(this.startupState?.context){
          this.startupState.authenticationForwarded=this.authenticationForwarded;
          this.startupState._event('authentication-forwarded');
        }
      }
    }
    const generation=this.generation,context=this.startup?.();
    this.activeForwarding++;let finished=false;
    const completed=()=>{
      if(finished)return;finished=true;this.activeForwarding--;
      if(attempt)this.inFlight.set(attempt,Math.max(0,(this.inFlight.get(attempt)||1)-1));
    };
    completed.initialization=initialization;
    completed.privateStartup=!!context?.binding_digest;
    completed.startupSignal=context?.signal;
    completed.startupDeadline=context?.deadline;
    completed.checkDispatch=()=>{
      if(this.phase==='fenced'||this.generation!==generation||requestCancelled(request)||
        (context&&(this.startup?.()!==context||context.signal.aborted||this.clock()>=context.deadline)))throw new Error('scope-mismatch');
      if(initialization)this.startupState.check(initialization);
    };
    return completed;
  }

  takeForwardingReceipt(request){
    const row=this.forwardingReceipts.get(request);this.forwardingReceipts.delete(request);
    if(!row||row.generation!==this.generation||row.phase!==this.phase||requestCancelled(request)||
      signature(describeRequest(request,this.origin,this.secrets))!==row.digest||
      (row.context&&(this.startup?.()!==row.context||row.context.signal.aborted||this.clock()>=row.context.deadline)))
      throw new Error('scope-mismatch');
    if(row.receipt){
      if(typeof this.consumeReceipt!=='function'||!row.context)throw new Error('scope-mismatch');
      return this.consumeReceipt(row.receipt,{descriptor_digest:row.digest,binding_digest:row.context.binding_digest,
        preauth_lifecycle:row.context.preauth_lifecycle,resume_id:row.context.resume_id,
        document_id:row.context.document_id,generation:row.context.generation});
    }
    return {kind:'ordinary'};
  }

  holdSetup(){
    if(this.setupHold)return;
    if(!['bootstrap','login-once'].includes(this.phase)||this.authenticationForwarded)throw new Error('capability-unsupported');
    if(this.activeChecks||this.activeForwarding||this.startup?.()||this.startupState?.pending.size)
      throw new Error('operation-in-progress');
    this.setupHold=true;this.generation++;
  }

  releaseSetup(){if(this.setupHold){this.setupHold=false;this.generation++;}}

  async drain(attempt){
    const deadline=Date.now()+22000;
    while((this.inFlight.get(attempt)||0)>0&&Date.now()<deadline&&this.phase!=='fenced')await new Promise(resolve=>setTimeout(resolve,20));
    if((this.inFlight.get(attempt)||0)>0)throw new Error('outcome-unknown');
    return this.forwarded.get(attempt)||0;
  }

  async authorize(request){
    if(this.setupHold||this.phase==='fenced'||requestCancelled(request))return false;
    if(this.phase==='grant-active'&&(!this.activeAttempt||this.clock()>=this.dispatchDeadline))return false;
    const generation=this.generation,context=this.startup?.();
    let descriptor;
    try {descriptor=describeRequest(request,this.origin,this.secrets);}
    catch(error){this.lastFailure=error.message;return false;}
    const key=signature(descriptor);
    let allowed=false,receipt=null;
    const startup=context?.binding_digest?{resume_id:context.resume_id,preauth_lifecycle:context.preauth_lifecycle,
      document_id:context.document_id,generation:context.generation}:undefined;
    this.activeChecks++;
    try {
      const reply=await this.requestPermit({phase:this.phase,attempt_id:this.activeAttempt,descriptor,digest:key,
        ...(startup?{startup}: {})},{isCancelled:()=>requestCancelled(request)});
      receipt=reply&&typeof reply==='object'&&reply.kind==='initialization-read'?reply:null;
      allowed=reply===true||!!receipt;
    }
    catch{return false;}
    finally{this.activeChecks--;}
    if(this.phase==='fenced'||this.generation!==generation||requestCancelled(request)||
      (this.phase==='grant-active'&&this.clock()>=this.dispatchDeadline))return false;
    if(!allowed){
      this.startupState?.deny(descriptor);
      const now=Date.now();
      for(const [pendingKey,row] of this.pending){
        if(now-row.at>120000)this.pending.delete(pendingKey);
      }
      if(!this.pending.has(key)&&this.pending.size<100){
        this.pending.set(key,{ref:randomUUID().replaceAll('-',''),descriptor,at:now});
      }
    }
    if(allowed)this.forwardingReceipts.set(request,{receipt,digest:key,generation,phase:this.phase,context});
    return allowed;
  }

  list(){
    return [...this.pending.values()].filter(row=>Date.now()-row.at<=120000).map(row=>({ref:row.ref,
      phase:this.phase,method:row.descriptor.method,path:row.descriptor.path,contentType:row.descriptor.contentType,
      body_fields:row.descriptor.body&&typeof row.descriptor.body==='object'?Object.keys(row.descriptor.body):[],
      query_fields:Object.keys(row.descriptor.query)}));
  }

  resolve(ref){
    const row=[...this.pending.values()].find(value=>value.ref===ref&&Date.now()-value.at<=120000);
    if(!row)throw new Error('request-contract-unavailable');
    return structuredClone(row.descriptor);
  }
}
