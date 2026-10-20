import {randomUUID} from 'node:crypto';
import {normalizeResponseChecks} from './web_initialization_contracts.mjs';
import {decodeV3Capture} from './web_request_profiles.mjs';

export class WorkerAuthority {
  constructor({emit,onRevoke,startup}){
    this.emit=emit;this.onRevoke=onRevoke;this.pending=new Map();this.closed=false;this.generation=0;
    this.startup=typeof startup==='function'?startup:null;
    this.retired=new Map();this.staticQueue=[];this.staticActive=null;this.context=null;
    this.receipts=new WeakMap();
  }

  _pruneRetired(){
    const now=Date.now();
    for(const [id,row] of this.retired)if(now>=row.deadline)this.retired.delete(id);
  }

  _settle(id,allowed,retire=false){
    const entry=this.pending.get(id);if(!entry)return;
    this.pending.delete(id);clearTimeout(entry.timer);
    entry.signal?.removeEventListener('abort',entry.abort);
    if(retire&&entry.emitted){
      this._pruneRetired();
      while(this.retired.size>=64)this.retired.delete(this.retired.keys().next().value);
      this.retired.set(id,{deadline:Date.now()+60000,batch:entry.batch});
    }
    const current=!this.closed&&!entry.signal?.aborted&&Date.now()<entry.deadline;
    entry.resolve(current&&(allowed===true||(allowed&&typeof allowed==='object'&&this.receipts.has(allowed)))?allowed:false);
    this._pump();
  }

  _send(request,signal,context=null){
    if(this.closed||this.pending.size>=16||signal?.aborted)return Promise.resolve(false);
    const id=randomUUID().replaceAll('-','');
    const {promise,entry}=this._register(id,signal,null);
    if(context){entry.request=structuredClone(request);entry.context=context;}
    try {this.emit({event:'authorization-check',id,request});entry.emitted=true;}
    catch{this._settle(id,false);}
    return promise;
  }

  _register(id,signal,batch){
    let entry;
    const promise=new Promise(resolve=>{
      entry={resolve,signal,batch,deadline:Date.now()+10000,monotonicDeadline:performance.now()+10000,emitted:false,abort:()=>this._settle(id,false,true)};
      entry.timer=setTimeout(entry.abort,10000);
      this.pending.set(id,entry);signal?.addEventListener('abort',entry.abort,{once:true});
    });
    return {promise,entry};
  }

  _batchFrame(rows){
    return {event:'authorization-check-batch',checks:rows.map(row=>({id:row.id,request:row.request}))};
  }

  _sendBatch(rows){
    if(this.closed||rows.length+this.pending.size>16)return Promise.resolve(rows.map(()=>false));
    const batch=new Set(rows.map(row=>row.id));
    const waiting=rows.map(row=>this._register(row.id,row.controller.signal,batch));
    try {
      this.emit(this._batchFrame(rows));
      for(const row of waiting)row.entry.emitted=true;
    }catch{for(const row of rows)this._settle(row.id,false);}
    return Promise.all(waiting.map(row=>row.promise));
  }

  _isStatic(request){
    const descriptor=request?.descriptor;
    return request?.kind==='network'&&['bootstrap','login-once'].includes(request.phase)&&request.attempt_id===null&&
      descriptor?.method==='GET'&&typeof descriptor.path==='string'&&/^\/[A-Za-z0-9/_.~-]{0,511}\.(?:js|css)$/i.test(descriptor.path)&&
      ['script','stylesheet'].includes(descriptor.resourceType)&&descriptor.body===null&&
      descriptor.query&&typeof descriptor.query==='object'&&!Array.isArray(descriptor.query)&&Object.keys(descriptor.query).length===0;
  }

  _cancelStatic(){
    for(const row of this.staticQueue.splice(0))row.finish(false);
    for(const row of this.staticActive||[])row.controller.abort();
  }

  _bindContext(context){
    if(context===this.context)return;
    clearTimeout(this.contextTimer);
    this.contextSignal?.removeEventListener('abort',this.contextAbort);
    this._cancelStatic();this.context=context;
    this.contextDeadline=0;this.contextPolicy=null;this.contextSignal=null;this.contextActive=false;
    if(!context||!Number.isFinite(context.deadline)||!context.signal||typeof context.signal.addEventListener!=='function')return;
    const policy=context.policy;
    try {
      const origin=new URL(policy.origin);
      if(origin.protocol!=='https:'||origin.origin!==policy.origin||!['bootstrap','login-once'].includes(context.phase))return;
    }catch{return;}
    this.contextPolicy=policy;this.contextOrigin=policy.origin;this.contextPhase=context.phase;
    this.contextPolicyGeneration=context.generation;this.contextGeneration=this.generation;
    this.contextDeadline=Math.min(context.deadline,Date.now()+45000);this.contextSignal=context.signal;
    this.contextActive=true;
    this.contextAbort=()=>{this.contextActive=false;clearTimeout(this.contextTimer);this._cancelStatic();};
    this.contextSignal.addEventListener('abort',this.contextAbort,{once:true});
    this.contextTimer=setTimeout(this.contextAbort,Math.max(0,this.contextDeadline-Date.now()));
  }

  _current(context){
    if(this.closed||!context||context!==this.context||this.generation!==this.contextGeneration||
      !this.contextActive||!this.contextPolicy||this.contextSignal.aborted||Date.now()>=this.contextDeadline)return false;
    try {
      return this.startup()===context&&this.contextPolicy.origin===this.contextOrigin&&
        this.contextPolicy.phase===this.contextPhase&&this.contextPolicy.generation===this.contextPolicyGeneration;
    }catch{return false;}
  }

  _pump(){
    if(this.closed||this.staticActive||this.pending.size>=16)return;
    const rows=[],slots=16-this.pending.size;
    while(this.staticQueue.length){
      const row=this.staticQueue.shift();
      if(!this._current(row.context)||row.cancelled()){row.finish(false);continue;}
      row.id=randomUUID().replaceAll('-','');rows.push(row);
      if(rows.length>=slots)break;
    }
    if(!rows.length)return;
    // Use only the already queued FIFO prefix; never wait to fill a transaction.
    while(rows.length>1&&Buffer.byteLength(JSON.stringify(this._batchFrame(rows))+'\n')>32768)
      this.staticQueue.unshift(rows.pop());
    this.staticActive=rows;
    const pending=rows.length===1?this._send(rows[0].request,rows[0].controller.signal).then(value=>[value]):this._sendBatch(rows);
    pending.then(values=>{
      rows.forEach((row,index)=>row.finish(values[index]&&this._current(row.context)&&!row.cancelled()));
    }).finally(()=>{
      if(this.staticActive===rows)this.staticActive=null;
      this._pump();
    });
  }

  check(request,{signal,isCancelled}={}){
    const cancelled=()=>{
      try {return signal?.aborted===true||(isCancelled!==undefined&&isCancelled()!==false);}
      catch{return true;}
    };
    if(this.closed||cancelled())return Promise.resolve(false);
    if(!this.startup||!this._isStatic(request))return this._send(request,signal);
    let context;
    try {context=this.startup();}catch{context=null;}
    this._bindContext(context);
    if(!this._current(context)||request.phase!==this.contextPhase||
      this.staticQueue.length+(this.staticActive?.length||0)>=64)return Promise.resolve(false);
    let snapshot;
    try {snapshot=structuredClone(request);}catch{return Promise.resolve(false);}
    // These descriptors have already passed NetworkPolicy's exact-origin check.
    // Queue before asking the broker; never cache or reuse a returned permission.
    return new Promise(resolve=>{
      let finished=false;
      const row={context,request:snapshot,cancelled,controller:new AbortController(),finish:value=>{
        if(finished)return;finished=true;signal?.removeEventListener('abort',cancel);resolve(value);
      }};
      const cancel=()=>{
        const index=this.staticQueue.indexOf(row);if(index!==-1)this.staticQueue.splice(index,1);
        row.controller.abort();row.finish(false);this._pump();
      };
      signal?.addEventListener('abort',cancel,{once:true});
      this.staticQueue.push(row);this._pump();
    });
  }

  checkNetwork(request,options={}){
    if(!request||request.kind!=='network')return Promise.resolve(false);
    if(request.version!==undefined){
      try{
        if(request.version!==3||Object.keys(request).sort().join(',')!=='attempt_id,capture,kind,phase,startup,version'||
          request.attempt_id!==null||!['bootstrap','login-once'].includes(request.phase))throw new Error();
        decodeV3Capture(request.capture);
      }catch{return Promise.resolve(false);}
    }
    if(this._isStatic(request))return this.check(request,options);
    if(!request.startup)return this.check(request,options);
    let context;
    try{context=this.startup?.();this._bindContext(context);}catch{return Promise.resolve(false);}
    if(!this._current(context)||request.phase!==context.phase||options.signal?.aborted||options.isCancelled?.()===true)
      return Promise.resolve(false);
    if(request.version===3&&request.capture.origin!==this.contextOrigin)return Promise.resolve(false);
    const signal=options.signal?AbortSignal.any([context.signal,options.signal]):context.signal;
    return this._send(request,signal,context);
  }

  consumeNetworkReceipt(receipt,expected){
    const row=this.receipts.get(receipt);
    this.receipts.delete(receipt);
    if(receipt?.kind==='initialization-permit-v3'){
      if(!row||!this._current(row.context)||Date.now()>=receipt.expires_at_ms||performance.now()>=row.monotonicDeadline||
        !expected||Object.keys(expected).sort().join(',')!=='binding_digest,capture,document_id,generation,preauth_lifecycle,resume_id'||
        ['binding_digest','preauth_lifecycle','resume_id','document_id','generation'].some(key=>receipt[key]!==expected[key])||
        JSON.stringify(expected.capture)!==JSON.stringify(row.request.capture))throw new Error('scope-mismatch');
      return Object.freeze({...receipt,dispatch_deadline:row.monotonicDeadline});
    }
    if(!row||!this._current(row.context)||Date.now()>=receipt.expires_at_ms||performance.now()>=row.monotonicDeadline||
      !expected||Object.keys(expected).sort().join(',')!=='binding_digest,descriptor_digest,document_id,generation,preauth_lifecycle,resume_id'||
      Object.entries(expected).some(([key,value])=>receipt[key]!==value))throw new Error('scope-mismatch');
    return Object.freeze({...receipt,dispatch_deadline:row.monotonicDeadline});
  }

  _typedReply(frame){
    if(frame.permit?.kind==='initialization-permit-v3')return this._typedReplyV3(frame);
    if(Object.keys(frame).sort().join(',')!=='allowed,authorization_reply,permit'||frame.allowed!==true||
      typeof frame.authorization_reply!=='string'||!/^[a-f0-9]{32}$/.test(frame.authorization_reply))return false;
    const entry=this.pending.get(frame.authorization_reply),p=frame.permit;
    if(!entry){this._pruneRetired();return !this.retired.get(frame.authorization_reply)?.batch&&this.retired.delete(frame.authorization_reply);}
    if(!entry.context||entry.batch||!this._current(entry.context)||!p||typeof p!=='object'||Array.isArray(p)||
      Object.keys(p).sort().join(',')!=='binding_digest,check_id,descriptor_digest,document_id,expires_at_ms,generation,kind,preauth_lifecycle,prerequisite_id,response_checks,resume_id'||
      p.kind!=='initialization-read'||p.check_id!==frame.authorization_reply||p.descriptor_digest!==entry.request.digest||
      !/^[a-f0-9]{64}$/.test(p.prerequisite_id)||!Number.isSafeInteger(p.expires_at_ms)||
      p.expires_at_ms<=Date.now()||p.expires_at_ms>entry.context.deadline||
      ['binding_digest','preauth_lifecycle','resume_id','document_id','generation'].some(key=>p[key]!==entry.context[key])||
      entry.request.descriptor?.method!=='POST')return false;
    let checks;
    try{checks=normalizeResponseChecks(p.response_checks);}catch{return false;}
    const receipt=Object.freeze({...p,expires_at_ms:Math.min(p.expires_at_ms,entry.deadline),response_checks:checks});
    this.receipts.set(receipt,{context:entry.context,monotonicDeadline:entry.monotonicDeadline});
    this._settle(frame.authorization_reply,receipt);return true;
  }

  _typedReplyV3(frame){
    if(Object.keys(frame).sort().join(',')!=='allowed,authorization_reply,permit'||frame.allowed!==true||
      typeof frame.authorization_reply!=='string'||!/^[a-f0-9]{32}$/.test(frame.authorization_reply))return false;
    const entry=this.pending.get(frame.authorization_reply),p=frame.permit;
    if(!entry){this._pruneRetired();return !this.retired.get(frame.authorization_reply)?.batch&&this.retired.delete(frame.authorization_reply);}
    const keys=['kind','version','binding_digest','grant_id','item_id','intent_ref','intent_commitment','prerequisite_id',
      'receipt_id','preauth_lifecycle','resume_id','document_id','generation','check_id','expires_at_ms','response_checks','permit_commitment'];
    if(!entry.context||entry.batch||entry.request?.version!==3||!this._current(entry.context)||
      !p||typeof p!=='object'||Array.isArray(p)||Object.keys(p).sort().join(',')!==keys.sort().join(',')||
      p.version!==3||p.check_id!==frame.authorization_reply||
      ['grant_id','intent_ref','receipt_id'].some(key=>typeof p[key]!=='string'||!/^[a-f0-9]{32}$/.test(p[key]))||
      ['intent_commitment','prerequisite_id','permit_commitment'].some(key=>typeof p[key]!=='string'||!/^[a-f0-9]{64}$/.test(p[key]))||
      typeof p.item_id!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(p.item_id)||
      !Number.isSafeInteger(p.expires_at_ms)||p.expires_at_ms<=Date.now()||p.expires_at_ms>entry.context.deadline||
      ['binding_digest','preauth_lifecycle','resume_id','document_id','generation'].some(key=>p[key]!==entry.context[key]))return false;
    let checks;try{checks=normalizeResponseChecks(p.response_checks);}catch{return false;}
    const receipt=Object.freeze({...p,expires_at_ms:Math.min(p.expires_at_ms,entry.deadline),response_checks:checks});
    this.receipts.set(receipt,{context:entry.context,request:entry.request,monotonicDeadline:entry.monotonicDeadline});
    this._settle(frame.authorization_reply,receipt);return true;
  }

  handle(frame){
    if(!frame||typeof frame!=='object'||Array.isArray(frame))return false;
    if(Object.hasOwn(frame,'permit'))return this._typedReply(frame);
    if(Object.keys(frame).join(',')==='authorization_batch_reply'&&Array.isArray(frame.authorization_batch_reply)){
      const rows=frame.authorization_batch_reply;
      if(rows.length<2||rows.length>16||rows.some(row=>!row||typeof row!=='object'||Array.isArray(row)||
        Object.keys(row).sort().join(',')!=='allowed,authorization_reply'||typeof row.allowed!=='boolean'||
        typeof row.authorization_reply!=='string'||!/^[a-f0-9]{32}$/.test(row.authorization_reply))||
        new Set(rows.map(row=>row.authorization_reply)).size!==rows.length)return false;
      this._pruneRetired();
      const entries=rows.map(row=>this.pending.get(row.authorization_reply)||this.retired.get(row.authorization_reply));
      const batch=entries[0]?.batch;
      if(!batch||batch.size!==rows.length||entries.some(row=>!row||row.batch!==batch))return false;
      // Validate the entire membership before consuming any live or retired ID.
      for(const row of rows){
        if(this.pending.has(row.authorization_reply))this._settle(row.authorization_reply,row.allowed);
        else this.retired.delete(row.authorization_reply);
      }
      return true;
    }
    if(Object.keys(frame).sort().join(',')==='allowed,authorization_reply'&&typeof frame.allowed==='boolean'&&
      typeof frame.authorization_reply==='string'&&/^[a-f0-9]{32}$/.test(frame.authorization_reply)){
      if(this.pending.has(frame.authorization_reply)){
        if(this.pending.get(frame.authorization_reply).batch)return false;
        if(this.pending.get(frame.authorization_reply).request?.version===3&&frame.allowed===true)return false;
        this._settle(frame.authorization_reply,frame.allowed);return true;
      }
      this._pruneRetired();
      // An expired check stays denied; its one late reply is not a UI command.
      return !this.retired.get(frame.authorization_reply)?.batch&&this.retired.delete(frame.authorization_reply);
    }
    if(Object.keys(frame).sort().join(',')==='control_event,generation'&&frame.control_event==='revoke'&&Number.isSafeInteger(frame.generation)&&frame.generation>this.generation){
      this.generation=frame.generation;this.denyPending();this.onRevoke(this.generation);return true;
    }
    return false;
  }

  denyPending(){
    this._cancelStatic();
    for(const id of [...this.pending.keys()])this._settle(id,false,true);
  }

  dispose(){
    this.closed=true;this.denyPending();clearTimeout(this.contextTimer);
    this.contextSignal?.removeEventListener('abort',this.contextAbort);
  }
}
