import {randomUUID} from 'node:crypto';

export class WorkerAuthority {
  constructor({emit,onRevoke,startup}){
    this.emit=emit;this.onRevoke=onRevoke;this.pending=new Map();this.closed=false;this.generation=0;
    this.startup=typeof startup==='function'?startup:null;
    this.retired=new Map();this.staticQueue=[];this.staticActive=null;this.context=null;
  }

  _pruneRetired(){
    const now=Date.now();
    for(const [id,deadline] of this.retired)if(now>=deadline)this.retired.delete(id);
  }

  _settle(id,allowed,retire=false){
    const entry=this.pending.get(id);if(!entry)return;
    this.pending.delete(id);clearTimeout(entry.timer);
    entry.signal?.removeEventListener('abort',entry.abort);
    if(retire&&entry.emitted){
      this._pruneRetired();
      while(this.retired.size>=64)this.retired.delete(this.retired.keys().next().value);
      this.retired.set(id,Date.now()+60000);
    }
    entry.resolve(allowed===true&&!this.closed&&!entry.signal?.aborted);
    this._pump();
  }

  _send(request,signal){
    if(this.closed||this.pending.size>=16||signal?.aborted)return Promise.resolve(false);
    const id=randomUUID().replaceAll('-','');
    return new Promise(resolve=>{
      const entry={resolve,signal,emitted:false,abort:()=>this._settle(id,false,true)};
      entry.timer=setTimeout(entry.abort,10000);
      this.pending.set(id,entry);signal?.addEventListener('abort',entry.abort,{once:true});
      try {this.emit({event:'authorization-check',id,request});entry.emitted=true;}
      catch{this._settle(id,false);}
    });
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
    this.staticActive?.controller.abort();
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
    while(this.staticQueue.length){
      const row=this.staticQueue.shift();
      if(!this._current(row.context)){row.finish(false);continue;}
      this.staticActive=row;
      this._send(row.request,row.controller.signal).then(allowed=>{
        row.finish(allowed&&this._current(row.context));
      }).finally(()=>{
        if(this.staticActive===row)this.staticActive=null;
        this._pump();
      });
      return;
    }
  }

  check(request,{signal}={}){
    if(this.closed||signal?.aborted)return Promise.resolve(false);
    if(!this.startup||!this._isStatic(request))return this._send(request,signal);
    let context;
    try {context=this.startup();}catch{context=null;}
    this._bindContext(context);
    if(!this._current(context)||request.phase!==this.contextPhase||
      this.staticQueue.length+(this.staticActive?1:0)>=64)return Promise.resolve(false);
    let snapshot;
    try {snapshot=structuredClone(request);}catch{return Promise.resolve(false);}
    // These descriptors have already passed NetworkPolicy's exact-origin check.
    // Queue before asking the broker; never cache or reuse a returned permission.
    return new Promise(resolve=>{
      let finished=false;
      const row={context,request:snapshot,controller:new AbortController(),finish:value=>{
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

  handle(frame){
    if(!frame||typeof frame!=='object'||Array.isArray(frame))return false;
    if(Object.keys(frame).sort().join(',')==='allowed,authorization_reply'&&typeof frame.allowed==='boolean'&&
      typeof frame.authorization_reply==='string'&&/^[a-f0-9]{32}$/.test(frame.authorization_reply)){
      if(this.pending.has(frame.authorization_reply)){this._settle(frame.authorization_reply,frame.allowed);return true;}
      this._pruneRetired();
      // An expired check stays denied; its one late reply is not a UI command.
      return this.retired.delete(frame.authorization_reply);
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
