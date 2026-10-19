import {normalizeResponseChecks} from './web_initialization_contracts.mjs';
const signature=value=>JSON.stringify(value);

export class StartupState {
  constructor({lifecycle,clock=Date.now,monotonic=()=>performance.now(),emit=()=>{}}){
    this.lifecycle=lifecycle;this.clock=clock;this.emit=emit;this.required=new Map();this.context=null;
    this.pending=new Map();this.ready=new Set();this.blocked=new Set();this.seen=new Set();
    this.armed=false;this.authenticationForwarded=0;
    this.monotonic=monotonic;
  }

  register(contracts){
    if(this.authenticationForwarded)throw new Error('outcome-unknown');
    const staged=new Map(this.required);
    for(const contract of Object.values(contracts)){
      if(contract.purpose!=='initialization-read')continue;
      normalizeResponseChecks(contract.response_checks);
      for(const old of staged.values())if(signature(old.descriptor)===signature(contract.descriptor)&&
        (old.prerequisite_id!==contract.prerequisite_id||signature(old.response_checks)!==signature(contract.response_checks)))
        throw new Error('scope-mismatch');
      staged.set(contract.prerequisite_id,structuredClone(contract));
    }
    this.required=staged;
  }

  open(context){
    if(this.authenticationForwarded||!context||context.preauth_lifecycle!==this.lifecycle||
      context.signal.aborted||this.clock()>=context.deadline)throw new Error('session-unavailable');
    this.context=context;this.pending.clear();this.ready.clear();this.blocked.clear();this.seen.clear();this.armed=false;
  }

  check(receipt){
    const c=this.context;
    if(!c||c.signal.aborted||this.clock()>=c.deadline||this.armed||this.authenticationForwarded||
      ['preauth_lifecycle','resume_id','document_id','generation'].some(key=>receipt[key]!==c[key]))throw new Error('scope-mismatch');
  }

  updateContext(context){
    const old=this.context;
    if(!this.canInsertCredentials()||!old||context.resume_id!==old.resume_id||context.document_id!==old.document_id||
      context.preauth_lifecycle!==old.preauth_lifecycle||context.deadline!==old.deadline||context.signal!==old.signal||
      context.phase!=='login-once'||context.generation!==old.generation+1)throw new Error('scope-mismatch');
    this.context=context;
  }

  deny(descriptor){
    if(this.context&&!this.armed)for(const [id,c] of this.required)
      if(signature(c.descriptor)===signature(descriptor))this.blocked.add(id);
  }

  begin(permit){
    this.check(permit);
    if(permit.kind!=='initialization-read'||!this.required.has(permit.prerequisite_id)||
      this.clock()>=permit.expires_at_ms||this.seen.has(permit.check_id))throw new Error('scope-mismatch');
    const deadline=Math.min(permit.dispatch_deadline??Infinity,this.monotonic()+Math.max(0,Math.min(10000,permit.expires_at_ms-this.clock())));
    const receipt=Object.freeze({...permit,dispatch_deadline:deadline});this.seen.add(permit.check_id);
    this.pending.set(receipt,{forwarded:false});return receipt;
  }

  _event(kind,receipt,extra={}){
    const c=this.context;
    this.emit({kind,resume_id:c.resume_id,preauth_lifecycle:c.preauth_lifecycle,document_id:c.document_id,
      phase:c.phase,generation:c.generation,authentication_forwarded:this.authenticationForwarded,
      ...(receipt?{check_id:receipt.check_id,prerequisite_id:receipt.prerequisite_id}:{}),...extra});
  }

  forward(receipt){
    this.check(receipt);const row=this.pending.get(receipt);
    if(!row||row.forwarded||this.clock()>=receipt.expires_at_ms||this.monotonic()>=receipt.dispatch_deadline)throw new Error('scope-mismatch');
    row.forwarded=true;this._event('initialization-forwarded',receipt);
  }

  response(receipt,{ready}){
    this.check(receipt);const row=this.pending.get(receipt);
    if(!row?.forwarded||typeof ready!=='boolean')throw new Error('scope-mismatch');
    this.pending.delete(receipt);(ready?this.ready:this.blocked).add(receipt.prerequisite_id);
    this._event('prerequisite-response',receipt,{ready});
  }

  canInsertCredentials(){
    return !!this.context&&!this.context.signal.aborted&&this.clock()<this.context.deadline&&!this.armed&&!this.authenticationForwarded&&
      this.pending.size===0&&this.blocked.size===0&&[...this.required.keys()].every(id=>this.ready.has(id));
  }

  armCredentials(){
    if(!this.canInsertCredentials())throw new Error('initialization-required');
    this._event('controls-ready');this.armed=true;this._event('credentials-armed');
  }

  end(context){if(this.context===context){this.context=null;this.pending.clear();}}

  status(){
    const ready=[...this.ready].filter(id=>!this.blocked.has(id)).length;
    return {required:this.required.size,ready,pending:this.pending.size,blocked:this.blocked.size,
      state:this.armed||this.authenticationForwarded?'sealed':this.canInsertCredentials()?'ready':'pending'};
  }
}
