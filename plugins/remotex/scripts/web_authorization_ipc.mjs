import {randomUUID} from 'node:crypto';

export class WorkerAuthority {
  constructor({emit,onRevoke}){
    this.emit=emit;this.onRevoke=onRevoke;this.pending=new Map();this.closed=false;this.generation=0;
  }

  check(request){
    if(this.closed||this.pending.size>=16)return Promise.resolve(false);
    const id=randomUUID().replaceAll('-','');
    return new Promise(resolve=>{
      const timer=setTimeout(()=>{this.pending.delete(id);resolve(false);},10000);
      this.pending.set(id,{resolve,timer});
      try {this.emit({event:'authorization-check',id,request});}
      catch{clearTimeout(timer);this.pending.delete(id);resolve(false);}
    });
  }

  handle(frame){
    if(!frame||typeof frame!=='object'||Array.isArray(frame))return false;
    if(Object.keys(frame).sort().join(',')==='allowed,authorization_reply'&&typeof frame.allowed==='boolean'){
      const pending=this.pending.get(frame.authorization_reply);if(!pending)return false;
      this.pending.delete(frame.authorization_reply);clearTimeout(pending.timer);pending.resolve(frame.allowed);return true;
    }
    if(Object.keys(frame).sort().join(',')==='control_event,generation'&&frame.control_event==='revoke'&&Number.isSafeInteger(frame.generation)&&frame.generation>this.generation){
      this.generation=frame.generation;this.denyPending();this.onRevoke(this.generation);return true;
    }
    return false;
  }

  denyPending(){
    for(const pending of this.pending.values()){clearTimeout(pending.timer);pending.resolve(false);}
    this.pending.clear();
  }

  dispose(){this.closed=true;this.denyPending();}
}
