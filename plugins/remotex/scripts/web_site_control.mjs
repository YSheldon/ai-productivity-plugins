import {createHash,randomUUID} from 'node:crypto';

const id=()=>randomUUID().replaceAll('-','');
const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const ref=value=>typeof value==='string'&&/^[a-f0-9]{32}$/.test(value);
const sensitive=/delete|remove|erase|purge|revoke|grant|permission|privilege|disable|uninstall|reset|shutdown|reboot|\u5220\u9664|\u6e05\u7a7a|\u64a4\u9500|\u6388\u6743|\u6743\u9650|\u5173\u95ed\u9632\u62a4|\u7981\u7528|\u5378\u8f7d|\u91cd\u542f/i;
const manual=/password|passwd|credential|private.key|token|cookie|captcha|payment|purchase|transfer.money|\u5bc6\u7801|\u9a8c\u8bc1\u7801|\u4ed8\u6b3e|\u652f\u4ed8/i;
const fields=['observation_id','component_ref','action','risk','value'];

export class SiteNetworkPolicy {
  constructor({origin,check,onComplete=()=>{}}){Object.assign(this,{origin,check,onComplete});this.closed=false;this.waiting=[];this.running=0;this.requests=new WeakMap();}
  async permit(request){
    if(this.closed)return false;
    let url;try{url=new URL(request.url());}catch{return false;}
    if(url.protocol!=='https:'||url.origin!==this.origin||url.username||url.password||
      !['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'].includes(request.method()))return false;
    let tracked=this.requests.get(request);
    if(!tracked){tracked={id:id(),complete:false};this.requests.set(request,tracked);}
    if(tracked.complete)return false;
    if(this.running>=4){
      if(this.waiting.length>=128||!await new Promise(resolve=>this.waiting.push(resolve)))return false;
    }else this.running++;
    try{return !this.closed&&await this.check({kind:'site-network',origin:url.origin,method:request.method(),request_id:tracked.id})===true;}
    finally{const next=this.waiting.shift();if(next)next(true);else this.running--;}
  }
  authorize(request){return this.permit(request);}
  beginForwarding(request){
    const tracked=this.requests.get(request);
    if(!tracked||tracked.complete)throw new Error('grant-revoked');
    let known=false;
    const done=()=>{
      if(tracked.complete)return;
      tracked.complete=true;
      this.onComplete({kind:'site-network-complete',request_id:tracked.id,known});
    };
    done.received=()=>{known=true;};
    done.privateStartup=true;
    done.checkDispatch=async()=>{if(!await this.permit(request))throw new Error('grant-revoked');};
    return done;
  }
  fence(){this.closed=true;for(const resolve of this.waiting.splice(0))resolve(false);}
}

function targetContext(node){
  const root=node.closest('form,[role="dialog"],dialog,tr,[role="row"]')||node.parentElement;
  const form=node.form||node.closest('form');
  if(!root||!node.isConnected)throw new Error('component-stale');
  const blocked='input,textarea,select,option,script,style,noscript,[hidden],[aria-hidden="true"]';
  const visible=el=>!!el?.getClientRects().length&&!el.closest('[hidden],[aria-hidden="true"]')&&getComputedStyle(el).visibility!=='hidden';
  const walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);
  let child,text='',visited=0;
  while((child=walker.nextNode())){
    if(++visited>20000)throw new Error('request-too-large');
    if(!child.parentElement.closest(blocked)&&visible(child.parentElement))text+=child.textContent.replace(/\s+/g,' ').trim()+' ';
    if(text.length>16000)throw new Error('request-too-large');
  }
  const values=[],identifiers=[];
  const formFields=form?.elements?Array.from(form.elements).filter(field=>['INPUT','TEXTAREA','SELECT'].includes(field.tagName)):
    (form||root).querySelectorAll('input,textarea,select');
  for(const field of formFields){
    if(['password','file'].includes(field.type)||field.type!=='hidden'&&!visible(field))continue;
    if(field.type!=='hidden'&&/password|passwd|token|cookie|secret|credential|auth/i.test(field.id+' '+field.name+' '+field.autocomplete))continue;
    if(values.length>=100||String(field.value).length>4096)throw new Error('request-too-large');
    values.push([field.id,field.name,field.type,field.type==='checkbox'||field.type==='radio'?field.checked:field.value]);
    const name=field.name||field.id;
    if(field.type==='hidden'&&/^(?:record|host|device|resource|row)?id$/i.test(name)&&/^[A-Za-z0-9_.:-]{1,128}$/.test(field.value))
      identifiers.push(name+'='+field.value);
  }
  const selection=[];
  for(const field of document.querySelectorAll('input:checked')){
    if(!visible(field))continue;
    if(selection.length>=200)throw new Error('request-too-large');
    selection.push([field.id,field.name,field.value]);
  }
  // This destination is retained only in the worker's private context hash.
  // Public component metadata deliberately omits query/token-bearing URLs.
  const destination=node.tagName==='A'?node.href:node.formAction||node.form?.action||null;
  const fullTarget=text.trim()+(identifiers.length?' ['+identifiers.join(', ')+']':'');
  return {target:fullTarget.slice(0,2000),truncated:fullTarget.length>2000,
    state:{text,values,selection,form:form?[form.id,form.action,form.method,form.enctype]:null,
      submitter:[node.name,node.value,node.type]},destination};
}

export class SiteControl {
  constructor({registry,authorize}){Object.assign(this,{registry,authorize});this.actions=new Map();}
  async preview(args){
    if(!args||typeof args!=='object'||Array.isArray(args)||Object.keys(args).some(k=>!fields.includes(k))||
      !ref(args.observation_id)||!ref(args.component_ref)||!['click','fill','select','check','read','read-table'].includes(args.action)||
      !['ordinary','sensitive'].includes(args.risk)||
      (['click','read','read-table'].includes(args.action)?Object.hasOwn(args,'value'):
        args.action==='check'?typeof args.value!=='boolean':typeof args.value!=='string'||Buffer.byteLength(args.value,'utf8')>1024))throw new Error('request-invalid');
    const entry=await this.registry.resolve(args.observation_id,args.component_ref);
    if(JSON.stringify(args)!==JSON.stringify(this.registry.redact(args)))throw new Error('request-invalid');
    const context=await entry.node.evaluate(targetContext);
    const effectContext=entry.meta.name+' '+entry.meta.id+' '+(context.state?.text??context.target);
    const mutating=!['read','read-table'].includes(args.action);
    if(mutating&&manual.test(effectContext))throw new Error('manual-operation-required');
    for(const [key,value] of this.actions)if(Date.now()>=value.deadline)this.actions.delete(key);
    if(this.actions.size>=32)throw new Error('request-too-large');
    const action_ref=id(),isSensitive=mutating&&(args.risk==='sensitive'||sensitive.test(effectContext));
    if(isSensitive&&(context.truncated||typeof context.state?.text==='string'&&context.state.text.length>2000))throw new Error('manual-operation-required');
    // Cache lifetime covers native review plus transport and the separate ticket;
    // the supervisor still supplies a current at-most-30-second action permit.
    this.actions.set(action_ref,{entry,args:structuredClone(args),context:hash(context),sensitive:isSensitive,deadline:Date.now()+300000});
    return {ok:true,action_ref,sensitive:isSensitive,preview:this.registry.redact({
      action:args.action,control:entry.meta.name,target:context.target,...(Object.hasOwn(args,'value')?{after:args.value}:{})})};
  }
  async execute(args){
    if(!args||Object.keys(args).sort().join(',')!=='action_ref,attempt_id'||!ref(args.action_ref)||!ref(args.attempt_id))throw new Error('request-invalid');
    const action=this.actions.get(args.action_ref);this.actions.delete(args.action_ref);
    if(!action||Date.now()>=action.deadline)throw new Error('component-stale');
    let dispatched=false;
    try{
      await this.registry.check(action.entry);
      if(hash(await action.entry.node.evaluate(targetContext))!==action.context)throw new Error('target-state-changed');
      const permit=async()=>{
        if(await this.authorize({kind:'site-action',attempt_id:args.attempt_id})!==true)return false;
        if(hash(await action.entry.node.evaluate(targetContext))!==action.context)throw new Error('target-state-changed');
        return true;
      };
      if(await permit()!==true)throw new Error('approval-required');
      let result;
      if(['read','read-table'].includes(action.args.action)){
        result=await this.registry.project(action.entry,action.args.action==='read'?'web.read_region':'web.read_table',
          {rows:100,columns:30,bytes:65536});
      }else{
        dispatched=true;
        result=await this.registry.perform(action.entry,action.args.action,action.args.value,permit);
      }
      if(await this.authorize({kind:'site-action',attempt_id:args.attempt_id})!==true)throw new Error('grant-revoked');
      return this.registry.redact({...result,businessSuccessVerified:false});
    }catch(error){error.dispatched=dispatched;throw error;}
  }
}
