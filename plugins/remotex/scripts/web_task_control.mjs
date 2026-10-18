import {createHash,randomUUID} from 'node:crypto';
import {bindWriteContract} from './web_task_contracts.mjs';

const token=()=>randomUUID().replaceAll('-','');
const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const clone=value=>structuredClone(value);
const capabilities=new Set(['web.navigate','web.read_region','web.read_table','web.query_input',
  'web.page_step','web.read_result','web.inspect_action','web.business_action']);

function object(value,allowed,required=[]){
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(key=>!allowed.includes(key))||required.some(key=>!(key in value)))throw new Error('request-invalid');
}
function boundedInteger(value,min,max){if(!Number.isInteger(value)||value<min||value>max)throw new Error('request-invalid');return value;}
function literal(value){
  if(typeof value!=='string'&&typeof value!=='boolean'&&!Number.isSafeInteger(value))throw new Error('request-invalid');
  if(typeof value==='string'&&(Buffer.byteLength(value,'utf8')>1024||/[\x00-\x1f]/.test(value)||/-----BEGIN |\b(?:ghp_|glpat-|sk-proj-)/.test(value)))throw new Error('request-invalid');
  return value;
}

export class TaskControl {
  constructor({registry,authorize,readResult,network,clock=Date.now}){
    this.registry=registry;this.authorize=authorize;this.readResult=readResult;this.network=network;this.clock=clock;
    this.receipts=new Map();this.drafts=new Map();
    this.executions=new Map();this.receiptSequence=0;
  }

  contracts(refs){
    if(!Array.isArray(refs)||refs.length>32||new Set(refs).size!==refs.length)throw new Error('request-invalid');
    return refs.map(ref=>({ref,descriptor:this.network?.resolve(ref)})).map(row=>{
      if(!row.descriptor)throw new Error('request-contract-unavailable');return row;
    });
  }

  async resolveItems(items){
    if(!Array.isArray(items)||items.length<1||items.length>32)throw new Error('request-too-large');
    const result=[];
    for(const item of items){
      object(item,['item_id','capability','observation_id','component_ref','max_uses','depends_on','parameters','limits','network_refs','network_evidence','action_draft_ref'],
        ['item_id','capability','observation_id','component_ref']);
      if(typeof item.item_id!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(item.item_id)||!capabilities.has(item.capability))throw new Error('request-invalid');
      const entry=await this.registry.resolve(item.observation_id,item.component_ref);
      const limits={rows:100,columns:30,bytes:98304,...item.limits};
      object(limits,['rows','columns','bytes'],['rows','columns','bytes']);
      boundedInteger(limits.rows,0,100);boundedInteger(limits.columns,0,30);boundedInteger(limits.bytes,0,98304);
      const contracts=this.contracts(item.network_refs||[]);
      let parameters=item.parameters||{},targets=[],approvalClass='task-bounded',fields=[],effectDigest=hash(contracts),display={label:entry.meta.name};
      if(item.capability==='web.business_action'){
        const draft=this.drafts.get(item.action_draft_ref);
        if(!draft||this.clock()>=draft.expires||draft.fingerprint!==entry.fingerprint)throw new Error('component-stale');
        parameters={action_draft_ref:item.action_draft_ref,network_refs:draft.network_refs};
        targets=draft.targets.map(value=>value.identity);approvalClass=draft.preview.approval_class;
        fields=draft.effect.fields;effectDigest=draft.digest;display={label:entry.meta.name,preview:JSON.stringify(draft.preview)};
      }else{
        if(item.action_draft_ref)throw new Error('request-invalid');
        if(['web.navigate','web.page_step'].includes(item.capability)&&entry.meta.kind!=='action')throw new Error('capability-unsupported');
        if(item.capability==='web.read_table'&&entry.meta.kind!=='table')throw new Error('capability-unsupported');
        if(['web.inspect_action','web.query_input'].includes(item.capability)&&entry.meta.kind!=='field')throw new Error('capability-unsupported');
        if(item.capability==='web.query_input'){
          object(parameters,['action','value'],['action','value']);
          if(!['fill','select','check'].includes(parameters.action))throw new Error('request-invalid');literal(parameters.value);
        }else object(parameters,[]);
        parameters={...parameters,network_refs:item.network_refs||[]};
        if(contracts.length)display.network=JSON.stringify(contracts.map(row=>row.descriptor));
      }
      result.push({item_id:item.item_id,capability:item.capability,fingerprint:entry.fingerprint,
        page:this.registry.pageInfo().route,max_uses:boundedInteger(item.max_uses||1,1,approvalClass==='task-bounded'?50:1),
        depends_on:item.depends_on||[],targets,parameters,output:limits,display,
        effect:{class:approvalClass,fields,digest:effectDigest}});
    }
    return result;
  }

  receipt(ref){
    const receipt=this.receipts.get(ref);
    if(!receipt||this.clock()>=receipt.expires)throw new Error('component-stale');
    return receipt;
  }

  async prepareAction(args){
    object(args,['observation_id','component_ref','target_refs','read_receipts','changes','effect','network_refs','network_bindings','target_state'],
      ['observation_id','component_ref','target_refs','read_receipts','changes','effect','network_refs']);
    const entry=await this.registry.resolve(args.observation_id,args.component_ref);
    if(entry.meta.kind!=='action')throw new Error('capability-unsupported');
    if(!Array.isArray(args.target_refs)||!args.target_refs.length||args.target_refs.length>100||new Set(args.target_refs).size!==args.target_refs.length)throw new Error('request-invalid');
    if(!Array.isArray(args.read_receipts)||args.read_receipts.length>32)throw new Error('request-invalid');
    const reads=args.read_receipts.map(ref=>this.receipt(ref));
    const targets=args.target_refs.map(ref=>{
      const target=this.registry.targets.get(ref);
      if(!target||!reads.some(read=>read.result.target_refs?.includes(ref)))throw new Error('target-state-changed');
      return {...clone(target),ref};
    });
    if(new Set(targets.map(value=>value.identity)).size!==targets.length)throw new Error('request-invalid');
    object(args.effect,['kind','name','risks','fields','evidence','requires_cas'],['kind','name','risks','fields','evidence']);
    const effect=clone(args.effect);
    if(!['create','update','delete','assign','command','cancel','compensate'].includes(effect.kind)||typeof effect.name!=='string'||effect.name.length>160)throw new Error('request-invalid');
    if(!Array.isArray(effect.risks)||effect.risks.some(value=>!['irreversible','weakens-protection','expands-access','availability','inherited-policy','external-concurrency'].includes(value)))throw new Error('request-invalid');
    if(!Array.isArray(effect.fields)||!effect.fields.length||effect.fields.length>30||effect.fields.some(value=>typeof value!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value)))throw new Error('request-invalid');
    if(!Array.isArray(effect.evidence)||!effect.evidence.length||effect.evidence.length>8)throw new Error('request-contract-unavailable');
    for(const evidence of effect.evidence){object(evidence,['kind','reference'],['kind','reference']);if(!['source-review','api-document','verified-record','operator-inspected'].includes(evidence.kind)||typeof evidence.reference!=='string'||evidence.reference.length>512)throw new Error('request-invalid');}
    if(effect.requires_cas)throw new Error('precondition-unenforceable');
    const targetState=args.target_state||{};
    object(targetState,effect.fields);
    if(['update','assign'].includes(effect.kind)&&Object.keys(targetState).length!==effect.fields.length)throw new Error('readback-required');
    for(const [field,state] of Object.entries(targetState)){
      object(state,['header','after'],['header','after']);
      if(typeof state.header!=='string'||!state.header.length||state.header.length>160)throw new Error('request-invalid');
      literal(state.after);
      for(const target of targets){
        const read=reads.find(receipt=>receipt.scope.capability==='web.read_table'&&receipt.result.target_refs?.includes(target.ref));
        const table=read?.result.tables?.[0];
        const columns=table?.headers.map((value,index)=>({value,index})).filter(row=>row.value===state.header)||[];
        if(columns.length!==1||typeof table.rows[target.row]?.[columns[0].index]!=='string')throw new Error('readback-required');
        target.before={...target.before,[field]:table.rows[target.row][columns[0].index]};
        target.after={...target.after,[field]:state.after};
      }
    }
    if(targets.some(target=>target.version===null)&&!effect.risks.includes('external-concurrency'))throw new Error('precondition-unenforceable');
    if(!Array.isArray(args.changes)||args.changes.length>30)throw new Error('request-invalid');
    const changes=[];
    for(const change of args.changes){
      object(change,['component_ref','receipt_ref','value','action'],['component_ref','receipt_ref','value','action']);
      const field=await this.registry.resolve(args.observation_id,change.component_ref),read=this.receipt(change.receipt_ref);
      if(field.meta.kind!=='field'||read.scope.capability!=='web.inspect_action'||read.scope.fingerprint!==field.fingerprint)throw new Error('scope-mismatch');
      if(!['fill','select','check'].includes(change.action))throw new Error('request-invalid');
      const fieldName=effect.fields.includes(field.meta.id)?field.meta.id:effect.fields.length===1?effect.fields[0]:null;
      if(!fieldName)throw new Error('scope-mismatch');
      changes.push({field:fieldName,fingerprint:field.fingerprint,meta:clone(field.meta),before:read.result.value,
        after:literal(change.value),action:change.action});
    }
    const contracts=this.contracts(args.network_refs);
    if(new Set(changes.map(change=>change.field)).size!==changes.length||
      changes.some(change=>targetState[change.field]&&targetState[change.field].after!==change.after))throw new Error('scope-mismatch');
    const bindings=args.network_bindings||[];
    if(!Array.isArray(bindings)||bindings.length!==contracts.length)throw new Error('request-contract-unavailable');
    for(const {ref,descriptor} of contracts){
      const binding=bindings.find(row=>row.network_ref===ref);
      object(binding,['network_ref','target_path','change_paths'],['network_ref','target_path','change_paths']);
      bindWriteContract(descriptor,{targets:targets.map(target=>target.identity),changes:Object.fromEntries(changes.map(change=>[change.field,change.after]))},
        {target_path:binding.target_path,change_paths:binding.change_paths});
    }
    const approvalClass=effect.kind==='delete'||effect.risks.some(value=>['irreversible','weakens-protection','expands-access'].includes(value))?'action-time':
      effect.kind==='update'&&effect.risks.length===0?'task-bounded':'action-bound';
    const preview={operation:effect.name,kind:effect.kind,approval_class:approvalClass,
      targets:targets.map(({identity,label,version,before,after})=>({identity,label,version,before:before||{},after:after||{}})),changes:changes.map(({meta,before,after,action})=>({field:meta.name,before,after,action})),
      risks:effect.risks,evidence:effect.evidence,network:contracts.map(value=>value.descriptor),network_bindings:clone(bindings),atomicPrecondition:false};
    const draft={fingerprint:entry.fingerprint,page:this.registry.pageInfo(),targets,changes,effect,target_state:clone(targetState),preview,
      network_refs:clone(args.network_refs),network_bindings:clone(bindings),contracts,expires:this.clock()+300000};
    draft.digest=hash({...draft,expires:undefined});
    if(this.drafts.size>=100)throw new Error('request-too-large');
    const ref=token();this.drafts.set(ref,draft);
    return {ok:true,action_draft_ref:ref,scope_digest:draft.digest,preview,configurationStored:false,executable:false};
  }

  async execute(args){
    object(args,['attempt_id','scope','observation_id','component_ref','deadline'],['attempt_id','scope','observation_id','component_ref']);
    const scope=args.scope;
    if(!scope||!capabilities.has(scope.capability)||!/^[a-f0-9]{32}$/.test(args.attempt_id))throw new Error('request-invalid');
    const entry=await this.registry.resolve(args.observation_id,args.component_ref);
    if(entry.fingerprint!==scope.fingerprint||this.registry.pageInfo().route!==scope.page)throw new Error('scope-mismatch');
    const permit=async()=>await this.authorize({kind:'action',attempt_id:args.attempt_id,consume:false})===true;
    if(!await permit())throw new Error('approval-required');
    let result,state='verified';
    if(['web.read_region','web.read_table','web.inspect_action'].includes(scope.capability)){
      result=await this.registry.project(entry,scope.capability,scope.output);
    }else if(scope.capability==='web.read_result')result=await this.readResult();
    else if(['web.navigate','web.page_step'].includes(scope.capability)){
      this.network?.arm(args.attempt_id);
      const before=this.registry.pageInfo().route;result=await this.registry.perform(entry,'click',null,permit);
      if(before===result.page.route)state='partial';
    }else if(scope.capability==='web.query_input'){
      this.network?.arm(args.attempt_id);
      result=await this.registry.perform(entry,scope.parameters.action,scope.parameters.value,permit);state='partial';
    }else{
      const draft=this.drafts.get(scope.parameters.action_draft_ref);
      if(!draft||this.clock()>=draft.expires||draft.digest!==scope.effect.digest)throw new Error('component-stale');
      if(!Array.isArray(scope.targets)||!scope.targets.length||scope.targets.some(identity=>!draft.targets.some(target=>target.identity===identity)))throw new Error('scope-mismatch');
      const selected=draft.targets.filter(target=>scope.targets.includes(target.identity));
      await this.registry.verifyTargets(selected);
      for(const target of selected){
        const values=await this.registry.targetValues(target,Object.fromEntries(Object.entries(draft.target_state).map(([field,state])=>[field,state.header])));
        if(JSON.stringify(values)!==JSON.stringify(target.before||{}))throw new Error('target-state-changed');
      }
      const changes=[];
      for(const change of draft.changes){
        const field=await this.registry.find(change.fingerprint);
        const current=await this.registry.project(field,'web.inspect_action',{rows:1,columns:1,bytes:98304});
        if(current.value!==change.before)throw new Error('target-state-changed');
        changes.push({field,change});
      }
      if(this.executions.size>=200)throw new Error('request-too-large');
      this.executions.set(args.attempt_id,{scope:hash(scope),draft,sequence:this.receiptSequence});
      this.network?.arm(args.attempt_id);
      await this.registry.selectTargets(draft.targets,scope.targets,permit);
      for(const {field,change} of changes)await this.registry.perform(field,change.action,change.after,permit);
      result=await this.registry.perform(entry,'click',null,permit);
      result.target_count=selected.length;result.scope_digest=draft.digest;
      state='partial';
    }
    if(!await permit())throw new Error('grant-revoked');
    if(this.receipts.size>=128)throw new Error('response-too-large');
    const receiptRef=token();result={...result,receipt_ref:receiptRef};
    this.receipts.set(receiptRef,{scope:clone(scope),result:clone(result),sequence:++this.receiptSequence,expires:Math.min(this.clock()+300000,args.deadline||Infinity)});
    return {ok:true,state,summary:{count:result.tables?.[0]?.rows.length||0},result};
  }

  async reconcile(args){
    object(args,['attempt_id','scope','read_receipts'],['attempt_id','scope','read_receipts']);
    const execution=this.executions.get(args.attempt_id);
    if(!execution||execution.scope!==hash(args.scope)||!Array.isArray(args.read_receipts)||!args.read_receipts.length||args.read_receipts.length>32)throw new Error('readback-required');
    const reads=args.read_receipts.map(ref=>this.receipt(ref));
    if(reads.some(read=>read.scope.capability!=='web.read_table'||read.sequence<=execution.sequence))throw new Error('readback-required');
    if(!Object.keys(execution.draft.target_state).length)throw new Error('readback-required');
    const outcomes=[];
    for(const target of execution.draft.targets.filter(value=>args.scope.targets.includes(value.identity))){
      let verified=false;
      for(const read of reads){
        if(read.scope.fingerprint!==target.table_fingerprint)continue;
        for(const ref of read.result.target_refs||[]){
          const current=this.registry.targets.get(ref);
          if(current?.identity!==target.identity)continue;
          const table=read.result.tables[0];
          verified=Object.entries(execution.draft.target_state).every(([field,state])=>{
            const columns=table.headers.map((value,index)=>({value,index})).filter(row=>row.value===state.header);
            return columns.length===1&&table.rows[current.row]?.[columns[0].index]===String(target.after[field]);
          });
        }
      }
      outcomes.push({identity:target.identity,state:verified?'verified':'outcome-unknown'});
    }
    const count=outcomes.filter(value=>value.state==='verified').length;
    return {ok:true,state:count===outcomes.length?'verified':'partial',summary:{count,target_count:outcomes.length},targets:outcomes};
  }
}
