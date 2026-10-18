import {createHash} from 'node:crypto';

const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const ownObject=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).every(key=>keys.includes(key));

export function evidence(value){
  if(!Array.isArray(value)||!value.length||value.length>8)throw new Error('request-contract-unavailable');
  for(const row of value){
    if(!ownObject(row,['kind','reference'])||!['source-review','api-document','verified-record','operator-inspected'].includes(row.kind)||
      typeof row.reference!=='string'||!row.reference.length||row.reference.length>512)throw new Error('request-contract-unavailable');
  }
  return structuredClone(value);
}

function networkItem(id,descriptor,{phase,parent,semantics,proof,uses,targets=[]}){
  const preview=JSON.stringify({phase,semantics,descriptor,evidence:proof,targets});
  if(Buffer.byteLength(preview)>4096)throw new Error('request-too-large');
  return {row:{item_id:id,capability:'web.page_step',fingerprint:hash({descriptor,phase}),page:'#/',
    max_uses:uses,depends_on:[],targets:[],parameters:{network_ref:id,review_kind:semantics},output:{rows:0,columns:0,bytes:0},
    display:{label:`Network: ${descriptor.method} ${descriptor.path}`,preview},
    effect:{class:'task-bounded',fields:[],digest:hash({descriptor,semantics,proof,targets})}},
    contract:{phase,parent_id:parent,semantics,descriptor:structuredClone(descriptor),targets:structuredClone(targets)}};
}

export function bindWriteContract(descriptor,scope,binding){
  const path=value=>{
    if(!Array.isArray(value)||value.length<2||value.length>8||!['body','query'].includes(value[0])||
      value.some(part=>typeof part!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(part)||['__proto__','constructor','prototype'].includes(part)))throw new Error('scope-mismatch');
    return value;
  };
  const at=parts=>path(parts).reduce((value,key)=>value&&Object.hasOwn(value,key)?value[key]:undefined,descriptor);
  if(!ownObject(binding,['target_path','change_paths'])||!ownObject(binding.change_paths,Object.keys(scope.changes)))throw new Error('scope-mismatch');
  const target=at(binding.target_path),actual=Array.isArray(target)?target:[target];
  if(actual.some(value=>typeof value!=='string')||new Set(actual).size!==actual.length||
    [...actual].sort().join('\0')!==[...scope.targets].sort().join('\0'))throw new Error('scope-mismatch');
  if(Object.keys(binding.change_paths).length!==Object.keys(scope.changes).length)throw new Error('scope-mismatch');
  for(const [field,value] of Object.entries(scope.changes)){
    if(JSON.stringify(at(binding.change_paths[field]))!==JSON.stringify(value))throw new Error('scope-mismatch');
  }
  const visit=(value,parts=[])=>{
    if(JSON.stringify(parts)===JSON.stringify(binding.target_path))return;
    if(typeof value==='string'&&scope.targets.some(target=>value.includes(target)))throw new Error('scope-mismatch');
    if(value&&typeof value==='object')for(const [key,part] of Object.entries(value))visit(part,[...parts,key]);
  };
  visit(descriptor);
  return {target_path:structuredClone(binding.target_path),change_paths:structuredClone(binding.change_paths)};
}

export function taskContracts(scopes,declarations,network,drafts){
  const items=structuredClone(scopes),contracts={};
  for(let index=0;index<scopes.length;index++){
    const scope=scopes[index],declaration=declarations[index],refs=scope.parameters.network_refs||[];
    if(!refs.length)continue;
    if(scope.item_id.length>100)throw new Error('request-invalid');
    const draft=scope.capability==='web.business_action'?drafts.get(scope.parameters.action_draft_ref):null;
    const proof=evidence(draft?draft.effect.evidence:declaration.network_evidence);
    for(let at=0;at<refs.length;at++){
      const descriptor=network.resolve(refs[at]);
      const semantics=draft?'write':'unclassified';
      const id=`${scope.item_id}.network.${at+1}`;
      const resolved=networkItem(id,descriptor,{phase:'grant-active',parent:scope.item_id,semantics,proof,
        uses:draft?1:scope.max_uses,targets:draft?scope.targets:[]});
      if(draft){
        const binding=draft.network_bindings?.find(row=>row.network_ref===refs[at]);
        if(!binding)throw new Error('request-contract-unavailable');
        Object.assign(resolved.contract,bindWriteContract(descriptor,{targets:scope.targets,
          changes:Object.fromEntries(draft.changes.map(change=>[change.field,change.after]))},
          {target_path:binding.target_path,change_paths:binding.change_paths}));
      }
      items.push(resolved.row);contracts[id]=resolved.contract;
    }
  }
  if(items.length>32)throw new Error('request-too-large');
  return {ok:true,items,contracts};
}

export function setupContracts(setup,network){
  if(!ownObject(setup,['phase','network_refs','evidence','max_uses'])||
    !['bootstrap','login-once'].includes(setup.phase)||setup.phase!==network.phase||
    !Array.isArray(setup.network_refs)||!setup.network_refs.length||setup.network_refs.length>32||
    new Set(setup.network_refs).size!==setup.network_refs.length)throw new Error('request-invalid');
  const proof=evidence(setup.evidence),uses=setup.max_uses??2;
  if(!Number.isInteger(uses)||uses<1||uses>10)throw new Error('request-invalid');
  const items=[],contracts={};
  for(let index=0;index<setup.network_refs.length;index++){
    const descriptor=network.resolve(setup.network_refs[index]);
    if(setup.phase==='bootstrap'&&(!['GET','HEAD'].includes(descriptor.method)||descriptor.body!==null||
      !['document','stylesheet','script','image','font'].includes(descriptor.resourceType)))throw new Error('request-contract-unavailable');
    const id=`setup.network.${index+1}`;
    const resolved=networkItem(id,descriptor,{phase:setup.phase,parent:null,
      semantics:setup.phase==='bootstrap'?'bootstrap':'login',proof,
      uses:setup.phase==='login-once'&&!['GET','HEAD'].includes(descriptor.method)?1:uses});
    items.push(resolved.row);contracts[id]=resolved.contract;
  }
  return {ok:true,items,contracts};
}
