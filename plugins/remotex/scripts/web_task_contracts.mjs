import {createHash} from 'node:crypto';
import {normalizeResponseChecks,validateInitializationDescriptor,validateStaticDescriptor} from './web_initialization_contracts.mjs';
import {parseV3Profile,MAX_REFERENCE_UNITS,MAX_PROPOSAL_UNITS} from './web_request_profiles.mjs';

const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const ownObject=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).every(key=>keys.includes(key));

export function publicV3Digest(value){
  const ordered=part=>Array.isArray(part)?part.map(ordered):part&&typeof part==='object'?
    Object.fromEntries(Object.keys(part).sort().map(key=>[key,ordered(part[key])])):part;
  const ascii=JSON.stringify(ordered(value)).replace(/[\u007f-\uffff]/g,ch=>'\\u'+ch.charCodeAt(0).toString(16).padStart(4,'0'));
  return createHash('sha256').update(ascii,'ascii').digest('hex');
}

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
  if(setup?.revision===3)return setupContractsV3(setup,network);
  if(setup?.revision!==undefined)return setupContractsV2(setup,network);
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

function setupContractsV3(setup,network){
  const invalid=()=>{throw new Error('request-invalid');},hex=value=>typeof value==='string'&&/^[a-f0-9]{32}$/.test(value);
  if(!ownObject(setup,['revision','phase','requests'])||setup.revision!==3||!['bootstrap','login-once'].includes(setup.phase)||
    setup.phase!==network.phase||!hex(network.preauthLifecycle)||!Array.isArray(setup.requests)||
    !setup.requests.length||setup.requests.length>32||typeof network.resolveV3!=='function')invalid();
  const refs=new Set(),items=[],contracts={},private_initialization={},prerequisites=[];
  let units=0,viewBytes=0;
  const phases=['bootstrap','login-once'];
  for(const [index,row] of setup.requests.entries()){
    if(!ownObject(row,['network_ref','purpose','representation_ref','literal_review_refs','max_uses','response_checks','evidence'])||
      row.purpose!=='initialization-read'||!hex(row.network_ref)||refs.has(row.network_ref)||!hex(row.representation_ref)||
      !Array.isArray(row.literal_review_refs)||!row.literal_review_refs.length||row.literal_review_refs.length>MAX_REFERENCE_UNITS||
      row.literal_review_refs.some(ref=>!hex(ref))||new Set(row.literal_review_refs).size!==row.literal_review_refs.length)invalid();
    refs.add(row.network_ref);
    const uses=row.max_uses??2;if(!Number.isInteger(uses)||uses<1||uses>10)invalid();
    const proof=evidence(row.evidence),checks=normalizeResponseChecks(row.response_checks);
    const source=network.resolveV3(row.network_ref,row.representation_ref,row.literal_review_refs);
    const view=parseV3Profile(source.capture,source.profile_id,network.parseTree);
    if(source.representation_ref!==row.representation_ref||view.unit_count!==row.literal_review_refs.length||
      JSON.stringify(source.literal_review_refs)!==JSON.stringify(row.literal_review_refs))invalid();
    units+=view.unit_count;viewBytes+=Buffer.byteLength(JSON.stringify(view));
    const id=`setup.network.${index+1}`;
    // These public digests contain only opaque owned refs and caller-visible scope, never capture bytes.
    const prerequisite_id=publicV3Digest({preauth_lifecycle:network.preauthLifecycle,network_ref:row.network_ref,
      representation_ref:row.representation_ref,literal_review_refs:row.literal_review_refs,response_checks:checks});
    const contract={revision:3,phase:setup.phase,parent_id:null,semantics:'initialization-read',targets:[],purpose:'initialization-read',
      phase_applicability:phases,preauth_lifecycle:network.preauthLifecycle,required:true,response_checks:checks,prerequisite_id,
      intent_ref:row.representation_ref,profile_id:source.profile_id,network_ref:row.network_ref,
      representation_ref:row.representation_ref,literal_review_refs:structuredClone(row.literal_review_refs),evidence:proof};
    const preview=JSON.stringify(contract);
    if(Buffer.byteLength(preview)>4096)throw new Error('setup-plan-capacity-required');
    const item={item_id:id,capability:'web.page_step',fingerprint:publicV3Digest(contract),page:'#/',max_uses:uses,
      depends_on:[],targets:[],parameters:{network_ref:id,review_kind:'initialization-read'},output:{rows:0,columns:0,bytes:0},
      display:{label:'Initialization POST (private scope)',preview},
      effect:{class:'task-bounded',fields:[],digest:publicV3Digest({scope:contract,semantics:'initialization-read',targets:[]})}};
    items.push(item);contracts[id]=contract;private_initialization[id]=structuredClone(source.capture);prerequisites.push(prerequisite_id);
  }
  const result={ok:true,items,contracts,setup_revision:3,preauth_lifecycle:network.preauthLifecycle,
    phase_applicability:phases,prerequisites,private_initialization};
  if(units>MAX_PROPOSAL_UNITS||items.reduce((sum,row)=>sum+row.max_uses,0)>200||
    Buffer.byteLength(JSON.stringify(result))+viewBytes>32768)throw new Error('setup-plan-capacity-required');
  return result;
}

function setupContractsV2(setup,network){
  const invalid=()=>{throw new Error('request-invalid');};
  if(!ownObject(setup,['revision','phase','requests','replace_grant_ids'])||setup.revision!==2||
    !['bootstrap','login-once'].includes(setup.phase)||setup.phase!==network.phase||
    !/^[a-f0-9]{32}$/.test(network.preauthLifecycle)||!Array.isArray(setup.requests)||
    !setup.requests.length||setup.requests.length>32)invalid();
  const sources=setup.replace_grant_ids??[];
  if(!Array.isArray(sources)||sources.length>2||new Set(sources).size!==sources.length||
    sources.some(id=>typeof id!=='string'||!/^[a-f0-9]{32}$/.test(id)))invalid();
  const refs=new Set(),items=[],contracts={},prerequisites=[];
  const phases=['bootstrap','login-once'];
  for(const [index,row] of setup.requests.entries()){
    if(!ownObject(row,['network_ref','purpose','max_uses','evidence','response_checks'])||
      typeof row.network_ref!=='string'||!/^[a-f0-9]{32}$/.test(row.network_ref)||refs.has(row.network_ref)||
      !['bootstrap-resource','initialization-read'].includes(row.purpose))invalid();
    refs.add(row.network_ref);
    const proof=evidence(row.evidence),uses=row.max_uses??2;
    if(!Number.isInteger(uses)||uses<1||uses>10)invalid();
    const descriptor=network.resolve(row.network_ref),init=row.purpose==='initialization-read';
    if(init)validateInitializationDescriptor(descriptor);
    else {
      if(row.response_checks!==undefined)throw new Error('request-contract-unavailable');
      validateStaticDescriptor(descriptor);
    }
    const checks=init?normalizeResponseChecks(row.response_checks):[];
    const id=`setup.network.${index+1}`,semantics=init?'initialization-read':'bootstrap';
    const extra={revision:2,purpose:row.purpose,phase_applicability:phases,preauth_lifecycle:network.preauthLifecycle,
      required:init,response_checks:checks,prerequisite_id:init?hash({lifecycle:network.preauthLifecycle,descriptor,checks}):null};
    const resolved=networkItem(id,descriptor,{phase:setup.phase,parent:null,semantics,proof,uses});
    Object.assign(resolved.contract,extra);
    resolved.row.display.preview=JSON.stringify({...JSON.parse(resolved.row.display.preview),...extra});
    if(Buffer.byteLength(resolved.row.display.preview)>4096)throw new Error('request-too-large');
    resolved.row.fingerprint=hash({descriptor,...extra});
    resolved.row.effect.digest=hash({descriptor,semantics,proof,targets:[],...extra});
    items.push(resolved.row);contracts[id]=resolved.contract;
    if(init)prerequisites.push(extra.prerequisite_id);
  }
  if(items.reduce((sum,row)=>sum+row.max_uses,0)>200||Buffer.byteLength(JSON.stringify(items))>32768)throw new Error('request-too-large');
  return {ok:true,items,contracts,setup_revision:2,preauth_lifecycle:network.preauthLifecycle,
    phase_applicability:phases,prerequisites,replace_grant_ids:[...sources]};
}
