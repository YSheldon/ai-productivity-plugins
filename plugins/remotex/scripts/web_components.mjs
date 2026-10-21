import {createHash,randomUUID} from 'node:crypto';

const token=()=>randomUUID().replaceAll('-','');
const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');

function collectComponents(onlyNode, siteNavigation=false) {
  const all=onlyNode===true||onlyNode?.all===true;
  if(onlyNode?.siteNavigation===true){siteNavigation=true;onlyNode=null;}
  const secretName=/password|passwd|token|cookie|secret|credential|authorization|loginPass/i;
  const hidden='[hidden],[aria-hidden="true"],script,style,noscript,iframe,svg,canvas,[contenteditable]';
  const visible=node=>{
    if(!node||!node.isConnected||node.closest(hidden)||!node.getClientRects().length)return false;
    for(let parent=node;parent;parent=parent.parentElement){
      const css=getComputedStyle(parent);
      if(css.display==='none'||css.visibility==='hidden'||css.visibility==='collapse'||css.opacity==='0')return false;
    }
    return true;
  };
  const text=(root,limit)=>{
    const walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);let node,visited=0,result='';
    while((node=walker.nextNode())&&++visited<20000&&result.length<limit){
      if(node.parentElement.closest('input,textarea,select,option')||!visible(node.parentElement))continue;
      const part=node.textContent.replace(/\s+/g,' ').trim();if(part)result+=(result?' ':'')+part;
    }
    return result.slice(0,limit);
  };
  const describe=node=>{
    if(!visible(node)||node.disabled||node.getAttribute('aria-disabled')==='true')return null;
    const tag=node.tagName.toLowerCase(),id=node.id||'',role=node.getAttribute('role')||'';
    const field=['input','textarea','select'].includes(tag);
    if(field&&(secretName.test(id+' '+node.getAttribute('name'))||['password','hidden','file','email'].includes(node.type)))return null;
    const table=tag==='table'||['table','grid'].includes(role);
    const action=['a','button','li'].includes(tag)||['button','menuitem','tab'].includes(role)||node.hasAttribute('onclick');
    const kind=table?'table':field?'field':action?'action':'region';
    let name=node.getAttribute('aria-label')||'';
    if(!name&&field&&id){const label=Array.from(document.querySelectorAll('label')).find(value=>value.htmlFor===id);if(label)name=text(label,160);}
    if(!name)name=kind==='region'||kind==='table'?id||role||tag:text(node,160)||id||tag;
    let href=null;
    if(tag==='a'){
      const raw=node.getAttribute('href')||'';
      try {
        const url=new URL(node.href),current=new URL(location.href);
        if(siteNavigation&&url.protocol==='https:'&&url.origin===current.origin&&!url.username&&!url.password)href=url.pathname;
        else if(url.origin===current.origin&&url.pathname===current.pathname&&!url.search&&!current.search&&!url.username&&!url.password&&/^#\/[A-Za-z0-9/_-]{0,511}$/.test(url.hash))href=url.hash;
        else if(!['#','','javascript:void(0);','javascript:void(0)'].includes(raw))return null;
      }catch{return null;}
    }
    const parents=[];
    for(let parent=node.parentElement;parent&&parents.length<6;parent=parent.parentElement)parents.push(parent.tagName.toLowerCase()+(parent.id?'#'+parent.id:''));
    return {tag,id,role,kind,name:name.slice(0,160),href,type:field?node.type||tag:null,path:parents.join('/')};
  };
  if(onlyNode&&onlyNode.nodeType===1){const meta=describe(onlyNode);return meta?[{meta}]:[];}
  const nodes=document.querySelectorAll('main,nav,section,table,[role="table"],[role="grid"],[role="navigation"],[role="menuitem"],[role="tab"],button,a[href],input,textarea,select,li,div[id],[role="button"],[onclick]');
  const result=[];let visited=0;
  for(const node of nodes){
    if(++visited>20000||result.length>=(all?20000:100))break;
    const meta=describe(node);if(meta)result.push({node,meta});
  }
  return result;
}

function projectNode(node,{capability,limits}) {
  const excluded='input,textarea,select,option,[contenteditable],script,style,noscript,iframe,svg,canvas,[hidden],[aria-hidden="true"]';
  const visible=element=>{
    if(!element||!element.isConnected||element.closest('[hidden],[aria-hidden="true"]')||!element.getClientRects().length)return false;
    for(let parent=element;parent;parent=parent.parentElement){const css=getComputedStyle(parent);if(css.display==='none'||css.visibility==='hidden'||css.visibility==='collapse'||css.opacity==='0')return false;}
    return true;
  };
  const read=(root,limit)=>{
    const walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);let child,visited=0,result='';
    while((child=walker.nextNode())&&++visited<20000&&result.length<limit){
      if(child.parentElement.closest(excluded)||!visible(child.parentElement))continue;
      const part=child.textContent.replace(/\s+/g,' ').trim();if(part)result+=(result?'\n':'')+part;
    }
    return result.slice(0,limit);
  };
  if(!visible(node))throw new Error('component-stale');
  if(capability==='web.inspect_action'){
    const name=node.id+' '+node.getAttribute('name')+' '+node.getAttribute('autocomplete');
    if(!['INPUT','TEXTAREA','SELECT'].includes(node.tagName)||/password|passwd|token|cookie|secret|credential|auth|login/i.test(name)||['password','hidden','file'].includes(node.type))throw new Error('capability-unsupported');
    return {value:node.type==='checkbox'?node.checked:String(node.value).slice(0,1024),type:node.type||node.tagName.toLowerCase()};
  }
  if(capability==='web.read_region')return {text:read(node,16000),truncated:read(node,16001).length>16000};
  if(capability!=='web.read_table')throw new Error('capability-unsupported');
  const headerNodes=Array.from(node.querySelectorAll('thead th,[role="columnheader"]')).filter(visible);
  const headers=headerNodes.slice(0,limits.columns).map(value=>read(value,160));
  const rowNodes=Array.from(node.querySelectorAll('tbody tr,[role="row"]')).filter(row=>visible(row)&&!row.querySelector('[role="columnheader"]'));
  const rows=[],identities=[];let characters=0,truncated=headerNodes.length>limits.columns;
  for(const row of rowNodes){
    if(rows.length>=limits.rows||characters>=16000){truncated=true;break;}
    const cells=Array.from(row.querySelectorAll('td,[role="cell"],[role="gridcell"]')).filter(visible);
    if(!cells.length)continue;
    const values=cells.slice(0,limits.columns).map(cell=>read(cell,Math.min(1024,16000-characters)));
    characters+=values.reduce((sum,value)=>sum+value.length,0);
    if(characters>16000){truncated=true;break;}
    rows.push(values);
    const identity=row.getAttribute('data-id')||row.getAttribute('data-host-id')||row.getAttribute('data-row-key')||row.getAttribute('data-key');
    identities.push(identity&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(identity)?{identity,version:row.getAttribute('data-version')||null,label:values[0]||''}:null);
    if(cells.length>limits.columns)truncated=true;
  }
  return {tables:[{headers,rows,truncated}],identities};
}

export class Components {
  constructor(page,{admit,redact,clock=Date.now,geometryRoot='main',siteNavigation=false}){
    this.page=page;this.admit=admit;this.redact=redact;this.clock=clock;
    this.entries=new Map();this.targets=new Map();this.handle=null;this.observation=null;
    this.geometryRoot=geometryRoot;
    this.siteNavigation=siteNavigation;
  }

  pageInfo(){
    const url=new URL(this.page.url());
    return this.redact({origin:url.origin,path:/^\/[A-Za-z0-9/_.~-]{0,511}$/.test(url.pathname)?url.pathname:'[omitted]',route:/^#\/[A-Za-z0-9/_-]{0,511}$/.test(url.hash)?url.hash:null});
  }

  async clear(){
    for(const value of this.entries.values())await value.node.dispose().catch(()=>{});
    this.entries.clear();await this.handle?.dispose().catch(()=>{});this.handle=null;
  }

  async dispose(){await this.clear();this.targets.clear();this.observation=null;}

  async scan(){
    await this.admit();await this.clear();const url=this.page.url();
    this.handle=await this.page.evaluateHandle(collectComponents,this.siteNavigation?{siteNavigation:true}:undefined);
    const metas=await this.handle.evaluate(rows=>rows.map(row=>row.meta));
    const counts=new Map();for(const meta of metas){const key=hash(meta);counts.set(key,(counts.get(key)||0)+1);}
    const components=[];
    for(let index=0;index<metas.length;index++){
      const meta=metas[index],fingerprint=hash(meta),ref=token();
      if(JSON.stringify(meta)!==JSON.stringify(this.redact(meta)))continue;
      const entry=await this.handle.getProperty(String(index));const node=await entry.getProperty('node');await entry.dispose();
      const ambiguous=counts.get(fingerprint)!==1;
      this.entries.set(ref,{node,meta,fingerprint,ref,url,ambiguous});
      components.push({...this.redact(meta),ref,ambiguous});
    }
    await this.admit();if(this.page.url()!==url)throw new Error('component-stale');
    this.observation={id:token(),at:this.clock(),url};
    const geometry=await this.page.evaluate(selector=>{
      const dimension=value=>Number.isFinite(value)?Math.max(0,Math.min(100000,Math.round(value))):null;
      const roots=document.querySelectorAll(selector),bounds=roots.length===1?roots[0].getBoundingClientRect():null;
      return {viewport:{width:dimension(innerWidth),height:dimension(innerHeight)},
        window:{width:dimension(outerWidth),height:dimension(outerHeight)},
        content:bounds?{width:dimension(bounds.width),height:dimension(bounds.height)}:null};
    },this.geometryRoot);
    await this.admit();if(this.page.url()!==url)throw new Error('component-stale');
    const result={ok:true,observationId:this.observation.id,components,page:this.pageInfo(),
      geometry:{...geometry,mode:this.page.viewportSize()===null?'window':'emulated'},
      observationExpiresInSeconds:30,contentTrust:'untrusted-page-data'};
    while(Buffer.byteLength(JSON.stringify(result),'utf8')>32768&&result.components.length){result.components.pop();result.truncated=true;}
    return result;
  }

  async resolve(observationId,ref){
    await this.admit();
    if(!this.observation||this.observation.id!==observationId||this.clock()-this.observation.at>30000||this.page.url()!==this.observation.url)throw new Error('component-stale');
    const entry=this.entries.get(ref);if(!entry)throw new Error('component-stale');
    if(entry.ambiguous)throw new Error('component-ambiguous');
    await this.check(entry);return entry;
  }

  async check(entry){
    await this.admit();
    if(this.page.url()!==entry.url)throw new Error('component-stale');
    const current=await entry.node.evaluate(collectComponents,this.siteNavigation);
    if(current.length!==1||hash(current[0].meta)!==entry.fingerprint)throw new Error('component-stale');
    const handle=await this.page.evaluateHandle(collectComponents,this.siteNavigation?{siteNavigation:true,all:true}:true);
    try {
      const metas=await handle.evaluate(rows=>rows.map(row=>row.meta));
      if(metas.length>=20000||metas.filter(meta=>hash(meta)===entry.fingerprint).length!==1)throw new Error('component-ambiguous');
    } finally {await handle.dispose();}
  }

  async find(fingerprint){
    const matches=[...this.entries.values()].filter(entry=>entry.fingerprint===fingerprint);
    if(matches.length!==1)throw new Error('component-ambiguous');
    await this.check(matches[0]);return matches[0];
  }

  async targetRow(target,checkVersion=true){
    const table=await this.find(target.table_fingerprint);
    const handle=await table.node.evaluateHandle((node,expected)=>{
      const rows=Array.from(node.querySelectorAll('tbody tr,[role="row"]')).filter(row=>{
        const identity=row.getAttribute('data-id')||row.getAttribute('data-host-id')||row.getAttribute('data-row-key')||row.getAttribute('data-key');
        return identity===expected.identity&&row.getClientRects().length&&!row.closest('[hidden],[aria-hidden="true"]');
      });
      if(rows.length!==1||(expected.checkVersion&&(rows[0].getAttribute('data-version')||null)!==expected.version))throw new Error('target-state-changed');
      return rows[0];
    },{identity:target.identity,version:target.version,checkVersion});
    if(!handle.asElement()){await handle.dispose();throw new Error('target-state-changed');}
    return handle;
  }

  async verifyTargets(targets){
    for(const target of targets){const row=await this.targetRow(target);await row.dispose();}
  }

  async targetValues(target,fields){
    const table=await this.find(target.table_fingerprint);
    const data=await table.node.evaluate(projectNode,{capability:'web.read_table',limits:{rows:100,columns:30}});
    const matches=data.identities.map((identity,index)=>({identity,index})).filter(row=>row.identity?.identity===target.identity);
    if(matches.length!==1)throw new Error('target-state-changed');
    const values={};
    for(const [field,header] of Object.entries(fields)){
      const columns=data.tables[0].headers.map((value,index)=>({value,index})).filter(row=>row.value===header);
      if(columns.length!==1)throw new Error('target-state-changed');
      values[field]=data.tables[0].rows[matches[0].index][columns[0].index];
    }
    await this.check(table);return values;
  }

  async selectTargets(targets,selected,authorize){
    for(const target of targets){
      const row=await this.targetRow(target,selected.includes(target.identity));
      let choices=[];
      try {
        choices=await row.asElement().$$('input[type="checkbox"]');
        const visible=[];for(const choice of choices)if(await choice.isVisible())visible.push(choice);
        if(visible.length!==1)throw new Error('target-selection-unavailable');
        if(await authorize()!==true)throw new Error('grant-revoked');
        await visible[0].setChecked(selected.includes(target.identity),{timeout:5000});
      } finally {for(const choice of choices)await choice.dispose();await row.dispose();}
    }
  }

  async project(entry,capability,limits){
    await this.check(entry);
    if(!limits||!Number.isInteger(limits.rows)||limits.rows<0||limits.rows>100||!Number.isInteger(limits.columns)||limits.columns<0||limits.columns>30||!Number.isInteger(limits.bytes)||limits.bytes<0||limits.bytes>98304)throw new Error('scope-mismatch');
    const projected=await entry.node.evaluate(projectNode,{capability,limits});
    await this.check(entry);
    const identities=projected.identities||[];delete projected.identities;
    const output={ok:true,...this.redact(projected),target_refs:[]};
    while(Buffer.byteLength(JSON.stringify(output),'utf8')>limits.bytes){
      if(output.tables?.[0]?.rows.length){output.tables[0].rows.pop();identities.pop();output.tables[0].truncated=true;}
      else if(output.text?.length){output.text=output.text.slice(0,Math.floor(output.text.length/2));output.truncated=true;}
      else throw new Error('response-too-large');
    }
    for(let index=0;index<identities.length;index++){
      const identity=identities[index];if(!identity)continue;
      if(JSON.stringify(identity)!==JSON.stringify(this.redact(identity)))continue;
      if(identities.filter(value=>value?.identity===identity.identity).length!==1)continue;
      if(this.targets.size>=1000)throw new Error('response-too-large');
      const ref=token();this.targets.set(ref,{...identity,page:this.pageInfo(),table_fingerprint:entry.fingerprint,row:index});output.target_refs.push(ref);
    }
    if(Buffer.byteLength(JSON.stringify(output),'utf8')>limits.bytes)throw new Error('response-too-large');
    return output;
  }

  async perform(entry,action,value,authorize){
    await this.check(entry);
    if(typeof authorize!=='function'||await authorize()!==true)throw new Error('approval-required');
    await this.check(entry);
    const element=entry.node.asElement();if(!element)throw new Error('component-stale');
    if(action==='click'&&entry.meta.kind==='action')await element.click({timeout:5000});
    else if(action==='fill'&&entry.meta.kind==='field'&&typeof value==='string'&&Buffer.byteLength(value,'utf8')<=1024)await element.fill(value,{timeout:5000});
    else if(action==='select'&&entry.meta.tag==='select'&&typeof value==='string')await element.selectOption(value,{timeout:5000});
    else if(action==='check'&&entry.meta.kind==='field'&&typeof value==='boolean')await element.setChecked(value,{timeout:5000});
    else throw new Error('capability-unsupported');
    await this.admit();return {ok:true,newObservationRequired:true,page:this.pageInfo(),businessSuccessVerified:false};
  }
}
