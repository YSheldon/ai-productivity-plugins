import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {SiteControl} from '../scripts/web_site_control.mjs';
import {Components} from '../scripts/web_components.mjs';

// Only DOM primitives are doubled. The actual collectors, fingerprint checks,
// private context snapshot, and dispatch admission run unchanged.
function fixture(nested=false){
  const old=new Map(['NodeFilter','getComputedStyle','location','document'].map(k=>[k,Object.getOwnPropertyDescriptor(globalThis,k)]));
  const hidden={id:'recordId',name:'recordId',type:'hidden',value:'A',autocomplete:''};
  const form={tagName:'FORM',id:'edit',parentElement:null,getClientRects:()=>[{}],closest:()=>null,querySelectorAll:()=>[hidden]};
  const row={tagName:'TR',id:'row',parentElement:form,getClientRects:()=>[{}],closest:()=>null,querySelectorAll:()=>[]};
  let clicked=null;
  const anchor={tagName:'A',id:'delete',nodeType:1,parentElement:nested?row:form,isConnected:true,disabled:false,
    href:'https://console.example/delete?id=A',getClientRects:()=>[{}],
    closest:selector=>selector==='form'?form:selector.startsWith('form,')?(nested?row:form):null,
    getAttribute(name){return name==='href'?this.href:null;},hasAttribute:()=>false,
    async click(){clicked={href:this.href,record:hidden.value};}};
  const text={textContent:'Delete selected record',parentElement:anchor};
  globalThis.NodeFilter={SHOW_TEXT:4};
  globalThis.getComputedStyle=()=>({display:'block',visibility:'visible',opacity:'1'});
  globalThis.location={href:'https://console.example/list'};
  globalThis.document={querySelectorAll:selector=>selector==='input:checked'?[]:[anchor],createTreeWalker:()=>{
    let used=false;return {nextNode(){if(used)return null;used=true;return text;}};
  }};
  const page={url:()=>location.href,evaluateHandle:async(fn,arg)=>{
    const rows=fn(arg);return {evaluate:async f=>f(rows),dispose:async()=>{}};
  }};
  const registry=new Components(page,{admit:async()=>{},redact:x=>x,siteNavigation:true});
  const meta={tag:'a',id:'delete',role:'',kind:'action',name:'Delete selected record',href:'/delete',type:null,path:nested?'tr#row/form#edit':'form#edit'};
  const entry={meta,url:location.href,fingerprint:createHash('sha256').update(JSON.stringify(meta)).digest('hex'),
    node:{evaluate:async(fn,arg)=>fn(anchor,arg),asElement:()=>anchor}};
  registry.resolve=async()=>entry;
  const runtime=new SiteControl({registry,authorize:async()=>true});
  return {runtime,anchor,hidden,clicked:()=>clicked,cleanup:()=>{
    for(const [key,descriptor] of old)if(descriptor)Object.defineProperty(globalThis,key,descriptor);else delete globalThis[key];
  }};
}

for(const change of ['href-query','hidden-record','associated-hidden-record'])test(`real component path rejects changed ${change} after confirmation`,async()=>{
  const h=fixture(change==='associated-hidden-record');
  try{
    const proposal=await h.runtime.preview({observation_id:'a'.repeat(32),component_ref:'b'.repeat(32),action:'click',risk:'sensitive'});
    assert.equal(proposal.sensitive,true);
    assert.match(proposal.preview.target,/recordId=A/);
    if(change==='href-query')h.anchor.href='https://console.example/delete?id=B';else h.hidden.value='B';
    await assert.rejects(()=>h.runtime.execute({action_ref:proposal.action_ref,attempt_id:'c'.repeat(32)}),/target-state-changed/);
    assert.equal(h.clicked(),null);
  }finally{h.cleanup();}
});
