import {randomUUID} from 'node:crypto';

export async function* readFrames(stream) {
  let pending = Buffer.alloc(0);
  try {
    for await (const chunk of stream) {
      pending = Buffer.concat([pending, chunk]);
      let end;
      while ((end = pending.indexOf(10)) !== -1) {
        if (end > 65536) throw new Error('invalid-job');
        const frame = pending.subarray(0,end);
        let value;
        try {value = JSON.parse(frame.toString('utf8'));} finally {frame.fill(0);}
        pending = Buffer.from(pending.subarray(end+1));
        yield value;
      }
      if (pending.length > 65536) throw new Error('invalid-job');
    }
    if (pending.length) yield JSON.parse(pending.toString('utf8'));
  } finally {pending.fill(0);}
}

export function boundResult(value) {
  const result={...value};
  if(Array.isArray(result.links))result.links=[...result.links];
  if(Array.isArray(result.results))result.results=[...result.results];
  while(Buffer.byteLength(JSON.stringify(result),'utf8')>98304){
    result.truncated=true;
    if(result.links?.length)result.links.pop();
    else if(result.results?.length)result.results.shift();
    else if(typeof result.text==='string' && result.text.length)result.text=result.text.slice(0,Math.floor(result.text.length/2));
    else return {ok:false,failureCode:'response-too-large'};
  }
  return result;
}

function commandName(request, url) {
  const names = [url.searchParams.get('cmd'), url.searchParams.get('command')];
  const body = request.postData();
  if (typeof body === 'string' && body.length <= 16384) {
    try {const data=JSON.parse(body);names.push(data?.cmd,data?.command);} catch {
      const params=new URLSearchParams(body);names.push(params.get('cmd'),params.get('command'));
    }
  }
  return names.find(value=>typeof value==='string' && /^(?:get|list|query|read)_[A-Za-z0-9_]{1,96}$/.test(value)) || null;
}

export function projectResponse(request, status, body) {
  if (!['xhr','fetch'].includes(request.resourceType()) || !Buffer.isBuffer(body) || body.length > 262144) return null;
  let data;
  try {data=JSON.parse(body.toString('utf8'));} catch {return null;}
  if (!data || Array.isArray(data) || typeof data !== 'object') return null;
  const result={};
  for (const field of ['nResult','code','status','success','total','count']) {
    let value=data[field];
    if (typeof value==='string' && /^-?\d{1,9}$/.test(value)) value=Number(value);
    if (typeof value==='boolean' || (Number.isSafeInteger(value) && Math.abs(value)<=2147483647)) result[field]=value;
  }
  if (!Object.keys(result).length) return null;
  const url=new URL(request.url());
  return {path:/^\/[A-Za-z0-9/_.~-]{0,511}$/.test(url.pathname)?url.pathname:'[path-omitted]',
    method:request.method(),command:commandName(request,url),httpStatus:status,result};
}

function routeUrl(value, origin) {
  const url=new URL(value);
  if (url.protocol!=='https:' || url.origin!==origin || url.username || url.password) throw new Error('origin-blocked');
  return {origin:url.origin,path:url.pathname,route:/^#\/[A-Za-z0-9/_-]{0,511}$/.test(url.hash)?url.hash:null,queryOmitted:!!url.search};
}

function fragmentDestination(href, current) {
  try {
    const target=new URL(href),source=new URL(current);
    return target.origin===source.origin && target.pathname===source.pathname && !target.search && !source.search &&
      !target.username && !target.password && /^#\/[A-Za-z0-9/_-]{0,511}$/.test(target.hash);
  } catch {return false;}
}

export class SessionControl {
  constructor(page, config, {deadline, secret, check}) {
    this.page=page;this.config=config;this.deadline=deadline;this.check=check;
    this.secrets=[...new Set([secret,encodeURIComponent(secret),Buffer.from(secret).toString('base64')])].filter(Boolean);
    this.results=[];this.sequence=0;this.snapshot=null;this.handle=null;this.links=new Map();
  }

  redact(value) {
    if (typeof value==='string') {for (const secret of this.secrets)value=value.split(secret).join('[redacted]');return value;}
    if (Array.isArray(value)) return value.map(item=>this.redact(item));
    if (value && typeof value==='object') return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,this.redact(item)]));
    return value;
  }

  pageInfo(url) {
    const info=routeUrl(url,this.config.origin);
    return {...info,path:this.redact(info.path),route:this.redact(info.route)};
  }

  async admit() {
    this.check();
    if (this.page.isClosed() || Date.now()>=this.deadline) throw new Error('session-unavailable');
    routeUrl(this.page.url(),this.config.origin);
    if (!this.config.success_selector || await this.page.locator(this.config.password_selector).isVisible() ||
        !await this.page.locator(this.config.success_selector).isVisible()) throw new Error('authentication-required');
  }

  async invalidate() {
    this.snapshot=null;
    for(const link of this.links.values())await link.node.dispose().catch(()=>{});
    this.links.clear();
    await this.handle?.dispose().catch(()=>{});this.handle=null;
  }

  async dispose() {await this.invalidate();this.results=[];this.secrets=[];}

  async observe() {
    await this.admit();await this.invalidate();
    const current=this.page.url();
    // DOM values are never read. Hidden/editable/embedded content is excluded, not masked after export.
    this.handle=await this.page.evaluateHandle(selector=>{
      const root=document.querySelector(selector);
      if (!root || document.querySelectorAll(selector).length!==1) throw new Error();
      const blocked='input,textarea,select,option,[contenteditable],script,style,noscript,iframe,svg,canvas,[hidden],[aria-hidden="true"]';
      const visible=el=>{
        if (!el || el.closest(blocked) || !el.getClientRects().length) return false;
        for(let p=el;p;p=p.parentElement){const css=getComputedStyle(p);if(css.display==='none'||css.visibility==='hidden'||css.visibility==='collapse'||css.opacity==='0')return false;}
        return true;
      };
      const readText=(parent,limit)=>{
        const walker=document.createTreeWalker(parent,NodeFilter.SHOW_TEXT);
        const lines=[];let characters=0,visited=0,node,truncated=false;
        while((node=walker.nextNode())){
          if(++visited>20000 || characters>=limit){truncated=true;break;}
          if(visible(node.parentElement)){
            const text=node.textContent.replace(/\s+/g,' ').trim();
            if(text){const part=text.slice(0,limit-characters);lines.push(part);characters+=part.length;if(part.length<text.length)truncated=true;}
          }
        }
        return {text:lines.join('\n'),truncated};
      };
      const content=readText(root,16000);
      const links=[];
      for(const anchor of root.querySelectorAll('a[href]')){
        if(links.length>=100){content.truncated=true;break;}
        if(visible(anchor)){
          const label=readText(anchor,160);if(label.truncated)content.truncated=true;
          links.push({node:anchor,href:anchor.href,label:label.text});
        }
      }
      return {...content,links};
    },this.config.success_selector);
    const snapshot=await this.handle.evaluate(value=>({text:value.text,truncated:value.truncated,links:value.links.map(({href,label},index)=>({href,label,index}))}));
    await this.admit();
    if(this.page.url()!==current){await this.invalidate();throw new Error('stale-observation');}
    const links=[],array=await this.handle.getProperty('links');
    try {
      for(const item of snapshot.links){
        if(!fragmentDestination(item.href,current))continue;
        const ref=randomUUID().replaceAll('-',''),entry=await array.getProperty(String(item.index)),node=await entry.getProperty('node');
        await entry.dispose();this.links.set(ref,{node,href:item.href});
        links.push({ref,label:this.redact(item.label),route:this.redact(new URL(item.href).hash)});
      }
    } finally {await array.dispose();}
    this.snapshot={id:randomUUID().replaceAll('-',''),url:current,at:Date.now()};
    return boundResult({ok:true,authenticationVerified:true,controlScope:'same-session',observationId:this.snapshot.id,
      page:this.pageInfo(current),text:this.redact(snapshot.text),truncated:snapshot.truncated,links,
      observationExpiresInSeconds:30,businessSuccessVerified:false,contentTrust:'untrusted-page-data'});
  }

  async navigate(args) {
    await this.admit();
    if(!this.snapshot || args.observation_id!==this.snapshot.id || this.page.url()!==this.snapshot.url ||
        Date.now()-this.snapshot.at>30000) throw new Error('stale-observation');
    const link=this.links.get(args.element_ref);
    if(!link || !fragmentDestination(link.href,this.page.url()) ||
        !await link.node.evaluate((node,href)=>node.isConnected && node.href===href,link.href) ||
        !await link.node.asElement().isVisible()) throw new Error('stale-observation');
    const target=this.pageInfo(link.href);
    if(args.confirm!==true)return {ok:true,preview:true,navigation:target,action:'same-document-fragment-navigation',clickHandlersExecuted:false};
    const href=link.href;await this.invalidate();await this.admit();
    // Do not execute arbitrary link click handlers, submit forms, or accept caller-provided URLs.
    await this.page.goto(href,{waitUntil:'domcontentloaded',timeout:10000});
    await this.admit();
    return {ok:true,preview:false,page:this.pageInfo(this.page.url()),newObservationRequired:true,businessSuccessVerified:false};
  }

  record(summary) {
    this.results.push({...summary,responseId:++this.sequence,observedAt:new Date().toISOString()});
    if(this.results.length>64)this.results.shift();
  }

  async readResult() {
    await this.admit();
    return boundResult({ok:true,authenticationVerified:true,controlScope:'same-session',source:'passive-page-responses',
      results:this.results.slice(-20).map(row=>({...row,path:this.redact(row.path),command:this.redact(row.command)})),
      retainedCount:this.results.length,newRequestSent:false,
      businessSuccessVerified:false,interpretation:'Result codes are evidence, not proof of task permissions or business success.'});
  }
}

export async function dispatch(control, command) {
  if(!command || typeof command!=='object' || Object.keys(command).sort().join(',')!=='arguments,id,operation' ||
     !/^[a-f0-9]{32}$/.test(command.id) || !command.arguments || typeof command.arguments!=='object' || Array.isArray(command.arguments)) throw new Error('invalid-command');
  const args=command.arguments,keys=Object.keys(args).sort().join(',');
  if(command.operation==='observe' && keys==='')return control.observe();
  if(command.operation==='read-result' && keys==='')return control.readResult();
  if(command.operation==='navigate' && keys==='confirm,element_ref,observation_id' && typeof args.confirm==='boolean' &&
     /^[a-f0-9]{32}$/.test(args.element_ref) && /^[a-f0-9]{32}$/.test(args.observation_id))return control.navigate(args);
  throw new Error('invalid-command');
}
