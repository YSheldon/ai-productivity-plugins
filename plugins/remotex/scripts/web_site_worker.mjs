import fs from 'node:fs/promises';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {launchEdge,createWebContext,verifyNetworkGuard,guardRoute,sameOrigin,validateJob,submitLogin,loadConfiguredDocument} from './web_login_worker.mjs';
import {readFrames,SessionControl} from './web_control.mjs';
import {Components} from './web_components.mjs';
import {WorkerAuthority} from './web_authorization_ipc.mjs';
import {SiteControl,SiteNetworkPolicy} from './web_site_control.mjs';

const safeCodes=new Set(['request-invalid','request-too-large','component-stale','component-ambiguous','target-state-changed',
  'capability-unsupported','approval-required','grant-revoked','origin-blocked','session-unavailable','authentication-required',
  'manual-operation-required','authentication-already-verified','operation-in-progress','response-too-large']);

export async function siteLogin(page,cfg,job,{check,write,alreadySubmitted}){
  if(alreadySubmitted.value)return {ok:true,authenticationVerified:false,doNotResubmit:true};
  check();
  await loadConfiguredDocument(page,cfg);
  await Promise.all(['username_selector','password_selector','submit_selector'].map(key=>page.locator(cfg[key]).waitFor({state:'visible',timeout:10000})));
  check();
  if(!sameOrigin(page.url(),cfg.origin))throw new Error('origin-blocked');
  const before=cfg.success_selector?await page.locator(cfg.success_selector).isVisible():false;
  alreadySubmitted.value=true;
  try{
    await submitLogin(page,cfg,job.username,job.password,check);
    await write({state:'submitted',loginSubmitted:true});
    const secret=page.locator(cfg.password_selector);
    try{await secret.waitFor({state:'hidden',timeout:3000});}catch{}
    const verified=!!(cfg.success_selector&&!before&&sameOrigin(page.url(),cfg.origin)&&
      !await secret.isVisible()&&await page.locator(cfg.success_selector).isVisible());
    check();
    if(await secret.isVisible())await secret.fill('');
    await write({state:verified?'verified':'needs-user-check',authenticationVerified:verified,failureCode:null});
    return {ok:true,authenticationVerified:verified,doNotResubmit:!verified};
  }finally{job.password='';}
}

async function main(){
  const directory=process.argv[2],modulePath=process.argv[3];
  let job,browser,deny,context,page,authority,policy,registry,control,timer,stopTimer;
  let failure=null,state={state:'starting',loginSubmitted:false,authenticationVerified:false,failureCode:null};
  let writes=Promise.resolve();
  const write=patch=>{
    state={...state,...patch,updatedAt:new Date().toISOString()};const body=JSON.stringify(state);
    writes=writes.then(async()=>{const temp=path.join(directory,'state.tmp');await fs.writeFile(temp,body,{mode:0o600});await fs.rename(temp,path.join(directory,'state.json'));});
    return writes;
  };
  try{
    const frames=readFrames(process.stdin);job=(await frames.next()).value;
    const cfg=validateJob(job);
    if(job.authorization_mode!=='site'||job.mode==='probe')throw new Error('invalid-job');
    const cancellation=new AbortController();
    const check=()=>{if(failure||cancellation.signal.aborted||Date.now()>=job.deadline)throw new Error('session-unavailable');};
    const emit=value=>process.stdout.write(JSON.stringify(value)+'\n');
    authority=new WorkerAuthority({emit,onRevoke:()=>{policy?.fence();cancellation.abort();void context?.close().catch(()=>{});}});
    policy=new SiteNetworkPolicy({origin:cfg.origin,check:request=>authority.check(request,{signal:cancellation.signal}),
      onComplete:state=>emit({event:'startup-state',state})});
    ({browser,deny}=await launchEdge(createRequire(import.meta.url)(modulePath)));
    await verifyNetworkGuard(browser);
    context=await createWebContext(browser);await context.setOffline(true);
    const fail=code=>{failure=code;policy.fence();cancellation.abort();void context.close().catch(()=>{});};
    await context.route('**/*',route=>guardRoute(route,cfg.origin,fail,cfg.certificate_sha256,cancellation.signal,null,policy,page));
    await context.routeWebSocket('**/*',socket=>{socket.close();fail('unsupported-transport');});
    page=await context.newPage();page.once('close',()=>cancellation.abort());
    browser.once('disconnected',()=>cancellation.abort());
    context.on('page',extra=>{if(extra!==page)void extra.close();});
    timer=setTimeout(()=>{cancellation.abort();void context.close().catch(()=>{});},Math.max(1,job.deadline-Date.now()));
    stopTimer=setInterval(async()=>{try{await fs.access(path.join(directory,'close.request'));cancellation.abort();void context.close().catch(()=>{});}catch{}},500);
    control=new SessionControl(page,cfg,{deadline:job.deadline,secret:job.password,check});
    registry=new Components(page,{admit:()=>control.admit(),redact:value=>control.redact(value),geometryRoot:cfg.success_selector||'main',siteNavigation:true});
    const actions=new SiteControl({registry,authorize:request=>authority.check(request,{signal:cancellation.signal})});
    const submitted={value:false};
    await write({state:'needs-user-check',failureCode:'authorization-contract-required'});
    let sequence=Promise.resolve(),queued=0;
    const commands=async()=>{
      for await(const command of frames){
        if(authority.handle(command))continue;
        if(++queued>4)throw new Error('invalid-command');
        sequence=sequence.then(async()=>{
          let result;
          try{
            if(!command||Object.keys(command).sort().join(',')!=='arguments,id,operation'||
              !/^[a-f0-9]{32}$/.test(command.id)||!command.arguments||Array.isArray(command.arguments)||typeof command.arguments!=='object')throw new Error('request-invalid');
            check();
            const args=command.arguments;
            if(command.operation==='resume-login'&&Object.keys(args).length===0){
              if(!await authority.check({kind:'site-login'},{signal:cancellation.signal}))throw new Error('approval-required');
              result=await siteLogin(page,cfg,job,{check,write,alreadySubmitted:submitted});
            }else if(command.operation==='components'&&Object.keys(args).length===0)result=await registry.scan();
            else if(command.operation==='site-preview')result=await actions.preview(args);
            else if(command.operation==='site-execute')result=await actions.execute(args);
            else throw new Error('request-invalid');
          }catch(error){
            result={ok:false,failureCode:safeCodes.has(error?.message)?error.message:'control-failed',
              ...(command?.operation==='site-execute'&&error?.dispatched===false?{dispatched:false}:{})};
          }
          emit({id:command?.id,result});queued--;
        });
      }
      await sequence;
    };
    await Promise.race([commands(),new Promise(resolve=>page.once('close',resolve))]);
    await write({state:'closed'});
  }catch{
    await write({state:'failed',failureCode:failure||'login-flow-failed'}).catch(()=>{});
  }finally{
    if(job)job.password='';clearTimeout(timer);clearInterval(stopTimer);authority?.dispose();policy?.fence();
    await registry?.dispose().catch(()=>{});await control?.dispose().catch(()=>{});
    await context?.close().catch(()=>{});await browser?.close().catch(()=>{});deny?.close();process.stdin.destroy();
  }
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  if(process.argv[2]==='--describe-protocol')process.stdout.write('{"site_authorization":1}\n');
  else main().catch(()=>{process.exitCode=1;});
}
