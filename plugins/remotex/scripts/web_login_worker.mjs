import fs from 'node:fs/promises';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import net from 'node:net';
import dgram from 'node:dgram';
import {randomUUID} from 'node:crypto';
import {pinnedResponse,guardedResponse,initializationResponse} from './web_tls.mjs';
import {evaluateInitializationResponse} from './web_initialization_contracts.mjs';
import {StartupState} from './web_startup_state.mjs';
import {SessionControl, projectResponse, readFrames} from './web_control.mjs';
import {Components} from './web_components.mjs';
import {TaskControl} from './web_task_control.mjs';
import {NetworkPolicy,requestCancelled} from './web_network_authorization.mjs';
import {WorkerAuthority} from './web_authorization_ipc.mjs';
import {WorkerRuntime} from './web_worker_runtime.mjs';

export async function launchEdge(pw, headless = false) {
  const deny = net.createServer(socket=>socket.destroy());
  await new Promise((resolve,reject)=>{deny.once('error',reject);deny.listen(0,'127.0.0.1',resolve);});
  try {
    const browser = await pw.chromium.launch({channel:'msedge',headless,
      args:[`--proxy-server=http://127.0.0.1:${deny.address().port}`,'--proxy-bypass-list=<-loopback>','--host-resolver-rules=MAP * ~NOTFOUND','--force-webrtc-ip-handling-policy=disable_non_proxied_udp'],
      env:{...process.env,DEBUG:'',PWDEBUG:'',NODE_OPTIONS:''}});
    return {browser,deny};
  } catch(error) {deny.close();throw error;}
}

export function createWebContext(browser) {
  // Visible sessions follow the user's window instead of Playwright's fixed test viewport.
  return browser.newContext({viewport:null,ignoreHTTPSErrors:false,serviceWorkers:'block',acceptDownloads:false});
}

export async function verifyNetworkGuard(browser) {
  let packets=0,connections=0;
  const udp=dgram.createSocket('udp4'),tcp=net.createServer(socket=>{connections++;socket.destroy();});
  udp.on('message',()=>packets++);
  let context;
  try {
    await new Promise((r,j)=>{udp.once('error',j);udp.bind(0,'127.0.0.1',r);});
    await new Promise((r,j)=>{tcp.once('error',j);tcp.listen(0,'127.0.0.1',r);});
    context=await browser.newContext({serviceWorkers:'block'});
    await context.setOffline(true);
    await context.route('**/*',r=>r.fulfill({contentType:'text/html',body:'<title>RemoteX network check</title>'}));
    const page=await context.newPage();await page.goto('https://remotex-canary.invalid/');
    await page.evaluate(async ports=>{
      const peer=new RTCPeerConnection({iceServers:[{urls:`stun:127.0.0.1:${ports.udp}`},{urls:`turn:127.0.0.1:${ports.tcp}?transport=tcp`,username:'fixture',credential:'fixture'}]});
      try {peer.createDataChannel('probe');await peer.setLocalDescription(await peer.createOffer());await new Promise(r=>setTimeout(r,1500));}finally{peer.close();}
    },{udp:udp.address().port,tcp:tcp.address().port});
    if(packets || connections)throw new Error('network-guard-failed');
    return {udpPackets:packets,tcpConnections:connections};
  } finally {await context?.close();udp.close();tcp.close();}
}

export function sameOrigin(url, origin) {
  try { const u = new URL(url); return u.protocol === 'https:' && !u.username && !u.password && u.origin === origin; }
  catch { return false; }
}

export function browserCancellation(context) {
  const cancellation = new AbortController();
  context.once('close',()=>cancellation.abort());
  return cancellation;
}

export async function loadConfiguredDocument(page,cfg,{deadline=Date.now()+45000}={}){
  if(!sameOrigin(cfg.url,cfg.origin))throw new Error('origin-blocked');
  const started=performance.now(),now=Date.now();
  const end=Math.min(deadline,now+45000),budget=end-now;
  const remaining=()=>{
    const value=Math.min(end-Date.now(),budget-(performance.now()-started));
    if(!Number.isFinite(value)||value<=0)throw new Error('startup-deadline-exceeded');
    return Math.ceil(value);
  };
  const documentUrl=new URL(cfg.url);documentUrl.hash='';
  // A same-URL fragment navigation does not fetch the newly authorized document.
  // Explicit GET navigation also avoids reload's possible POST-body replay.
  await page.goto(documentUrl.href,{waitUntil:'domcontentloaded',timeout:remaining()});
  if(documentUrl.href!==cfg.url){
    if(!sameOrigin(page.url(),cfg.origin))throw new Error('origin-blocked');
    await page.goto(cfg.url,{waitUntil:'domcontentloaded',timeout:remaining()});
  }
}

export async function guardRoute(route, origin, failed, certificateSha256, signal, observed, policy, owner) {
  if (!sameOrigin(route.request().url(), origin)) { failed('origin-blocked'); await route.abort(); return; }
  let completed;
  try {
    const request=route.request();
    if(owner&&request.frame().page()!==owner){await route.abort();return;}
    if(policy && !await policy.authorize(request)){
      if(request.isNavigationRequest?.()&&request.frame().parentFrame()===null){
        // Keep a denied document in this page; Chromium's internal error-page
        // navigation can otherwise race the next explicitly authorized load.
        await route.fulfill({status:403,headers:{'content-type':'text/html; charset=utf-8',
          'cache-control':'no-store','content-security-policy':"default-src 'none'; form-action 'none'; frame-ancestors 'none'; sandbox",
          'referrer-policy':'no-referrer','x-content-type-options':'nosniff'},
          body:'<!doctype html><meta charset="utf-8"><title>RemoteX request blocked</title><p>Request blocked pending local authorization.</p>'});
      }else await route.abort();
      return;
    }
    if(signal?.aborted||requestCancelled(request)){await route.abort();return;}
    completed=policy?.beginForwarding?.(route.request());
    const activeSignal=completed?.startupSignal?(signal?AbortSignal.any([signal,completed.startupSignal]):completed.startupSignal):signal;
    if(completed?.initialization){
      const receipt=completed.initialization;
      const response=await initializationResponse(request,origin,certificateSha256,activeSignal,
        completed.startupDeadline??Date.now()+45000,()=>{
          completed.checkDispatch?.();policy.startupState.forward(receipt);
        });
      evaluateInitializationResponse(response,receipt.response_checks,policy.parseTree);
      completed.checkDispatch?.();policy.startupState.check(receipt);
      await route.fulfill(response);policy.startupState.response(receipt,{ready:true});return;
    }
    if(completed?.privateStartup){
      const response=await guardedResponse(request,origin,certificateSha256,activeSignal,
        {deadline:completed.startupDeadline,beforeSend:completed.checkDispatch});
      if(response.status>=300&&response.status<400&&response.status!==304){failed('redirect-blocked');await route.abort();return;}
      await route.fulfill(response);return;
    }
    if (certificateSha256 !== undefined) {
      const response = await pinnedResponse(route.request(), origin, certificateSha256, activeSignal,{beforeSend:completed?.checkDispatch});
      if (response.status >= 300 && response.status < 400 && response.status !== 304) {
        failed('redirect-blocked');await route.abort();return;
      }
      await route.fulfill(response);
      if(observed){const summary=projectResponse(route.request(),response.status,response.body);if(summary)observed(summary);}
      return;
    }
    // Fulfil only a non-redirect response: automatic redirect replay could send a POST elsewhere.
    const response = await route.fetch({maxRedirects:0, timeout:20000});
    if (response.status() >= 300 && response.status() < 400 && response.status() !== 304) {
      failed('redirect-blocked'); await route.abort(); return;
    }
    await route.fulfill({response});
    if(observed && ['xhr','fetch'].includes(route.request().resourceType())){
      const summary=projectResponse(route.request(),response.status(),await response.body());if(summary)observed(summary);
    }
  } catch (error) {
    if(completed?.initialization&&['initialization-response-rejected','response-too-large'].includes(error?.message)){
      try{policy.startupState.response(completed.initialization,{ready:false});}catch{}
      await route.abort().catch(()=>{});return;
    }
    if(error?.message==='scope-mismatch'){await route.abort().catch(()=>{});return;}
    const allowed = new Set(['invalid-job','origin-blocked','certificate-pin-mismatch','certificate-validity-failed','request-too-large','response-too-large']);
    failed(allowed.has(error?.message)?error.message:'tls-or-navigation-failed');
    await route.abort().catch(()=>{});
  } finally {completed?.();}
}

export function validateJob(job) {
  const c = job.config;
  const mode = job.mode || 'login';
  if (!['login','probe'].includes(mode) || !c || !sameOrigin(c.url,c.origin)) throw new Error('invalid-job');
  if (mode === 'login' && (typeof job.password !== 'string' || !job.password || job.password.length > 4096 || job.username !== c.account)) throw new Error('invalid-job');
  for (const field of ['username_selector','password_selector','submit_selector']) {
    if (!/^#[A-Za-z][A-Za-z0-9_-]{0,95}$/.test(c[field])) throw new Error('invalid-job');
  }
  if (c.success_selector && !/^#[A-Za-z][A-Za-z0-9_-]{0,95}$/.test(c.success_selector)) throw new Error('invalid-job');
  if ('certificate_sha256' in c && (typeof c.certificate_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(c.certificate_sha256))) throw new Error('invalid-job');
  if (!Number.isFinite(job.deadline) || job.deadline <= Date.now() || job.deadline > Date.now()+46800000) throw new Error('invalid-job');
  return c;
}

export async function submitLogin(page, cfg, username, password, check) {
  check();
  if (!sameOrigin(page.url(), cfg.origin)) throw new Error('origin-blocked');
  const user = page.locator(cfg.username_selector), secret = page.locator(cfg.password_selector), submit = page.locator(cfg.submit_selector);
  if (await user.count() !== 1 || await secret.count() !== 1 || await submit.count() !== 1) throw new Error('form-unavailable');
  await user.fill(username, {timeout:10000});
  await secret.click({timeout:10000});
  // Some legacy consoles use a text input plus keyboard handlers. Mask before typing.
  await secret.evaluate(el => { if (el.tagName !== 'INPUT') throw new Error(); el.type = 'password'; });
  if (await secret.getAttribute('type') !== 'password') throw new Error('form-unavailable');
  check();
  if (!sameOrigin(page.url(), cfg.origin)) throw new Error('origin-blocked');
  await secret.pressSequentially(password, {timeout:15000});
  check();
  if (!sameOrigin(page.url(), cfg.origin)) throw new Error('origin-blocked');
  await submit.click({timeout:10000});
}

async function main() {
  const directory = process.argv[2], modulePath = process.argv[3];
  let browser, deny, context, page, timer, stopTimer, job, cancellation, control, registry, authority, network;
  let startupContext=null;
  let failure = null, state = {state:'starting',loginSubmitted:false,authenticationVerified:false,failureCode:null};
  let writeSequence = Promise.resolve();
  const write = patch => {
    state = {...state,...patch,updatedAt:new Date().toISOString()};
    const body = JSON.stringify(state);
    writeSequence = writeSequence.then(async()=>{const temporary=path.join(directory,'state.tmp');await fs.writeFile(temporary,body,{mode:0o600});await fs.rename(temporary,path.join(directory,'state.json'));});
    return writeSequence;
  };
  const check = () => { if (failure) throw new Error(failure); };
  try {
    const frames=readFrames(process.stdin);
    job = (await frames.next()).value; const cfg = validateJob(job);
    const emit=value=>process.stdout.write(JSON.stringify(value)+'\n');
    authority=new WorkerAuthority({emit,startup:()=>startupContext,
      onRevoke:()=>{network?.fence();cancellation?.abort();void context?.close().catch(()=>{});}});
    network=new NetworkPolicy({origin:cfg.origin,secret:job.password,
      startup:()=>startupContext,consumeReceipt:(receipt,expected)=>authority.consumeNetworkReceipt(receipt,expected),
      requestPermit:(value,options)=>authority.checkNetwork({kind:'network',...value},options)});
    network.startupState=new StartupState({lifecycle:network.preauthLifecycle,emit:frame=>{
      if(startupContext?.binding_digest)emit({event:'startup-state',state:frame});
    }});
    const require = createRequire(import.meta.url);
    const parserModule=process.argv[4]||path.join(modulePath,'..','jsonc-parser');
    const parserVersion=JSON.parse(await fs.readFile(path.join(parserModule,'package.json'),'utf8')).version;
    if(parserVersion!=='3.3.1')throw new Error('invalid-job');
    network.parseTree=require(parserModule).parseTree;
    if(typeof network.parseTree!=='function')throw new Error('invalid-job');
    const pw = require(modulePath);
    ({browser,deny}=await launchEdge(pw));
    await verifyNetworkGuard(browser);
    context = await createWebContext(browser);
    cancellation = browserCancellation(context);
    browser.once('disconnected',()=>cancellation.abort());
    await context.setOffline(true);
    const rejected=code=>{failure=code;cancellation.abort();void context.close().catch(()=>{});};
    await context.route('**/*', route=>guardRoute(route,cfg.origin,rejected,cfg.certificate_sha256,cancellation.signal,
      summary=>{if(state.authenticationVerified)control?.record(summary);},network,page));
    await context.routeWebSocket('**/*', socket=>{
      rejected('unsupported-transport');socket.close();
    });
    page = await context.newPage();
    page.once('close',()=>cancellation.abort());
    context.on('page', extra=>{if(extra!==page) void extra.close();});
    const close = () => {network.fence();authority.dispose();cancellation.abort();return context.close().catch(()=>{});};
    timer = setTimeout(close, Math.max(1,job.deadline-Date.now()));
    stopTimer = setInterval(async()=>{try{await fs.access(path.join(directory,'close.request'));void close();}catch{}},500);
    control=new SessionControl(page,cfg,{deadline:job.deadline,secret:job.password||'',check});
    registry=new Components(page,{admit:()=>control.admit(),redact:value=>control.redact(value),geometryRoot:cfg.success_selector||'main'});
    const task=new TaskControl({registry,authorize:value=>authority.check(value),readResult:()=>control.readResult(),network});
    let successVisibleBefore=null;
    const resume=async(ticket=null)=>{
      check();
      if(state.authenticationVerified)throw new Error('authentication-already-verified');
      if(network.authenticationForwarded>0){
        const verified=!!(state.loginSubmitted&&cfg.success_selector&&sameOrigin(page.url(),cfg.origin)&&
          !await page.locator(cfg.password_selector).isVisible()&&await page.locator(cfg.success_selector).isVisible());
        if(verified){network.setPhase('discovery-only');job.password='';await write({state:'verified',authenticationVerified:true,failureCode:null});}
        return {ok:true,authenticationVerified:verified,...(!verified?{loginOutcomeUnknown:true,doNotResubmit:true}:{})};
      }
      if(ticket&&(ticket.preauth_lifecycle!==network.preauthLifecycle||ticket.deadline_ms>job.deadline))throw new Error('invalid-command');
      const startupAbort=new AbortController();
      const snapshot=Object.freeze({policy:network,phase:network.phase,generation:network.generation,
        deadline:Math.min(job.deadline,Date.now()+45000,ticket?.deadline_ms??Infinity),signal:startupAbort.signal,
        preauth_lifecycle:network.preauthLifecycle,resume_id:ticket?.resume_id,
        binding_digest:ticket?.binding_digest,document_id:randomUUID().replaceAll('-','')});
      const startupTimer=setTimeout(()=>startupAbort.abort(),Math.max(0,snapshot.deadline-Date.now()));
      startupContext=snapshot;
      network.startupState.open(snapshot);
      network.startupState._event('document-opening');
      let committed=false;
      const documentCommitted=frame=>{
        if(!committed&&frame===page.mainFrame()&&startupContext===snapshot){
          committed=true;network.startupState._event('document-committed');
        }
      };
      page.on('framenavigated',documentCommitted);
      try {
        await write({state:'opening',failureCode:null});
        try {await loadConfiguredDocument(page,cfg,{deadline:snapshot.deadline});}
        catch {check();await write({state:'needs-user-check',failureCode:'authorization-contract-required'});return {ok:true,authenticationVerified:false,contractRequired:true};}
        const secret=page.locator(cfg.password_selector);
        if(state.loginSubmitted&&cfg.success_selector&&!await secret.isVisible()&&await page.locator(cfg.success_selector).isVisible()){
          network.setPhase('discovery-only');job.password='';
          await write({state:'verified',authenticationVerified:true,failureCode:null});
          return {ok:true,authenticationVerified:true};
        }
        let ready=false;
        const readinessDeadline=Math.min(snapshot.deadline,Date.now()+(network.startupState.required.size?45000:6000));
        while(Date.now()<readinessDeadline&&!startupAbort.signal.aborted){
          check();
          if(network.startupState.status().blocked)break;
          const visible=await Promise.all(['username_selector','password_selector','submit_selector'].map(name=>page.locator(cfg[name]).isVisible()));
          if(committed&&visible.every(Boolean)&&network.startupState.canInsertCredentials()){ready=true;break;}
          await new Promise(resolve=>setTimeout(resolve,20));
        }
        if(!ready){check();await write({state:'needs-user-check',failureCode:'authorization-contract-required'});return {ok:true,authenticationVerified:false,contractRequired:true};}
        if(job.mode==='probe'){await write({state:'ready'});return {ok:true,authenticationVerified:false};}
        if(state.loginSubmitted&&network.authenticationForwarded>0){
          await write({state:'needs-user-check',failureCode:null});
          return {ok:true,authenticationVerified:false,loginOutcomeUnknown:true,doNotResubmit:true};
        }
        if(successVisibleBefore===null)successVisibleBefore=cfg.success_selector?await page.locator(cfg.success_selector).isVisible():false;
        // A seal invalidates all pre-credential checks without extending this resume.
        network.setPhase('login-once');
        const sealedContext=Object.freeze({...snapshot,phase:network.phase,generation:network.generation});
        network.startupState.updateContext(sealedContext);startupContext=sealedContext;
        network.startupState.armCredentials();
        await submitLogin(page,cfg,job.username,job.password,check);
        await write({state:'submitted',loginSubmitted:true});
        try {await secret.waitFor({state:'hidden',timeout:3000});}catch{}
        check();
        const verified=!!(cfg.success_selector&&!successVisibleBefore&&!await secret.isVisible()&&
          await page.locator(cfg.success_selector).isVisible()&&sameOrigin(page.url(),cfg.origin));
        if(verified){network.startupState._event('authentication-verified');network.setPhase('discovery-only');job.password='';}
        if(await secret.isVisible())await secret.fill('');
        await write({state:verified?'verified':'needs-user-check',authenticationVerified:verified,
          failureCode:!verified&&network.list().length?'authorization-contract-required':null});
        return {ok:true,authenticationVerified:verified,contractRequired:!verified&&network.list().length>0};
      } finally {
        page.off('framenavigated',documentCommitted);
        if(startupContext?.document_id===snapshot.document_id){
          network.startupState._event('resume-ended');network.startupState.end(startupContext);startupContext=null;
        }
        clearTimeout(startupTimer);startupAbort.abort();
      }
    };
    const runtime=new WorkerRuntime({control,registry,task,network,resume});
    let commandSequence=resume();
    if(job.mode==='probe'){await commandSequence;return;}
    let queued=0;
    const commands=async()=>{
      for await(const command of frames){
        if(authority.handle(command))continue;
        if(++queued>4)throw new Error('invalid-command');
        commandSequence=commandSequence.then(async()=>{
          let result;
          try {result=await runtime.dispatch(command);}
          catch(error){
            const allowed=new Set(['invalid-command','authentication-required','origin-blocked','session-unavailable',
              'approval-required','request-invalid','request-too-large','component-stale','component-ambiguous','scope-mismatch',
              'target-state-changed','request-contract-unavailable','capability-unsupported','precondition-unenforceable',
              'grant-revoked','target-selection-unavailable','response-too-large','outcome-unknown','authentication-already-verified']);
            result={ok:false,failureCode:allowed.has(error?.message)?error.message:'control-failed'};
          }
          const id=typeof command?.id==='string'&&/^[a-f0-9]{32}$/.test(command.id)?command.id:null;
          emit({id,result});queued--;
        });
      }
      await commandSequence;
    };
    await Promise.race([commands(),new Promise(resolve=>{if(page.isClosed())resolve();else page.once('close',resolve);})]);
    check();
    await write({state:'closed'});
  } catch (error) {
    const allowed = new Set(['invalid-job','origin-blocked','redirect-blocked','tls-or-navigation-failed','certificate-pin-mismatch','certificate-validity-failed','request-too-large','response-too-large','form-unavailable','network-guard-failed','unsupported-transport']);
    const code = failure || (allowed.has(error?.message)?error.message:'login-flow-failed');
    if (page && job?.config) await page.locator(job.config.password_selector).fill('').catch(()=>{});
    await write({state:'failed',failureCode:code}).catch(()=>{});
  } finally {
    if(job)job.password=''; clearTimeout(timer);clearInterval(stopTimer);
    authority?.dispose();network?.fence();await registry?.dispose();
    cancellation?.abort();
    await control?.dispose();
    await context?.close().catch(()=>{});await browser?.close().catch(()=>{});
    deny?.close();
    process.stdin.destroy();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  // Never print browser errors: call logs can include fill/keypress argument values.
  main().catch(()=>{process.exitCode=1;});
}
