import fs from 'node:fs/promises';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import net from 'node:net';
import dgram from 'node:dgram';
import {pinnedResponse} from './web_tls.mjs';
import {SessionControl, dispatch, projectResponse, readFrames} from './web_control.mjs';

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

export async function guardRoute(route, origin, failed, certificateSha256, signal, observed) {
  if (!sameOrigin(route.request().url(), origin)) { failed('origin-blocked'); await route.abort(); return; }
  try {
    if (certificateSha256 !== undefined) {
      const response = await pinnedResponse(route.request(), origin, certificateSha256, signal);
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
    const allowed = new Set(['invalid-job','origin-blocked','certificate-pin-mismatch','certificate-validity-failed','request-too-large','response-too-large']);
    failed(allowed.has(error?.message)?error.message:'tls-or-navigation-failed');
    await route.abort().catch(()=>{});
  }
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
  if (!Number.isFinite(job.deadline) || job.deadline <= Date.now() || job.deadline > Date.now()+3600000) throw new Error('invalid-job');
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
  let browser, deny, context, page, timer, stopTimer, job, cancellation, control, failure = null, state = {state:'starting',loginSubmitted:false,authenticationVerified:false,failureCode:null};
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
    const require = createRequire(import.meta.url);
    const pw = require(modulePath);
    ({browser,deny}=await launchEdge(pw));
    await verifyNetworkGuard(browser);
    context = await createWebContext(browser);
    cancellation = browserCancellation(context);
    browser.once('disconnected',()=>cancellation.abort());
    await context.setOffline(true);
    const rejected=code=>{failure=code;cancellation.abort();void context.close().catch(()=>{});};
    await context.route('**/*', route=>guardRoute(route,cfg.origin,rejected,cfg.certificate_sha256,cancellation.signal,
      summary=>{if(state.authenticationVerified)control?.record(summary);}));
    await context.routeWebSocket('**/*', socket=>{
      rejected('unsupported-transport');socket.close();
    });
    page = await context.newPage();
    page.once('close',()=>cancellation.abort());
    context.on('page', extra=>{if(extra!==page) void extra.close();});
    const close = () => {cancellation.abort();return context.close().catch(()=>{});};
    timer = setTimeout(close, Math.max(1,job.deadline-Date.now()));
    stopTimer = setInterval(async()=>{try{await fs.access(path.join(directory,'close.request'));void close();}catch{}},500);
    await write({state:'opening'});
    await page.goto(cfg.url,{waitUntil:'domcontentloaded',timeout:30000});
    for (const name of ['username_selector','password_selector','submit_selector']) await page.locator(cfg[name]).waitFor({state:'visible',timeout:10000});
    check();
    if (job.mode === 'probe') {await write({state:'ready'});return;}
    control=new SessionControl(page,cfg,{deadline:job.deadline,secret:job.password,check});
    const successVisibleBefore = cfg.success_selector ? await page.locator(cfg.success_selector).isVisible() : false;
    await submitLogin(page,cfg,job.username,job.password,check);
    job.password='';
    await write({state:'submitted',loginSubmitted:true});
    const secret = page.locator(cfg.password_selector);
    try { await secret.waitFor({state:'hidden',timeout:20000}); } catch {}
    check();
    let verified = false;
    if (cfg.success_selector && !successVisibleBefore && !await secret.isVisible()) {
      verified = await page.locator(cfg.success_selector).isVisible() && sameOrigin(page.url(),cfg.origin);
    }
    if (await secret.isVisible()) await secret.fill('');
    await write({state:verified?'verified':'needs-user-check',authenticationVerified:verified});
    const commands=async()=>{
      for await(const command of frames){
        let result;
        try {
          if(!state.authenticationVerified)throw new Error('authentication-required');
          result=await dispatch(control,command);
        } catch(error) {
          const allowed=new Set(['invalid-command','authentication-required','origin-blocked','stale-observation','session-unavailable']);
          const code=allowed.has(error?.message)?error.message:'control-failed';
          if(code==='authentication-required')await write({state:'needs-user-check',authenticationVerified:false});
          result={ok:false,failureCode:code};
        }
        const id=typeof command?.id==='string' && /^[a-f0-9]{32}$/.test(command.id)?command.id:null;
        await new Promise((resolve,reject)=>process.stdout.write(JSON.stringify({id,result})+'\n',error=>error?reject(error):resolve()));
      }
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
