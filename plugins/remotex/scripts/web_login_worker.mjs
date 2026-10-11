import fs from 'node:fs/promises';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import net from 'node:net';
import dgram from 'node:dgram';

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

export async function guardRoute(route, origin, failed) {
  if (!sameOrigin(route.request().url(), origin)) { failed('origin-blocked'); await route.abort(); return; }
  try {
    // Fulfil only a non-redirect response: automatic redirect replay could send a POST elsewhere.
    const response = await route.fetch({maxRedirects:0, timeout:20000});
    if (response.status() >= 300 && response.status() < 400 && response.status() !== 304) {
      failed('redirect-blocked'); await route.abort(); return;
    }
    await route.fulfill({response});
  } catch { failed('tls-or-navigation-failed'); await route.abort().catch(()=>{}); }
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

async function readJob() {
  const chunks = []; let bytes = 0;
  for await (const chunk of process.stdin) { bytes += chunk.length; if (bytes > 65536) throw new Error('invalid-job'); chunks.push(chunk); }
  const raw = Buffer.concat(chunks);
  try { return JSON.parse(raw.toString('utf8')); } finally { raw.fill(0); for (const c of chunks) c.fill(0); }
}

async function main() {
  const directory = process.argv[2], modulePath = process.argv[3];
  let browser, deny, context, page, timer, stopTimer, job, failure = null, state = {state:'starting',loginSubmitted:false,authenticationVerified:false,failureCode:null};
  let writeSequence = Promise.resolve();
  const write = patch => {
    state = {...state,...patch,updatedAt:new Date().toISOString()};
    const body = JSON.stringify(state);
    writeSequence = writeSequence.then(async()=>{const temporary=path.join(directory,'state.tmp');await fs.writeFile(temporary,body,{mode:0o600});await fs.rename(temporary,path.join(directory,'state.json'));});
    return writeSequence;
  };
  const check = () => { if (failure) throw new Error(failure); };
  try {
    job = await readJob(); const cfg = validateJob(job);
    const require = createRequire(import.meta.url);
    const pw = require(modulePath);
    ({browser,deny}=await launchEdge(pw));
    await verifyNetworkGuard(browser);
    context = await browser.newContext({ignoreHTTPSErrors:false,serviceWorkers:'block',acceptDownloads:false});
    await context.setOffline(true);
    await context.route('**/*', route=>guardRoute(route,cfg.origin,code=>{failure=code;}));
    await context.routeWebSocket('**/*', socket=>{
      failure='unsupported-transport';socket.close();
    });
    page = await context.newPage();
    context.on('page', extra=>{if(extra!==page) void extra.close();});
    const close = () => context.close().catch(()=>{});
    timer = setTimeout(close, Math.max(1,job.deadline-Date.now()));
    stopTimer = setInterval(async()=>{try{await fs.access(path.join(directory,'close.request'));void close();}catch{}},500);
    await write({state:'opening'});
    await page.goto(cfg.url,{waitUntil:'domcontentloaded',timeout:30000});
    for (const name of ['username_selector','password_selector','submit_selector']) await page.locator(cfg[name]).waitFor({state:'visible',timeout:10000});
    check();
    if (job.mode === 'probe') {await write({state:'ready'});return;}
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
    await new Promise(resolve=>{if(page.isClosed())resolve();else page.once('close',resolve);});
    await write({state:'closed'});
  } catch (error) {
    const allowed = new Set(['invalid-job','origin-blocked','redirect-blocked','tls-or-navigation-failed','form-unavailable','network-guard-failed','unsupported-transport']);
    const code = failure || (allowed.has(error?.message)?error.message:'login-flow-failed');
    if (page && job?.config) await page.locator(job.config.password_selector).fill('').catch(()=>{});
    await write({state:'failed',failureCode:code}).catch(()=>{});
  } finally {
    if(job)job.password=''; clearTimeout(timer);clearInterval(stopTimer);
    await context?.close().catch(()=>{});await browser?.close().catch(()=>{});
    deny?.close();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  // Never print browser errors: call logs can include fill/keypress argument values.
  main().catch(()=>{process.exitCode=1;});
}
