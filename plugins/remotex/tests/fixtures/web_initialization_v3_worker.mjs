import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import readline from 'node:readline';
import {createRequire} from 'node:module';
import {execFileSync} from 'node:child_process';
import {X509Certificate} from 'node:crypto';
import {launchEdge,createWebContext} from '../../scripts/web_login_worker.mjs';

const directory=await fs.realpath(process.argv[2]),root=await fs.realpath(os.tmpdir());
const relative=path.relative(root,directory),mode=process.argv[3];
if(!relative||relative.startsWith('..')||path.isAbsolute(relative)||(await fs.readdir(directory)).length)
  throw new Error('Use an empty synthetic directory under the local temporary root');
const keyPath=path.join(directory,'key.pem'),certPath=path.join(directory,'cert.pem'),configPath=path.join(directory,'openssl.cnf');
await fs.writeFile(configPath,'[req]\ndistinguished_name=dn\n[dn]\n');
execFileSync(process.env.REMOTEX_TEST_OPENSSL||'openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',keyPath,
  '-out',certPath,'-days','2','-subj','/CN=remotex-v3-fixture.invalid','-config',configPath],{stdio:'pipe',timeout:60000});
const key=await fs.readFile(keyPath),cert=await fs.readFile(certPath);
const secret='synthetic-v3-password-only-canary',names=mode==='manual'?['one']:['one','two','three'];
const bodyFor=name=>JSON.stringify({mode:name,[mode==='auth-field'?'token':'userSession']:'PUBLIC_V3_MARKER'});
const stats={requests:0,roots:0,initialization:0,logins:0,writes:0,credentialOutsideLogin:false,wrongLogin:false};
const pendingCookieResponses=[];let releaseCookieResponses=false;
const markup='<input id="user"><input id="pass"><button id="login">Login</button><main id="main" hidden><h1>Synthetic V3 Center</h1></main>';
const server=https.createServer({key,cert},async(req,res)=>{
  stats.requests++;const chunks=[];for await(const chunk of req)chunks.push(chunk);const body=Buffer.concat(chunks).toString();
  if(req.url!=='/login'&&body.includes(secret))stats.credentialOutsideLogin=true;
  const send=(type,value,headers={})=>{res.writeHead(200,{'content-type':type,'cache-control':'no-store',...headers});res.end(value);};
  if(req.url==='/'){
    stats.roots++;
    const bodies=names.map(name=>bodyFor(name)+(mode==='wire-change'&&stats.roots>1?' ':''));
    const page=`<script>
      const calls=${JSON.stringify(names)}.map((name,index)=>fetch('/init/'+name,{method:'POST',
        headers:{'content-type':'application/x-www-form-urlencoded'},body:${JSON.stringify(bodies)}[index]}).then(r=>r.json()));
      Promise.all(calls).then(values=>{
        if(${mode==='new-document'}){location.reload();return;}
        if(!values.every(v=>v.ready===true))return;
        document.body.innerHTML=${JSON.stringify(markup)};
        document.getElementById('login').onclick=async()=>{
          const response=await fetch('/login',{method:'POST',headers:{'content-type':'application/json'},
            body:JSON.stringify({password:document.getElementById('pass').value})});
          if(!response.ok)return;document.getElementById('pass').hidden=true;document.getElementById('main').hidden=false;
          fetch('/write',{method:'POST',body:'never-approved'}).catch(()=>{});
        };
      }).catch(()=>{});
    </script>`;
    send('text/html',page,{'set-cookie':`fixture_preauth=${mode==='cookie-change'&&stats.roots>1?'changed-cookie-only':'prelogin-cookie-only'}; Secure; HttpOnly; Path=/`});return;
  }
  if(names.some(name=>req.url==='/init/'+name)){
    stats.initialization++;
    const reply=()=>send('application/json','{"ready":true,"private_guid":"synthetic-private-guid"}',
      mode==='response-cookie'?{'set-cookie':'forbidden_init=one; Secure; Path=/'}:{});
    if(mode==='response-cookie'&&!releaseCookieResponses)pendingCookieResponses.push(reply);else reply();
    return;
  }
  if(req.url==='/login'){
    stats.logins++;stats.wrongLogin=JSON.parse(body).password!==secret;
    send('application/json','{"ok":true}',{'set-cookie':'fixture_auth=one; Secure; HttpOnly; Path=/'});return;
  }
  if(req.url==='/write'){stats.writes++;send('application/json','{"ok":true}');return;}
  res.writeHead(404);res.end();
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin=`https://127.0.0.1:${server.address().port}`;
// Source references use a separate offline browser's public configuration, never intercepted POST bytes.
const require=createRequire(import.meta.url),pw=require('../../scripts/web-runtime/node_modules/playwright-core');
const {browser,deny}=await launchEdge(pw);
let metadata;
try{
  const context=await createWebContext(browser);await context.setOffline(true);
  await context.route('**/*',route=>route.fulfill({contentType:'text/html',body:'<!doctype html><title>Public browser configuration</title>'}));
  const page=await context.newPage();await page.goto('https://remotex-config-fixture.invalid/');
  metadata=await page.evaluate(()=>({agent:navigator.userAgent,brands:navigator.userAgentData.brands,
    mobile:navigator.userAgentData.mobile,platform:navigator.userAgentData.platform}));
}finally{await browser.close();deny.close();}
const publicHeaders=[{name:'accept',value:'*/*'},{name:'origin',value:origin},{name:'referer',value:origin+'/'},
  {name:'sec-ch-ua',value:metadata.brands.map(row=>`"${row.brand}";v="${row.version}"`).join(', ')},
  {name:'sec-ch-ua-mobile',value:metadata.mobile?'?1':'?0'},{name:'sec-ch-ua-platform',value:JSON.stringify(metadata.platform)},
  {name:'user-agent',value:metadata.agent}];
const references=names.map(name=>({profile_id:'form-json-name-view-v1',target_text:'/init/'+name,
  content_type:'application/x-www-form-urlencoded',body_text:bodyFor(name),public_headers:publicHeaders}));
process.stdout.write(JSON.stringify({origin,certificate_sha256:new X509Certificate(cert).fingerprint256.replaceAll(':','').toLowerCase(),references})+'\n');
try{
  for await(const line of readline.createInterface({input:process.stdin})){
    const command=JSON.parse(line);
    if(command.operation==='stop')break;
    if(command.operation==='release-cookie'&&mode==='response-cookie'&&Number.isInteger(command.id)){
      releaseCookieResponses=true;const replies=pendingCookieResponses.splice(0);replies.forEach(reply=>reply());
      process.stdout.write(JSON.stringify({id:command.id,result:{released:replies.length}})+'\n');continue;
    }
    if(command.operation!=='stats'||!Number.isInteger(command.id))throw new Error('Invalid synthetic command');
    process.stdout.write(JSON.stringify({id:command.id,result:stats})+'\n');
  }
}finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
