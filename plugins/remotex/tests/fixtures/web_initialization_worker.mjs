import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import readline from 'node:readline';
import {execFileSync} from 'node:child_process';
import {X509Certificate} from 'node:crypto';

const directory=await fs.realpath(process.argv[2]),root=await fs.realpath(os.tmpdir());
const relative=path.relative(root,directory);
if(!relative||relative.startsWith('..')||path.isAbsolute(relative)||(await fs.readdir(directory)).length)
  throw new Error('Use an empty fixture directory under the local temporary root');
const keyPath=path.join(directory,'key.pem'),certPath=path.join(directory,'cert.pem');
const configPath=path.join(directory,'openssl.cnf');
await fs.writeFile(configPath,'[req]\ndistinguished_name=dn\n[dn]\n');
execFileSync(process.env.REMOTEX_TEST_OPENSSL||'openssl',['req','-x509','-newkey','rsa:2048','-nodes',
  '-keyout',keyPath,'-out',certPath,'-days','2','-subj','/CN=remotex-fixture.invalid','-config',configPath],
  {stdio:['ignore','pipe','pipe'],timeout:60000});
const key=await fs.readFile(keyPath),cert=await fs.readFile(certPath);
const image=await fs.readFile(new URL('../../assets/remotex.svg',import.meta.url));
const secret='synthetic-prelogin-only-canary';
const mode=process.argv[3],holdLogin=mode==='hold-login',pendingLogins=[],pendingInitialization=[];
const replaceComplete=mode==='replace-complete',replacePending=mode==='replace-pending';
const stats={requests:0,roots:0,assets:0,images:0,initialization:0,logins:0,writes:0,
  credentialOutsideLogin:false,invalidPreauthCookie:false,wrongLogin:false,replacements:0};
const markup='<input id="user"><input id="pass"><button id="login">Login</button><main id="main" hidden><h1>Fixture Center</h1><button id="write">Write</button></main>';
const page=`<script>
  window.assetCount=0;window.imagesReady=0;window.indexReady=false;window.initReady=false;
  window.tryMount=()=>{if(!window.initReady||!window.indexReady||window.imagesReady!==2)return;
    document.body.innerHTML=${JSON.stringify(markup)};
    document.getElementById('login').onclick=async()=>{
      const response=await fetch('/login',{method:'POST',headers:{'content-type':'application/json'},
        body:JSON.stringify({password:document.getElementById('pass').value})});
      if(!response.ok)return;document.getElementById('pass').hidden=true;
      document.getElementById('main').hidden=false;
      setTimeout(()=>fetch('/write',{method:'POST',headers:{'content-type':'application/json'},body:'{"cmd":"never-approved"}'}).catch(()=>{}),50);
    };
  };
  window.startInitialization=()=>{
    const script=document.createElement('script');script.src='/script/index.js';document.head.append(script);
    for(const name of ['front','back']){const img=new Image();img.onload=()=>{window.imagesReady++;window.tryMount();};img.src='/img/'+name+'.svg';}
    const calls=['production','db','guid'].map(cmd=>fetch('/init/'+cmd,{method:'POST',
      headers:{'content-type':'application/json'},body:JSON.stringify({cmd})}).then(r=>r.json()));
    if(${replacePending})calls[0].then(()=>location.reload()).catch(()=>{});
    Promise.all(calls).then(values=>{if(${replaceComplete}){location.reload();return;}
      window.initReady=values.every(v=>v.ready===true);window.tryMount();}).catch(()=>{});
  };
</script>`+Array.from({length:47},(_,i)=>`<script defer src="/assets/${i}.js"></script>`).join('');
const server=https.createServer({key,cert},async(req,res)=>{
  stats.requests++;const chunks=[];for await(const chunk of req)chunks.push(chunk);
  const body=Buffer.concat(chunks).toString();
  if(req.url!=='/login'&&body.includes(secret))stats.credentialOutsideLogin=true;
  const send=(type,value,headers={})=>{res.writeHead(200,{'content-type':type,'cache-control':'no-store',...headers});res.end(value);};
  if(req.url==='/'){
    stats.roots++;
    if((replaceComplete||replacePending)&&stats.initialization>0){stats.replacements++;send('text/html',markup);return;}
    send('text/html',page,{'set-cookie':'fixture_preauth=one; Secure; HttpOnly; Path=/'});return;
  }
  if(/^\/assets\/[0-9]+\.js$/.test(req.url)){
    stats.assets++;send('application/javascript','window.assetCount++;if(window.assetCount===47)window.startInitialization();');return;
  }
  if(req.url==='/script/index.js'){send('application/javascript','window.indexReady=true;window.tryMount();');return;}
  if(req.url.startsWith('/img/')){stats.images++;send('image/svg+xml',image);return;}
  if(req.url.startsWith('/init/')){
    stats.initialization++;if(!(req.headers.cookie||'').includes('fixture_preauth=one'))stats.invalidPreauthCookie=true;
    const reply=()=>send('application/json','{"ready":true,"guid":"fixture-private-guid"}');
    if(replacePending){
      pendingInitialization.push({production:req.url==='/init/production',reply});
      if(pendingInitialization.length===3)pendingInitialization.find(row=>row.production).reply();
      return;
    }
    reply();return;
  }
  if(req.url==='/login'){
    stats.logins++;stats.wrongLogin=JSON.parse(body).password!==secret;
    if(holdLogin){pendingLogins.push(()=>send('application/json','{"ok":true}',{'set-cookie':'fixture_auth=one; Secure; HttpOnly; Path=/'}));return;}
    send('application/json','{"ok":true}',{'set-cookie':'fixture_auth=one; Secure; HttpOnly; Path=/'});return;
  }
  if(req.url==='/write'){stats.writes++;send('application/json','{"ok":true}');return;}
  res.writeHead(404);res.end();
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
process.stdout.write(JSON.stringify({origin:`https://127.0.0.1:${server.address().port}`,
  certificate_sha256:new X509Certificate(cert).fingerprint256.replaceAll(':','').toLowerCase()})+'\n');
try{
  for await(const line of readline.createInterface({input:process.stdin})){
    const command=JSON.parse(line);
    if(command.operation==='stop')break;
    if(command.operation==='release-initialization'){
      const released=pendingInitialization.filter(row=>!row.production);pendingInitialization.length=0;
      for(const row of released)row.reply();
      process.stdout.write(JSON.stringify({id:command.id,result:{released:released.length}})+'\n');continue;
    }
    if(command.operation==='release-login'){
      const released=pendingLogins.splice(0);for(const reply of released)reply();
      process.stdout.write(JSON.stringify({id:command.id,result:{released:released.length}})+'\n');continue;
    }
    if(command.operation!=='stats'||!Number.isInteger(command.id))throw new Error('Invalid fixture command');
    process.stdout.write(JSON.stringify({id:command.id,result:stats})+'\n');
  }
}finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
