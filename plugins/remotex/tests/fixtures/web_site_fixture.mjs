import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import readline from 'node:readline';
import {execFileSync} from 'node:child_process';
import {X509Certificate} from 'node:crypto';

const directory=await fs.realpath(process.argv[2]),relative=path.relative(await fs.realpath(os.tmpdir()),directory);
if(!relative||relative.startsWith('..')||path.isAbsolute(relative)||(await fs.readdir(directory)).length)throw new Error('Use an empty owned temporary directory');
const keyPath=path.join(directory,'key.pem'),certPath=path.join(directory,'cert.pem'),cnf=path.join(directory,'openssl.cnf');
await fs.writeFile(cnf,'[req]\ndistinguished_name=dn\n[dn]\n');
execFileSync(process.env.REMOTEX_TEST_OPENSSL||'openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',keyPath,
  '-out',certPath,'-days','2','-subj','/CN=remotex-site-fixture.invalid','-config',cnf],{stdio:'pipe',timeout:60000});
const key=await fs.readFile(keyPath),cert=await fs.readFile(certPath);
const secret='synthetic-site-password-only';
const stats={initialization:0,logins:0,writes:0,credentialOutsideLogin:false,wrongLogin:false};
const server=https.createServer({key,cert},async(req,res)=>{
  const chunks=[];for await(const chunk of req)chunks.push(chunk);const body=Buffer.concat(chunks).toString();
  if(req.url!=='/login'&&body.includes(secret))stats.credentialOutsideLogin=true;
  const send=(type,text,headers={})=>{res.writeHead(200,{'content-type':type,'cache-control':'no-store',...headers});res.end(text);};
  if(req.url==='/'){
    send('text/html',`<!doctype html><script>
      fetch('/initialize',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({userSession:'PUBLIC_FIXED_VALUE'})})
      .then(r=>r.json()).then(data=>{if(data.ready)document.body.innerHTML='<input id="user"><input id="pass"><button id="login">Login</button><main id="main" hidden><h1>Synthetic Site Center</h1><form><label for="group">Group</label><input id="group" value="old"><button id="save" type="button">Save</button><p id="result">Ready</p></form></main>';
        document.getElementById('login').onclick=async()=>{
          const response=await fetch('/login',{method:'POST',body:JSON.stringify({password:document.getElementById('pass').value})});
          if(response.ok){document.getElementById('pass').hidden=true;document.getElementById('main').hidden=false;}
        };
        document.getElementById('save').onclick=async()=>{const response=await fetch('/save',{method:'POST',body:JSON.stringify({group:document.getElementById('group').value})});
          if(response.ok)document.getElementById('result').textContent='Saved '+document.getElementById('group').value;};
      });</script>`);return;
  }
  if(req.url==='/initialize'){stats.initialization++;send('application/json','{"ready":true}',{'set-cookie':'preauth=public; Secure; HttpOnly; Path=/'});return;}
  if(req.url==='/login'){stats.logins++;stats.wrongLogin=JSON.parse(body).password!==secret;send('application/json','{"ok":true}',{'set-cookie':'session=synthetic; Secure; HttpOnly; Path=/'});return;}
  if(req.url==='/save'){stats.writes++;send('application/json','{"ok":true}');return;}
  res.writeHead(404);res.end();
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
process.stdout.write(JSON.stringify({origin:`https://127.0.0.1:${server.address().port}`,
  certificate_sha256:new X509Certificate(cert).fingerprint256.replaceAll(':','').toLowerCase()})+'\n');
try{
  for await(const line of readline.createInterface({input:process.stdin})){
    const command=JSON.parse(line);if(command.operation==='stop')break;
    if(command.operation!=='stats')throw new Error('Invalid fixture command');
    process.stdout.write(JSON.stringify({id:command.id,result:stats})+'\n');
  }
}finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
