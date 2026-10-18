import readline from 'node:readline';
import {WorkerAuthority} from '../../scripts/web_authorization_ipc.mjs';
import {NetworkPolicy} from '../../scripts/web_network_authorization.mjs';

// Inert transport fixture: no browser, credentials, remote connection or real authority.
const input=readline.createInterface({input:process.stdin});
const emit=frame=>process.stdout.write(JSON.stringify(frame)+'\n');
let authority,batchCount=0;
input.on('line',async line=>{
  const frame=JSON.parse(line);
  if(authority?.handle(frame))return;
  if(frame.operation!=='exercise')throw new Error('unexpected-fixture-command');
  const stopped=new AbortController();
  const policy=new NetworkPolicy({origin:'https://console.example',requestPermit:(request,options)=>
    authority.check({kind:'network',...request},options)});
  const context={policy,phase:'bootstrap',generation:0,deadline:Date.now()+45000,signal:stopped.signal};
  authority=new WorkerAuthority({emit:value=>{if(value.event==='authorization-check-batch')batchCount++;emit(value);},
    onRevoke:()=>policy.fence(),startup:()=>context});
  const request=(path,resourceType,method='GET')=>({url:()=>policy.origin+path,method:()=>method,
    postData:()=>null,headers:()=>({}),resourceType:()=>resourceType,failure:()=>null});
  try{
    const root=await policy.authorize(request('/','document'));
    const requests=[...Array.from({length:48},(_,n)=>request(`/assets/${n}.js`,'script')),
      request('/one.png','image'),request('/two.png','image'),request('/unapproved','xhr','POST')];
    const allowed=[root,...await Promise.all(requests.map(value=>policy.authorize(value)))];
    emit({id:frame.id,result:{ok:true,allowed,batchCount}});
  }finally{stopped.abort();authority.dispose();input.close();}
});
