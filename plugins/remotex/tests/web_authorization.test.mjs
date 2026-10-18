import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {launchEdge} from '../scripts/web_login_worker.mjs';

let componentModule;
try {componentModule=await import('../scripts/web_components.mjs');} catch(error) {
  if(error.code!=='ERR_MODULE_NOT_FOUND')throw error;
}
let taskModule;
try {taskModule=await import('../scripts/web_task_control.mjs');}catch(error){if(error.code!=='ERR_MODULE_NOT_FOUND')throw error;}

const html=`<input id="pass" type="password" hidden><main id="main">Signed in</main>
<nav id="nav"><button id="terminals" onclick="location.hash='/assets'">Terminals</button><button id="delete" onclick="window.writeCount=(window.writeCount||0)+1;window.selected=Array.from(document.querySelectorAll('tr[data-id] input[type=checkbox]:checked')).map(node=>node.closest('tr').dataset.id)">Delete</button></nav>
<section id="content"><table id="assets"><thead><tr><th>Name</th><th>OS</th><th>Group</th></tr></thead><tbody>
<tr data-id="host-one" data-version="v1"><td>Host One<input type="checkbox"></td><td>Linux<input value="private-input"><span hidden>private-hidden</span></td><td>Old Group</td></tr>
<tr data-id="host-two" hidden><td>private-row</td></tr></tbody></table>
<label for="group">Group</label><input id="group" value="Old Group"><input id="apiToken" value="private-token"></section>`;

async function fixture(run){
  assert.ok(componentModule,'The approved component registry has not been implemented');
  const require=createRequire(import.meta.url);
  const {chromium}=require('../scripts/web-runtime/node_modules/playwright-core');
  const {browser,deny}=await launchEdge({chromium},true);
  try {
    const context=await browser.newContext();await context.setOffline(true);
    await context.route('**/*',route=>route.fulfill({contentType:'text/html',body:html}));
    const page=await context.newPage();await page.goto('https://console.example/#/home');
    const registry=new componentModule.Components(page,{admit:async()=>{},redact:value=>value});
    try {await run({page,registry});} finally {await registry.dispose();}
  } finally {await browser.close();deny.close();}
}

test('discovery finds navigation outside the success marker without exposing field values',async()=>fixture(async({registry})=>{
  const view=await registry.scan();
  assert.ok(view.components.some(x=>x.name==='Terminals'));
  assert.ok(view.components.some(x=>x.kind==='table'));
  assert.ok(!JSON.stringify(view).includes('Old Group'));
  assert.ok(!JSON.stringify(view).includes('private-token'));
  assert.ok(!view.components.some(x=>x.name==='apiToken'));
}));

test('approved table projection contains rendered cells and stable opaque target refs only',async()=>fixture(async({registry})=>{
  const view=await registry.scan();
  const table=view.components.find(x=>x.kind==='table');
  const entry=await registry.resolve(view.observationId,table.ref);
  const result=await registry.project(entry,'web.read_table',{rows:100,columns:30,bytes:98304});
  assert.deepEqual(result.tables,[{headers:['Name','OS','Group'],rows:[['Host One','Linux','Old Group']],truncated:false}]);
  assert.equal(result.target_refs.length,1);
  assert.match(result.target_refs[0],/^[a-f0-9]{32}$/);
  assert.ok(!JSON.stringify(result).includes('private-'));
  assert.equal(registry.targets.get(result.target_refs[0]).identity,'host-one');
}));

test('component identity and fresh references are checked before every mutation',async()=>fixture(async({registry,page})=>{
  const view=await registry.scan();const button=view.components.find(x=>x.name==='Terminals');
  await page.locator('#terminals').evaluate(node=>node.textContent='Different action');
  await assert.rejects(()=>registry.resolve(view.observationId,button.ref),/component-stale/);
  assert.ok(page.url().endsWith('#/home'));
}));

test('a newly duplicated control makes a previously unique reference ambiguous',async()=>fixture(async({registry,page})=>{
  const view=await registry.scan(),button=view.components.find(value=>value.id==='terminals');
  await page.locator('#terminals').evaluate(node=>node.after(node.cloneNode(true)));
  await assert.rejects(()=>registry.resolve(view.observationId,button.ref),/component-ambiguous/);
}));

test('inspection reads only the expressly selected non-secret field',async()=>fixture(async({registry})=>{
  const view=await registry.scan();const field=view.components.find(x=>x.kind==='field'&&x.id==='group');
  const entry=await registry.resolve(view.observationId,field.ref);
  const result=await registry.project(entry,'web.inspect_action',{rows:1,columns:1,bytes:98304});
  assert.equal(result.value,'Old Group');
  await assert.rejects(()=>registry.perform(entry,'fill','New Group'),/approval-required/);
}));

test('typed approved navigation follows the exact observed menu control',async()=>fixture(async({registry,page})=>{
  const view=await registry.scan();const button=view.components.find(x=>x.name==='Terminals');
  const entry=await registry.resolve(view.observationId,button.ref);
  await registry.perform(entry,'click',null,async()=>true);
  assert.ok(page.url().endsWith('#/assets'));
}));

test('task resolution grounds a scope but cannot execute it without broker authority',async()=>fixture(async({registry})=>{
  assert.ok(taskModule,'The typed task control has not been implemented');
  const task=new taskModule.TaskControl({registry,authorize:async()=>false,readResult:async()=>({results:[]}),network:null});
  const view=await registry.scan(),table=view.components.find(x=>x.kind==='table');
  const rows=await task.resolveItems([{item_id:'read',capability:'web.read_table',observation_id:view.observationId,component_ref:table.ref,max_uses:1,depends_on:[]}]);
  assert.equal(rows[0].capability,'web.read_table');assert.match(rows[0].fingerprint,/^[a-f0-9]{64}$/);
  await assert.rejects(()=>task.execute({attempt_id:'a'.repeat(32),scope:rows[0],observation_id:view.observationId,component_ref:table.ref}),/approval-required/);
  await assert.rejects(()=>task.resolveItems([{item_id:'raw',capability:'web.read_table',observation_id:view.observationId,component_ref:table.ref,url:'https://evil.example/'}]),/request-invalid/);
}));

test('business preparation uses authorized read receipts and has no page side effect',async()=>fixture(async({registry,page})=>{
  assert.ok(taskModule);
  const task=new taskModule.TaskControl({registry,authorize:async()=>true,readResult:async()=>({results:[]}),network:null});
  const view=await registry.scan(),table=view.components.find(x=>x.kind==='table'),field=view.components.find(x=>x.id==='group'),button=view.components.find(x=>x.id==='delete');
  const declarations=[{item_id:'read',capability:'web.read_table',observation_id:view.observationId,component_ref:table.ref,max_uses:1,depends_on:[]},
    {item_id:'inspect',capability:'web.inspect_action',observation_id:view.observationId,component_ref:field.ref,max_uses:1,depends_on:[]}];
  const scopes=await task.resolveItems(declarations);
  const tableRead=await task.execute({attempt_id:'a'.repeat(32),scope:scopes[0],observation_id:view.observationId,component_ref:table.ref});
  const fieldRead=await task.execute({attempt_id:'b'.repeat(32),scope:scopes[1],observation_id:view.observationId,component_ref:field.ref});
  const draft=await task.prepareAction({observation_id:view.observationId,component_ref:button.ref,
    target_refs:tableRead.result.target_refs,read_receipts:[tableRead.result.receipt_ref],
    changes:[{component_ref:field.ref,receipt_ref:fieldRead.result.receipt_ref,value:'New Group',action:'fill'}],
    effect:{kind:'delete',name:'Delete selected fixture',risks:['irreversible'],fields:['group'],evidence:[{kind:'source-review',reference:'Synthetic fixture handler'}]},network_refs:[]});
  assert.match(draft.action_draft_ref,/^[a-f0-9]{32}$/);
  assert.equal(draft.preview.approval_class,'action-time');
  assert.equal(draft.preview.targets[0].identity,'host-one');
  assert.equal(draft.preview.changes[0].before,'Old Group');
  assert.equal(draft.preview.changes[0].after,'New Group');
  assert.equal(await page.locator('#group').inputValue(),'Old Group');
  assert.equal(draft.configurationStored,false);
}));

async function preparedBusiness(registry){
  const task=new taskModule.TaskControl({registry,authorize:async()=>true,readResult:async()=>({results:[]}),network:null});
  const view=await registry.scan(),table=view.components.find(x=>x.kind==='table'),field=view.components.find(x=>x.id==='group'),button=view.components.find(x=>x.id==='delete');
  const scopes=await task.resolveItems([
    {item_id:'read',capability:'web.read_table',observation_id:view.observationId,component_ref:table.ref},
    {item_id:'inspect',capability:'web.inspect_action',observation_id:view.observationId,component_ref:field.ref}]);
  const rows=await task.execute({attempt_id:'a'.repeat(32),scope:scopes[0],observation_id:view.observationId,component_ref:table.ref});
  const fields=await task.execute({attempt_id:'b'.repeat(32),scope:scopes[1],observation_id:view.observationId,component_ref:field.ref});
  const draft=await task.prepareAction({observation_id:view.observationId,component_ref:button.ref,
    target_refs:rows.result.target_refs,read_receipts:[rows.result.receipt_ref],
    target_state:{group:{header:'Group',after:'New Group'}},
    changes:[{component_ref:field.ref,receipt_ref:fields.result.receipt_ref,value:'New Group',action:'fill'}],
    effect:{kind:'update',name:'Update synthetic group',risks:[],fields:['group'],evidence:[{kind:'source-review',reference:'Synthetic action fixture'}]},network_refs:[]});
  const [scope]=await task.resolveItems([{item_id:'write',capability:'web.business_action',observation_id:view.observationId,
    component_ref:button.ref,action_draft_ref:draft.action_draft_ref}]);
  return {task,view,button,scope,draft,table};
}

test('approved business workflow selects exact targets and writes only approved values',async()=>fixture(async({registry,page})=>{
  const {task,view,button,scope}=await preparedBusiness(registry);
  const result=await task.execute({attempt_id:'c'.repeat(32),scope,observation_id:view.observationId,component_ref:button.ref});
  assert.equal(await page.locator('#group').inputValue(),'New Group');
  assert.equal(await page.evaluate(()=>window.writeCount),1);
  assert.deepEqual(await page.evaluate(()=>window.selected),['host-one']);
  assert.equal(result.result.businessSuccessVerified,false);
}));

test('changed before-state stops a business workflow before selecting or submitting',async()=>fixture(async({registry,page})=>{
  const {task,view,button,scope}=await preparedBusiness(registry);
  await page.locator('#group').fill('Someone Else Changed It');
  await assert.rejects(()=>task.execute({attempt_id:'c'.repeat(32),scope,observation_id:view.observationId,component_ref:button.ref}),/target-state-changed/);
  assert.equal(await page.evaluate(()=>window.writeCount),undefined);
  assert.equal(await page.locator('tr[data-id="host-one"] input[type=checkbox]').isChecked(),false);
}));

test('write preview uses actual resource before-state and checks it before clicking',async()=>fixture(async({registry,page})=>{
  const {task,view,button,scope,draft}=await preparedBusiness(registry);
  assert.deepEqual(draft.preview.targets[0].before,{group:'Old Group'});
  assert.deepEqual(draft.preview.targets[0].after,{group:'New Group'});
  await page.locator('tr[data-id="host-one"] td').nth(2).evaluate(node=>node.textContent='Changed by another operator');
  await assert.rejects(()=>task.execute({attempt_id:'c'.repeat(32),scope,observation_id:view.observationId,component_ref:button.ref}),/target-state-changed/);
  assert.equal(await page.evaluate(()=>window.writeCount),undefined);
}));

test('reconciliation needs a fresh approved target readback, not a click or claimed success',async()=>fixture(async({registry,page})=>{
  const {task,view,button,scope,table}=await preparedBusiness(registry);
  const attempt='c'.repeat(32);
  await task.execute({attempt_id:attempt,scope,observation_id:view.observationId,component_ref:button.ref});
  assert.equal(typeof task.reconcile,'function');
  await assert.rejects(()=>task.reconcile({attempt_id:attempt,scope,read_receipts:[]}),/readback-required/);
  await page.locator('tr[data-id="host-one"] td').nth(2).evaluate(node=>node.textContent='New Group');
  const [readScope]=await task.resolveItems([{item_id:'verify',capability:'web.read_table',observation_id:view.observationId,component_ref:table.ref}]);
  const read=await task.execute({attempt_id:'d'.repeat(32),scope:readScope,observation_id:view.observationId,component_ref:table.ref});
  const proof=await task.reconcile({attempt_id:attempt,scope,read_receipts:[read.result.receipt_ref]});
  assert.equal(proof.state,'verified');
  assert.deepEqual(proof.targets,[{identity:'host-one',state:'verified'}]);
}));
