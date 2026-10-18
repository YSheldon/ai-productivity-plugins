import {taskContracts,setupContracts} from './web_task_contracts.mjs';

export class WorkerRuntime {
  constructor({control,registry,task,network,resume}){
    Object.assign(this,{control,registry,task,network,resume});
  }

  async dispatch(command){
    if(!command||typeof command!=='object'||Array.isArray(command)||
      Object.keys(command).some(key=>!['id','operation','arguments'].includes(key))||
      !command.arguments||typeof command.arguments!=='object'||Array.isArray(command.arguments))throw new Error('invalid-command');
    const args=command.arguments;
    if(['observe','navigate','read-result'].includes(command.operation))throw new Error('approval-required');
    if(command.operation==='network-status'&&Object.keys(args).length===0)return {ok:true,descriptors:this.network.list(),phase:this.network.phase};
    if(command.operation==='resolve-setup'&&Object.keys(args).join(',')==='setup')return setupContracts(args.setup,this.network);
    if(command.operation==='resume-login'&&Object.keys(args).length===0)return this.resume();
    await this.control.admit();
    if(command.operation==='components'&&Object.keys(args).length===0)return this.registry.scan();
    if(command.operation==='resolve-items'&&Object.keys(args).join(',')==='items'){
      const scopes=await this.task.resolveItems(args.items);
      return taskContracts(scopes,args.items,this.network,this.task.drafts);
    }
    if(command.operation==='prepare-action')return this.task.prepareAction(args);
    if(command.operation==='reconcile')return this.task.reconcile(args);
    if(command.operation==='execute'){
      if(this.network.activeAttempt)throw new Error('operation-in-progress');
      this.network.setPhase('grant-active');
      try {
        const result=await this.task.execute(args);
        // Observe requests created by synchronous event handlers before disarming.
        await new Promise(resolve=>setTimeout(resolve,0));
        const forwarded=await this.network.drain(args.attempt_id);
        return {...result,forwarded};
      } finally {
        this.network.activeAttempt=null;
        if(this.network.phase!=='fenced')this.network.setPhase('discovery-only');
      }
    }
    throw new Error('invalid-command');
  }
}
