import {taskContracts,setupContracts} from './web_task_contracts.mjs';
import {initializationProtocol} from './web_initialization_capabilities.mjs';

export class WorkerRuntime {
  constructor({control,registry,task,network,resume}){
    Object.assign(this,{control,registry,task,network,resume});
  }

  async dispatch(command){
    if(!command||typeof command!=='object'||Array.isArray(command)||
      Object.keys(command).some(key=>!['id','operation','arguments'].includes(key))||
      !command.arguments||typeof command.arguments!=='object'||Array.isArray(command.arguments))throw new Error('invalid-command');
    const args=command.arguments;
    if(this.network.setupHold&&!['network-status','resolve-setup','register-initialization','hold-setup','release-setup'].includes(command.operation))
      throw new Error('replacement-pending');
    if(command.operation==='hold-setup'&&Object.keys(args).length===0){this.network.holdSetup();return {ok:true,held:true};}
    if(command.operation==='hold-setup'&&Object.keys(args).join(',')==='revision'&&args.revision===3){
      this.network.holdSetup(3);return {ok:true,held:true};
    }
    if(command.operation==='release-setup'&&Object.keys(args).length===0){this.network.releaseSetup();return {ok:true,held:false};}
    if(['observe','navigate','read-result'].includes(command.operation))throw new Error('approval-required');
    if(command.operation==='network-status'&&Object.keys(args).length===0)return {ok:true,descriptors:this.network.list(),phase:this.network.phase,protocol:initializationProtocol()};
    if(command.operation==='resolve-setup'&&Object.keys(args).join(',')==='setup')return setupContracts(args.setup,this.network);
    if(command.operation==='register-initialization'&&Object.keys(args).join(',')==='contracts'){
      if(!args.contracts||typeof args.contracts!=='object'||Array.isArray(args.contracts))throw new Error('request-invalid');
      const rows=Object.values(args.contracts);
      if(rows.some(c=>c?.revision===3)){
        if(rows.some(c=>c?.revision!==3))throw new Error('request-invalid');
        this.network.registerV3Contracts(args.contracts);
      }
      this.network.startupState.register(args.contracts);return {ok:true};
    }
    if(command.operation==='resume-login'&&Object.keys(args).length===0)return this.resume();
    if(command.operation==='resume-login'&&Object.keys(args).join(',')==='startup'){
      const ticket=args.startup;
      if(!ticket||typeof ticket!=='object'||Array.isArray(ticket)||
        Object.keys(ticket).sort().join(',')!=='binding_digest,deadline_ms,preauth_lifecycle,resume_id'||
        !/^[a-f0-9]{32}$/.test(ticket.resume_id)||!/^[a-f0-9]{64}$/.test(ticket.binding_digest)||
        ticket.preauth_lifecycle!==this.network.preauthLifecycle||!Number.isSafeInteger(ticket.deadline_ms)||
        ticket.deadline_ms<=Date.now())throw new Error('invalid-command');
      // Different process clocks must only narrow the original startup budget.
      return this.resume({...ticket,deadline_ms:Math.min(ticket.deadline_ms,Date.now()+45000)});
    }
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
