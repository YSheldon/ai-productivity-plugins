import {PROFILES,MAX_REFERENCE_UNITS,MAX_PROPOSAL_UNITS} from './web_request_profiles.mjs';
import {captureInitializationIntent,createOwnedCookieContext,verifyInitializationCookieContext} from './web_outgoing_intent.mjs';
import {WorkerAuthority} from './web_authorization_ipc.mjs';
import {NetworkPolicy} from './web_network_authorization.mjs';
import {initializationIntentResponse} from './web_tls.mjs';

export function initializationProtocol(){
  if([captureInitializationIntent,createOwnedCookieContext,verifyInitializationCookieContext,initializationIntentResponse,
    WorkerAuthority.prototype.consumeNetworkReceipt,NetworkPolicy.prototype.resolveV3,NetworkPolicy.prototype.registerV3Contracts]
    .some(value=>typeof value!=='function'))throw new Error('capability-unsupported');
  return {setup_revisions:[1,2,3],profiles:[...PROFILES],reference_units:MAX_REFERENCE_UNITS,
    proposal_units:MAX_PROPOSAL_UNITS,transport:'fixed-egress-v1'};
}
