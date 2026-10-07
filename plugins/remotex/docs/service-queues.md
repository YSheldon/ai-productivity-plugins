# Host Maintenance and Service Queues

Service queues use `HOST::service::NAME` as a saved profile's `queue_resource`.
`NAME` is a nonempty ASCII identifier (letters, digits, dot, underscore, hyphen).
The existing `HOST` resource is the exclusive host-maintenance queue.

For example:

- Maintenance: `gitlab:host:192.168.100.238`
- Observer: `gitlab:host:192.168.100.238::service::observer`
- Website: `gitlab:host:192.168.100.238::service::website`

Different service owners may coexist. The same service retains FIFO exclusion.
Maintenance cannot be claimed while any child service is owned, even by the
same requester. A maintenance owner blocks every child claim. Waiting
maintenance also blocks NEW child claims to avoid maintenance starvation;
existing service owners can finish and release. This is writer preference,
not a global FIFO across distinct queues. There is no automatic lock upgrade.
Release the child before claiming maintenance. No owner is preempted.

Claims and conflict checks share the existing atomic queue-state lock. Active
operations retain their resource operation lock, preventing release or stale
recovery from clearing an owner mid-operation. An expired child is not silently
cleared by a parent claim: use the existing explicit stale-recovery workflow.
Status includes `blocking_resources` for cross-scope conflicts.

## Upgrade and Configuration

The first persisted service queue upgrades the queue file to version2. Older
clients reject this version instead of silently ignoring host/service exclusion.
Version2 is retained after services are released. Upgrade all clients sharing
that queue before enabling service profiles. Existing version1 queues without
services retain their format and behavior. Never downgrade a live queue file.
Version1 files already containing the reserved service syntax are rejected;
do not silently reinterpret legacy ownership. Resolve those records under the
old semantics and explicit operator coordination before enabling service queues.

Before splitting a host queue, verify Docker endpoints, mounts/directories,
ports and operation scope. Keep host-level operations (reboots, daemon changes,
disk cleanup, firewall and system settings) on the parent profile. Each service
profile must share the same exact canonical HOST prefix. Do not use a second
alias for the same host that would evade parent exclusion.

Migrate only idle workflows. Each requester cancels its OWN previous wait item
and requests its service queue; never clear another requester's owner/waiter.
An old parent waiter conservatively blocks new service claims until it finishes
or cancels. Do not edit live state by hand or force the migration through it.

This remains a local cooperative scheduler, not a command authorization or
remote security boundary. A service lease does not sandbox arbitrary SSH
commands. Operators/agents must still use maintenance scope for host changes.
Separate Docker daemons alone do not prove absence of shared host effects.
