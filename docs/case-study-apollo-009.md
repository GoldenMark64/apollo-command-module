# Case Study: Finding a Native Post-Mission Input Lock

This case study shows how Apollo was used during investigation of a native Linux
bug in the GoldenEye Native project.

The purpose of the case study is Apollo's investigative method. It does not
publish private runtime bundles or machine-specific configuration.

## Symptom

After successfully completing a mission, the program could transition into the
post-mission or front-end sequence while keyboard and mouse input became
permanently unresponsive.

Rendering continued.

That distinction mattered: the process was alive, frames were advancing, but
controller reads had stopped.

## Initial problem

The visible symptom looked like an input or front-end failure.

Several subsystems could plausibly have been responsible:

- keyboard/mouse translation
- stage transitions
- menu state
- save completion
- controller polling
- native scheduling behavior

Apollo captures and targeted runtime checkpoints were used to turn those
possibilities into observable state.

## Decisive evidence

A current-main instrumented Dam flight captured the exact failure schedule:

```text
event=MISSION_SAVE_END
poll=6558 branch=DISABLE_REQUEST depth=1 ... gap_polls=1
event=STATUS_BEGIN eligible_gap_polls=1 depth=1 dq=0/1 eq=1/1
queue-send kind=DISABLE_REQ rc=0 ...
queue-send kind=ENABLE_REQ rc=-1 ...
poll=6559 branch=DISABLE_REQUEST depth=2 ...
poll=6560 branch=ENABLE_REQUEST depth=1 ...
poll=6561 branch=EARLY_RETURN_DISABLED depth=1 dq=0/1 eq=0/1 reads=6547
...
poll=6600 branch=HEARTBEAT depth=1 dq=0/1 eq=0/1 reads=6547
```

The application had not hung. Rendering and polling continued, but the
controller-read count remained frozen.

The controller polling state had become permanently disabled.

## Root cause

The native port retained an asynchronous controller-poll disable/enable
handshake inherited from the original architecture.

That design assumes separately scheduled polling behavior and blocking message
queue semantics.

The native implementation performs the relevant work synchronously. During
mission completion, the save path can queue DISABLE and ENABLE requests. If
exactly one eligible `joyPoll()` runs before the following status handshake,
the save DISABLE is consumed while the save ENABLE remains in its one-slot
queue.

The subsequent status DISABLE can then be queued successfully, but the status
ENABLE collides with the still-pending ENABLE and is dropped. The failed send
is ignored.

Later polls consume the second DISABLE and the one surviving ENABLE. That leaves
poll-disable depth at 1 with both request queues empty. No future request can
bring the depth back to zero, so every later `joyPoll()` exits before reading
controller input.

## Deterministic regression

A ROM-free regression was built around the actual production `joy.c` functions
and native message-queue implementation, with synthetic controller and save
adapters.

The unchanged current production logic reproduced the dangerous one-poll-gap
schedule deterministically:

- the status ENABLE was the only dropped request
- disable depth remained 1
- both request queues drained to empty
- subsequent eligible polls produced no fresh controller reads

The same harness also demonstrated the balanced zero-poll-gap schedule, where
both status requests collide symmetrically and polling returns to depth zero.

## Repair

The repair removes the unnecessary asynchronous handshake from the native path:

- native `joyCheckStatusThreadSafe()` calls `joyCheckStatus()` directly
- native `joyDisablePoll()` is a no-op
- native `joyEnablePoll()` is a no-op
- non-native behavior remains unchanged

The change is intentionally scoped to the native implementation.

## Final verification

The repaired candidate was checked through multiple independent layers:

- the current unpatched production functions reproduced the dangerous schedule
  in the ROM-free regression
- the repaired native build kept polling depth at zero in both zero-gap and
  one-poll-gap schedules
- the non-native build continued exercising the original queue branches
- the exact decomp baseline accepted the complete source patch queue through
  patch 0031
- the complete Linux build succeeded
- an unpatched human Dam flight reproduced the post-mission input lock
- Apollo instrumentation measured `eligible_gap_polls=1` in that failing flight
- the same current baseline with the production repair completed Dam normally
- mouse and keyboard input remained functional after mission completion

The final human A/B therefore confirmed that the production repair fixes the
real gameplay failure, not just the synthetic schedule.

## Public upstream tracking

The current upstream report and fix are tracked as:

- GoldenEye Native issue #88: post-mission input freeze after mission save
- GoldenEye Native pull request #89: native joy polling repair

## Why Apollo helped

Apollo did not discover the fix by itself.

Its contribution was to make the runtime state precise enough that competing
explanations could be discarded.

The investigation moved from:

> input dies after completing a mission

to:

> one eligible poll occurs between mission save and status; the second ENABLE
> send is dropped; disable depth settles at 1 with empty queues; controller
> reads stop while rendering continues

That is a much smaller engineering problem, and one that could be reproduced in
a ROM-free deterministic harness before the production repair was accepted.

## Privacy

The public case study intentionally omits:

- machine hostnames
- user names
- local network information
- private filesystem paths
- process IDs
- graphical-session credentials
- private binaries
- full raw runtime bundles

Only the evidence needed to explain the engineering conclusion is reproduced.
