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

A failing capture exposed the controller-poll queue transition:

```text
queue-send kind=ENABLE_REQ rc=-1 before=1 after=1 cap=1 depth=1
poll ... DISABLE_REQUEST ... depth=1->2
poll ... ENABLE_REQUEST ... depth=2->1
poll ... EARLY_RETURN_DISABLED ... depth=1->1
```

Subsequent checkpoints showed frames and polling continuing while controller-read
counts remained frozen.

The application had not hung.

The controller polling state had.

## Root cause

The native port retained an asynchronous controller-poll disable/enable
handshake inherited from the original architecture.

That design assumes separately scheduled polling behavior and blocking message
queue semantics.

The native implementation performs the relevant work synchronously. A one-slot
queue could therefore reject an enable request while callers continued without
handling the failed send.

The resulting sequence left the native poll-disable depth permanently nonzero.

Future polls returned before controller input was read.

## Repair

The repair removed the unnecessary asynchronous handshake from the native path:

- native status checking is performed directly
- native poll-disable and poll-enable wrappers no longer enqueue the legacy
  synchronization requests
- non-native behavior remains unchanged

The change is intentionally scoped to the native implementation.

## Verification

The repaired candidate was checked through multiple layers:

- the port regression suite passed
- the complete build passed
- a headless run showed controller reads continuing with disable depth zero
- an Apollo session capture completed normally
- a human gameplay test successfully advanced into the next stage

The final Apollo capture therefore complemented, rather than replaced, ordinary
tests and human validation.

## Why Apollo helped

Apollo did not discover the fix by itself.

Its contribution was to make the runtime state precise enough that competing
explanations could be discarded.

The investigation moved from:

> input dies after completing a mission

to:

> rendering and polling continue, controller reads stop, and the native
> poll-disable depth remains permanently nonzero after a failed queue send

That is a much smaller engineering problem.

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
