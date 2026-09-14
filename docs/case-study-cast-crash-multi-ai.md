# Case Study: Solving GoldenEye's CAST Crash with Apollo and a Multi-AI Debugging Architecture

This case study describes a real native 64-bit crash investigation in GoldenEye Native and the multi-AI architecture used to solve it.

**CAST** here means the opening sequence immediately after the gun-barrel sequence, where characters are introduced one by one and displayed on screen.

## Result

The affected build followed a deterministic path:

```text
launch -> gun barrel -> CAST -> repeated character transitions -> crash
```

The final repair produced:

```text
Focused lifecycle regression: 14 / 14 passed
Unchanged-main negative control: failed expected lifecycle checks
Full port regression: 34 / 34 passed
Patch replay: all 26 source patches applied
Complete Linux build: passed
Repaired CAST runtime: 180 seconds, frame 10,561
Second-machine interactive test: passed
Upstream issue: #98
Upstream PR: #99
```

The **entire bug hunt and fix used less than 20% of the weekly Codex allowance**. The final Codex-heavy production-hardening stretch accounted for only about **8 percentage points** of weekly usage. Those figures are observations from the usage meter during this investigation, not a general cost guarantee.

## Architecture

The system deliberately gave each component a narrow job:

```text
                    HUMAN
                      |
                      v
              +----------------+
              |    Latitude    |
              | control/review |
              +----------------+
                 |          |
                 |          +------------------+
                 |                             |
                 v                             v
        +----------------+             +---------------+
        | Local Ollama   |             |    Codex      |
        | Qwen3-Coder    |             | supervisor /  |
        | 30B            |             | final review  |
        +----------------+             +---------------+
                 |
                 v
        +----------------+
        |   OpenCode     |
        | action harness |
        +----------------+
                 |
                 v
        +----------------+
        | Linux worker   |
        | build + test   |
        +----------------+
                 |
          +------+------+
          |             |
          v             v
     +---------+    +-----------+
     | Apollo  |    | GoldenEye |
     | measure |    | build/run |
     +---------+    +-----------+
```

Role summary:

```text
Codex      = engineering supervisor and final decision authority
Qwen       = local bounded investigator
OpenCode   = permissioned tool/action harness
Apollo     = deterministic measurement instrument
worker     = repeatable build/run/test executor
Latitude   = human control station and second-machine validation
```

The routing rule that emerged was:

```text
mechanical / enumerable fact  -> Apollo first
bounded source interpretation -> Qwen
runtime measurement           -> Apollo
causal judgment               -> Codex
production acceptance         -> Codex + tests + human smoke test
```

## Hardware

The control machine was a Dell Latitude 5530 with an i7-1270P, 32 GB RAM, Ubuntu 24.04, and CPU-only Ollama. It ran the local model, OpenCode, source review, orchestration, and final interactive testing.

A second 32 GB Linux worker based on an older i7-4790K handled dedicated worktrees, builds, deterministic tests, Apollo captures, and longer validation runs.

The useful point is that this did not require an AI workstation. A single 32 GB Linux PC can reproduce the basic architecture; a second machine mainly improves isolation and convenience.

## Local model: Qwen3-Coder 30B

The primary local reasoning model was **Qwen3-Coder 30B** through Ollama. On the Latitude it was the best practical balance found between capability and CPU-only speed for bounded C/code reasoning.

The goal was not to make the local model the final authority. Its useful role was:

> Give a capable local model a narrow engineering question, constrain its actions, and verify important conclusions with deterministic evidence.

## OpenCode's role

OpenCode wrapped the local Ollama model with a controlled tool environment. The Ollama provider used the local OpenAI-compatible endpoint:

```text
http://127.0.0.1:11434/v1
```

The harness kept tasks bounded and separated investigation from editing. OpenCode was the action boundary; it was not the source of truth about whether a hypothesis was correct.

## Apollo's role

Apollo supplied the facts that the reasoning systems had to respect.

For this bug it answered questions such as:

- Did the process actually crash?
- Where did it stop?
- Was the crash repeatable?
- Which allocation sequence failed?
- How many reusable slots remained?
- Did a proposed repair preserve reusable backing state?
- Did the repaired executable pass the old failure point?

The original crash narrowed to `modelSetScale()` in the CAST path. Instrumentation then showed ten spare animated-model slots being consumed until allocation #11 returned `NULL`.

That immediately changed the problem from "CAST crashes" to "why does this supposedly reusable model pool stop reusing slots?"

## The failed A/B that exposed the real bug

The first defect looked straightforward: native ownership used a separate `ge_inuse` flag, while legacy release code cleared `Model.obj`.

A one-variable repair cleared `ge_inuse` on release.

It failed -- usefully.

```text
original failure:
    free slots:     10 -> 0
    eligible slots: 10 -> 0

ge_inuse-only A/B:
    free slots:     stays available
    eligible slots: 10 -> 0
```

So ownership was not the whole problem.

The second defect was a 64-bit layout alias. Legacy slot storage `unk10` was still being used as reusable rwdata backing, but on native 64-bit builds it overlapped mutable `Model.obj`. Clearing `Model.obj` therefore destroyed the backing metadata needed for later reuse.

The causal chain became:

```text
CAST allocates animated model
        |
        v
slot claimed
        |
        v
legacy release clears Model.obj
        |
        +--> ownership lifecycle wrong
        |
        +--> reusable rwdata pointer destroyed
                |
                v
slots lose eligibility
                |
                v
allocation #11 returns NULL
                |
                v
modelSetScale(NULL)
                |
                v
SIGSEGV
```

The non-animated model pool shared the same structural hazard, so the final solution fixed the native slot-metadata design rather than adding a CAST-specific workaround.

## Production repair

The repair moved native ownership/rwdata metadata outside the mutable legacy `Model` overlay and used exact pool-membership checks before releasing pooled ownership. Non-native behavior and fallback allocation semantics were preserved.

A downstream null guard was deliberately rejected because it would hide allocator exhaustion rather than repair it.

## Why Codex usage stayed low

Codex was saved for strategy, causal judgment, productionization, regression design, and final review.

By the final stretch it received a compact evidence state containing the crash signature, allocator sequence, failed A/B, proven alias, relevant source locations, rejected hypotheses, and validation gates.

It did not have to spend premium context rediscovering the whole investigation.

That is why the final production-hardening phase consumed only about **8 percentage points** of weekly usage, while the **complete bug hunt and fix stayed under 20% of the weekly allowance**.

A wasteful architecture would use the premium model to search files, parse every log, run every command, and remember every experiment. This architecture instead used:

```text
Apollo      -> deterministic facts
Qwen        -> inexpensive bounded interpretation
OpenCode    -> controlled actions
Linux worker-> builds and runtime work
Codex       -> hard decisions and production hardening
human       -> checkpoints and final interactive validation
```

## What still needs improvement

The investigation exposed several orchestration improvements worth making:

- automatically compact Qwen context before it becomes stale or overloaded;
- preserve a durable checkpoint with objective, accepted facts, rejected hypotheses, evidence index, open questions, and next action;
- force a strategy change after repeated rejected local-model attempts;
- use source-location/xref steps before asking for a function in a guessed file;
- make Apollo/harness success criteria more machine-readable;
- support explicit writable report/session directories;
- keep repeated safe command shapes stable to reduce approval friction;
- record application exit, wrapper exit, and capture status separately.

A future Qwen checkpoint should look conceptually like:

```text
objective
accepted facts
current strategy
evidence index
changes made
rejected hypotheses
open questions
constraints
next action
```

Apollo can populate the mechanical facts while the reasoning layer contributes interpretation.

## Public upstream result

- [GoldenEye Native issue #98 - CAST sequence crashes after repeated character transitions on native 64-bit builds](https://github.com/seb-patron/goldeneye-native/issues/98)
- [GoldenEye Native PR #99 - Fix native model slot lifecycle metadata](https://github.com/seb-patron/goldeneye-native/pull/99)

This was therefore not just an AI benchmark. The workflow produced a reproducible diagnosis, a production repair, regression coverage, CI integration, and an upstream pull request.

## Larger lesson

A local model does not need to equal the best cloud model to be useful, and the strongest model does not need to perform every mechanical task.

The combination works when deterministic evidence sits underneath both:

```text
local model     -> cheap exploration
Apollo          -> reproducible facts
premium model   -> high-value reasoning
human           -> judgment and acceptance
```

Apollo's role is to make those facts portable across reasoning systems. Instead of asking every model to rediscover reality from source trees and giant logs, establish the relevant facts once, preserve them, and reason from the same evidence.

That is the core design idea behind Apollo Command Module.

## Privacy

This public case study omits private runtime bundles, private game data, account details, network information, user-specific filesystem paths, and credentials. Only the engineering facts needed to explain the workflow and conclusion are included.