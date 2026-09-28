# Active final mode

## Goal

Add an opt-in `ico-solve --active` mode for final-round task services and
local challenge artifacts. It must turn evidence from static solvers into
bounded live checks, record every interaction, and return a flag only when it
appears in a captured service or program response.

## Inputs and service discovery

The mode reads task statements, source files, Dockerfiles, Compose files and
provided scripts. It extracts HTTP(S) URLs, `host:port` endpoints and local
service definitions. Explicit `--service-url` values supplement discovery.
Only discovered or explicitly supplied endpoints are eligible for requests.

## Execution

Provided runnable binaries and local replicas run only when `--active` is set.
The runner uses a temporary working directory, a fresh process group, bounded
stdin/stdout/stderr, CPU, memory and wall-clock limits. Docker/Compose
replicas are preferred where present. Native execution records its command,
exit status, output and limit outcome in the task report.

## Active feedback loop

1. Static modules produce endpoints, paths, request templates, payloads or
   candidate inputs.
2. The active executor performs cheap reachability and service fingerprinting.
3. Web checks replay source-derived requests and bounded endpoint discovery.
   Pwn checks execute local binaries, use candidate stdin/payload artifacts and
   scan captured output.
4. Every response is scanned for flag values. New URLs, forms and error clues
   are returned to the scheduler for one further bounded pass.

## Evidence and stopping rules

Every request and program run is written under the debug report directory with
its source, request or stdin hash, response or output hash, status and elapsed
time. A flag is selected only when emitted by a local process or a task
service response. The mode stops on a flag, the global deadline, per-service
request budget, per-process time limit, or exhaustion of derived actions.

## CLI

`--active` enables the mode. `--service-url URL` supplies a task-service URL
when it cannot be parsed from files. `--active-request-budget N` and
`--active-timeout SECONDS` bound the live phase. Existing offline behavior is
unchanged unless `--active` is explicitly present.

## Tests

Tests use local HTTP servers and short fixture executables. They verify URL
discovery, replay of a source-derived request, local binary output flag
extraction, response provenance and enforcement of deadline/request limits.
