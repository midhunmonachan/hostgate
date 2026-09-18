# Hostgate project brief and working rules

## Product purpose and authority

Hostgate is an OAuth-protected MCP server that lets a remote ChatGPT web app operate the owner's Windows or Linux computer. Full capability under the operating-system account after successful authentication and authorization is intentional. Do not turn Hostgate into a sandbox or introduce command allowlists, path restrictions, or default restrictions that prevent an authorized connection from exercising that account's capabilities.

Perimeter security is the primary security objective: OAuth correctness, PKCE, token handling, credential protection, unauthenticated endpoints, public exposure, Tailscale Funnel, HTTPS/proxy handling, brute-force defenses, replay resistance, sensitive-data logging, and auditability. Reliability controls such as timeouts, output bounds, restart drains, and recovery policies are distinct from authority and must be explicit rather than silently changing authorized operation semantics.

Preserve exactly four MCP tools: `status`, `read`, `write`, and `shell`. New CLI commands are not additional MCP tools. Preserve Windows PowerShell, Linux Bash, root routes, and `/hostgate` routes. OAuth, registration, token, or issuer changes require a deliberate compatibility/migration plan. Do not silently rotate credentials, revoke active connections, or change the OS account or elevation level.

## Beginner experience

Build toward Windows-first guided setup that detects prerequisites, creates or preserves credentials appropriately, starts Hostgate, verifies HTTPS/tunneling, provides accurate ChatGPT connection steps and copyable URLs, checks health, and supports a safe first test. Users should not need to understand Node.js, MCP, OAuth, PKCE, ports, or systemd. Keep Linux onboarding explicit and usable.

Prefer small vertical slices toward an installer, guided wizard or protected local setup/status page, friendly diagnostics, automatic preflight checks, and actionable recovery guidance. Consult current official OpenAI documentation before changing ChatGPT UI instructions; do not invent interface names or assume one menu path applies to every account.

## Inspect and coordinate before changes

Read git status, branch, HEAD, remotes, relevant source, tests, workflows, package metadata, and live behavior before editing. Treat the live process and deployment as distinct from the developer checkout: an unchanged HTTP health response alone does not identify the running commit, verify credentials, or establish restart readiness.

State the goal, affected files, acceptance criteria, and compatibility risks before each change. Work in reviewable slices and avoid broad rewrites. Keep Windows and Linux behavior explicit, including unsupported functionality.

If files change concurrently, preserve that work. Use an isolated checkout when needed; do not overwrite another writer's edits or imply that a preserved original checkout is clean. Recheck branch, remote HEAD, staged file scope, and unstaged changes before committing or pushing.

After a change, run checks/tests, review the diff, and report the commit, branch, push result, tests actually executed, and limitations. Use normal commits and non-forced pushes. Never reset, force-push, or discard/delete unrelated work.

Never commit credentials, `.env` configuration, OAuth state, tokens, `node_modules`, local helpers, logs, temporary fixtures, archives, or generated artifacts. Review package contents as well as the staged diff. Do not print secrets while inspecting configuration. Keep stateful integration tests in isolated temporary homes and on loopback-only ports; do not brute-force, overload, or mutate the production OAuth state as a test.

## Managed Windows lifecycle

The managed deployment uses current-user DPAPI-protected environment settings, a private runtime, a Task Scheduler user-logon task, and a supervisor. Post-logon recovery is not a Windows service running before login, and task configuration is not proof that an actual reboot was tested.

Keep `configured`, `running`, and `restartReady` distinct. A successful managed launch, recoverable protected settings, runtime availability, matching task identity, recent process status, and health contribute different evidence. A foreground configuration file alone does not prove restart readiness.

Preserve the original environment and OAuth state during migration. Installation accepts an explicit local environment import via stdin; it does not extract arbitrary process memory. An unavailable or blocked import must not be replaced with invented or rotated credentials. Leave a healthy existing instance running until safe activation prerequisites are established. Report blocked activation separately from successful code implementation and testing.

Validate a candidate before stopping the identified old instance. Stop only verified owned processes, not unrelated process trees. Managed restarts and updates must report activation failure and whether rollback restored the previous runtime. Raw tool output and credentials are not lifecycle log data.

## GitHub updater contract

Update checks are separate from applying an update. Application requires explicit consent and the exact full commit that was checked, the trusted existing GitHub `origin`, `main`, forward ancestry, and a clean source tree including untracked files. Do not stash, ignore, delete, or reset local work merely to pass this check.

Prepare and validate a separate retained release. Install dependencies from the npm lockfile when npm is available; otherwise fail without disturbing the active deployment. Run candidate checks/tests without production OAuth environment values. Explicitly approved source and its tests remain trusted OS-account code, not a sandbox.

Recheck source and deployment consistency before activation. Keep previous releases and error receipts for rollback/recovery. Do not update credentials, OAuth state, unrelated files, or the developer checkout as a side effect of switching a managed release. Distinguish checkout, deployed, and remote commits in status. Manager API compatibility is explicit; do not silently replace the stable supervisor with incompatible code.

Windows managed application and Linux update checking have different support boundaries. Preserve existing Linux foreground/systemd behavior; document and reject unsupported managed operations rather than pretending they succeeded.

## Verification baseline

Use `node --run check` and `node --run test` (or the equivalent npm scripts). Check the npm package with `npm pack --dry-run`. Keep the Node.js 22/24 and Windows/Linux CI matrix meaningful. Report local execution separately from CI results; never claim CI passed without visible evidence.

For lifecycle/updater changes, cover exact process/task identity, protected environment round-trip, fresh-context startup, crash recovery, failed candidate activation, rollback, dirty-tree refusal, changed remote commits, missing dependencies, and concurrent source changes. Verify production health and preservation separately without claiming an unperformed live restart, update, or reboot.
