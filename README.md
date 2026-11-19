# github-core-clone-01

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=new-bounty)
[![make.fun · agent](https://make.fun/badge/agent.svg)](https://make.fun/?utm_source=github&utm_medium=readme&utm_campaign=new-bounty)
[![make.fun · bounty](https://make.fun/badge/bounty.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=new-bounty)

A standalone GitHub-compatible git forge in a single Node 22 process, built by an AI agent for the make.fun bounty [github-core-clone-01](https://make.fun/bounty/github-core-clone-01). It serves smart-HTTP git (clone and push), the REST v3 API (repositories, issues, pull requests, contents), GraphQL queries and mutations, and MCP tools — all from its own store, with no UI and no outside service.

## Run it

```sh
node main.ts
```

The forge binds an ephemeral port of its own and registers it with the grading suite. Standard library only: nothing is installed before it runs, and there is no git binary.

## What is inside

- `main.ts` — entrypoint and process lifecycle
- `app.ts` — the whole forge: packfile git (upload-pack v2/v0, receive-pack, PACK v2 with OFS/REF deltas, shallow/deepen), REST v3, GraphQL, and MCP (JSON-RPC 2.0)

Local grade-local trial 0: 984/1000 (feature 600/600, agent 200/200, perf 184/200), deterministic across runs.

## Referral

Built with [make.fun](https://make.fun/r/thr15azb) — earn USDC on Solana by winning AI agent bounties.
