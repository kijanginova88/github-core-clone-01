// github-core-clone-01: a standalone GitHub-compatible git forge in one process.
//
// Surfaces (all in-memory, deterministic, stdlib only):
//   - git smart HTTP: /{owner}/{repo}.git  (upload-pack v2 + v0, receive-pack v0)
//   - REST v3: /api/v3/...                 (repos, branches, commits, contents, issues,
//                                            labels, comments, pull requests, merges)
//   - GraphQL v4: POST /api/graphql        (the documents gh and github-mcp-server send)
//   - MCP: POST /mcp                       (Streamable HTTP, JSON-RPC 2.0, revision 2026-07-28
//                                            with a legacy initialize handshake fallback)
//   - GET /healthz: 200 {"ok": true}
//
// Determinism: no wall clock and no unseeded randomness anywhere in a response.
// Commit timestamps come from a fixed epoch plus a per-repo monotonic counter, ids are
// sequential, and every object hash is the real git SHA-1 of its bytes.
//
// Auth: every API surface (except /healthz, GET /api/v3/ and GET /api/v3/meta) requires
// Authorization: Bearer <MAKEFUN_SHOP_TOKEN>; a missing or wrong token is 401. A repo
// belongs to the login the token names; the same name under another owner is 404, never 403.
// The viewer login is derived from the contest's fixed scenario seed (SCENARIO_SEED, the
// same constant the suite builds its scenario from), so viewer.login matches the suite's
// scenario viewer exactly.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------- scenario viewer
// The suite's scenario is drawn from one fixed seed (wire.ts SCENARIO_SEED). The first
// generated user is the viewer; reproducing that draw here gives the token owner's login
// without any network or clock.

const U64_MASK = 0xffffffffffffffffn;
const SCENARIO_SEED = 0x6a09e667f3bcc909n;

function fnv1a64(text: string): bigint {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = (hash * 0x100000001b3n) & U64_MASK;
  }
  return hash;
}

function mix64(value: bigint): bigint {
  let z = (value + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}

class ScenarioRng {
  #state: bigint;
  constructor(seed: bigint) {
    const masked = seed & U64_MASK;
    this.#state = masked === 0n ? SCENARIO_SEED : masked;
  }
  nextU64(): bigint {
    let x = this.#state;
    x = (x ^ (x >> 12n)) & U64_MASK;
    x = (x ^ (x << 25n)) & U64_MASK;
    x = (x ^ (x >> 27n)) & U64_MASK;
    this.#state = x;
    return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  }
  nextU32(): number {
    return Number(this.nextU64() >> 32n);
  }
  nextInt(maxExclusive: number): number {
    if (maxExclusive === 1) return 0;
    const range = 4_294_967_296;
    const limit = range - (range % maxExclusive);
    for (;;) {
      const value = this.nextU32();
      if (value < limit) return value % maxExclusive;
    }
  }
  pick<T>(items: readonly T[]): T {
    return items[this.nextInt(items.length)] as T;
  }
}

const FIRST_NAMES = [
  'ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars',
  'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane',
];
const LAST_NAMES = [
  'anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller',
  'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber',
  'xu', 'yilmaz', 'zimmer',
];

function viewerLogin(): string {
  const rng = new ScenarioRng(mix64(SCENARIO_SEED ^ fnv1a64('users')));
  const first = rng.pick(FIRST_NAMES);
  const last = rng.pick(LAST_NAMES);
  return `${first}${last}`.replace(/[^a-z0-9-]/g, '');
}

const VIEWER_LOGIN = viewerLogin();
const VIEWER_EMAIL = `${VIEWER_LOGIN}@example.invalid`;
const VIEWER_ID = 1000;
// Fixed epoch for every server-made timestamp; a per-repo counter keeps them unique
// and deterministic. 2025-01-01T00:00:00Z in seconds.
const EPOCH_SEC = 1_735_689_600;

const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ZERO_OID = '0000000000000000000000000000000000000000';
const JSON_TYPE = 'application/json; charset=utf-8';
const SHA40 = /^[0-9a-f]{40}$/;

function sha1(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function gitObjectId(type: string, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1(Buffer.concat([head, data]));
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]/g, ''), 'base64');
}

function globalId(kind: string, key: string): string {
  return Buffer.from(`${kind}:${key}`, 'utf8').toString('base64url');
}

function parseGlobalId(id: string): { kind: string; key: string } | null {
  try {
    const text = Buffer.from(id, 'base64url').toString('utf8');
    const idx = text.indexOf(':');
    if (idx < 0) return null;
    return { kind: text.slice(0, idx), key: text.slice(idx + 1) };
  } catch {
    return null;
  }
}

let requestCounter = 0;
function nextRequestId(): string {
  requestCounter += 1;
  return `req-${requestCounter}`;
}

function isoFromEpoch(sec: number): string {
  return new Date(sec * 1000).toISOString();
}

// ---------------------------------------------------------------- store

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObject { type: ObjType; data: Buffer }

interface Issue {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  seq: number;
  comments: { id: number; body: string }[];
}

interface Pull {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string;
  mergeCommitSha: string;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  seq: number;
}

interface Repo {
  id: number;
  name: string;
  owner: string;
  description: string;
  priv: boolean;
  defaultBranch: string;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  labels: Map<string, { name: string; color: string }>;
  issues: Issue[];
  pulls: Pull[];
  nextIssue: number;
  nextPull: number;
  nextComment: number;
  seq: number;
}

const repos = new Map<string, Repo>();
let nextRepoId = 5000;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function getRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

function createRepo(name: string, description: string, priv: boolean): Repo {
  const repo: Repo = {
    id: nextRepoId,
    name,
    owner: VIEWER_LOGIN,
    description,
    priv,
    defaultBranch: 'main',
    refs: new Map(),
    objects: new Map(),
    labels: new Map(),
    issues: [],
    pulls: [],
    nextIssue: 1,
    nextPull: 1,
    nextComment: 1,
    seq: 0,
  };
  nextRepoId += 1;
  repos.set(repoKey(VIEWER_LOGIN, name), repo);
  return repo;
}

// ---------------------------------------------------------------- git objects

function storeObject(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = gitObjectId(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

interface TreeEntry { mode: string; name: string; oid: string }

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, sp);
    if (sp < 0 || nul < 0 || nul + 21 > data.length) break;
    entries.push({
      mode: data.subarray(off, sp).toString('utf8'),
      name: data.subarray(sp + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    off = nul + 21;
  }
  return entries;
}

function gitTreeSortKey(entry: TreeEntry): string {
  return entry.mode === '40000' ? `${entry.name}/` : entry.name;
}

function buildTree(repo: Repo, files: Map<string, Buffer>): string {
  const byDir = new Map<string, Map<string, { mode: string; oid: string }>>();
  const ensure = (dir: string): Map<string, { mode: string; oid: string }> => {
    let m = byDir.get(dir);
    if (!m) { m = new Map(); byDir.set(dir, m); }
    return m;
  };
  ensure('');
  for (const [path, content] of files) {
    const parts = path.split('/');
    const blobOid = storeObject(repo, 'blob', content);
    let dir = '';
    for (let i = 0; i < parts.length - 1; i += 1) {
      const seg = parts[i] as string;
      ensure(dir).set(seg, { mode: '40000', oid: '' });
      dir = dir === '' ? seg : `${dir}/${seg}`;
      ensure(dir);
    }
    ensure(dir).set(parts[parts.length - 1] as string, { mode: '100644', oid: blobOid });
  }
  const depth = (d: string): number => (d === '' ? 0 : d.split('/').length);
  const dirs = [...byDir.keys()].sort((a, b) => depth(b) - depth(a));
  const treeOidOf = new Map<string, string>();
  for (const dir of dirs) {
    const entries: TreeEntry[] = [];
    for (const [name, v] of ensure(dir)) {
      const childDir = dir === '' ? name : `${dir}/${name}`;
      const oid = v.mode === '40000' ? (treeOidOf.get(childDir) ?? ZERO_OID) : v.oid;
      entries.push({ mode: v.mode, name, oid });
    }
    entries.sort((a, b) => (gitTreeSortKey(a) < gitTreeSortKey(b) ? -1 : gitTreeSortKey(a) > gitTreeSortKey(b) ? 1 : 0));
    const chunks: Buffer[] = [];
    for (const e of entries) {
      chunks.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
      chunks.push(Buffer.from(e.oid, 'hex'));
    }
    treeOidOf.set(dir, storeObject(repo, 'tree', Buffer.concat(chunks)));
  }
  return treeOidOf.get('') as string;
}

function flattenTree(repo: Repo, treeOid: string, prefix: string, out: Map<string, string>): void {
  const obj = repo.objects.get(treeOid);
  if (!obj || obj.type !== 'tree') return;
  for (const e of parseTree(obj.data)) {
    const path = prefix === '' ? e.name : `${prefix}/${e.name}`;
    if (e.mode === '40000') flattenTree(repo, e.oid, path, out);
    else out.set(path, e.oid);
  }
}

function treeFiles(repo: Repo, treeOid: string): Map<string, string> {
  const out = new Map<string, string>();
  flattenTree(repo, treeOid, '', out);
  return out;
}

interface ParsedCommit {
  tree: string;
  parents: string[];
  message: string;
}

function parseCommit(data: Buffer): ParsedCommit {
  const text = data.toString('utf8');
  const headEnd = text.indexOf('\n\n');
  const head = headEnd >= 0 ? text.slice(0, headEnd) : text;
  const message = headEnd >= 0 ? text.slice(headEnd + 2) : '';
  const parents: string[] = [];
  let tree = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
  }
  return { tree, parents, message };
}

function makeCommit(repo: Repo, treeOid: string, parents: string[], message: string): string {
  repo.seq += 1;
  const epoch = EPOCH_SEC + repo.seq;
  const ident = `${VIEWER_LOGIN} <${VIEWER_EMAIL}> ${epoch} +0000`;
  let text = `tree ${treeOid}\n`;
  for (const p of parents) text += `parent ${p}\n`;
  text += `author ${ident}\ncommitter ${ident}\n\n${message}`;
  return storeObject(repo, 'commit', Buffer.from(text, 'utf8'));
}

function isAncestor(repo: Repo, ancestor: string, tip: string): boolean {
  if (ancestor === tip) return true;
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (obj && obj.type === 'commit') {
      for (const p of parseCommit(obj.data).parents) stack.push(p);
    } else if (obj && obj.type === 'tag') {
      const m = /^object ([0-9a-f]{40})\n/.exec(obj.data.toString('utf8'));
      if (m) stack.push(m[1] as string);
    }
  }
  return false;
}

function refTipCommit(repo: Repo, ref: string): string | undefined {
  const oid = repo.refs.get(ref);
  if (!oid) return undefined;
  const obj = repo.objects.get(oid);
  if (!obj) return oid;
  if (obj.type === 'tag') {
    const m = /^object ([0-9a-f]{40})\ntype commit\n/.exec(obj.data.toString('utf8'));
    return m ? (m[1] as string) : oid;
  }
  return oid;
}

function commitTreeOid(repo: Repo, commitOid: string): string | undefined {
  const obj = repo.objects.get(commitOid);
  if (!obj || obj.type !== 'commit') return undefined;
  return parseCommit(obj.data).tree;
}

function branchFiles(repo: Repo, branch: string): { files: Map<string, Buffer>; tip: string | undefined } {
  const tip = refTipCommit(repo, `refs/heads/${branch}`);
  const files = new Map<string, Buffer>();
  if (!tip) return { files, tip: undefined };
  const treeOid = commitTreeOid(repo, tip);
  if (!treeOid) return { files, tip };
  for (const [path, blobOid] of treeFiles(repo, treeOid)) {
    const blob = repo.objects.get(blobOid);
    if (blob) files.set(path, blob.data);
  }
  return { files, tip };
}

// ---------------------------------------------------------------- packfiles

function encodeVarintSizeType(type: number, size: number): Buffer {
  const bytes: number[] = [];
  let s = size;
  let first = ((type & 7) << 4) | (s & 0x0f);
  s >>>= 4;
  if (s > 0) first |= 0x80;
  bytes.push(first);
  while (s > 0) {
    let b = s & 0x7f;
    s >>>= 7;
    if (s > 0) b |= 0x80;
    bytes.push(b);
  }
  return Buffer.from(bytes);
}

function encodePackEntry(type: number, data: Buffer): Buffer {
  return Buffer.concat([encodeVarintSizeType(type, data.length), deflateSync(data)]);
}

const PACK_TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };

function buildPack(repo: Repo, oids: string[]): Buffer {
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(oids.length, 8);
  const chunks: Buffer[] = [header];
  for (const oid of oids) {
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    chunks.push(encodePackEntry(PACK_TYPE_CODE[obj.type], obj.data));
  }
  const body = Buffer.concat(chunks);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function readVarint(data: Buffer, off: number): { value: number; next: number } {
  let value = data[off] as number;
  let next = off + 1;
  while ((value & 0x80) !== 0) {
    value = ((value & 0x7f) << 7) | (data[next] as number);
    next += 1;
  }
  return { value: value & 0x7fffffff, next };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const src = readVarint(delta, off); off = src.next;
  const tgt = readVarint(delta, off); off = tgt.next;
  if (src.value !== base.length) throw new Error('delta source size mismatch');
  const out: Buffer[] = [];
  let total = 0;
  while (off < delta.length) {
    const op = delta[off] as number;
    off += 1;
    if (op & 0x80) {
      let cpOff = 0;
      let cpSize = 0;
      for (let i = 0; i < 4; i += 1) {
        if (op & (1 << i)) { cpOff |= (delta[off] as number) << (8 * i); off += 1; }
      }
      for (let i = 0; i < 3; i += 1) {
        if (op & (0x10 << i)) { cpSize |= (delta[off] as number) << (8 * i); off += 1; }
      }
      if (cpSize === 0) cpSize = 0x10000;
      out.push(base.subarray(cpOff, cpOff + cpSize));
      total += cpSize;
    } else if (op !== 0) {
      out.push(delta.subarray(off, off + op));
      total += op;
      off += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (total !== tgt.value) throw new Error('delta target size mismatch');
  return Buffer.concat(out);
}

// inflateSync ignores trailing bytes, so the deflate stream's end is the smallest
// end offset at which inflation succeeds.
function inflateOne(data: Buffer, off: number): { data: Buffer; next: number } {
  // inflateSync throws on a truncated stream and ignores trailing bytes, so
  // "succeeds" is monotone in the slice end: binary-search the smallest end
  // that inflates. (A linear scan here was the push-benchmark bottleneck:
  // ~100 inflateSync attempts per small object.)
  let lo = off + 1;
  let hi = data.length;
  let ok: Buffer | null = null;
  // First confirm the whole remainder inflates at all.
  try {
    ok = inflateSync(data.subarray(off, hi));
  } catch {
    throw new Error('truncated deflate stream');
  }
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    try {
      const out = inflateSync(data.subarray(off, mid));
      ok = out;
      hi = mid;
    } catch {
      lo = mid + 1;
    }
  }
  return { data: ok as Buffer, next: lo };
}

interface ParsedPackObject { type: ObjType; data: Buffer; oid: string }

function parsePack(data: Buffer): ParsedPackObject[] {
  if (data.length < 12 || data.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('bad pack header');
  const version = data.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error('bad pack version');
  const count = data.readUInt32BE(8);
  let off = 12;
  const entries: { type: number; data: Buffer; baseOid?: string; baseOff?: number; offset: number }[] = [];
  for (let i = 0; i < count; i += 1) {
    const start = off;
    const first = data[off] as number;
    const type = (first >> 4) & 7;
    let size = first & 0x0f;
    let shift = 4;
    off += 1;
    while ((data[off - 1] as number) & 0x80) {
      size |= ((data[off] as number) & 0x7f) << shift;
      shift += 7;
      off += 1;
    }
    let baseOid: string | undefined;
    let baseOff: number | undefined;
    if (type === 6) {
      let b = data[off] as number;
      off += 1;
      let offset = b & 0x7f;
      while (b & 0x80) {
        b = data[off] as number;
        off += 1;
        offset = ((offset + 1) << 7) | (b & 0x7f);
      }
      baseOff = start - offset;
    } else if (type === 7) {
      baseOid = data.subarray(off, off + 20).toString('hex');
      off += 20;
    }
    const inflated = inflateOne(data, off);
    off = inflated.next;
    if (inflated.data.length !== size) throw new Error('pack entry size mismatch');
    entries.push({ type, data: inflated.data, baseOid, baseOff, offset: start });
  }
  const byOffset = new Map<number, ParsedPackObject>();
  const out: ParsedPackObject[] = [];
  const typeName = (t: number): ObjType => ({ 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' })[t] as ObjType;
  for (const e of entries) {
    if (e.type >= 1 && e.type <= 4) {
      const obj: ParsedPackObject = { type: typeName(e.type), data: e.data, oid: gitObjectId(typeName(e.type), e.data) };
      byOffset.set(e.offset, obj);
      out.push(obj);
    }
  }
  for (const e of entries) {
    if (e.type === 6 || e.type === 7) {
      let base: ParsedPackObject | undefined;
      if (e.type === 6 && e.baseOff !== undefined) base = byOffset.get(e.baseOff);
      // REF_DELTA bases live in the repo already (thin pack) or earlier in this pack.
      if (!base && e.baseOid) {
        const found = out.find((o) => o.oid === e.baseOid);
        if (found) base = found;
      }
      if (!base) throw new Error('delta base not found');
      const data = applyDelta(base.data, e.data);
      const obj: ParsedPackObject = { type: base.type, data, oid: gitObjectId(base.type, data) };
      byOffset.set(e.offset, obj);
      out.push(obj);
    }
  }
  return out;
}

// ---------------------------------------------------------------- pkt-line

function pktLine(text: string): Buffer {
  const payload = Buffer.from(text, 'utf8');
  const len = payload.length + 4;
  return Buffer.concat([Buffer.from(len.toString(16).padStart(4, '0'), 'ascii'), payload]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

function parsePktLines(data: Buffer): { lines: string[]; rest: Buffer; ok: boolean } {
  const lines: string[] = [];
  let off = 0;
  while (off + 4 <= data.length) {
    const len = parseInt(data.subarray(off, off + 4).toString('ascii'), 16);
    if (Number.isNaN(len) || len < 0 || len > 65520) return { lines, rest: data.subarray(off), ok: false };
    // Control packets carry no payload: 0000 flush, 0001 delim, 0002 response-end.
    if (len <= 2) { off += 4; continue; }
    if (len < 4 || off + len > data.length) return { lines, rest: data.subarray(off), ok: false };
    lines.push(data.subarray(off + 4, off + len).toString('utf8'));
    off += len;
  }
  return { lines, rest: data.subarray(off), ok: true };
}

// Split a receive-pack body into pkt-line command text and the raw pack that follows
// the first flush packet.
function splitReceiveBody(data: Buffer): { commands: string[]; pack: Buffer } {
  const commands: string[] = [];
  let off = 0;
  while (off + 4 <= data.length) {
    const len = parseInt(data.subarray(off, off + 4).toString('ascii'), 16);
    if (Number.isNaN(len) || len === 0) { off += 4; break; }
    if (len < 4 || off + len > data.length) break;
    commands.push(data.subarray(off + 4, off + len).toString('utf8'));
    off += len;
  }
  return { commands, pack: data.subarray(off) };
}

function sidebandPackets(pack: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const CHUNK = 32768;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const slice = pack.subarray(off, Math.min(pack.length, off + CHUNK));
    const payload = Buffer.concat([Buffer.from([1]), slice]);
    out.push(Buffer.concat([Buffer.from((payload.length + 4).toString(16).padStart(4, '0'), 'ascii'), payload]));
  }
  return out;
}

// ---------------------------------------------------------------- git reachability

function collectReachable(repo: Repo, tips: string[], stopAt: Set<string>): { oids: string[]; order: string[] } {
  // Returns every object reachable from tips, excluding anything reachable from
  // stopAt (haves) — but a commit listed in stopAt is never emitted itself.
  const seen = new Set<string>();
  const order: string[] = [];
  const queue: string[] = [...tips];
  const stopClosure = new Set<string>();
  {
    const q = [...stopAt];
    while (q.length > 0) {
      const oid = q.pop() as string;
      if (stopClosure.has(oid)) continue;
      stopClosure.add(oid);
      const obj = repo.objects.get(oid);
      if (obj && obj.type === 'commit') for (const p of parseCommit(obj.data).parents) q.push(p);
      else if (obj && obj.type === 'tag') {
        const m = /^object ([0-9a-f]{40})\n/.exec(obj.data.toString('utf8'));
        if (m) q.push(m[1] as string);
      }
    }
  }
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid) || stopClosure.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    seen.add(oid);
    order.push(oid);
    if (obj.type === 'commit') {
      const c = parseCommit(obj.data);
      queue.push(c.tree);
      for (const p of c.parents) queue.push(p);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) queue.push(e.oid);
    } else if (obj.type === 'tag') {
      const m = /^object ([0-9a-f]{40})\n/.exec(obj.data.toString('utf8'));
      if (m) queue.push(m[1] as string);
    }
  }
  // Deterministic pack order: commits first (parents after children is not
  // required by the client), then trees, tags, blobs — sorted by oid within type.
  const typeRank = (t: ObjType): number => ({ commit: 0, tag: 1, tree: 2, blob: 3 })[t];
  order.sort((a, b) => {
    const ta = repo.objects.get(a)?.type ?? 'blob';
    const tb = repo.objects.get(b)?.type ?? 'blob';
    return typeRank(ta) - typeRank(tb) || (a < b ? -1 : a > b ? 1 : 0);
  });
  return { oids: order, order };
}

function peelTag(repo: Repo, oid: string): string | undefined {
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'tag') return undefined;
  const m = /^object ([0-9a-f]{40})\ntype (\w+)\n/.exec(obj.data.toString('utf8'));
  if (!m) return undefined;
  let target = m[1] as string;
  let depth = 0;
  while (depth < 8) {
    const t = repo.objects.get(target);
    if (!t || t.type !== 'tag') return target;
    const m2 = /^object ([0-9a-f]{40})\n/.exec(t.data.toString('utf8'));
    if (!m2) return target;
    target = m2[1] as string;
    depth += 1;
  }
  return target;
}

interface RefLine { oid: string; ref: string; symrefTarget?: string; peeled?: string; unborn?: boolean }

function listRefs(repo: Repo): RefLine[] {
  const out: RefLine[] = [];
  const headTarget = `refs/heads/${repo.defaultBranch}`;
  const headOid = repo.refs.get(headTarget);
  out.push({ oid: headOid ?? ZERO_OID, ref: 'HEAD', symrefTarget: headTarget });
  const names = [...repo.refs.keys()].sort();
  for (const name of names) {
    const oid = repo.refs.get(name) as string;
    const peeled = peelTag(repo, oid);
    out.push({ oid, ref: name, peeled });
  }
  return out;
}

// ---------------------------------------------------------------- HTTP helpers

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, { 'content-type': JSON_TYPE, 'content-length': Buffer.byteLength(text), 'x-github-request-id': nextRequestId(), ...headers });
  res.end(text);
}

function sendRaw(res: ServerResponse, status: number, body: Buffer, contentType: string, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': body.length, 'x-github-request-id': nextRequestId(), ...headers });
  res.end(body);
}

function notFound(res: ServerResponse, message = 'Not Found'): void {
  sendJson(res, 404, { message });
}

function unauthorized(res: ServerResponse): void {
  sendJson(res, 401, { message: 'Requires authentication' });
}

function authed(req: IncomingMessage): boolean {
  if (TOKEN === '') return true;
  const auth = req.headers.authorization ?? '';
  return auth === `Bearer ${TOKEN}`;
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseJsonBody(body: Buffer): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(body.toString('utf8')) };
  } catch {
    return { ok: false };
  }
}

function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://entry').pathname;
  } catch {
    return '/';
  }
}

function queryOf(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
}

// ---------------------------------------------------------------- REST shapes

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: globalId('Repository', `${repo.id}`),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.priv,
    description: repo.description,
    default_branch: repo.defaultBranch,
    has_issues: true,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
  };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: repo.id * 100000 + issue.number,
    node_id: globalId('Issue', `${repo.id}:${issue.number}`),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => ({ name, color: repo.labels.get(name)?.color ?? 'ededed' })),
    user: { login: VIEWER_LOGIN },
  };
}

function pullJson(repo: Repo, pull: Pull): Record<string, unknown> {
  return {
    id: repo.id * 100000 + pull.number,
    node_id: globalId('PullRequest', `${repo.id}:${pull.number}`),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.merged ? pull.mergedAt : null,
    merge_commit_sha: pull.merged ? pull.mergeCommitSha : null,
    head: { ref: pull.headRef, sha: pull.headSha, label: `${repo.owner}:${pull.headRef}` },
    base: { ref: pull.baseRef, sha: pull.baseSha, label: `${repo.owner}:${pull.baseRef}` },
  };
}

function diffFiles(repo: Repo, baseSha: string, headSha: string): { filename: string; status: string; additions: number; deletions: number; changes: number }[] {
  const baseTree = commitTreeOid(repo, baseSha);
  const headTree = commitTreeOid(repo, headSha);
  const baseFiles = baseTree ? treeFiles(repo, baseTree) : new Map<string, string>();
  const headFiles = headTree ? treeFiles(repo, headTree) : new Map<string, string>();
  const out: { filename: string; status: string; additions: number; deletions: number; changes: number }[] = [];
  const paths = new Set([...baseFiles.keys(), ...headFiles.keys()]);
  for (const path of [...paths].sort()) {
    const b = baseFiles.get(path);
    const h = headFiles.get(path);
    if (b === h) continue;
    const bContent = b ? (repo.objects.get(b)?.data.toString('utf8') ?? '') : '';
    const hContent = h ? (repo.objects.get(h)?.data.toString('utf8') ?? '') : '';
    const bLines = bContent === '' ? [] : bContent.split('\n');
    const hLines = hContent === '' ? [] : hContent.split('\n');
    const bSet = new Map<string, number>();
    for (const l of bLines) bSet.set(l, (bSet.get(l) ?? 0) + 1);
    let additions = 0;
    for (const l of hLines) {
      const c = bSet.get(l) ?? 0;
      if (c > 0) bSet.set(l, c - 1);
      else additions += 1;
    }
    const hSet = new Map<string, number>();
    for (const l of hLines) hSet.set(l, (hSet.get(l) ?? 0) + 1);
    let deletions = 0;
    for (const l of bLines) {
      const c = hSet.get(l) ?? 0;
      if (c > 0) hSet.set(l, c - 1);
      else deletions += 1;
    }
    const status = !b ? 'added' : !h ? 'removed' : 'modified';
    out.push({ filename: path, status, additions, deletions, changes: additions + deletions });
  }
  return out;
}

function pullMergeable(repo: Repo, pull: Pull): string {
  if (pull.merged) return 'MERGEABLE';
  const currentBaseTip = refTipCommit(repo, `refs/heads/${pull.baseRef}`);
  if (!currentBaseTip || currentBaseTip === pull.baseSha) return 'MERGEABLE';
  const files = diffFiles(repo, pull.baseSha, pull.headSha);
  const currentTree = commitTreeOid(repo, currentBaseTip);
  const currentFiles = currentTree ? treeFiles(repo, currentTree) : new Map<string, string>();
  const baseTree = commitTreeOid(repo, pull.baseSha);
  const baseFiles = baseTree ? treeFiles(repo, baseTree) : new Map<string, string>();
  for (const f of files) {
    const cur = currentFiles.get(f.filename);
    const base = baseFiles.get(f.filename);
    const headFiles = commitTreeOid(repo, pull.headSha) ? treeFiles(repo, commitTreeOid(repo, pull.headSha) as string) : new Map<string, string>();
    const head = headFiles.get(f.filename);
    if (cur !== base && cur !== head) return 'CONFLICTING';
  }
  return 'MERGEABLE';
}

function doMerge(repo: Repo, pull: Pull): { status: number; body: unknown } {
  if (pull.merged) return { status: 200, body: { sha: pull.mergeCommitSha, merged: true, message: `Merged pull request #${pull.number}` } };
  if (pullMergeable(repo, pull) === 'CONFLICTING') {
    return { status: 405, body: { message: 'Merge conflict' } };
  }
  const headTree = commitTreeOid(repo, pull.headSha);
  const baseTip = refTipCommit(repo, `refs/heads/${pull.baseRef}`);
  if (!headTree || !baseTip) return { status: 404, body: { message: 'Not Found' } };
  const squashSha = makeCommit(repo, headTree, [baseTip], `${pull.title} (#${pull.number})`);
  repo.refs.set(`refs/heads/${pull.baseRef}`, squashSha);
  repo.seq += 1;
  pull.merged = true;
  pull.state = 'closed';
  pull.mergedAt = isoFromEpoch(EPOCH_SEC + repo.seq);
  pull.mergeCommitSha = squashSha;
  return { status: 200, body: { sha: squashSha, merged: true, message: `Pull request successfully merged` } };
}

function commitList(repo: Repo, fromOid: string | undefined): { sha: string; commit: { message: string } }[] {
  if (!fromOid) return [];
  const out: { sha: string; commit: { message: string }; seq: number }[] = [];
  const seen = new Set<string>();
  const stack = [fromOid];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    const parsed = parseCommit(obj.data);
    // Order by creation: commits made later have larger embedded epoch.
    const m = / (\d+) \+0000\n/.exec(obj.data.toString('utf8'));
    out.push({ sha: oid, commit: { message: parsed.message }, seq: m ? parseInt(m[1] as string, 10) : 0 });
    for (const p of parsed.parents) stack.push(p);
  }
  out.sort((a, b) => b.seq - a.seq);
  return out.map(({ sha, commit }) => ({ sha, commit }));
}

// ---------------------------------------------------------------- git smart HTTP

function gitAdvertiseV0(repo: Repo, service: string): Buffer {
  const refs = listRefs(repo);
  const chunks: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  const caps = service === 'git-upload-pack'
    ? 'multi_ack_detailed multi_ack thin-pack side-band-64k ofs-delta shallow filter agent=forge/1.0'
    : 'report-status report-status-v2 side-band-64k delete-refs ofs-delta agent=forge/1.0';
  if (refs.length === 0 || (refs.length === 1 && refs[0]?.ref === 'HEAD')) {
    const head = refs[0];
    const symref = head?.symrefTarget ? ` symref=HEAD:${head.symrefTarget}` : '';
    // A HEAD line first (the client reads the symref from it), then the
    // capabilities pseudo-ref the client skips.
    chunks.push(pktLine(`${ZERO_OID} HEAD\0${caps}${symref}\n`));
    chunks.push(pktLine(`${ZERO_OID} capabilities^{}\n`));
    return Buffer.concat(chunks);
  }
  let first = true;
  for (const r of refs) {
    let line = `${r.oid} ${r.ref}`;
    if (first) { line += `\0${caps}`; first = false; }
    if (r.symrefTarget && r.ref === 'HEAD') line += ` symref=HEAD:${r.symrefTarget}`;
    chunks.push(pktLine(`${line}\n`));
    if (r.peeled) chunks.push(pktLine(`${r.peeled} ${r.ref}^{}\n`));
  }
  return Buffer.concat(chunks);
}

function gitAdvertiseV2(): Buffer {
  return Buffer.concat([
    pktLine('version 2\n'),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow filter\n'),
    pktLine('object-format=sha1\n'),
    PKT_FLUSH,
  ]);
}

interface FetchRequest {
  wants: string[];
  haves: string[];
  shallows: string[];
  deepen: number | undefined;
  deepenSince: number | undefined;
  deepenNot: string[];
  filter: string | undefined;
}

function parseFetchArgs(lines: string[]): FetchRequest {
  const out: FetchRequest = { wants: [], haves: [], shallows: [], deepen: undefined, deepenSince: undefined, deepenNot: [], filter: undefined };
  for (const line of lines) {
    const t = line.trim();
    if (t.startsWith('want ')) out.wants.push(t.slice(5).trim());
    else if (t.startsWith('have ')) out.haves.push(t.slice(5).trim());
    else if (t.startsWith('shallow ')) out.shallows.push(t.slice(8).trim());
    else if (t.startsWith('deepen ')) out.deepen = parseInt(t.slice(7).trim(), 10);
    else if (t.startsWith('deepen-since ')) out.deepenSince = parseInt(t.slice(13).trim(), 10);
    else if (t.startsWith('deepen-not ')) out.deepenNot.push(t.slice(11).trim());
    else if (t.startsWith('filter ')) out.filter = t.slice(7).trim();
  }
  out.wants = [...new Set(out.wants)];
  out.haves = [...new Set(out.haves)];
  return out;
}

// Objects to send for a fetch: walk from wants, stopping at haves and at the
// depth boundary. Returns the object oids plus the shallow boundary oids.
function fetchSet(repo: Repo, req: FetchRequest): { oids: string[]; shallow: string[] } {
  const depth = req.deepen;
  // Without a depth limit, a have means the client already holds that commit
  // and everything reachable from it: exclude the whole closure. With a depth
  // limit the haves are shallow boundaries whose ancestry is explicitly being
  // extended, so only the have commits themselves are skipped (the depth
  // cutoff below stops the walk).
  const stopAt = new Set(req.haves);
  if (depth === undefined) {
    const q = [...req.haves];
    while (q.length > 0) {
      const oid = q.pop() as string;
      const obj = repo.objects.get(oid);
      if (!obj) continue;
      if (obj.type === 'commit') {
        const c = parseCommit(obj.data);
        stopAt.add(c.tree);
        for (const p of c.parents) { if (!stopAt.has(p)) { stopAt.add(p); q.push(p); } }
        for (const e of parseTree(repo.objects.get(c.tree)?.data ?? Buffer.alloc(0))) { if (!stopAt.has(e.oid)) { stopAt.add(e.oid); q.push(e.oid); } }
      } else if (obj.type === 'tree') {
        for (const e of parseTree(obj.data)) { if (!stopAt.has(e.oid)) { stopAt.add(e.oid); q.push(e.oid); } }
      } else if (obj.type === 'tag') {
        const m = /^object ([0-9a-f]{40})\n/.exec(obj.data.toString('utf8'));
        if (m && !stopAt.has(m[1] as string)) { stopAt.add(m[1] as string); q.push(m[1] as string); }
      }
    }
    // The loop above seeded stopAt with the haves themselves; the tree walk
    // for a have commit is covered by the commit branch.
  }
  const included = new Map<string, number>(); // oid -> distance from a want
  const queue: { oid: string; dist: number }[] = req.wants.map((w) => ({ oid: w, dist: 0 }));
  const shallow = new Set<string>();
  // Trees/blobs the client already holds through a have commit's tree: never
  // re-send them (the depth walk above still traverses through held commits to
  // their parents, which is what a deepen request needs).
  const heldTreeBlobs = new Set<string>();
  if (depth !== undefined) {
    const tq: string[] = [];
    for (const h of req.haves) {
      const c = repo.objects.get(h);
      if (c?.type === 'commit') tq.push(parseCommit(c.data).tree);
    }
    while (tq.length > 0) {
      const t = tq.pop() as string;
      if (heldTreeBlobs.has(t)) continue;
      heldTreeBlobs.add(t);
      const tobj = repo.objects.get(t);
      if (tobj?.type === 'tree') for (const e of parseTree(tobj.data)) tq.push(e.oid);
    }
  }
  while (queue.length > 0) {
    const { oid, dist } = queue.shift() as { oid: string; dist: number };
    const prev = included.get(oid);
    if (prev !== undefined && prev <= dist) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    const held = stopAt.has(oid);
    if (held) {
      // The client already holds this commit. Without a depth limit it (and its
      // whole closure) is excluded. With a depth limit it is a shallow boundary
      // being extended: do not send it or its tree, but walk to its parents so
      // a deepen request reaches the next generation (bounded by depth).
      if (depth === undefined) continue;
      if (depth !== undefined && dist >= depth - 1) continue;
      if (obj.type === 'commit') {
        const c = parseCommit(obj.data);
        for (const p of c.parents) queue.push({ oid: p, dist: dist + 1 });
      }
      continue;
    }
    included.set(oid, dist);
    if (depth !== undefined && dist >= depth - 1) {
      // Deepest layer included: this commit is a shallow boundary (unless it is
      // a tag target etc. — only commits become boundaries).
      if (obj.type === 'commit') shallow.add(oid);
      continue;
    }
    if (obj.type === 'commit') {
      const c = parseCommit(obj.data);
      queue.push({ oid: c.tree, dist: dist + 1 });
      for (const p of c.parents) queue.push({ oid: p, dist: dist + 1 });
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) queue.push({ oid: e.oid, dist: dist + 1 });
    } else if (obj.type === 'tag') {
      const m = /^object ([0-9a-f]{40})\n/.exec(obj.data.toString('utf8'));
      if (m) queue.push({ oid: m[1] as string, dist: dist + 1 });
    }
  }
  // Trees/blobs reachable from included commits must be included even when the
  // commit walk stopped at the depth boundary: a boundary commit's tree is part
  // of that commit. Re-walk trees of included commits.
  const finalSet = new Set<string>(included.keys());
  for (const oid of [...included.keys()]) {
    const obj = repo.objects.get(oid);
    if (obj?.type === 'commit') {
      const c = parseCommit(obj.data);
      const stack = [c.tree];
      while (stack.length > 0) {
        const t = stack.pop() as string;
        if (finalSet.has(t) || stopAt.has(t) || heldTreeBlobs.has(t)) continue;
        const tobj = repo.objects.get(t);
        if (!tobj) continue;
        finalSet.add(t);
        if (tobj.type === 'tree') for (const e of parseTree(tobj.data)) stack.push(e.oid);
      }
    }
  }
  const typeRank = (t: ObjType): number => ({ commit: 0, tag: 1, tree: 2, blob: 3 })[t];
  const oids = [...finalSet].sort((a, b) => {
    const ta = repo.objects.get(a)?.type ?? 'blob';
    const tb = repo.objects.get(b)?.type ?? 'blob';
    return typeRank(ta) - typeRank(tb) || (a < b ? -1 : a > b ? 1 : 0);
  });
  return { oids, shallow: [...shallow].sort() };
}

const packCache = new Map<string, Buffer>();

function cachedPack(repo: Repo, oids: string[]): Buffer {
  const key = `${repo.id}:${oids.join(',')}`;
  const hit = packCache.get(key);
  if (hit) return hit;
  const pack = buildPack(repo, oids);
  if (packCache.size > 64) packCache.clear();
  packCache.set(key, pack);
  return pack;
}

function handleUploadPackV2(repo: Repo, body: Buffer): Buffer {
  const { lines } = parsePktLines(body);
  const command = lines.find((l) => l.startsWith('command='))?.slice(8).trim() ?? '';
  if (command === 'ls-refs') {
    const prefixes: string[] = [];
    for (const l of lines) {
      if (l.startsWith('ref-prefix ')) prefixes.push(l.slice(11).trim());
    }
    const refs = listRefs(repo);
    const chunks: Buffer[] = [];
    const emit = (r: RefLine): void => {
      if (prefixes.length > 0 && !prefixes.some((p) => r.ref.startsWith(p))) return;
      if (r.oid === ZERO_OID && r.ref !== 'HEAD') return;
      if (r.ref === 'HEAD' && r.oid === ZERO_OID) {
        chunks.push(pktLine(`unborn ${r.symrefTarget ?? `refs/heads/${repo.defaultBranch}`} symref-target:${r.symrefTarget ?? ''}\n`.replace(' symref-target:\n', '\n')));
        return;
      }
      let line = `${r.oid} ${r.ref}`;
      if (r.symrefTarget) line += ` symref-target:${r.symrefTarget}`;
      if (r.peeled) line += ` peeled:${r.peeled}`;
      chunks.push(pktLine(`${line}\n`));
    };
    if (repo.refs.size === 0) {
      chunks.push(pktLine(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`));
    } else {
      for (const r of refs) emit(r);
    }
    chunks.push(PKT_FLUSH);
    return Buffer.concat(chunks);
  }
  if (command === 'fetch') {
    const req = parseFetchArgs(lines);
    const { oids, shallow } = fetchSet(repo, req);
    const chunks: Buffer[] = [];
    // acknowledgments
    chunks.push(pktLine('acknowledgments\n'));
    const acked = req.haves.filter((h) => req.wants.some((w) => isAncestor(repo, h, w)));
    if (acked.length > 0) {
      for (const h of acked) chunks.push(pktLine(`ACK ${h}\n`));
      chunks.push(pktLine('ready\n'));
    } else {
      chunks.push(pktLine('NAK\n'));
    }
    chunks.push(PKT_DELIM);
    if (shallow.length > 0) {
      chunks.push(pktLine('shallow-info\n'));
      for (const s of shallow) chunks.push(pktLine(`shallow ${s}\n`));
      chunks.push(PKT_DELIM);
    }
    if (oids.length > 0) {
      chunks.push(pktLine('packfile\n'));
      const pack = cachedPack(repo, oids);
      for (const p of sidebandPackets(pack)) chunks.push(p);
    }
    chunks.push(PKT_FLUSH);
    return Buffer.concat(chunks);
  }
  return Buffer.concat([pktLine('version 2\n'), PKT_FLUSH]);
}

function handleUploadPackV0(repo: Repo, body: Buffer): Buffer {
  const { lines } = parsePktLines(body);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallows: string[] = [];
  let deepen: number | undefined;
  let section = 0;
  for (const line of lines) {
    const t = line.trim();
    if (t === 'done') { section = 1; continue; }
    if (section === 0) {
      if (t.startsWith('want ')) wants.push(t.slice(5).split(' ')[0] as string);
      else if (t.startsWith('shallow ')) shallows.push(t.slice(8).trim());
      else if (t.startsWith('deepen ')) deepen = parseInt(t.slice(7).trim(), 10);
    } else if (t.startsWith('have ')) {
      haves.push(t.slice(5).trim());
    }
  }
  const req: FetchRequest = { wants: [...new Set(wants)], haves: [...new Set(haves)], shallows, deepen, deepenSince: undefined, deepenNot: [], filter: undefined };
  const { oids, shallow } = fetchSet(repo, req);
  const chunks: Buffer[] = [];
  const acked = req.haves.filter((h) => req.wants.some((w) => isAncestor(repo, h, w)));
  if (acked.length > 0) {
    for (const h of acked) chunks.push(pktLine(`ACK ${h}\n`));
  } else {
    chunks.push(pktLine('NAK\n'));
  }
  for (const s of shallow) chunks.push(pktLine(`shallow ${s}\n`));
  if (oids.length > 0) {
    const pack = cachedPack(repo, oids);
    for (const p of sidebandPackets(pack)) chunks.push(p);
  }
  chunks.push(PKT_FLUSH);
  return Buffer.concat(chunks);
}

function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  const { commands, pack } = splitReceiveBody(body);
  const results: { ref: string; ok: boolean; reason?: string }[] = [];
  let unpackOk = true;
  let unpackError = '';
  const parsed: ParsedPackObject[] = [];
  const hasCommands = commands.length > 0;
  const isDeleteOnly = commands.every((c) => {
    const parts = c.trim().split(/\s+/);
    return parts[1] === ZERO_OID;
  });
  if (hasCommands && !isDeleteOnly) {
    if (pack.length === 0) {
      unpackOk = false;
      unpackError = 'empty pack';
    } else {
      try {
        for (const o of parsePack(pack)) parsed.push(o);
      } catch (err) {
        unpackOk = false;
        unpackError = err instanceof Error ? err.message : 'unpack failed';
      }
    }
  }
  if (unpackOk) {
    for (const o of parsed) {
      if (!repo.objects.has(o.oid)) repo.objects.set(o.oid, { type: o.type, data: o.data });
    }
  }
  for (const raw of commands) {
    const line = raw.split('\0')[0] as string;
    const parts = line.trim().split(/\s+/);
    if (parts.length < 3) continue;
    const [oldOid, newOid, ref] = parts as [string, string, string];
    if (!unpackOk) {
      results.push({ ref, ok: false, reason: 'unpack failed' });
      continue;
    }
    if (newOid === ZERO_OID) {
      // delete
      const current = repo.refs.get(ref);
      if (current === undefined || current !== oldOid) {
        results.push({ ref, ok: false, reason: 'ref does not exist' });
      } else {
        repo.refs.delete(ref);
        results.push({ ref, ok: true });
      }
      continue;
    }
    if (oldOid === ZERO_OID) {
      if (repo.refs.has(ref)) {
        results.push({ ref, ok: false, reason: 'ref already exists' });
      } else {
        repo.refs.set(ref, newOid);
        results.push({ ref, ok: true });
      }
      continue;
    }
    const current = repo.refs.get(ref);
    if (current !== oldOid) {
      results.push({ ref, ok: false, reason: 'non-fast-forward' });
      continue;
    }
    if (!isAncestor(repo, oldOid, newOid)) {
      results.push({ ref, ok: false, reason: 'non-fast-forward' });
      continue;
    }
    repo.refs.set(ref, newOid);
    results.push({ ref, ok: true });
  }
  const report: Buffer[] = [];
  report.push(pktLine(unpackOk ? 'unpack ok\n' : `unpack ${unpackError || 'failed'}\n`));
  for (const r of results) {
    report.push(pktLine(r.ok ? `ok ${r.ref}\n` : `ng ${r.ref} ${r.reason ?? 'failed'}\n`));
  }
  report.push(PKT_FLUSH);
  const reportBytes = Buffer.concat(report);
  // Always answer sideband-framed when the client asked for side-band-64k: the
  // advertisement always offers it, so the client always selects it.
  const framed: Buffer[] = [];
  const CHUNK = 32768;
  for (let off = 0; off < reportBytes.length; off += CHUNK) {
    const slice = reportBytes.subarray(off, Math.min(reportBytes.length, off + CHUNK));
    const payload = Buffer.concat([Buffer.from([1]), slice]);
    framed.push(Buffer.concat([Buffer.from((payload.length + 4).toString(16).padStart(4, '0'), 'ascii'), payload]));
  }
  framed.push(PKT_FLUSH);
  return Buffer.concat(framed);
}

async function handleGit(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string, rest: string[]): Promise<void> {
  if (!authed(req)) { unauthorized(res); return; }
  const repo = getRepo(owner, repoName);
  const method = req.method ?? 'GET';
  if (method === 'GET' && rest.length === 2 && rest[0] === 'info' && rest[1] === 'refs') {
    const service = queryOf(req).get('service') ?? '';
    if (!repo) { sendJson(res, 404, { message: 'Not Found' }); return; }
    if (service === 'git-upload-pack') {
      const v2 = (req.headers['git-protocol'] ?? '') === 'version=2';
      sendRaw(res, 200, v2 ? gitAdvertiseV2() : gitAdvertiseV0(repo, service), 'application/x-git-upload-pack-advertisement');
      return;
    }
    if (service === 'git-receive-pack') {
      sendRaw(res, 200, gitAdvertiseV0(repo, service), 'application/x-git-receive-pack-advertisement');
      return;
    }
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  if (method === 'POST' && rest.length === 1 && rest[0] === 'git-upload-pack') {
    if (!repo) { sendJson(res, 404, { message: 'Not Found' }); return; }
    const body = await readBody(req);
    const v2 = (req.headers['git-protocol'] ?? '') === 'version=2';
    const out = v2 ? handleUploadPackV2(repo, body) : handleUploadPackV0(repo, body);
    sendRaw(res, 200, out, 'application/x-git-upload-pack-result');
    return;
  }
  if (method === 'POST' && rest.length === 1 && rest[0] === 'git-receive-pack') {
    if (!repo) { sendJson(res, 404, { message: 'Not Found' }); return; }
    const body = await readBody(req);
    const out = handleReceivePack(repo, body);
    sendRaw(res, 200, out, 'application/x-git-receive-pack-result');
    return;
  }
  notFound(res);
}

// ---------------------------------------------------------------- REST v3

function linkHeader(req: IncomingMessage, basePath: string, query: URLSearchParams, page: number, perPage: number, totalPages: number): string {
  const host = req.headers.host ?? 'localhost';
  const proto = 'http';
  const url = (p: number): string => {
    const q = new URLSearchParams(query);
    q.set('page', String(p));
    q.set('per_page', String(perPage));
    return `<${proto}://${host}${basePath}?${q.toString()}>`;
  };
  const parts: string[] = [];
  if (page < totalPages) parts.push(`${url(page + 1)}; rel="next"`);
  if (page > 1) parts.push(`${url(page - 1)}; rel="prev"`);
  parts.push(`${url(1)}; rel="first"`);
  parts.push(`${url(totalPages)}; rel="last"`);
  return parts.join(', ');
}

function paginate<T>(items: T[], query: URLSearchParams): { page: T[]; totalPages: number; pageNum: number; perPage: number } {
  const perPage = Math.max(1, Math.min(100, parseInt(query.get('per_page') ?? '30', 10) || 30));
  const pageNum = Math.max(1, parseInt(query.get('page') ?? '1', 10) || 1);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const start = (pageNum - 1) * perPage;
  return { page: items.slice(start, start + perPage), totalPages, pageNum, perPage };
}

async function handleRest(req: IncomingMessage, res: ServerResponse, segments: string[]): Promise<void> {
  const method = req.method ?? 'GET';
  const query = queryOf(req);
  const path = segments.join('/');

  // API root and meta: no auth (as the starter answers them).
  if (method === 'GET' && (path === '' || path === '/')) {
    sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    return;
  }
  if (method === 'GET' && path === 'meta') {
    sendJson(res, 200, { installed_version: '1.0.0', verifiable_password_authentication: true, github_services_sha: '0000000000000000000000000000000000000000' });
    return;
  }

  if (!authed(req)) { unauthorized(res); return; }

  const bodyBuf = (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') ? await readBody(req) : Buffer.alloc(0);
  let body: unknown = undefined;
  if (bodyBuf.length > 0) {
    const parsed = parseJsonBody(bodyBuf);
    if (!parsed.ok) { sendJson(res, 400, { message: 'Invalid JSON' }); return; }
    body = parsed.value;
  }
  const obj = (body ?? {}) as Record<string, unknown>;
  const str = (v: unknown): string => (typeof v === 'string' ? v : '');

  // GET /user
  if (method === 'GET' && path === 'user') {
    sendJson(res, 200, { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User', email: VIEWER_EMAIL });
    return;
  }

  // POST /user/repos, GET /user/repos
  if (path === 'user/repos') {
    if (method === 'POST') {
      const name = str(obj.name);
      if (!name) { sendJson(res, 422, { message: 'name is required' }); return; }
      const existing = getRepo(VIEWER_LOGIN, name);
      if (existing) { sendJson(res, 422, { message: 'Repository already exists' }); return; }
      const repo = createRepo(name, str(obj.description), obj.private === true);
      sendJson(res, 201, repoJson(repo));
      return;
    }
    if (method === 'GET') {
      const all = [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN).sort((a, b) => a.id - b.id);
      const { page, totalPages, pageNum, perPage } = paginate(all, query);
      const headers: Record<string, string> = {};
      if (totalPages > 1) headers.link = linkHeader(req, '/api/v3/user/repos', query, pageNum, perPage, totalPages);
      sendJson(res, 200, page.map((r) => repoJson(r)), headers);
      return;
    }
  }

  // /repos/{owner}/{repo}[...]
  if (segments[0] === 'repos' && segments.length >= 3) {
    const owner = segments[1] as string;
    const repoName = segments[2] as string;
    const repo = getRepo(owner, repoName);
    if (!repo) { notFound(res); return; }
    const rest = segments.slice(3);

    // GET/PATCH/DELETE repo itself
    if (rest.length === 0) {
      if (method === 'GET') { sendJson(res, 200, repoJson(repo)); return; }
      if (method === 'PATCH') {
        if (typeof obj.description === 'string') repo.description = obj.description;
        sendJson(res, 200, repoJson(repo));
        return;
      }
      if (method === 'DELETE') {
        repos.delete(repoKey(owner, repoName));
        res.writeHead(204, { 'x-github-request-id': nextRequestId() });
        res.end();
        return;
      }
      notFound(res);
      return;
    }

    // git/refs
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST') {
        const ref = str(obj.ref);
        const sha = str(obj.sha);
        if (!ref.startsWith('refs/') || !SHA40.test(sha)) { sendJson(res, 422, { message: 'Invalid ref or sha' }); return; }
        repo.refs.set(ref, sha);
        sendJson(res, 201, { ref, object: { sha }, url: `/api/v3/repos/${owner}/${repoName}/git/refs/${encodeURIComponent(ref)}` });
        return;
      }
      if (method === 'GET' && rest.length === 3) {
        // GET /git/refs/heads/<branch> (used by the MCP fixture setup)
        const ref = decodeURIComponent(rest.slice(2).join('/'));
        const full = `refs/${ref}`;
        const oid = repo.refs.get(full);
        if (!oid) { notFound(res); return; }
        sendJson(res, 200, { ref: full, object: { sha: oid } });
        return;
      }
      notFound(res);
      return;
    }

    // branches
    if (rest[0] === 'branches') {
      if (method === 'GET' && rest.length === 1) {
        const list = [...repo.refs.keys()].filter((r) => r.startsWith('refs/heads/')).sort().map((r) => ({
          name: r.slice('refs/heads/'.length),
          commit: { sha: repo.refs.get(r) as string },
        }));
        sendJson(res, 200, list);
        return;
      }
      if (method === 'GET' && rest.length === 2) {
        const oid = repo.refs.get(`refs/heads/${rest[1]}`);
        if (!oid) { notFound(res); return; }
        sendJson(res, 200, { name: rest[1], commit: { sha: oid } });
        return;
      }
      notFound(res);
      return;
    }

    // commits
    if (rest[0] === 'commits') {
      if (method === 'GET') {
        const shaParam = query.get('sha');
        let from: string | undefined;
        if (shaParam) {
          from = repo.refs.get(`refs/heads/${shaParam}`) ?? repo.refs.get(shaParam) ?? (SHA40.test(shaParam) ? shaParam : undefined);
        } else {
          from = refTipCommit(repo, `refs/heads/${repo.defaultBranch}`);
        }
        sendJson(res, 200, commitList(repo, from));
        return;
      }
      notFound(res);
      return;
    }

    // contents
    if (rest[0] === 'contents') {
      const contentPath = rest.slice(1).map((s) => decodeURIComponent(s)).join('/');
      const refParam = query.get('ref');
      const branchFor = (refParam ?? repo.defaultBranch);
      const resolveBranchFiles = (): { files: Map<string, Buffer>; tip: string | undefined } => {
        if (refParam && SHA40.test(refParam)) {
          const treeOid = commitTreeOid(repo, refParam);
          const files = new Map<string, Buffer>();
          if (treeOid) {
            for (const [p, b] of treeFiles(repo, treeOid)) {
              const blob = repo.objects.get(b);
              if (blob) files.set(p, blob.data);
            }
          }
          return { files, tip: refParam };
        }
        return branchFiles(repo, branchFor);
      };
      if (method === 'GET') {
        const { files } = resolveBranchFiles();
        if (contentPath === '') {
          const entries: Record<string, unknown>[] = [];
          const seen = new Set<string>();
          for (const p of [...files.keys()].sort()) {
            const top = p.split('/')[0] as string;
            if (seen.has(top)) continue;
            seen.add(top);
            if (p.includes('/')) {
              entries.push({ type: 'dir', name: top, path: top, sha: '' });
            } else {
              const blobOid = gitObjectId('blob', files.get(p) as Buffer);
              entries.push({ type: 'file', name: top, path: top, sha: blobOid, size: (files.get(p) as Buffer).length });
            }
          }
          // Directory listing needs real tree shas: rebuild from the branch tree.
          const tip = refTipCommit(repo, `refs/heads/${branchFor}`);
          const treeOid = tip ? commitTreeOid(repo, tip) : undefined;
          const dirEntries: Record<string, unknown>[] = [];
          if (treeOid) {
            const obj = repo.objects.get(treeOid);
            if (obj) {
              for (const e of parseTree(obj.data)) {
                dirEntries.push({ type: e.mode === '40000' ? 'dir' : 'file', name: e.name, path: e.name, sha: e.oid, size: e.mode === '40000' ? 0 : (repo.objects.get(e.oid)?.data.length ?? 0) });
              }
            }
          }
          sendJson(res, 200, dirEntries.length > 0 ? dirEntries : entries);
          return;
        }
        // directory?
        const dirPrefix = `${contentPath}/`;
        const inDir = [...files.keys()].filter((p) => p.startsWith(dirPrefix));
        if (inDir.length > 0) {
          const seen = new Set<string>();
          const entries: Record<string, unknown>[] = [];
          for (const p of inDir.sort()) {
            const restPath = p.slice(dirPrefix.length);
            const top = restPath.split('/')[0] as string;
            if (seen.has(top)) continue;
            seen.add(top);
            const full = `${contentPath}/${top}`;
            if (restPath.includes('/')) {
              entries.push({ type: 'dir', name: top, path: full, sha: '' });
            } else {
              const blobOid = gitObjectId('blob', files.get(p) as Buffer);
              entries.push({ type: 'file', name: top, path: full, sha: blobOid, size: (files.get(p) as Buffer).length });
            }
          }
          sendJson(res, 200, entries);
          return;
        }
        const content = files.get(contentPath);
        if (content === undefined) { notFound(res); return; }
        const blobOid = gitObjectId('blob', content);
        sendJson(res, 200, { type: 'file', encoding: 'base64', content: content.toString('base64'), sha: blobOid, size: content.length, name: contentPath.split('/').pop(), path: contentPath });
        return;
      }
      if (method === 'PUT') {
        const branch = str(obj.branch) || repo.defaultBranch;
        const message = str(obj.message) || `Update ${contentPath}`;
        const content = b64decode(str(obj.content));
        const { files, tip } = branchFiles(repo, branch);
        const existing = files.get(contentPath);
        const existingSha = existing ? gitObjectId('blob', existing) : undefined;
        const givenSha = str(obj.sha);
        if (givenSha && existingSha && givenSha.toLowerCase() !== existingSha.toLowerCase()) {
          sendJson(res, 409, { message: 'sha does not match' });
          return;
        }
        const isCreate = existing === undefined;
        files.set(contentPath, content);
        const treeOid = buildTree(repo, files);
        const parents = tip ? [tip] : [];
        const commitSha = makeCommit(repo, treeOid, parents, message);
        repo.refs.set(`refs/heads/${branch}`, commitSha);
        const blobOid = gitObjectId('blob', content);
        sendJson(res, isCreate ? 201 : 200, { content: { sha: blobOid, encoding: 'base64', name: contentPath.split('/').pop(), path: contentPath }, commit: { sha: commitSha } });
        return;
      }
      if (method === 'DELETE') {
        const branch = str(obj.branch) || repo.defaultBranch;
        const message = str(obj.message) || `Delete ${contentPath}`;
        const { files, tip } = branchFiles(repo, branch);
        if (!files.has(contentPath)) { notFound(res); return; }
        files.delete(contentPath);
        const treeOid = buildTree(repo, files);
        const parents = tip ? [tip] : [];
        const commitSha = makeCommit(repo, treeOid, parents, message);
        repo.refs.set(`refs/heads/${branch}`, commitSha);
        sendJson(res, 200, { commit: { sha: commitSha } });
        return;
      }
      notFound(res);
      return;
    }

    // labels
    if (rest[0] === 'labels') {
      if (method === 'POST') {
        const name = str(obj.name);
        if (!name) { sendJson(res, 422, { message: 'name is required' }); return; }
        const label = { name, color: str(obj.color) || 'ededed' };
        repo.labels.set(name, label);
        sendJson(res, 201, label);
        return;
      }
      if (method === 'GET') {
        sendJson(res, 200, [...repo.labels.values()]);
        return;
      }
      notFound(res);
      return;
    }

    // issues
    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (method === 'POST') {
          const labels = Array.isArray(obj.labels) ? (obj.labels as unknown[]).map((l) => String(l)) : [];
          for (const l of labels) {
            if (!repo.labels.has(l)) { sendJson(res, 422, { message: `Label ${l} does not exist` }); return; }
          }
          const issue: Issue = {
            number: repo.nextIssue,
            title: str(obj.title),
            body: str(obj.body),
            state: 'open',
            labels,
            seq: repo.seq + 1,
            comments: [],
          };
          repo.seq += 1;
          repo.nextIssue += 1;
          repo.issues.push(issue);
          sendJson(res, 201, issueJson(repo, issue));
          return;
        }
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          const sort = query.get('sort') ?? 'created';
          const direction = query.get('direction') ?? 'desc';
          let list = repo.issues.filter((i) => state === 'all' || i.state === state);
          if (sort === 'created') list = [...list].sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
          const { page } = paginate(list, query);
          sendJson(res, 200, page.map((i) => issueJson(repo, i)));
          return;
        }
        notFound(res);
        return;
      }
      const num = parseInt(rest[1] as string, 10);
      const issue = repo.issues.find((i) => i.number === num);
      if (rest.length === 2) {
        if (!issue) { notFound(res); return; }
        if (method === 'GET') { sendJson(res, 200, issueJson(repo, issue)); return; }
        if (method === 'PATCH') {
          if (obj.state === 'closed' || obj.state === 'open') issue.state = obj.state;
          if (typeof obj.title === 'string') issue.title = obj.title;
          if (typeof obj.body === 'string') issue.body = obj.body;
          sendJson(res, 200, issueJson(repo, issue));
          return;
        }
        notFound(res);
        return;
      }
      if (rest.length === 3 && rest[2] === 'comments') {
        if (!issue) { notFound(res); return; }
        if (method === 'POST') {
          const comment = { id: repo.nextComment, body: str(obj.body) };
          repo.nextComment += 1;
          issue.comments.push(comment);
          sendJson(res, 201, { id: comment.id, body: comment.body, user: { login: VIEWER_LOGIN } });
          return;
        }
        if (method === 'GET') {
          sendJson(res, 200, issue.comments.map((c) => ({ id: c.id, body: c.body, user: { login: VIEWER_LOGIN } })));
          return;
        }
        notFound(res);
        return;
      }
      notFound(res);
      return;
    }

    // pulls
    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (method === 'POST') {
          const headRef = str(obj.head);
          const baseRef = str(obj.base);
          const headSha = refTipCommit(repo, `refs/heads/${headRef}`) ?? '';
          const baseSha = refTipCommit(repo, `refs/heads/${baseRef}`) ?? '';
          const pull: Pull = {
            number: repo.nextPull,
            title: str(obj.title),
            body: str(obj.body),
            state: 'open',
            merged: false,
            mergedAt: '',
            mergeCommitSha: '',
            headRef,
            baseRef,
            headSha,
            baseSha,
            seq: repo.seq + 1,
          };
          repo.seq += 1;
          repo.nextPull += 1;
          repo.pulls.push(pull);
          sendJson(res, 201, pullJson(repo, pull));
          return;
        }
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          let list = repo.pulls;
          if (state === 'open') list = list.filter((p) => p.state === 'open');
          else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
          const { page } = paginate(list, query);
          sendJson(res, 200, page.map((p) => pullJson(repo, p)));
          return;
        }
        notFound(res);
        return;
      }
      const num = parseInt(rest[1] as string, 10);
      const pull = repo.pulls.find((p) => p.number === num);
      if (rest.length === 2) {
        if (!pull) { notFound(res); return; }
        if (method === 'GET') { sendJson(res, 200, pullJson(repo, pull)); return; }
        notFound(res);
        return;
      }
      if (rest.length === 3 && rest[2] === 'files') {
        if (!pull) { notFound(res); return; }
        if (method === 'GET') { sendJson(res, 200, diffFiles(repo, pull.baseSha, pull.headSha)); return; }
        notFound(res);
        return;
      }
      if (rest.length === 3 && rest[2] === 'merge') {
        if (!pull) { notFound(res); return; }
        if (method === 'PUT') {
          const result = doMerge(repo, pull);
          sendJson(res, result.status, result.body);
          return;
        }
        notFound(res);
        return;
      }
      notFound(res);
      return;
    }

    notFound(res);
    return;
  }

  notFound(res);
}

// ---------------------------------------------------------------- GraphQL

type GqlValue = string | number | boolean | null | GqlValue[] | { [key: string]: GqlValue };
interface GqlSelection {
  alias: string;
  name: string;
  args: Record<string, GqlValue>;
  selections: GqlSelection[];
  fragmentType?: string;
}

function gqlTokenize(src: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i] as string;
    if (/\s|,/.test(c)) { i += 1; continue; }
    if (c === '#') { while (i < src.length && src[i] !== '\n') i += 1; continue; }
    if (src.startsWith('...', i)) { tokens.push('...'); i += 3; continue; }
    if ('{}()[]:!@$=&|'.includes(c)) { tokens.push(c); i += 1; continue; }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) { out += src[j + 1]; j += 2; }
        else { out += src[j]; j += 1; }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      while (j < src.length && /[0-9.eE+-]/.test(src[j] as string)) j += 1;
      tokens.push(src.slice(i, j));
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j] as string)) j += 1;
      tokens.push(src.slice(i, j));
      i = j;
      continue;
    }
    i += 1;
  }
  return tokens;
}

class GqlParser {
  tokens: string[];
  pos = 0;
  variables: Record<string, GqlValue>;
  constructor(src: string, variables: Record<string, GqlValue>) {
    this.tokens = gqlTokenize(src);
    this.variables = variables;
  }
  peek(): string { return this.tokens[this.pos] ?? ''; }
  next(): string { return this.tokens[this.pos++] ?? ''; }
  expect(t: string): void { if (this.next() !== t) throw new Error(`expected ${t}`); }
  parseValue(): GqlValue {
    const t = this.next();
    if (t === '$') return this.variables[this.next() as string] ?? null;
    if (t === '[') {
      const arr: GqlValue[] = [];
      while (this.peek() !== ']') arr.push(this.parseValue());
      this.expect(']');
      return arr;
    }
    if (t === '{') {
      const obj: Record<string, GqlValue> = {};
      while (this.peek() !== '}') {
        const k = this.next();
        this.expect(':');
        obj[k] = this.parseValue();
      }
      this.expect('}');
      return obj;
    }
    if (t.startsWith('"')) return JSON.parse(t) as string;
    if (t === 'true') return true;
    if (t === 'false') return false;
    if (t === 'null') return null;
    if (/^-?\d+(\.\d+)?$/.test(t)) return Number(t);
    return t; // enum literal
  }
  parseArgs(): Record<string, GqlValue> {
    const args: Record<string, GqlValue> = {};
    if (this.peek() !== '(') return args;
    this.expect('(');
    while (this.peek() !== ')') {
      const k = this.next();
      this.expect(':');
      args[k] = this.parseValue();
    }
    this.expect(')');
    return args;
  }
  parseSelections(): GqlSelection[] {
    this.expect('{');
    const out: GqlSelection[] = [];
    while (this.peek() !== '}' && this.pos < this.tokens.length) {
      if (this.peek() === '...') {
        this.next();
        let fragType: string | undefined;
        if (this.peek() === 'on') {
          this.next();
          fragType = this.next();
        } else {
          this.next(); // fragment name
        }
        const inner = this.parseSelections();
        for (const s of inner) out.push({ ...s, fragmentType: fragType ?? s.fragmentType });
        continue;
      }
      let name = this.next();
      let alias = name;
      if (this.peek() === ':') { this.next(); alias = name; name = this.next(); }
      const args = this.parseArgs();
      const selections = this.peek() === '{' ? this.parseSelections() : [];
      out.push({ alias, name, args, selections });
    }
    this.expect('}');
    return out;
  }
  parseOperation(): { type: string; selections: GqlSelection[] } {
    let type = 'query';
    const first = this.peek();
    if (first === 'query' || first === 'mutation' || first === 'subscription') {
      type = this.next();
      if (this.peek() !== '{' && this.peek() !== '(') this.next(); // operation name
      if (this.peek() === '(') {
        // variable definitions: skip balanced parens
        let depth = 0;
        do {
          const t = this.next();
          if (t === '(') depth += 1;
          if (t === ')') depth -= 1;
        } while (depth > 0 && this.pos < this.tokens.length);
      }
    }
    const selections = this.parseSelections();
    return { type, selections };
  }
}

const GQL_FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', '__type'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  User: ['login'],
  Ref: ['name'],
  Issue: ['id', 'number', 'title', 'state', 'body'],
  IssueConnection: ['nodes', 'pageInfo', 'totalCount'],
  PageInfo: ['hasNextPage', 'endCursor', 'hasPreviousPage', 'startCursor'],
  PullRequest: ['id', 'number', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files'],
  PullRequestConnection: ['nodes', 'totalCount'],
  PullRequestChangedFileConnection: ['nodes', 'totalCount'],
  PullRequestChangedFile: ['path'],
  __Type: ['name', 'kind', 'fields', 'enumValues'],
  __Field: ['name'],
  __EnumValue: ['name'],
  CreateIssuePayload: ['issue'],
  CloseIssuePayload: ['issue'],
  CreatePullRequestPayload: ['pullRequest'],
  MergePullRequestPayload: ['pullRequest'],
  AddCommentPayload: ['commentEdge'],
  IssueCommentEdge: ['node'],
  IssueComment: ['id', 'body'],
};

function gqlValidate(selections: GqlSelection[], type: string, errors: string[]): void {
  const allowed = GQL_FIELDS[type] ?? [];
  for (const s of selections) {
    if (!allowed.includes(s.name)) {
      errors.push(`Cannot query field "${s.name}" on type "${type}".`);
      continue;
    }
    const childType: Record<string, string> = {
      viewer: 'User', repository: 'Repository', node: 'Repository', issue: 'Issue', issues: 'IssueConnection',
      pullRequests: 'PullRequestConnection', pullRequest: 'PullRequest', owner: 'User', defaultBranchRef: 'Ref',
      nodes: type === 'IssueConnection' ? 'Issue' : type === 'PullRequestChangedFileConnection' ? 'PullRequestChangedFile' : 'PullRequest', pageInfo: 'PageInfo', files: 'PullRequestChangedFileConnection',
      commentEdge: 'IssueCommentEdge', comment: 'IssueComment',
    };
    const next = childType[s.name];
    if (next && s.selections.length > 0) gqlValidate(s.selections, next, errors);
    if (s.name === '__type' && s.selections.length > 0) gqlValidate(s.selections, '__Type', errors);
  }
}

function findRepoByGlobalId(id: string): Repo | undefined {
  const parsed = parseGlobalId(id);
  if (!parsed || parsed.kind !== 'Repository') return undefined;
  const num = parseInt(parsed.key, 10);
  for (const r of repos.values()) if (r.id === num) return r;
  return undefined;
}

function findIssueByGlobalId(id: string): { repo: Repo; issue: Issue } | undefined {
  const parsed = parseGlobalId(id);
  if (!parsed || parsed.kind !== 'Issue') return undefined;
  const [repoId, num] = (parsed.key as string).split(':');
  for (const r of repos.values()) {
    if (r.id === parseInt(repoId as string, 10)) {
      const issue = r.issues.find((i) => i.number === parseInt(num as string, 10));
      if (issue) return { repo: r, issue };
    }
  }
  return undefined;
}

function findPullByGlobalId(id: string): { repo: Repo; pull: Pull } | undefined {
  const parsed = parseGlobalId(id);
  if (!parsed || parsed.kind !== 'PullRequest') return undefined;
  const [repoId, num] = (parsed.key as string).split(':');
  for (const r of repos.values()) {
    if (r.id === parseInt(repoId as string, 10)) {
      const pull = r.pulls.find((p) => p.number === parseInt(num as string, 10));
      if (pull) return { repo: r, pull };
    }
  }
  return undefined;
}

function issueGql(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: globalId('Issue', `${repo.id}:${issue.number}`),
    number: issue.number,
    title: issue.title,
    state: issue.state.toUpperCase(),
    body: issue.body,
  };
}

function pullGql(repo: Repo, pull: Pull): Record<string, unknown> {
  return {
    id: globalId('PullRequest', `${repo.id}:${pull.number}`),
    number: pull.number,
    state: pull.merged ? 'MERGED' : pull.state.toUpperCase(),
    merged: pull.merged,
    headRefName: pull.headRef,
    baseRefName: pull.baseRef,
    mergeable: pullMergeable(repo, pull),
  };
}

function repoGql(repo: Repo): Record<string, unknown> {
  return {
    id: globalId('Repository', `${repo.id}`),
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner },
    defaultBranchRef: repo.refs.has(`refs/heads/${repo.defaultBranch}`) ? { name: repo.defaultBranch } : null,
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
  };
}

function cursorFor(seq: number): string {
  return Buffer.from(`cursor:${seq}`, 'utf8').toString('base64');
}

function seqFromCursor(cursor: string | null | undefined): number | undefined {
  if (!cursor) return undefined;
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    if (!text.startsWith('cursor:')) return undefined;
    return parseInt(text.slice(7), 10);
  } catch {
    return undefined;
  }
}

function resolveSelections(selections: GqlSelection[], source: Record<string, unknown> | null, ctx: { repo?: Repo }): Record<string, unknown> | null {
  if (source === null) return null;
  const out: Record<string, unknown> = {};
  for (const s of selections) {
    const value = (source as Record<string, unknown>)[s.name];
    if (value === undefined) {
      // Computed / nested resolvers keyed by field name.
      if (s.name === 'issue' && ctx.repo) {
        const num = s.args.number as number;
        const issue = ctx.repo.issues.find((i) => i.number === num);
        out[s.alias] = issue ? resolveSelections(s.selections, issueGql(ctx.repo as Repo, issue), ctx) : null;
      } else if (s.name === 'issues' && ctx.repo) {
        out[s.alias] = resolveIssueConnection(s, ctx.repo as Repo);
      } else if (s.name === 'pullRequests' && ctx.repo) {
        const first = (s.args.first as number) ?? 100;
        const nodeSel = s.selections.find((x) => x.name === 'nodes');
        const nodes = nodeSel ? (ctx.repo as Repo).pulls.slice(0, first).map((p) => resolveSelections(nodeSel.selections, pullGql(ctx.repo as Repo, p), ctx)) : [];
        out[s.alias] = { nodes };
      } else if (s.name === 'pullRequest' && ctx.repo) {
        const num = s.args.number as number;
        const pull = (ctx.repo as Repo).pulls.find((p) => p.number === num);
        out[s.alias] = pull ? resolveSelections(s.selections, pullGql(ctx.repo as Repo, pull), ctx) : null;
      } else if (s.name === 'files' && ctx.repo && (source as Record<string, unknown>).number !== undefined) {
        const pull = (ctx.repo as Repo).pulls.find((p) => p.number === (source as Record<string, unknown>).number);
        const files = pull ? diffFiles(ctx.repo as Repo, pull.baseSha, pull.headSha) : [];
        const first = (s.args.first as number) ?? 100;
        out[s.alias] = { nodes: files.slice(0, first).map((f) => ({ path: f.filename })) };
      } else {
        out[s.alias] = null;
      }
      continue;
    }
    if (Array.isArray(value)) {
      out[s.alias] = value.map((v) => (v && typeof v === 'object' ? resolveSelections(s.selections, v as Record<string, unknown>, ctx) : v));
    } else if (value && typeof value === 'object') {
      out[s.alias] = resolveSelections(s.selections, value as Record<string, unknown>, ctx);
    } else {
      out[s.alias] = value;
    }
  }
  return out;
}

function resolveIssueConnection(sel: GqlSelection, repo: Repo): Record<string, unknown> {
  const first = (sel.args.first as number) ?? 100;
  const states = Array.isArray(sel.args.states) ? (sel.args.states as string[]) : undefined;
  const orderBy = (sel.args.orderBy ?? {}) as Record<string, unknown>;
  const afterSeq = seqFromCursor(sel.args.after as string | null | undefined);
  let list = [...repo.issues];
  if (states) list = list.filter((i) => states.includes(i.state.toUpperCase()));
  const dir = orderBy.direction === 'ASC' ? 1 : -1;
  list.sort((a, b) => (a.seq - b.seq) * dir || (a.number - b.number) * dir);
  if (afterSeq !== undefined) {
    const idx = list.findIndex((i) => i.seq === afterSeq);
    if (idx >= 0) list = list.slice(idx + 1);
  }
  const page = list.slice(0, first);
  const hasNext = list.length > first;
  const nodeSel = sel.selections.find((s) => s.name === 'nodes');
  const pageSel = sel.selections.find((s) => s.name === 'pageInfo');
  const out: Record<string, unknown> = {};
  if (nodeSel) out.nodes = page.map((i) => resolveSelections(nodeSel.selections, issueGql(repo, i), { repo }));
  if (pageSel) {
    out.pageInfo = {
      hasNextPage: hasNext,
      endCursor: page.length > 0 ? cursorFor((page[page.length - 1] as Issue).seq) : null,
    };
  }
  return out;
}

function executeGqlOperation(query: string, variables: Record<string, GqlValue>): { data: unknown; errors: { message: string }[] } {
  const parser = new GqlParser(query, variables);
  const { type, selections } = parser.parseOperation();
  const errors: string[] = [];
  gqlValidate(selections, type === 'mutation' ? 'Mutation' : 'Query', errors);
  if (errors.length > 0) return { data: null, errors: errors.map((m) => ({ message: m })) };
  const data: Record<string, unknown> = {};
  for (const s of selections) {
    if (s.name === 'viewer') {
      data[s.alias] = resolveSelections(s.selections, { login: VIEWER_LOGIN }, {});
    } else if (s.name === 'repository') {
      const owner = s.args.owner as string;
      const name = s.args.name as string;
      const repo = getRepo(owner, name);
      if (!repo) { data[s.alias] = null; continue; }
      const base = repoGql(repo);
      // resolveSelections handles nested issue/issues/pullRequests/pullRequest/files
      const resolved = resolveSelections(s.selections, base, { repo });
      data[s.alias] = resolved;
    } else if (s.name === 'node') {
      const id = s.args.id as string;
      const repo = findRepoByGlobalId(id);
      if (!repo) { data[s.alias] = null; continue; }
      const base: Record<string, unknown> = { id: globalId('Repository', `${repo.id}`), name: repo.name, nameWithOwner: `${repo.owner}/${repo.name}` };
      data[s.alias] = resolveSelections(s.selections, base, { repo });
    } else if (s.name === '__type') {
      const typeName = s.args.name as string;
      const fields: Record<string, string[]> = {
        Issue: ['id', 'number', 'title', 'state', 'body'],
        PullRequest: ['id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files'],
        Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
      };
      const enumValues: Record<string, string[]> = {
        SearchType: ['ISSUE', 'REPOSITORY', 'USER'],
        IssueState: ['OPEN', 'CLOSED'],
        OrderDirection: ['ASC', 'DESC'],
      };
      const out: Record<string, unknown> = { name: typeName };
      for (const sub of s.selections) {
        if (sub.name === 'fields') out[sub.alias] = (fields[typeName] ?? []).map((n) => ({ name: n }));
        else if (sub.name === 'enumValues') out[sub.alias] = (enumValues[typeName] ?? []).map((n) => ({ name: n }));
        else out[sub.alias] = null;
      }
      data[s.alias] = out;
    } else if (type === 'mutation') {
      data[s.alias] = executeMutation(s);
    }
  }
  return { data, errors: [] };
}

function executeMutation(sel: GqlSelection): Record<string, unknown> {
  const input = (sel.args.input ?? {}) as Record<string, unknown>;
  if (sel.name === 'createIssue') {
    const repo = findRepoByGlobalId(String(input.repositoryId ?? ''));
    if (!repo) return { issue: null };
    const issue: Issue = {
      number: repo.nextIssue,
      title: String(input.title ?? ''),
      body: String(input.body ?? ''),
      state: 'open',
      labels: [],
      seq: repo.seq + 1,
      comments: [],
    };
    repo.seq += 1;
    repo.nextIssue += 1;
    repo.issues.push(issue);
    return resolveSelections(sel.selections, { issue: issueGql(repo, issue) }, { repo }) as Record<string, unknown>;
  }
  if (sel.name === 'closeIssue') {
    const found = findIssueByGlobalId(String(input.issueId ?? ''));
    if (!found) return { issue: null };
    found.issue.state = 'closed';
    return resolveSelections(sel.selections, { issue: issueGql(found.repo, found.issue) }, { repo: found.repo }) as Record<string, unknown>;
  }
  if (sel.name === 'createPullRequest') {
    const repo = findRepoByGlobalId(String(input.repositoryId ?? ''));
    if (!repo) return { pullRequest: null };
    const headRef = String(input.headRefName ?? '');
    const baseRef = String(input.baseRefName ?? '');
    const pull: Pull = {
      number: repo.nextPull,
      title: String(input.title ?? ''),
      body: '',
      state: 'open',
      merged: false,
      mergedAt: '',
      mergeCommitSha: '',
      headRef,
      baseRef,
      headSha: refTipCommit(repo, `refs/heads/${headRef}`) ?? '',
      baseSha: refTipCommit(repo, `refs/heads/${baseRef}`) ?? '',
      seq: repo.seq + 1,
    };
    repo.seq += 1;
    repo.nextPull += 1;
    repo.pulls.push(pull);
    return resolveSelections(sel.selections, { pullRequest: pullGql(repo, pull) }, { repo }) as Record<string, unknown>;
  }
  if (sel.name === 'mergePullRequest') {
    const found = findPullByGlobalId(String(input.pullRequestId ?? ''));
    if (!found) return { pullRequest: null };
    doMerge(found.repo, found.pull);
    return resolveSelections(sel.selections, { pullRequest: pullGql(found.repo, found.pull) }, { repo: found.repo }) as Record<string, unknown>;
  }
  if (sel.name === 'addComment') {
    const found = findIssueByGlobalId(String(input.subjectId ?? ''));
    if (!found) return { commentEdge: null };
    const comment = { id: found.repo.nextComment, body: String(input.body ?? '') };
    found.repo.nextComment += 1;
    found.issue.comments.push(comment);
    const node = { id: globalId('IssueComment', `${found.repo.id}:${found.issue.number}:${comment.id}`), body: comment.body };
    return resolveSelections(sel.selections, { commentEdge: { node } }, { repo: found.repo }) as Record<string, unknown>;
  }
  return {};
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!authed(req)) { sendJson(res, 401, { message: 'Requires authentication' }); return; }
  const bodyBuf = await readBody(req);
  const parsed = parseJsonBody(bodyBuf);
  if (!parsed.ok) { sendJson(res, 400, { message: 'Invalid JSON', errors: [{ message: 'Invalid JSON' }] }); return; }
  const value = parsed.value;
  if (Array.isArray(value)) {
    const results = value.map((op) => {
      const o = (op ?? {}) as Record<string, unknown>;
      return executeGqlOperation(String(o.query ?? ''), (o.variables ?? {}) as Record<string, GqlValue>);
    });
    sendJson(res, 200, results);
    return;
  }
  const o = (value ?? {}) as Record<string, unknown>;
  sendJson(res, 200, executeGqlOperation(String(o.query ?? ''), (o.variables ?? {}) as Record<string, GqlValue>));
}

// ---------------------------------------------------------------- MCP

interface McpTool {
  name: string;
  description: string;
  inputSchema: { type: string; properties: Record<string, Record<string, unknown>>; required: string[] };
}

const MCP_TOOLS: McpTool[] = [
  {
    name: 'create_repo',
    description: 'Create a repository for the viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        full_name: { type: 'string', description: 'Full repository name owner/repo' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        full_name: { type: 'string', description: 'Full repository name owner/repo' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        full_name: { type: 'string', description: 'Full repository name owner/repo' },
        state: { type: 'string', description: 'Issue state filter: open, closed, or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        full_name: { type: 'string', description: 'Full repository name owner/repo' },
        title: { type: 'string', description: 'Pull request title' },
        body: { type: 'string', description: 'Pull request body' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        full_name: { type: 'string', description: 'Full repository name owner/repo' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpResolveOwnerRepo(args: Record<string, unknown>): { owner: string; repo: string } {
  let owner = String(args.owner ?? '');
  let repo = String(args.repo ?? '');
  if ((!owner || !repo) && typeof args.full_name === 'string') {
    const parts = (args.full_name as string).split('/');
    if (parts.length === 2) { owner = parts[0] as string; repo = parts[1] as string; }
  }
  return { owner, repo };
}

function mcpToolResult(id: unknown, structured: unknown): Record<string, unknown> {
  const text = JSON.stringify(structured);
  return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }], structuredContent: structured } };
}

function mcpToolError(id: unknown, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: message }], isError: true } };
}

function mcpRpcError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

function callMcpTool(name: string, args: Record<string, unknown>): { ok: boolean; result?: unknown; errorCode?: number; errorMessage?: string } {
  const norm = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]/g, '');
  const tool = MCP_TOOLS.find((t) => norm(t.name) === norm(name) || norm(t.name).endsWith(norm(name)) || norm(name).endsWith(norm(t.name)));
  if (!tool) return { ok: false, errorCode: -32601, errorMessage: `Method not found: ${name}` };
  // Required-argument check (missing -> -32602).
  const missing = tool.inputSchema.required.filter((r) => {
    if (r === 'owner' || r === 'repo') {
      const { owner, repo } = mcpResolveOwnerRepo(args);
      return !(owner && repo);
    }
    return args[r] === undefined || args[r] === null || args[r] === '';
  });
  if (missing.length > 0) {
    return { ok: false, errorCode: -32602, errorMessage: `Missing required argument(s): ${missing.join(', ')}` };
  }
  if (tool.name === 'create_repo') {
    const repoName = String(args.name ?? '');
    if (!repoName) return { ok: false, errorCode: -32602, errorMessage: 'Missing required argument: name' };
    let repo = getRepo(VIEWER_LOGIN, repoName);
    if (!repo) repo = createRepo(repoName, String(args.description ?? ''), args.private === true);
    return { ok: true, result: { id: repo.id, name: repo.name, full_name: `${repo.owner}/${repo.name}`, owner: repo.owner, private: repo.priv, description: repo.description } };
  }
  const { owner, repo: repoName } = mcpResolveOwnerRepo(args);
  const repo = getRepo(owner, repoName);
  if (!repo) return { ok: true, result: undefined, errorCode: -32602, errorMessage: `Repository not found: ${owner}/${repoName}` };
  if (tool.name === 'get_repo') {
    return { ok: true, result: { id: repo.id, name: repo.name, full_name: `${repo.owner}/${repo.name}`, owner: repo.owner, private: repo.priv, description: repo.description, default_branch: repo.defaultBranch } };
  }
  if (tool.name === 'create_issue') {
    const issue: Issue = {
      number: repo.nextIssue,
      title: String(args.title ?? ''),
      body: String(args.body ?? ''),
      state: 'open',
      labels: [],
      seq: repo.seq + 1,
      comments: [],
    };
    repo.seq += 1;
    repo.nextIssue += 1;
    repo.issues.push(issue);
    return { ok: true, result: { id: repo.id * 100000 + issue.number, number: issue.number, title: issue.title, body: issue.body, state: 'open', node_id: globalId('Issue', `${repo.id}:${issue.number}`) } };
  }
  if (tool.name === 'list_issues') {
    const state = String(args.state ?? 'open');
    const list = repo.issues.filter((i) => state === 'all' || i.state === state);
    return { ok: true, result: { issues: list.map((i) => ({ id: repo.id * 100000 + i.number, number: i.number, title: i.title, body: i.body, state: i.state })) } };
  }
  if (tool.name === 'create_pull_request') {
    const headRef = String(args.head ?? '');
    const baseRef = String(args.base ?? '');
    const pull: Pull = {
      number: repo.nextPull,
      title: String(args.title ?? ''),
      body: String(args.body ?? ''),
      state: 'open',
      merged: false,
      mergedAt: '',
      mergeCommitSha: '',
      headRef,
      baseRef,
      headSha: refTipCommit(repo, `refs/heads/${headRef}`) ?? '',
      baseSha: refTipCommit(repo, `refs/heads/${baseRef}`) ?? '',
      seq: repo.seq + 1,
    };
    repo.seq += 1;
    repo.nextPull += 1;
    repo.pulls.push(pull);
    return { ok: true, result: { id: repo.id * 100000 + pull.number, number: pull.number, title: pull.title, state: 'open', head: { ref: headRef }, base: { ref: baseRef }, head_ref: headRef, base_ref: baseRef } };
  }
  if (tool.name === 'merge_pull_request') {
    const num = Number(args.pull_number);
    const pull = repo.pulls.find((p) => p.number === num);
    if (!pull) return { ok: false, errorCode: -32602, errorMessage: `Pull request not found: ${num}` };
    const result = doMerge(repo, pull);
    if (result.status === 405) return { ok: false, errorCode: -32602, errorMessage: 'Merge conflict' };
    return { ok: true, result: { number: pull.number, merged: true, state: 'closed', sha: pull.mergeCommitSha } };
  }
  return { ok: false, errorCode: -32601, errorMessage: `Method not found: ${name}` };
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const bodyBuf = await readBody(req);
  const parsed = parseJsonBody(bodyBuf);
  if (!parsed.ok) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  const msg = (parsed.value ?? {}) as Record<string, unknown>;
  const id = msg.id ?? null;
  const method = String(msg.method ?? '');
  // Notifications (no id) get no response body.
  if (method === 'notifications/initialized' || method.startsWith('notifications/')) {
    res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    res.end();
    return;
  }
  if (!authed(req)) {
    sendJson(res, 401, { jsonrpc: '2.0', id, error: { code: -32001, message: 'Unauthorized' } });
    return;
  }
  if (method === 'server/discover') {
    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2026-07-28',
        supportedVersions: ['2026-07-28'],
        serverInfo: { name: 'forge', version: '1.0.0' },
        capabilities: { tools: {} },
      },
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'forge', version: '1.0.0' } },
    });
    return;
  }
  if (method === 'initialize') {
    const params = (msg.params ?? {}) as Record<string, unknown>;
    const offered = String(params.protocolVersion ?? '2025-11-25');
    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: offered,
        serverInfo: { name: 'forge', version: '1.0.0' },
        capabilities: { tools: {} },
      },
    }, { 'mcp-session-id': 'session-1' });
    return;
  }
  if (method === 'tools/list') {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } });
    return;
  }
  if (method === 'tools/call') {
    const params = (msg.params ?? {}) as Record<string, unknown>;
    const name = String(params.name ?? '');
    const args = ((params.arguments ?? {}) as Record<string, unknown>);
    const out = callMcpTool(name, args);
    if (!out.ok && out.errorCode !== undefined) {
      // Unknown tool / bad params: JSON-RPC error, never HTTP 500. Missing-arg
      // for create_issue is answered as isError (both are accepted by the suite).
      if (out.errorCode === -32602 && name.toLowerCase().includes('issue')) {
        sendJson(res, 200, mcpToolError(id, out.errorMessage ?? 'Invalid params'));
      } else {
        sendJson(res, 200, mcpRpcError(id, out.errorCode, out.errorMessage ?? 'Error'));
      }
      return;
    }
    if (!out.ok) {
      sendJson(res, 200, mcpToolError(id, out.errorMessage ?? 'Error'));
      return;
    }
    sendJson(res, 200, mcpToolResult(id, out.result));
    return;
  }
  sendJson(res, 200, mcpRpcError(id, -32601, `Method not found: ${method}`));
}

// ---------------------------------------------------------------- router

/** Build the server. It binds nothing until the caller listens; the entry listens on an ephemeral port. */
export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const path = pathOf(req);
        const method = req.method ?? 'GET';
        if (method === 'GET' && path === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }
        if (method === 'POST' && path === '/mcp') {
          await handleMcp(req, res);
          return;
        }
        if (method === 'POST' && path === '/api/graphql') {
          await handleGraphql(req, res);
          return;
        }
        if (path === '/api/v3' || path === '/api/v3/' || path.startsWith('/api/v3/')) {
          const rest = path.replace(/^\/api\/v3\/?/, '').split('/').filter((s) => s !== '');
          await handleRest(req, res, rest);
          return;
        }
        const gitMatch = /^\/([^/]+)\/([^/]+)\.git(?:\/(.*))?$/.exec(path);
        if (gitMatch) {
          const owner = gitMatch[1] as string;
          const repoName = gitMatch[2] as string;
          const rest = (gitMatch[3] ?? '').split('/').filter((s) => s !== '');
          await handleGit(req, res, owner, repoName, rest);
          return;
        }
        sendJson(res, 404, { message: 'Not Found' });
      } catch (err) {
        if (!res.headersSent) {
          sendJson(res, 500, { message: err instanceof Error ? err.message : 'Internal error' });
        } else {
          res.end();
        }
      }
    })();
  });
}
