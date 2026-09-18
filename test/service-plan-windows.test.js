import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createPlanProbes, planContext, plannerProcessEnvironment } from "../src/plan-probes.js";
import { parsePlanArgs, taskSpecification } from "../src/service-plan.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const windowsOnly = { skip: process.platform !== "win32", timeout: 45000 };
const snapshot = (dir) => fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name)).flatMap((entry) => {
  const name = path.join(dir, entry.name);
  return entry.isDirectory() ? [[name, "directory"], ...snapshot(name)] : [[name, crypto.createHash("sha256").update(fs.readFileSync(name)).digest("hex")]];
});

// Executed in a separate Node process so the test runner itself is unaffected.
// Catch attempted operations even if the planner catches their thrown errors.
function guardedCliScript(home, operation) {
  return `
import fs from 'node:fs';
import cp from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import {syncBuiltinESMExports} from 'node:module';
import {pathToFileURL} from 'node:url';
import process from 'node:process';
const attempted=[];
const deny=(kind)=>{attempted.push(kind);throw new Error('Prohibited planner effect');};
const privateFile=(p)=>typeof p!=='number' && /(?:^|[\\\\/])(?:\\.env(?:\\..*)?|environment\\.dpapi|deployment\\.json|oauth-state\\.json)$/.test(String(p));
for(const name of ['readFileSync','readFile','createReadStream']){
 const original=fs[name]; fs[name]=function(p,...args){if(privateFile(p))return deny('private read');return original.call(this,p,...args);};
}
for(const target of [fs,fs.promises]){
 for(const name of Object.keys(target)){
  if(/^(?:write|append|mkdir|mkdtemp|rename|unlink|rm|rmdir|copy|cp$|chmod|chown|lchmod|lchown|link|symlink|truncate|utimes|lutimes)/.test(name)&&typeof target[name]==='function')target[name]=()=>deny('filesystem mutation');
 }
 for(const name of ['open','openSync'])if(typeof target[name]==='function'){
  const original=target[name];target[name]=function(p,flags,...rest){
   if(privateFile(p))return deny('private open');
   if(typeof flags==='number'? (flags & (fs.constants.O_WRONLY|fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_TRUNC|fs.constants.O_APPEND))!==0 : flags!=='r')return deny('writable open');
   return original.call(this,p,flags,...rest);
  };
 }
}
const originalRead=fs.promises.readFile;fs.promises.readFile=function(p,...args){if(privateFile(p))return deny('private async read');return originalRead.call(this,p,...args);};
const originalSpawn=cp.spawnSync;
cp.spawnSync=function(command,args,options){
 if(options.shell!==false||!options.env||options.env.HOSTGATE_OAUTH_PASSWORD!==undefined)return deny('unsafe child environment');
 const exe=path.basename(command).toLowerCase();
 if(exe==='git.exe'){
  const cmd=args[args.indexOf('-C')+2];
  if(!['rev-parse','ls-tree','ls-files','status','remote','branch','show','config'].includes(cmd)||!args.includes('--no-optional-locks')||!args.includes('core.fsmonitor=false'))return deny('mutating git');
 }else if(exe==='whoami.exe'){
  if(!['/user','/groups'].includes(args[0])||args.slice(1).join(' ')!=='/fo csv /nh')return deny('unexpected token query');
 }else if(exe==='cscript.exe'){
  if(args.length!==4||args.slice(0,3).join(' ')!=='//NoLogo //B //U'||path.basename(args[3])!=='windows-plan.wsf')return deny('mutable adapter');
  const input=options.input.toString('utf16le');
  if(!input.includes('<mode>inspect</mode>')&&!input.includes('<mode>validate</mode>'))return deny('mutable adapter mode');
 }else return deny('unexpected executable');
 return originalSpawn.call(this,command,args,options);
};
for(const name of ['spawn','fork','exec','execFile','execSync','execFileSync'])cp[name]=()=>deny('unexpected process control');
process.kill=()=>deny('process signal');

const environment=process.env;
process.env=new Proxy(environment,{ownKeys(){return deny('environment enumeration');},get(target,key){if(typeof key==='string'&&/^(HOST|PORT|HOSTGATE_)/.test(key))return deny('environment value');return Reflect.get(target,key);}});
os.homedir=()=>${JSON.stringify(home)};
syncBuiltinESMExports();
Object.defineProperty(process,'stdin',{configurable:true,get(){return deny('stdin read');}});
process.argv=[process.execPath,${JSON.stringify(path.join(root, "bin/hostgate.js"))},'service',${JSON.stringify(operation)},'--json','--environment-source','saved-file'];
await import(pathToFileURL(process.argv[1]).href);
if(attempted.length){process.stderr.write('Forbidden planner effects detected');process.exitCode=55;}
`;
}

async function runGuarded(home, operation) {
  const child = spawn(process.execPath, ["--input-type=module", "-e", guardedCliScript(home, operation)], {
    cwd: root, env: { ...plannerProcessEnvironment(home), HOSTGATE_OAUTH_PASSWORD: "test-sentinel-never-read" },
    windowsHide: true, stdio: ["pipe", "pipe", "pipe"], timeout: 30000
  });
  // An open stdin must not make the planner wait for credential input.
  child.stdin.on("error", () => {});
  child.stdin.write("sentinel-input-must-not-be-consumed");
  let output = ""; let errors = "";
  child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { errors += chunk; });
  const [code] = await once(child, "close");
  assert.equal(errors, "");
  assert([0, 1].includes(code), `Unexpected planner exit ${code}`);
  assert(!output.includes("test-sentinel-never-read"));
  return JSON.parse(output);
}

test("real plan and prepare CLI never read secret files/stdin/environment or mutate a fresh context", windowsOnly, async (t) => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "hostgate-plan-readonly-"));
  // Fixtures are established by this test, never by the planner under test.
  fs.mkdirSync(path.join(home, ".config", "hostgate"), { recursive: true });
  fs.mkdirSync(path.join(home, "AppData", "Roaming"), { recursive: true });
  fs.mkdirSync(path.join(home, "AppData", "Local", "Temp"), { recursive: true });
  fs.writeFileSync(path.join(home, ".config", "hostgate", ".env"), "SENTINEL=not-a-credential\n");
  const before = snapshot(home);
  const first = await runGuarded(home, "plan");
  const second = await runGuarded(home, "prepare");
  assert.equal(first.approvalToken, second.approvalToken);
  assert.equal(first.plan.environmentSource.availability, "user-file");
  assert.equal(first.plan.task.validation.xmlValid, true);
  assert.equal(first.plan.task.validation.taskRegistered, false);
  assert.equal(first.plan.environmentSource.stdinConsumed, false);
  assert.deepEqual(snapshot(home), before);
  t.diagnostic("Guarded native CLI plan/prepare verified without credential access, writes, or task registration.");
});

test("existing encrypted/manifest files are detected without opening or decrypting them", windowsOnly, async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "hostgate-plan-existing-"));
  const managed = path.join(home, ".config", "hostgate", "managed");
  fs.mkdirSync(managed, { recursive: true });
  fs.mkdirSync(path.join(home, "AppData", "Roaming"), { recursive: true });
  fs.mkdirSync(path.join(home, "AppData", "Local", "Temp"), { recursive: true });
  for (const name of ["environment.dpapi", "deployment.json", "oauth-state.json"]) fs.writeFileSync(path.join(managed, name), "not-readable-by-the-planner");
  const before = snapshot(home);
  const report = await runGuarded(home, "plan");
  assert.equal(report.exitCode, 1);
  assert.equal(report.plan.pathStates.encryptedStore, "file");
  assert.equal(report.plan.pathStates.manifest, "file");
  assert.equal(report.plan.checks.find((c) => c.id === "destination").status, "blocked");
  assert.deepEqual(snapshot(home), before);
});

test("native Task Scheduler validates exact XML/command with no registration or destination creation", windowsOnly, () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "hostgate-plan-xml-"));
  const destination = path.join(parent, "O'Neil & Team", "managed");
  const context = { ...planContext(root), home: os.homedir() };
  const probes = createPlanProbes(context, parsePlanArgs([]));
  const info = probes.windowsInspect(destination);
  const task = taskSpecification(destination, "a".repeat(40), info.sid);
  const before = snapshot(parent);
  const result = probes.validateTask(task);
  assert.equal(result.validationFlag, 1);
  assert.equal(result.xmlValid, true);
  assert.equal(result.commandMatches, true);
  assert.equal(result.taskRegistered, false);
  assert.deepEqual(probes.validateTask(task), result);
  assert.deepEqual(snapshot(parent), before);
  assert(!fs.existsSync(destination));
  assert.throws(() => probes.validateTask({ ...task, xml: task.xml.replace("<Command>", "<Command>wrong") }));
  assert.throws(() => probes.validateTask({ ...task, xml: '<!DOCTYPE Task [<!ENTITY ext SYSTEM "file:///C:/private">]>' + task.xml }));
  assert.deepEqual(snapshot(parent), before);
});

test("real CLI rejects activation options and its token without invoking installation", windowsOnly, () => {
  for (const args of [["--import-stdin"], ["--yes"], ["--adopt-pid", "29808"], ["--approval-token", "hostgate-plan-v1:" + "a".repeat(64)]]) {
    const result = spawnSync(process.execPath, [path.join(root, "bin/hostgate.js"), "service", "plan", ...args], {
      env: plannerProcessEnvironment(os.homedir()), encoding: "utf8", timeout: 10000, windowsHide: true
    });
    assert.equal(result.status, 2);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /Unknown plan option/);
  }
});
