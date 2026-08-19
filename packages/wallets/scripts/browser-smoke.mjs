// Browser viability gate. Bundles the crypto core for a browser target, runs it in headless Chromium, and
// asserts the leaf it computes is byte-identical to the one node computes.
//
// It exists because "the SDK works in a browser" was an assumption nobody had executed. It does not: the
// core needs three bundler shims, because `@aztec/foundation` imports node's `util` for `inspect.custom`,
// reaches `tty` through a logger, and its `poseidon2Hash` is backed by Barretenberg WASM behind
// `process.env.BB_WASM_PATH`. All three are build-time concerns, none is a code change, and this proves it.
//
// Run: node scripts/browser-smoke.mjs   (needs a Chromium; set CHROME_PATH to override discovery)
import { createServer } from "node:http";
import { readFile, mkdtemp, writeFile, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join, extname, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG = join(HERE, "..");
const require = createRequire(import.meta.url);

// The one fixture. Any drift here is a cross-environment parity break, which is the whole point.
const NOTE = {
  noteVersion: 1n,
  assetId: 0x1234567890123456789012345678901234567890n,
  noteType: 0n,
  conditionsHash: 0n,
  value: 100n,
  owner: 7n,
  psi: 9n,
  parents: 0n,
};

async function nodeLeaf() {
  const w = await import(join(PKG, "dist/index.js"));
  const out = await w.leaf({
    noteVersion: w.toFr(NOTE.noteVersion),
    assetId: w.toFr(NOTE.assetId),
    noteType: w.toFr(NOTE.noteType),
    conditionsHash: w.toFr(NOTE.conditionsHash),
    value: NOTE.value,
    owner: w.toFr(NOTE.owner),
    psi: w.toFr(NOTE.psi),
    parents: w.toFr(NOTE.parents),
  });
  return out.toString();
}

function findChrome() {
  if (process.env["CHROME_PATH"]) return process.env["CHROME_PATH"];
  const roots = [join(process.env["HOME"] ?? "", ".cache/ms-playwright")];
  for (const root of roots) {
    for (const name of ["chromium-1223", "chromium-1217"]) {
      const p = join(root, name, "chrome-linux64", "chrome");
      try {
        require("node:fs").accessSync(p);
        return p;
      } catch {
        /* keep looking */
      }
    }
  }
  return null;
}

async function main() {
  const expected = await nodeLeaf();

  const esbuild = require("esbuild");
  const dir = await mkdtemp(join(tmpdir(), "howl-browser-smoke-"));
  await writeFile(
    join(dir, "probe.mjs"),
    `import { toFr, leaf } from ${JSON.stringify(join(PKG, "dist/index.js"))};
const out = await leaf({ noteVersion: toFr(${NOTE.noteVersion}n), assetId: toFr(${NOTE.assetId}n),
  noteType: toFr(${NOTE.noteType}n), conditionsHash: toFr(${NOTE.conditionsHash}n), value: ${NOTE.value}n,
  owner: toFr(${NOTE.owner}n), psi: toFr(${NOTE.psi}n), parents: toFr(${NOTE.parents}n) });
globalThis.__LEAF__ = out.toString();`,
  );
  await writeFile(
    join(dir, "page.html"),
    `<!doctype html><body><div id=out>PENDING</div><script type=module>
const el=document.getElementById("out");
try { await import("./bundle.js"); el.textContent="OK:"+(globalThis.__LEAF__??"none"); }
catch(e){ el.textContent="ERR:"+(e&&e.message?e.message:String(e)); }
</script>`,
  );

  esbuild.buildSync({
    entryPoints: [join(dir, "probe.mjs")],
    bundle: true,
    platform: "browser",
    format: "esm",
    outfile: join(dir, "bundle.js"),
    logLevel: "silent",
    alias: {
      util: join(PKG, "browser-shims/util.js"),
      tty: join(PKG, "browser-shims/tty.js"),
    },
    inject: [join(PKG, "browser-shims/globals.js")],
  });

  // COOP/COEP so the page is cross-origin isolated, which is what bb.js checks before using threads.
  const server = createServer((q, s) => {
    const f = join(
      dir,
      q.url === "/" ? "page.html" : (q.url ?? "").split("?")[0],
    );
    readFile(f).then(
      (d) => {
        const mime =
          {
            ".html": "text/html",
            ".js": "text/javascript",
            ".wasm": "application/wasm",
          }[extname(f)] ?? "application/octet-stream";
        s.writeHead(200, {
          "Content-Type": mime,
          "Cross-Origin-Opener-Policy": "same-origin",
          "Cross-Origin-Embedder-Policy": "require-corp",
        });
        s.end(d);
      },
      () => {
        s.writeHead(404);
        s.end("nf");
      },
    );
  });
  await new Promise((r) => server.listen(0, r));
  const port = server.address().port;

  const chrome = findChrome();
  if (chrome === null) {
    server.close();
    await rm(dir, { recursive: true, force: true });
    throw new Error(
      "browser-smoke: no Chromium found. Set CHROME_PATH, or install one via playwright.",
    );
  }

  const dom = await new Promise((resolve, reject) => {
    const p = spawn(chrome, [
      "--headless",
      "--disable-gpu",
      "--no-sandbox",
      "--virtual-time-budget=30000",
      "--dump-dom",
      `http://127.0.0.1:${port}/`,
    ]);
    let buf = "";
    p.stdout.on("data", (d) => (buf += d));
    p.on("error", reject);
    p.on("close", () => resolve(buf));
  });

  server.close();
  await rm(dir, { recursive: true, force: true });

  const m = /id="out">([^<]*)/.exec(dom);
  const got = m === null ? "NO-OUTPUT" : m[1];
  if (!got.startsWith("OK:")) {
    throw new Error(
      `browser-smoke: the core did not run in Chromium -> ${got}`,
    );
  }
  const browserLeaf = got.slice(3);
  if (browserLeaf !== expected) {
    throw new Error(
      `browser-smoke: PARITY BROKEN\n  node    ${expected}\n  browser ${browserLeaf}`,
    );
  }
  console.log(`browser-smoke: OK, node and Chromium agree on ${expected}`);
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
