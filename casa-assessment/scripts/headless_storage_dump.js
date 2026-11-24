#!/usr/bin/env node
'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

(async () => {
  const [targetBase, portStr, email, password] = process.argv.slice(2);
  if (!targetBase || !portStr || !email || !password) {
    console.log(JSON.stringify({ ok: false, error: 'missing arguments' }));
    process.exit(0);
  }

  const chromeBin = process.env.CHROME_BIN || '/usr/bin/google-chrome';
  const userDir = fs.mkdtempSync(path.join(os.tmpdir(), 'casa3-chrome-'));
  const chrome = spawn(
    chromeBin,
    [
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      `--remote-debugging-port=${portStr}`,
      `--user-data-dir=${userDir}`,
      `${targetBase}/#/login`,
    ],
    { stdio: 'ignore' }
  );

  let wsUrl = null;
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 200));
    try {
      const list = await (await fetch(`http://127.0.0.1:${portStr}/json`)).json();
      const page = list.find((t) => t.type === 'page');
      if (page && page.webSocketDebuggerUrl) {
        wsUrl = page.webSocketDebuggerUrl;
        break;
      }
    } catch (_) {}
  }

  const out = { ok: false, before: {}, after: {} };
  if (wsUrl) {
    const ws = new WebSocket(wsUrl);
    await new Promise((res) => ws.addEventListener('open', res));
    let id = 1;
    const cdp = (method, params = {}) =>
      new Promise((res) => {
        const mid = id++;
        const handler = (ev) => {
          const msg = JSON.parse(ev.data);
          if (msg.id === mid) {
            ws.removeEventListener('message', handler);
            res(msg.result);
          }
        };
        ws.addEventListener('message', handler);
        ws.send(JSON.stringify({ id: mid, method, params }));
      });
    const ev = async (expr) => {
      const r = await cdp('Runtime.evaluate', {
        expression: expr,
        awaitPromise: true,
        returnByValue: true,
      });
      return r && r.result ? r.result.value : null;
    };

    for (let i = 0; i < 25; i++) {
      await new Promise((r) => setTimeout(r, 200));
      if (await ev('!!document.querySelector("#email, input[type=email], input[name=email]")')) break;
    }

    await ev(`(() => {
      const wb = document.querySelector('button[aria-label="Close Welcome Banner"]');
      if (wb) wb.click();
      const cb = document.querySelector('a.cc-btn.cc-dismiss');
      if (cb) cb.click();
    })()`);
    await new Promise((r) => setTimeout(r, 200));

    await ev(`(() => {
      const setVal = (sels, val) => {
        for (const sel of sels) {
          const el = document.querySelector(sel);
          if (el) {
            el.focus();
            el.value = val;
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
            return true;
          }
        }
        return false;
      };
      setVal(['#email', 'input[type="email"]', 'input[name="email"]'], ${JSON.stringify(email)});
      setVal(['#password', 'input[type="password"]', 'input[name="password"]'], ${JSON.stringify(password)});
      const btn = document.querySelector('#loginButton, button[type="submit"], input[type="submit"]');
      if (btn) btn.click();
    })()`);

    for (let i = 0; i < 25; i++) {
      await new Promise((r) => setTimeout(r, 200));
      if (
        await ev(
          '!!localStorage.getItem("token") || document.documentElement.dataset.aut08Logged === "1"'
        )
      ) {
        break;
      }
    }

    const dumpExpr = `(async () => {
      const ls = {};
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        ls[k] = localStorage.getItem(k);
      }
      const ss = {};
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        ss[k] = sessionStorage.getItem(k);
      }
      const idb = [];
      if (typeof indexedDB !== 'undefined' && indexedDB.databases) {
        const dbs = await indexedDB.databases();
        for (const dbInfo of dbs) {
          const entry = { name: dbInfo.name, version: dbInfo.version, stores: {} };
          try {
            const db = await new Promise((resolve, reject) => {
              const req = indexedDB.open(dbInfo.name);
              req.onsuccess = () => resolve(req.result);
              req.onerror = () => reject(req.error);
            });
            for (const storeName of Array.from(db.objectStoreNames || [])) {
              const vals = await new Promise((resolve) => {
                try {
                  const tx = db.transaction(storeName, 'readonly');
                  const st = tx.objectStore(storeName);
                  const gr = st.getAll(null, 50);
                  gr.onsuccess = () => resolve(gr.result || []);
                  gr.onerror = () => resolve([]);
                } catch (_) {
                  resolve([]);
                }
              });
              entry.stores[storeName] = vals;
            }
            db.close();
          } catch (_) {}
          idb.push(entry);
        }
      }
      return JSON.stringify({
        localStorage: ls,
        sessionStorage: ss,
        indexedDB: idb,
        nonHttpOnlyCookies: document.cookie,
        href: location.href
      });
    })()`;

    out.before = JSON.parse((await ev(dumpExpr)) || '{}');

    await ev(`(() => {
      const acc = document.querySelector('#navbarAccount');
      if (acc) acc.click();
    })()`);
    await new Promise((r) => setTimeout(r, 200));
    await ev(`(() => {
      const lo = document.querySelector('#navbarLogoutButton, #logoutButton, button[data-logout], a[href*="logout" i]');
      if (lo) lo.click();
    })()`);
    for (let i = 0; i < 15; i++) {
      await new Promise((r) => setTimeout(r, 150));
      if (
        await ev(
          'document.documentElement.dataset.aut08LogoutDone === "1" || (!localStorage.getItem("token") && !document.querySelector("#navbarLogoutButton"))'
        )
      ) {
        break;
      }
    }

    out.after = JSON.parse((await ev(dumpExpr)) || '{}');
    out.ok = true;
    ws.close();
  }

  chrome.kill('SIGKILL');
  fs.rmSync(userDir, { recursive: true, force: true });
  console.log(JSON.stringify(out));
})();
