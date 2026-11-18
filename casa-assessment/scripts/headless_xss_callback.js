#!/usr/bin/env node
'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

(async () => {
  const [portStr, targetBase, authToken, ...urls] = process.argv.slice(2);
  if (!portStr || !targetBase || urls.length === 0) {
    console.log(JSON.stringify({ ok: false, error: 'missing arguments' }));
    process.exit(0);
  }

  const chromeBin = process.env.CHROME_BIN || '/usr/bin/google-chrome';
  const userDir = fs.mkdtempSync(path.join(os.tmpdir(), 'casa3-xss-'));
  const chrome = spawn(
    chromeBin,
    [
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      `--remote-debugging-port=${portStr}`,
      `--user-data-dir=${userDir}`,
      urls[0],
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

    await new Promise((r) => setTimeout(r, 2200));
    if (authToken) {
      await cdp('Network.enable');
      await cdp('Network.setCookie', {
        name: 'token',
        value: authToken,
        url: targetBase,
      });
    }
    for (let u = 1; u < urls.length; u++) {
      await cdp('Page.navigate', { url: urls[u] });
      await new Promise((r) => setTimeout(r, 1800));
    }
    ws.close();
  }

  chrome.kill('SIGKILL');
  fs.rmSync(userDir, { recursive: true, force: true });
  console.log(JSON.stringify({ ok: Boolean(wsUrl), visited: urls.length }));
})();
