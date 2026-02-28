/*
  Minimal static dev server (no framework)
  - Serves this folder over HTTP
  - Automatically finds an available port starting at PORT or 5173
*/

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const net = require('net');

const ROOT_DIR = __dirname;
const DEFAULT_PORT = Number(process.env.PORT) || 5173;
const MAX_TRIES = 25;

function getContentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.html':
      return 'text/html; charset=utf-8';
    case '.css':
      return 'text/css; charset=utf-8';
    case '.js':
      return 'text/javascript; charset=utf-8';
    case '.json':
      return 'application/json; charset=utf-8';
    case '.svg':
      return 'image/svg+xml';
    case '.ico':
      return 'image/x-icon';
    case '.png':
      return 'image/png';
    case '.jpg':
    case '.jpeg':
      return 'image/jpeg';
    case '.gif':
      return 'image/gif';
    case '.txt':
      return 'text/plain; charset=utf-8';
    default:
      return 'application/octet-stream';
  }
}

function isPortFree(port) {
  return new Promise((resolve) => {
    const tester = net
      .createServer()
      .once('error', () => resolve(false))
      .once('listening', () => tester.once('close', () => resolve(true)).close())
      .listen(port, '0.0.0.0');
  });
}

async function findAvailablePort(startPort) {
  for (let i = 0; i < MAX_TRIES; i += 1) {
    const candidate = startPort + i;
    // eslint-disable-next-line no-await-in-loop
    const ok = await isPortFree(candidate);
    if (ok) return candidate;
  }
  throw new Error(`No free port found in range ${startPort}-${startPort + MAX_TRIES - 1}`);
}

function safeResolveUrlPath(urlPathname) {
  // Decode safely; if malformed, treat as not found.
  let decoded;
  try {
    decoded = decodeURIComponent(urlPathname);
  } catch {
    return null;
  }

  // Strip query/fragment already handled by URL parser; ensure leading slash.
  const pathname = decoded.startsWith('/') ? decoded : `/${decoded}`;

  // Resolve against root and prevent path traversal.
  const resolved = path.resolve(ROOT_DIR, `.${pathname}`);
  if (!resolved.startsWith(ROOT_DIR)) return null;

  return resolved;
}

function send(res, statusCode, headers, body) {
  res.writeHead(statusCode, headers);
  res.end(body);
}

function serveFile(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      send(res, 500, { 'Content-Type': 'text/plain; charset=utf-8' }, 'Internal Server Error');
      return;
    }

    send(
      res,
      200,
      {
        'Content-Type': getContentType(filePath),
        // Keep dev changes visible immediately
        'Cache-Control': 'no-store',
      },
      data
    );
  });
}

function createServer() {
  return http.createServer((req, res) => {
    const requestUrl = new URL(req.url || '/', 'http://localhost');

    const resolvedPath = safeResolveUrlPath(requestUrl.pathname);
    if (!resolvedPath) {
      send(res, 404, { 'Content-Type': 'text/plain; charset=utf-8' }, 'Not Found');
      return;
    }

    fs.stat(resolvedPath, (err, stat) => {
      if (err) {
        // Favicon is optional; avoid noisy errors
        send(res, 404, { 'Content-Type': 'text/plain; charset=utf-8' }, 'Not Found');
        return;
      }

      if (stat.isDirectory()) {
        const indexPath = path.join(resolvedPath, 'index.html');
        fs.stat(indexPath, (indexErr, indexStat) => {
          if (indexErr || !indexStat.isFile()) {
            send(res, 404, { 'Content-Type': 'text/plain; charset=utf-8' }, 'Not Found');
            return;
          }
          serveFile(res, indexPath);
        });
        return;
      }

      if (stat.isFile()) {
        serveFile(res, resolvedPath);
        return;
      }

      send(res, 404, { 'Content-Type': 'text/plain; charset=utf-8' }, 'Not Found');
    });
  });
}

(async () => {
  const port = await findAvailablePort(DEFAULT_PORT);
  const server = createServer();

  server.listen(port, '0.0.0.0', () => {
    // Print both localhost and 127.0.0.1 for convenience
    // (some environments resolve localhost differently)
    const urls = [`http://localhost:${port}/`, `http://127.0.0.1:${port}/`];

    // Persist the chosen port so tools (and humans) can easily find it.
    try {
      fs.writeFileSync(
        path.join(ROOT_DIR, '.dev-server.json'),
        JSON.stringify({ port, urls, startedAt: new Date().toISOString() }, null, 2),
        'utf8'
      );
    } catch {
      // ignore
    }

    console.log(`Dev server running:`);
    console.log(`  ${urls[0]}`);
    console.log(`  ${urls[1]}`);
    if (port !== DEFAULT_PORT) {
      console.log(`(Port ${DEFAULT_PORT} was busy, so I used ${port}.)`);
    }
  });
})();
