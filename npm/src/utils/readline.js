import { readFileSync, writeSync } from 'node:fs';
import { createInterface } from 'node:readline';

let pipeLines = null;
let pipeIndex = 0;
let chain = Promise.resolve();

function getPipeLines() {
  if (pipeLines === null) {
    pipeLines = [];
    pipeIndex = 0;
    if (!process.stdin.isTTY) {
      try {
        const data = readFileSync(0, 'utf8');
        pipeLines = data.split('\n').map((l) => l.replace(/\r$/, ''));
      } catch (_) {
        pipeLines = [];
      }
    }
  }
  return pipeLines;
}

function flushPrompt(prompt) {
  writeSync(1, prompt);
}

function readHiddenTTY() {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    let buffer = '';
    const cleanup = () => {
      stdin.removeListener('data', onData);
      try {
        stdin.setRawMode(false);
      } catch (_) {}
      try {
        stdin.pause();
      } catch (_) {}
    };
    const onData = (chunk) => {
      const text = chunk.toString('utf8');
      for (const char of text) {
        if (char === '\r' || char === '\n' || char === '\u0004') {
          cleanup();
          writeSync(1, '\n');
          resolve(buffer);
          return;
        }
        if (char === '\u0003') {
          cleanup();
          writeSync(1, '\n');
          try {
            process.kill(process.pid, 'SIGINT');
          } catch (_) {
            process.exit(130);
          }
          return;
        }
        if (char === '\u007f' || char === '\u0008') {
          buffer = buffer.slice(0, -1);
          continue;
        }
        buffer += char;
      }
    };
    stdin.setRawMode(true);
    stdin.resume();
    stdin.on('data', onData);
  });
}

function readVisibleTTY(prompt) {
  return new Promise((resolve, reject) => {
    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true
    });
    const finish = (answer) => {
      try {
        rl.close();
      } catch (_) {}
      resolve(answer);
    };
    try {
      rl.question(prompt, finish);
    } catch (err) {
      try {
        rl.close();
      } catch (_) {}
      reject(err);
    }
  });
}

function readOnce(prompt) {
  if (!process.stdin.isTTY) {
    flushPrompt(prompt);
    const lines = getPipeLines();
    if (pipeIndex < lines.length) {
      return Promise.resolve(lines[pipeIndex++]);
    }
    return Promise.resolve('');
  }
  try {
    flushPrompt(prompt);
    return readHiddenTTY();
  } catch (_) {
    return readVisibleTTY(prompt);
  }
}

export function askPassword(prompt) {
  const task = chain.then(() => readOnce(prompt));
  chain = task.catch(() => {});
  return task;
}

export function askLine(prompt) {
  const task = chain.then(() => {
    if (!process.stdin.isTTY) {
      flushPrompt(prompt);
      const lines = getPipeLines();
      if (pipeIndex < lines.length) {
        return Promise.resolve(lines[pipeIndex++]);
      }
      return Promise.resolve('');
    }
    // Prompt rendered by readline itself so it is visible and input echoes.
    return readVisibleTTY(prompt);
  });
  chain = task.catch(() => {});
  return task;
}
