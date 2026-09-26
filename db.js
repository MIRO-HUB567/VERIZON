import fs from 'fs';

const FILE = 'protector.json';
let state = { config: {}, api_keys: [], stats: [] };

if (fs.existsSync(FILE)) {
  try { state = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch {}
  state.config   ??= {};
  state.api_keys ??= [];
  state.stats    ??= [];
}

function persist() {
  fs.writeFileSync(FILE, JSON.stringify(state));
}

export function getConfig(key, fallback = null) {
  return state.config[key] ?? fallback;
}
export function setConfig(key, value) {
  state.config[key] = value;
  persist();
}
export function logStat(ip, status, event) {
  state.stats.push({ ts: Date.now(), ip, status, event });
  if (state.stats.length > 5000) state.stats.splice(0, state.stats.length - 5000);
  persist();
}

export const db = {
  pragma() {},
  prepare(sql) {
    return {
      run(...args) {
        if (sql.includes('INSERT INTO api_keys')) {
          const [hash, label, ts] = args;
          const id = (state.api_keys.at(-1)?.id || 0) + 1;
          state.api_keys.push({ id, key_hash: hash, label, created_at: ts, revoked: 0 });
          persist();
        } else if (sql.includes('UPDATE api_keys SET revoked')) {
          const k = state.api_keys.find(x => x.id == args[0]);
          if (k) k.revoked = 1;
          persist();
        }
      },
      get(...args) {
        if (sql.includes('SELECT * FROM api_keys WHERE key_hash')) {
          const [hash] = args;
          return state.api_keys.find(k => k.key_hash === hash && !k.revoked);
        }
        if (sql.includes('FROM stats') && sql.includes('WHERE status IN')) {
          return { c: state.stats.filter(s => [400,401,429,503].includes(s.status)).length };
        }
        if (sql.includes('FROM stats') && sql.includes("event LIKE 'rate%'")) {
          return { c: state.stats.filter(s => s.event.startsWith('rate')).length };
        }
        if (sql.includes('COUNT(*)') && sql.includes('FROM stats')) {
          return { c: state.stats.length };
        }
        return undefined;
      },
      all() {
        if (sql.includes('FROM api_keys')) {
          return state.api_keys.map(({id,label,created_at,revoked}) => ({id,label,created_at,revoked})).reverse();
        }
        if (sql.includes('FROM stats')) {
          return state.stats.slice(-100).reverse();
        }
        return [];
      }
    };
  }
};
