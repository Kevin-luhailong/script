// Clash.md Traffic Audit Assistant
// Stores host-level request counts in Clash's local $persistentStore.
// It does NOT capture payloads, per-connection byte counts, matched rules, or proxy nodes.

const STORE_KEY = "clashmd_audit_v1";
const MAX_HOSTS = 500;
const whitelistRaw = (typeof $argument === "string" ? $argument : "");
const whitelist = whitelistRaw.split("|").map(x => x.trim().toLowerCase()).filter(Boolean);

function loadState() {
  try {
    const raw = $persistentStore.read(STORE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && parsed.hosts && typeof parsed.hosts === "object") return parsed;
    }
  } catch (e) {
    console.log("Audit: failed to read local store: " + e);
  }
  return { version: 1, createdAt: new Date().toISOString(), hosts: {} };
}

function saveState(state) {
  try {
    const ok = $persistentStore.write(JSON.stringify(state), STORE_KEY);
    if (ok === false) console.log("Audit: local store write returned false");
  } catch (e) {
    console.log("Audit: failed to write local store: " + e);
  }
}

function getHost(url) {
  try {
    if (typeof URL !== "undefined") return new URL(url).hostname.toLowerCase();
  } catch (e) {}
  const m = String(url || "").match(/^https?:\/\/([^/:?#]+)/i);
  return m ? m[1].toLowerCase() : "";
}

function isWhitelisted(host) {
  return whitelist.some(d => host === d || host.endsWith("." + d));
}

function recordRequest() {
  const url = ($request && $request.url) ? String($request.url) : "";
  const host = getHost(url);
  if (!host) {
    $done({});
    return;
  }

  const now = new Date().toISOString();
  const state = loadState();
  const old = state.hosts[host] || {
    count: 0,
    firstSeen: now,
    lastSeen: now
  };
  old.count += 1;
  old.lastSeen = now;
  old.category = isWhitelisted(host) ? "WHITELIST" : "REVIEW";
  state.hosts[host] = old;

  // Bound storage growth: retain the most recently seen hosts.
  const keys = Object.keys(state.hosts);
  if (keys.length > MAX_HOSTS) {
    keys.sort((a, b) => String(state.hosts[a].lastSeen).localeCompare(String(state.hosts[b].lastSeen)));
    for (let i = 0; i < keys.length - MAX_HOSTS; i++) delete state.hosts[keys[i]];
  }
  state.updatedAt = now;
  saveState(state);
  $done({});
}

function renderPanel() {
  const state = loadState();
  const hosts = Object.keys(state.hosts).map(host => ({
    host,
    count: Number(state.hosts[host].count || 0),
    lastSeen: state.hosts[host].lastSeen || "",
    category: state.hosts[host].category || "REVIEW"
  })).sort((a, b) => b.count - a.count);

  const review = hosts.filter(x => !isWhitelisted(x.host));
  const allowed = hosts.filter(x => isWhitelisted(x.host));
  const lines = [
    "本地累计域名数：" + hosts.length,
    "待审核域名数：" + review.length,
    "白名单命中域名数：" + allowed.length,
    "累计请求次数：" + hosts.reduce((n, x) => n + x.count, 0),
    "存储上限：" + MAX_HOSTS + " 个最近活跃域名",
    "",
    "【待审核 · 最近/高频】"
  ];

  review.slice(0, 30).forEach(x => lines.push(x.host + "  · " + x.count + " 次"));
  lines.push("", "【白名单 · 最近/高频】");
  allowed.slice(0, 20).forEach(x => lines.push(x.host + "  · " + x.count + " 次"));
  lines.push("", "白名单来自模块设置 Whitelist，使用 | 分隔域名。");
  lines.push("仅统计脚本实际看到的请求；并非全部连接或流量账本。");
  lines.push("最后更新：" + (state.updatedAt || "尚无记录"));

  $done({ title: "Clash 流量审计", content: lines.join("\n") });
}

if (typeof $request !== "undefined" && $request && $request.url) {
  recordRequest();
} else {
  renderPanel();
}
