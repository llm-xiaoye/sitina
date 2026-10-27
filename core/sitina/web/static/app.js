"use strict";
const $ = id => document.getElementById(id);
const paths = {
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  team: '<rect x="8" y="3" width="8" height="6" rx="2"/><rect x="2" y="15" width="8" height="6" rx="2"/><rect x="14" y="15" width="8" height="6" rx="2"/><path d="M12 9v3M6 15v-3h12v3"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4 4"/>',
  more: '<circle cx="5" cy="12" r="1" fill="currentColor"/><circle cx="12" cy="12" r="1" fill="currentColor"/><circle cx="19" cy="12" r="1" fill="currentColor"/>',
  send: '<path d="m4 11 16-7-7 16-2-7-7-2Z"/><path d="m11 13 9-9"/>',
  clip: '<path d="m8 12 6-6a3 3 0 0 1 4 4l-8 8a5 5 0 0 1-7-7l9-9"/>',
  pause: '<path d="M8 5v14M16 5v14"/>',
  play: '<path d="m8 4 12 8-12 8V4Z"/>',
  stop: '<rect x="5" y="5" width="14" height="14" rx="2"/>',
  refresh: '<path d="M20 11a8 8 0 1 0-2 6M20 4v7h-7"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  folder: '<path d="M3 7V5a2 2 0 0 1 2-2h5l3 4h6a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/>',
  copy: '<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
  trash: '<path d="M3 6h18M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7M14 10v7"/>',
  file: '<path d="M5 3h9l5 5v13H5V3Z"/><path d="M14 3v6h5M8 13h8M8 17h6"/>',
  bot: '<rect x="4" y="6" width="16" height="13" rx="4"/><path d="M12 3v3M1 11v4M23 11v4M8 15h8"/><path d="M8 10h.1M16 10h.1" stroke-width="3"/>',
  check: '<rect x="3" y="3" width="18" height="18" rx="4"/><path d="m7 12 3 3 7-7"/>',
  external: '<path d="M14 3h7v7M21 3l-11 11M10 3H3v18h18v-7"/>',
};
function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.6");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.innerHTML = paths[name] || paths.bot; // Bundled constant artwork only.
  return svg;
}
class SitinaLogo extends HTMLElement {
  connectedCallback() {
    if (this.childNodes.length) return;
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "24 30 84 84");
    svg.style.animationDelay = (-performance.now() / 1000) + "s";
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", "/assets/logo.svg#sitina-mark");
    svg.append(use);
    this.append(svg);
  }
}
customElements.define("sitina-logo", SitinaLogo);
for (const [id, name] of Object.entries({
  "toggle-sessions": "menu", "toggle-team": "team", "search-icon": "search",
  "refresh-sessions": "refresh", "send": "send", "attach": "clip",
  "cancel-task": "stop", "team-empty-icon": "team",
})) $(id).append(icon(name));
document.querySelectorAll(".dialog-close").forEach(button => {
  button.append(icon("close"));
  button.addEventListener("click", () => button.closest("dialog").close());
});
document.querySelector(".delete-symbol").append(icon("trash"));
const welcomeTemplate = $("messages").firstElementChild.cloneNode(true);
const teamEmptyTemplate = $("agent-tree").firstElementChild.cloneNode(true);
const phase = {
  RUNNABLE: "执行中", WAITING_OPERATION: "执行中", WAITING_CHILD: "等待子 Agent",
  PAUSING: "正在暂停", PAUSED: "已暂停", CANCELLING: "正在取消", CANCELLED: "已取消",
  SUCCEEDED: "已完成", FAILED: "未完成", WAITING_INPUT: "等待补充或继续",
  STALLED: "暂时无法推进", RECOVERY_BLOCKED: "恢复待核对", CONTEXT_BLOCKED: "上下文待核对",
  ADMITTED: "已分工", DISPATCH_PENDING: "等待执行", RUNNING: "执行中",
  RESULT_PERSISTED: "结果已保存", SETTLED: "已收口", CANCEL_REQUESTED: "正在撤下",
  CANCELLED_VERIFIED: "已撤下", HANDED_OFF: "已交接", BLOCKED: "等待条件",
  WAITING: "等待中", COMPLETED: "已完成", ENDED: "已结束", UNKNOWN: "状态未知",
};
let csrf, selected = null, sessions = [], snapshot = null, version = "", menuSession = null;
let busy = false, polling = false, timer, toastTimer, staged = [], returnFocus = null;
let pendingTaskContinuation = null;
const agentFlowState = new Map();
const collapsedDates = new Set(JSON.parse(localStorage.getItem("sitina:collapsed-dates") || "[]"));
const selectedSessions = new Set();
let selectingSessions = false;
let deleteTargets = [];
let deleteJob = null, deletionPolling = false, pendingDeletionRequest = null;
let dismissedDeletionJob = null;
function toggleSessionSelection(ids, checked) {
  const choose = checked ?? !ids.every(id => selectedSessions.has(id));
  ids.forEach(id => choose ? selectedSessions.add(id) : selectedSessions.delete(id));
  renderList();
}
function renderDeletionProgress() {
  const card = $("deletion-progress"), job = deleteJob;
  card.hidden = !job || dismissedDeletionJob === job.id;
  if (!job) return;
  const outcome = item => item.outcome_status || (item.status === "FAILED" ? "UNCONFIRMED" : item.status);
  const retained = job.items.filter(item => outcome(item) === "FAILED");
  const uncertain = job.items.filter(item => outcome(item) === "UNCONFIRMED");
  const labels = {RUNNING:"正在永久删除",PAUSING:"正在暂停",PAUSED:"删除已暂停",COMPLETED:"删除完成",COMPLETED_WITH_ERRORS:"本批删除结果"};
  $("deletion-status").textContent = labels[job.status] || "删除状态待核对";
  $("deletion-count").textContent = "已删除 " + job.deleted + " / " + job.total
    + (retained.length ? " · 未删除 " + retained.length : "")
    + (uncertain.length ? " · 结果待确认 " + uncertain.length : "");
  $("deletion-bar").max = job.total; $("deletion-bar").value = job.deleted + job.failed;
  $("deletion-current").textContent = job.status === "PAUSING" ? "当前会话处理完后暂停，已删除内容不恢复。"
    : job.status === "PAUSED" ? "剩余 " + job.remaining + " 个待处理，点击继续。"
    : job.current ? "正在处理：" + job.current.title
    : job.status === "COMPLETED" ? "会话自有数据已永久删除，外部原文件保留。"
    : uncertain.length ? "部分结果尚未确认，请先核对状态；不会自动重试。"
    : retained.length ? "未删除项的目录仍在。展开查看原因，可核对后继续删除。" : "准备处理下一条会话。";
  const control = $("deletion-toggle");
  control.hidden = !["RUNNING","PAUSING","PAUSED"].includes(job.status);
  control.disabled = job.status === "PAUSING";
  control.textContent = job.status === "PAUSED" ? "继续" : job.status === "PAUSING" ? "暂停中" : "暂停";
  $("deletion-dismiss").hidden = ["RUNNING","PAUSING","PAUSED"].includes(job.status);
  const failures = job.items.filter(item => ["FAILED","UNCONFIRMED"].includes(outcome(item)));
  $("deletion-errors").hidden = !failures.length;
  $("deletion-error-label").textContent = "查看 " + failures.length + " 项详情";
  $("deletion-error-list").replaceChildren(...failures.map(item => {
    const row = element("li");
    row.append(element("strong","",item.title), element("span","",
      (outcome(item) === "FAILED" ? "未删除：" : "结果待确认：") + deletionReason(item)));
    const actions = element("div", "deletion-item-actions");
    const locate = element("button", "", "查看会话"); locate.type = "button";
    locate.disabled = busy;
    locate.addEventListener("click", () => choose(item.id).catch(error => toast(requestErrorMessage(error))));
    actions.append(locate);
    const retry = element("button", "", outcome(item) === "FAILED" ? "核对并继续删除" : "核对状态");
    retry.type = "button"; retry.disabled = busy || ["RUNNING","PAUSING","PAUSED"].includes(job.status);
    retry.addEventListener("click", async () => {
      if (outcome(item) === "UNCONFIRMED") {await refreshDeletion(); return;}
      deleteTargets = [item.id]; pendingDeletionRequest = null;
      $("delete-title").textContent = "核对并继续删除此会话？";
      $("delete-session").textContent = item.title;
      $("delete-result").hidden = false;
      $("delete-result").textContent = deletionReason(item) + "。确认后仅处理此会话，不会重发原业务。";
      $("delete-confirm").textContent = "核对并继续删除";
      $("delete-dialog").showModal(); $("delete-cancel").focus();
    });
    actions.append(retry); row.append(actions); return row;
  }));
}
function deletionReason(item) {
  const reasons = {unsettled:"任务、外部动作或资源尚未收口", control_endpoint_present:"原生控制端点尚未关闭",
    authority_busy:"会话仍被其他进程占用", still_draining:"Agent 或后台操作仍在收口",
    outcome_unknown:"前一次操作的结果尚未确认", cancel_unconfirmed:"取消请求尚未确认"};
  return item.error || reasons[item.reason_code] || "请核对会话状态后再处理。";
}
async function refreshDeletion() {
  if (!csrf || deletionPolling) return;
  deletionPolling = true;
  try {
    const {job} = await api("/api/deletions");
    const outcomes = value => JSON.stringify(value?.items.map(item => [item.id, item.outcome_status || item.status]));
    const changed = job?.id !== deleteJob?.id || job?.updated_at !== deleteJob?.updated_at || outcomes(job) !== outcomes(deleteJob);
    deleteJob = job; renderDeletionProgress();
    if (changed && job) {
      const deleted = new Set(job.items.filter(item => (item.outcome_status || item.status) === "DELETED").map(item => item.id));
      deleted.forEach(id => selectedSessions.delete(id));
      if (deleted.has(selected)) {
        selected = null; snapshot = null; version = ""; staged = [];
        localStorage.removeItem("sitina:selected-session");
      }
      await refreshList();
      if (!selected && sessions.length) await choose(sessions[0].id);
    }
  } catch (_) { /* The last confirmed progress remains visible during reconnect. */ }
  finally { deletionPolling = false; }
}
setInterval(refreshDeletion, 1000);
$("deletion-toggle").addEventListener("click", async () => {
  if (!deleteJob) return;
  const button = $("deletion-toggle"); button.disabled = true;
  try {
    const {job} = await api("/api/deletions/" + encodeURIComponent(deleteJob.id) + "/control", {
      method:"POST",body:{action:deleteJob.status === "PAUSED" ? "resume" : "pause"}});
    deleteJob = job; renderDeletionProgress();
  } catch(error) { toast(requestErrorMessage(error)); button.disabled = false; }
});
$("deletion-dismiss").addEventListener("click", () => {dismissedDeletionJob = deleteJob?.id; renderDeletionProgress();});
let contextCompacting = false, contextActivityPending = false;
setInterval(async () => {
  if (streamConnected || contextActivityPending || !selected || !snapshot?.task || !snapshot.connected) return;
  const sid = selected, taskId = snapshot.task.task_id;
  contextActivityPending = true;
  try {
    const activity = await api(apiPath(sid, "/context-activity"));
    if (selected !== sid || snapshot?.task?.task_id !== taskId || activity.task_id !== taskId) return;
    contextCompacting = activity.active === true;
    const progress = $("context-progress");
    progress.hidden = !contextCompacting && !activity.completed;
    progress.classList.toggle("active", contextCompacting);
    progress.textContent = contextCompacting ? "正在压缩上下文…原始记录会保留，无需操作。"
      : "本次连接已完成 " + activity.completed + " 次上下文压缩。";
    if (contextCompacting) $("task-status").textContent = "正在压缩上下文";
    else if ($("task-status").textContent === "正在压缩上下文") $("task-status").textContent = taskPhase(snapshot.task);
  } catch (_) {
    // The ordinary snapshot poll owns connection errors. Do not relabel a
    // failed activity read as a compaction or trigger any task operation.
  } finally {contextActivityPending = false;}
}, 400);
const executionPanels = new Map();
let flowSession = null;
const ended = new Set(["SUCCEEDED", "FAILED", "CANCELLED"]);
const resumable = new Set(["PAUSED", "WAITING_INPUT", "STALLED", "RECOVERY_BLOCKED", "CONTEXT_BLOCKED"]);
const apiPath = (sid, suffix = "") => "/api/sessions/" + sid + suffix;
const requestId = () => crypto.randomUUID();
// Read-only event transport. Mutations remain explicit POST requests with IDs.
let stateStream = null, streamSid = null, streamConnected = false;
let streamLastEvent = 0, streamNotice = "", streamRotationUntil = 0;
let streamSnapshotEpoch = 0;
let streamContextActivity = null;
function stopStateStream() {
  if (stateStream) stateStream.close();
  stateStream = null; streamSid = null; streamConnected = false;
  streamNotice = ""; streamLastEvent = 0;
  streamContextActivity = null;
}
function applyContextActivity(activity) {
  if (!snapshot?.task || activity.task_id !== snapshot.task.task_id) return;
  contextCompacting = activity.active === true;
  const progress = $("context-progress");
  progress.hidden = !contextCompacting && !activity.completed;
  progress.classList.toggle("active", contextCompacting);
  progress.textContent = contextCompacting ? "正在压缩上下文…原始记录会保留，无需操作。"
    : "本次连接已完成 " + activity.completed + " 次上下文压缩。";
  if (contextCompacting) $("task-status").textContent = "正在压缩上下文";
  else if ($("task-status").textContent === "正在压缩上下文") $("task-status").textContent = taskPhase(snapshot.task);
}
function startStateStream(sid) {
  stopStateStream();
  if (!sid || typeof EventSource === "undefined") return;
  streamSid = sid;
  const source = new EventSource(apiPath(sid, "/events"));
  stateStream = source;
  const current = () => selected === sid && stateStream === source;
  const received = () => {streamLastEvent = Date.now(); streamConnected = true;};
  function consume(event, callback) {
    if (!current()) return;
    try {
      const value = JSON.parse(event.data);
      if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("event shape");
      received(); callback(value);
    } catch (_) {
      streamNotice = "实时状态消息无法读取。已有内容保留，正在重新核对；任务不会重发。";
      notice(noticeBase);
      source.close(); stateStream = null; streamConnected = false;
    }
  }
  source.onopen = () => {if (current()) received();};
  source.addEventListener("snapshot", event => consume(event, data => {
    if (!data.session || data.session.id !== sid || typeof data.version !== "string"
        || !Array.isArray(data.messages)) throw new Error("snapshot identity");
    streamSnapshotEpoch += 1;
    streamNotice = ""; connection(true);
    if (version !== data.version || !snapshot) {version = data.version; render(data);}
    else notice(noticeBase);
    if (streamContextActivity) applyContextActivity(streamContextActivity);
  }));
  source.addEventListener("context", event => consume(event, activity => {
    streamContextActivity = activity; applyContextActivity(activity);
  }));
  source.addEventListener("heartbeat", event => consume(event, () => {}));
  source.addEventListener("reconnect", event => consume(event, () => {streamRotationUntil = Date.now() + 5000;}));
  source.addEventListener("problem", event => consume(event, data => {
    streamNotice = typeof data.message === "string" ? data.message : "实时状态暂不可用，已有记录保留。";
    notice(noticeBase);
    if (data.code === "expired" || data.code === "not_found") {
      source.close(); stateStream = null; streamConnected = false;
    }
  }));
  source.onerror = () => {
    if (!current()) return;
    streamConnected = false;
    if (Date.now() >= streamRotationUntil) {
      streamNotice = "实时连接中断，正在只读重连。已有对话和输入保留，不会重新提交任务。";
      connection(false); notice(noticeBase);
    }
  };
}
window.addEventListener("pagehide", stopStateStream);

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}
function inlineMarkdown(node, text) {
  const pattern = /(`[^`\n]+`|\*\*[^*\n]+\*\*|\[[^\]\n]+\]\(https?:\/\/[^\s)]+\))/g;
  let cursor = 0;
  for (const match of text.matchAll(pattern)) {
    node.append(document.createTextNode(text.slice(cursor, match.index)));
    const token = match[0];
    if (token.startsWith("`")) node.append(element("code", "", token.slice(1, -1)));
    else if (token.startsWith("**")) node.append(element("strong", "", token.slice(2, -2)));
    else {
      const link = /^\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)$/.exec(token);
      const anchor = element("a", "", link[1]);
      anchor.href = link[2]; anchor.target = "_blank"; anchor.rel = "noopener noreferrer";
      node.append(anchor);
    }
    cursor = match.index + token.length;
  }
  node.append(document.createTextNode(text.slice(cursor)));
}
function renderMarkdown(text) {
  const body = element("div", "message-text rich-text");
  const lines = String(text).replace(/\r\n?/g, "\n").split("\n");
  const cells = line => line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map(x => x.trim());
  const divider = line => typeof line === "string" && line.includes("|") &&
    cells(line).every(x => /^:?-{3,}:?$/.test(x));
  const block = line => /^(#{1,6}\s|```|>\s?|[-*]\s|\d+[.)]\s)/.test(line.trimStart());
  let i = 0;
  while (i < lines.length) {
    if (!lines[i].trim()) {i++; continue;}
    if (lines[i].trimStart().startsWith("```")) {
      const code = []; i++;
      while (i < lines.length && !lines[i].trimStart().startsWith("```")) code.push(lines[i++]);
      if (i < lines.length) i++;
      const pre = element("pre"); pre.append(element("code", "", code.join("\n"))); body.append(pre); continue;
    }
    const heading = /^(#{1,6})\s+(.+)$/.exec(lines[i]);
    if (heading) {
      const node = element("h" + Math.min(6, heading[1].length + 1));
      inlineMarkdown(node, heading[2]); body.append(node); i++; continue;
    }
    if (lines[i].includes("|") && divider(lines[i + 1])) {
      const table = element("table"), head = element("thead"), header = element("tr");
      for (const cell of cells(lines[i])) {const th = element("th"); inlineMarkdown(th, cell); header.append(th);}
      head.append(header); table.append(head); i += 2;
      const rows = element("tbody");
      while (i < lines.length && lines[i].trim() && lines[i].includes("|")) {
        const row = element("tr");
        for (const cell of cells(lines[i++])) {const td = element("td"); inlineMarkdown(td, cell); row.append(td);}
        rows.append(row);
      }
      table.append(rows); const scroll = element("div", "table-scroll"); scroll.append(table); body.append(scroll); continue;
    }
    if (/^>/.test(lines[i])) {
      const quote = element("blockquote");
      while (i < lines.length && /^>/.test(lines[i])) {
        const p = element("p"); inlineMarkdown(p, lines[i++].replace(/^>\s?/, "")); quote.append(p);
      }
      body.append(quote); continue;
    }
    const listItem = /^\s*([-*]|\d+[.)])\s+(.+)$/.exec(lines[i]);
    if (listItem) {
      const ordered = /^\d/.test(listItem[1]), list = element(ordered ? "ol" : "ul");
      while (i < lines.length) {
        const item = /^\s*([-*]|\d+[.)])\s+(.+)$/.exec(lines[i]);
        if (!item || /^\d/.test(item[1]) !== ordered) break;
        const li = element("li"); inlineMarkdown(li, item[2]); list.append(li); i++;
      }
      body.append(list); continue;
    }
    const paragraph = [lines[i++]];
    while (i < lines.length && lines[i].trim() && !block(lines[i]) && !divider(lines[i + 1]))
      paragraph.push(lines[i++]);
    const p = element("p"); inlineMarkdown(p, paragraph.join("\n")); body.append(p);
  }
  return body;
}

async function api(path, {method = "GET", body} = {}) {
  const headers = {};
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-Sitina-CSRF"] = csrf;
  }
  const response = await fetch(path, {method, headers, credentials: "same-origin",
    cache: "no-store", body: body === undefined ? undefined : JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) throw Object.assign(new Error(data.error?.message || "本地请求未完成。"),
    {code: data.error?.code, httpStatus: response.status});
  return data;
}
function toast(text) {
  $("toast").textContent = text;
  $("toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => $("toast").hidden = true, 4000);
}
function executionConnection(text) {
  const status = $("execution-connection");
  if (status) status.textContent = $("connection").classList.contains("offline")
    ? "连接中断 · 保留原进程" : text;
}
function connection(ok) {
  const wasOffline = $("connection").classList.contains("offline");
  $("connection").classList.toggle("offline", !ok);
  $("connection").lastElementChild.textContent = ok ? (streamConnected ? "实时连接" : "本机连接") : "连接中断 · 正在重连";
  if (!ok) executionConnection("连接中断 · 保留原进程");
  else if (wasOffline) executionConnection("等待核对原执行");
}
const noticeBox = $("notice");
let noticeBase = "";
noticeBox.setAttribute("role", "status");
noticeBox.setAttribute("aria-live", "polite");
function notice(text) {
  noticeBase = text;
  text = [text, streamNotice].filter(Boolean).join("\n");
  const messages = $("messages");
  const nearBottom = messages.scrollHeight - messages.scrollTop - messages.clientHeight < 90;
  noticeBox.textContent = text;
  noticeBox.hidden = !text;
  if (!text) return;
  const taskId = snapshot?.task?.task_id;
  const response = taskId && [...messages.querySelectorAll(".message.assistant")]
    .reverse().find(item => item.dataset.taskId === taskId);
  const body = response?.querySelector(".message-body");
  (body || messages).append(noticeBox);
  if (nearBottom) messages.scrollTop = messages.scrollHeight;
}
async function reconnectReadOnly() {
  const response = await fetch("/", {credentials: "same-origin", cache: "no-store"});
  if (!response.ok) throw new Error("本地服务尚未重新连接。已有任务保留。");
  const config = await api("/api/bootstrap");
  csrf = config.csrf;
  version = "";
}
function providerWaiting(task) {
  const recovery = task?.provider_response_recovery?.state;
  const waiting = ["WAITING_INPUT", "RECOVERY_BLOCKED"].includes(task?.status);
  const paused = ["PAUSED", "STALLED", "CONTEXT_BLOCKED"].includes(task?.status);
  const pendingRecovery = ["confirmation_required", "blocked", "unavailable"].includes(recovery);
  if (!waiting && !(paused && pendingRecovery)) return null;
  const blocker = task.waiting_reason?.blocker_id;
  if (blocker === "provider-required-output-empty" && !recovery) return {
    label: "模型回复缺失", controlLabel: "继续",
    message: "模型本次没有返回完整结果，任务与已完成工作已保存。可以点击“继续”，或补充要求；不会自动切换模型。",
  };
  const transport = blocker === "provider-transport-unavailable";
  if (!transport && blocker !== "missing-provider-response" &&
      !["confirmation_required", "blocked", "unavailable"].includes(recovery)) return null;
  const label = (paused ? phase[task.status] + " · " : "") + (transport ? "模型连接异常" : "模型回复缺失");
  const saved = label + "，上次请求未收到完整回复。任务与已完成工作已保存；上次请求的执行结果和费用尚未确认。";
  if (recovery === "blocked") return {
    label: label + " · 恢复待核对", controlLabel: "查看恢复说明",
    message: saved + "缺失回复尚不能安全核对，当前不能接续。原任务和未知记录已保留。",
  };
  if (recovery === "confirmation_required") return {
    label: label + " · 待确认", controlLabel: "核对并继续",
    message: saved + "点击“核对并继续”，确认后会发起新的模型请求，可能产生费用；旧请求不会重发。",
  };
  return {label: label + " · 待核对", controlLabel: "核对并继续",
    message: saved + (recovery === "unavailable"
      ? "点击“核对并继续”先连接原任务并核对恢复条件，再确认是否发起新的模型请求。"
      : "继续前需要核对缺失回复，并确认是否发起新的模型请求。"),
  };
}
function taskPhase(task) {
  const provider = providerWaiting(task);
  if (provider) return provider.label;
  if (task?.status === "WAITING_INPUT" && task?.waiting_reason?.blocker_id === "investigation-relevance-unresolved")
    return "执行停滞";
  return phase[task?.status] || task?.status;
}
function waitingMessage(task) {
  const provider = providerWaiting(task);
  if (provider) return provider.message;
  if (task?.runtime_notice) return task.runtime_notice;
  if (task?.status === "WAITING_INPUT" && task?.waiting_reason?.blocker_id === "investigation-relevance-unresolved")
    return "执行停滞：历史读取未取得与当前任务相关的有效证据，已停止执行并保留操作记录。";
  return task?.waiting_reason?.reason || task?.waiting_reason?.message || task?.waiting_reason?.blocker_id;
}
async function refreshList() {
  const data = await api("/api/sessions");
  sessions = data.sessions;
  renderList();
}
function renderList() {
  const query = $("search").value.toLocaleLowerCase();
  const list = $("session-list");
  if (list.contains(document.activeElement) && !query && !$("session-menu").hidden) return;
  list.replaceChildren();
  const visible = sessions.filter(item => item.title.toLocaleLowerCase().includes(query));
  const groups = new Map();
  for (const item of visible) {
    const date = new Date(item.updated_at * 1000);
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const yesterday = new Date(today); yesterday.setDate(today.getDate() - 1);
    const key = date.getFullYear() + "-" + (date.getMonth() + 1) + "-" + date.getDate();
    const label = date >= today ? "今天" : date >= yesterday ? "昨天" : date.toLocaleDateString("zh-CN", {year:"numeric", month:"long", day:"numeric"});
    if (!groups.has(key)) {
      const section = element("section", "session-date-group");
      const heading = element("div", "date-heading");
      const ids = visible.filter(other => {
        const d = new Date(other.updated_at * 1000);
        return d.getFullYear() + "-" + (d.getMonth() + 1) + "-" + d.getDate() === key;
      }).map(other => other.id);
      const toggle = element("button", "date-toggle", (collapsedDates.has(key) ? "▸ " : "▾ ") + label);
      toggle.type = "button"; toggle.setAttribute("aria-expanded", String(!collapsedDates.has(key)));
      const body = element("div", "date-sessions"); body.hidden = collapsedDates.has(key) && !query;
      const collapse = () => {
        if (collapsedDates.has(key)) collapsedDates.delete(key); else collapsedDates.add(key);
        localStorage.setItem("sitina:collapsed-dates", JSON.stringify([...collapsedDates])); renderList();
      };
      toggle.addEventListener("click", () => selectingSessions ? toggleSessionSelection(ids) : collapse());
      if (selectingSessions) {
        toggle.textContent = label;
        toggle.setAttribute("aria-pressed",String(ids.every(id => selectedSessions.has(id))));
        const fold = element("button", "date-fold", collapsedDates.has(key) ? "▸" : "▾");
        fold.type="button"; fold.setAttribute("aria-label",(collapsedDates.has(key) ? "展开" : "收起")+label);
        fold.addEventListener("click",collapse); heading.append(fold);
        heading.classList.toggle("selected",ids.every(id => selectedSessions.has(id)));
        heading.addEventListener("click",event=>{if (!event.target.closest("button,input")) toggleSessionSelection(ids);});
      }
      heading.append(toggle);
      if (selectingSessions) {
        const checkbox = document.createElement("input"); checkbox.type = "checkbox";
        checkbox.setAttribute("aria-label", "选择" + label + "的全部会话");
        checkbox.checked = ids.every(id => selectedSessions.has(id));
        checkbox.indeterminate = !checkbox.checked && ids.some(id => selectedSessions.has(id));
        checkbox.addEventListener("change", () => toggleSessionSelection(ids,checkbox.checked));
        heading.append(checkbox);
      }
      section.append(heading, body); list.append(section); groups.set(key, body);
    }
    const row = element("div", "session-row" + (item.id === selected ? " active" : ""));
    const select = element("button", "session-select");
    select.type = "button";
    select.setAttribute("aria-current", item.id === selected ? "true" : "false");
    select.title = item.title;
    select.append(element("span", "session-bullet"), element("span", "session-name",
      item.deleting ? item.title + " · 删除待核对" : item.title));
    select.disabled = busy;
    select.addEventListener("click", () => {if (!busy) selectingSessions ? toggleSessionSelection([item.id]) : choose(item.id);});
    if (selectingSessions) {
      row.classList.toggle("selected",selectedSessions.has(item.id));
      select.setAttribute("aria-pressed",String(selectedSessions.has(item.id)));
      row.addEventListener("click",event=>{if (!event.target.closest("button,input")) toggleSessionSelection([item.id]);});
    }
    const more = element("button", "icon-button");
    more.type = "button"; more.disabled = busy; more.setAttribute("aria-label", item.title + "的会话操作");
    more.setAttribute("aria-haspopup", "menu"); more.append(icon("more"));
    more.addEventListener("click", event => {
      event.stopPropagation();
      const bounds = more.getBoundingClientRect();
      showMenu(item.id, bounds.right, bounds.bottom, more);
    });
    row.addEventListener("contextmenu", event => {
      event.preventDefault();
      showMenu(item.id, event.clientX, event.clientY, select);
    });
    select.addEventListener("keydown", event => {
      if (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10")) {
        event.preventDefault(); const b = select.getBoundingClientRect();
        showMenu(item.id, b.left + 20, b.bottom, select);
      }
    });
    if (selectingSessions) {
      const checkbox = document.createElement("input"); checkbox.type = "checkbox"; checkbox.checked = selectedSessions.has(item.id);
      checkbox.setAttribute("aria-label", "选择会话：" + item.title); checkbox.disabled = busy;
      checkbox.addEventListener("change", () => toggleSessionSelection([item.id],checkbox.checked));
      row.append(checkbox);
    }
    row.append(select, more); groups.get(key).append(row);
  }
  $("session-selection").hidden = !selectingSessions;
  $("manage-sessions").textContent = selectingSessions ? "退出批量管理" : "批量管理";
  $("delete-selected").textContent = "删除已选（" + selectedSessions.size + "）";
  $("delete-selected").disabled = busy || !selectedSessions.size || ["RUNNING","PAUSING","PAUSED"].includes(deleteJob?.status);
  $("select-all-sessions").checked = sessions.length > 0 && sessions.every(item=>selectedSessions.has(item.id));
  $("select-all-sessions").indeterminate = !$("select-all-sessions").checked && sessions.some(item=>selectedSessions.has(item.id));
  $("select-filtered-label").hidden = !query;
  $("select-visible-sessions").checked = visible.length > 0 && visible.every(item => selectedSessions.has(item.id));
  $("select-visible-sessions").indeterminate = !$("select-visible-sessions").checked && visible.some(item => selectedSessions.has(item.id));
  if (!visible.length) list.append(element("div", "session-empty",
    query ? "没有找到匹配的会话。" : "还没有会话。\n从一个新目标开始。"));
}
$("manage-sessions").addEventListener("click", () => {selectingSessions = !selectingSessions; if (!selectingSessions) selectedSessions.clear(); renderList();});
$("select-all-sessions").addEventListener("change",event=>toggleSessionSelection(sessions.map(item=>item.id),event.target.checked));
$("select-visible-sessions").addEventListener("change", event => {
  const query = $("search").value.toLocaleLowerCase();
  sessions.filter(item => item.title.toLocaleLowerCase().includes(query)).forEach(item => event.target.checked ? selectedSessions.add(item.id) : selectedSessions.delete(item.id)); renderList();
});
$("collapse-dates").addEventListener("click", () => {
  const expand = $("collapse-dates").dataset.collapsed === "true";
  sessions.forEach(item => {const d = new Date(item.updated_at * 1000); const key = d.getFullYear() + "-" + (d.getMonth()+1) + "-" + d.getDate(); expand ? collapsedDates.delete(key) : collapsedDates.add(key);});
  localStorage.setItem("sitina:collapsed-dates", JSON.stringify([...collapsedDates]));
  $("collapse-dates").dataset.collapsed = String(!expand); $("collapse-dates").textContent = expand ? "收起全部日期" : "展开全部日期"; renderList();
});
$("delete-selected").addEventListener("click", () => {
  deleteTargets = sessions.filter(item => selectedSessions.has(item.id)).map(item => item.id);
  pendingDeletionRequest = null;
  if (!deleteTargets.length) return;
  $("delete-title").textContent = "永久删除 " + deleteTargets.length + " 个会话？";
  $("delete-session").textContent = sessions.filter(item => selectedSessions.has(item.id)).map(item => item.title).join("、");
  $("delete-result").hidden = true; $("delete-confirm").textContent = "永久删除已选会话";
  returnFocus = $("delete-selected"); $("delete-dialog").showModal(); $("delete-cancel").focus();
});
async function createSession() {
  const session = await api("/api/sessions", {method: "POST", body: {request_id: requestId()}});
  await refreshList();
  await choose(session.id);
  return session.id;
}
async function choose(sid) {
  stopStateStream();
  closeMenu(); closeDrawers();
  selected = sid; snapshot = null; version = ""; staged = [];
  contextCompacting = false; $("context-progress").hidden = true;
  showCapabilityView(false, false); resetExecutions();
  // Navigation owns this synchronous focus change; a later poll must not
  // steal focus after the user has moved to another control.
  $("composer").focus();
  localStorage.setItem("sitina:selected-session", sid);
  renderList(); renderStaged();
  $("messages").replaceChildren(welcomeTemplate.cloneNode(true));
  $("agent-tree").replaceChildren(teamEmptyTemplate.cloneNode(true));
  $("file-list").replaceChildren(); $("usage").textContent = "";
  $("composer").value = ""; $("composer").style.height = "auto";
  $("chat-title").textContent = sessions.find(item => item.id === sid)?.title || "会话";
  $("task-status").textContent = "读取中"; notice(""); updateSend();
  startStateStream(sid);
  if (!stateStream) await poll(true);
}
async function copyMessage(text, button) {
  try {
    if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(text);
    else {
      const focus = document.activeElement, area = element("textarea", "clipboard-buffer");
      area.value = text; area.setAttribute("aria-hidden", "true"); document.body.append(area);
      try { area.select(); if (!document.execCommand("copy")) throw new Error("clipboard unavailable"); }
      finally { area.remove(); if (focus?.isConnected) focus.focus(); }
    }
    button.replaceChildren(icon("check")); button.setAttribute("aria-label", "已复制消息");
    button.title = "已复制"; toast("已复制");
    setTimeout(() => {if (button.isConnected) {button.replaceChildren(icon("copy")); button.setAttribute("aria-label", "复制消息"); button.title = "复制消息";}}, 1500);
  } catch (_) { toast("复制失败，请选择消息文字后复制。"); }
}
function messageActions(item) {
  const footer = element("div", "message-actions"), time = element("time", "message-time");
  const value = item.at, date = typeof value === "number" ? new Date(value * 1000) : typeof value === "string" ? new Date(value) : null;
  if (date && Number.isFinite(date.getTime())) {
    time.dateTime = date.toISOString(); time.textContent = date.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
    time.title = date.toLocaleString(); time.setAttribute("aria-label", date.toLocaleString());
  } else { time.textContent = "时间未记录"; }
  const copy = element("button", "message-copy"); copy.type = "button";
  copy.title = "复制消息"; copy.setAttribute("aria-label", "复制消息"); copy.append(icon("copy"));
  copy.disabled = typeof item.text !== "string" || !item.text.length;
  copy.addEventListener("click", () => copyMessage(item.text, copy));
  footer.append(time, copy); return footer;
}
const activityPanels = new Map();
function activityRow(entry) {
  const row = element("li", "activity-row " + entry.status);
  const labels = {running: "进行中", done: "完成", failed: "失败", cancelled: "已取消", unknown: "待核对"};
  const text = element("div", "activity-row-text");
  text.append(element("span", "activity-row-title", entry.title));
  if (entry.detail) text.append(element("code", "activity-row-detail", entry.detail));
  row.append(element("span", "activity-mark", entry.status === "done" ? "✓" : entry.status === "failed" ? "!" : "·"),
    text, element("span", "activity-row-state", labels[entry.status] || "待核对"));
  return row;
}
async function refreshActivityHistory(panel, before = null) {
  if (panel.loading) return;
  panel.loading = true;
  panel.more.disabled = true;
  panel.feedback.textContent = "正在读取操作记录…";
  const sid = panel.sid, taskId = panel.taskId;
  try {
    const data = await api(apiPath(sid, "/activity?task_id=" + encodeURIComponent(taskId)
      + (before === null ? "" : "&before=" + before)));
    if (panel.sid !== sid || panel.taskId !== taskId) return;
    panel.rows = before === null ? data.entries : panel.rows.concat(data.entries);
    panel.history.replaceChildren(...panel.rows.map(activityRow));
    panel.more.hidden = data.next_before === null;
    panel.more.dataset.before = data.next_before ?? "";
    panel.feedback.textContent = "已显示 " + panel.rows.length + " / " + data.total + " 条；不包含模型内部推理。";
  } catch (error) {
    panel.feedback.textContent = "操作记录暂未读到：" + error.message;
  } finally { panel.loading = false; panel.more.disabled = false; }
}
function messageActivityPanel(item, plan) {
  const activity = item.activity;
  if (!activity) return document.createDocumentFragment();
  let panel = activityPanels.get(item.id);
  if (!panel) {
    const node = element("section", "activity-panel");
    node.setAttribute("aria-label", "执行过程");
    const header = element("div", "activity-heading"), state = element("span", "activity-current");
    header.append(element("strong", "", "当前操作"), state);
    const workPlan = element("sitina-work-plan");
    const recent = element("ol", "activity-recent"), details = element("details", "activity-all");
    const toggle = element("summary"), history = element("ol", "activity-history");
    const feedback = element("p", "activity-feedback"), more = element("button", "activity-more", "加载更早的操作");
    more.type = "button"; more.hidden = true;
    details.append(toggle, history, feedback, more); node.append(workPlan, header, recent, details);
    panel = {node, workPlan, state, recent, details, toggle, history, feedback, more, rows: [], loading: false};
    details.addEventListener("toggle", () => {if (details.open) refreshActivityHistory(panel);});
    more.addEventListener("click", () => refreshActivityHistory(panel, Number(more.dataset.before)));
    activityPanels.set(item.id, panel);
  }
  panel.sid = selected; panel.taskId = item.task_id;
  panel.workPlan.update(plan);
  panel.state.textContent = activity.current?.title || (ended.has(item.status) ? "本轮操作已结束" : "准备下一步操作");
  panel.state.classList.toggle("running", !!activity.current);
  panel.recent.replaceChildren(...activity.recent.map(activityRow));
  panel.toggle.textContent = "查看完整操作记录 · " + activity.total + " 条";
  if (panel.revision !== activity.revision && panel.details.open) refreshActivityHistory(panel);
  panel.revision = activity.revision;
  return panel.node;
}
function artifactPreviewUrl(file) {
  if (file.downloadable !== true || !/\.html?$/i.test(file.name)) return null;
  return apiPath(selected, "/preview?id=" + encodeURIComponent(file.id) + "&version=" + encodeURIComponent(file.version));
}
function linkArtifactPaths(content, item) {
  for (const code of content.querySelectorAll("code")) {
    if (code.closest("pre")) continue;
    const file = (snapshot?.files || []).find(file => file.task_id === item.task_id
      && code.textContent === snapshot.directory + "/workspace/" + file.id);
    const target = file && artifactPreviewUrl(file);
    if (!target) continue;
    const link = element("a", "artifact-open", "打开 " + file.name);
    link.href = target; link.target = "_blank"; link.rel = "noopener noreferrer";
    link.title = code.textContent; link.append(icon("external")); code.replaceWith(link);
  }
}
function messageExecutionPanel(item) {
  let panel = executionPanels.get(item.id);
  if (!panel) {
    const node = element("details", "execution-dock"), summary = element("summary");
    const title = element("span", "", "命令与终端 "), count = element("span", "count-label", "0");
    title.append(count, document.createTextNode(" 个进程"));
    title.title = "这里只统计终端进程；文件、Skills、MCP 和模型交互请查看执行过程。";
    const connection = element("span", "muted execution-connection", ""); summary.append(title);
    const workspace = element("div", "execution-workspace"), list = element("nav", "execution-list"), detail = element("div", "execution-detail");
    list.setAttribute("aria-label", "这条回答的命令"); workspace.append(list, detail); node.append(summary, workspace);
    node.hidden = true;
    panel = {node, list, detail, count, connection, selected: null, item}; executionPanels.set(item.id, panel);
    node.addEventListener("toggle", () => {if (node.open && selected) refreshExecutions(selected);});
  }
  panel.item = item; return panel.node;
}
const verificationExpanded = new Map();
const verificationGroupsExpanded = new Map();
function verificationPanel(activity) {
  if (!activity?.history?.length) return null;
  const section = element("details", "verification-history");
  const groupId = activity.history[0].id;
  section.open = verificationGroupsExpanded.get(groupId) === true;
  section.addEventListener("toggle", () => {if (section.isConnected) verificationGroupsExpanded.set(groupId, section.open);});
  section.setAttribute("aria-label", "核验记录");
  section.append(element("summary", "verification-heading", "核验记录 · " + activity.history.length + " 次"));
  const list = element("div", "verification-list");
  activity.history.forEach((entry, index) => {
    const row = element("details", "verification-entry");
    row.dataset.verificationId = entry.id;
    row.open = verificationExpanded.has(entry.id) ? verificationExpanded.get(entry.id)
      : false;
    row.addEventListener("toggle", () => {if (row.isConnected) verificationExpanded.set(entry.id, row.open);});
    const label = (entry.role === "reviewer" ? "成果评审" : "完成核验") + " · 第 " + entry.ordinal + " 次"
      + (entry.kind === "repair" ? "（修正核验答复）" : "");
    const summary = element("summary");
    const state = entry.status === "RUNNING" ? "正在核验" :
      entry.status === "CORRECTION_NEEDED" ? "核验答复不完整或无效" : "本次记录已保存";
    summary.append(element("span", "verification-title", label),
      element("span", "verification-state", state));
    const checks = element("ul", "verification-checks");
    (entry.checks || []).forEach(text => checks.append(element("li", "", text)));
    row.append(summary, element("div", "muted", "本次核对："), checks);
    if (entry.at) {
      const time = new Date(entry.at);
      if (Number.isFinite(time.getTime())) row.append(element("div", "message-time", time.toLocaleString()));
    }
    list.append(row);
  });
  section.append(list); return section;
}
function displayMessage(item) {
  const node = element("article", "message " + item.role);
  if (typeof item.task_id === "string") node.dataset.taskId = item.task_id;
  node.setAttribute("aria-label", item.role === "user" ? "你的消息" : "Sitina 的回答");
  const content = element("div", "message-body");
  const messageTask = item.task_id === snapshot?.task?.task_id ? snapshot.task : item;
  const runtimeNotice = item.role === "assistant" ? providerWaiting(messageTask)?.message
    || messageTask?.runtime_notice || item.runtime_notice : null;
  const replyText = item.text || runtimeNotice;
  if (item.role === "assistant") {
    const avatar = element("div", "message-avatar");
    const logo = element("sitina-logo");
    logo.setAttribute("aria-hidden", "true");
    if (item.animating) logo.setAttribute("responding", "");
    avatar.append(logo); node.append(avatar);
    if (replyText) content.append(renderMarkdown(replyText));
    else {
      const waiting = element("div", "response-phase");
      waiting.append(element("span", "phase-text", messagePhase(messageTask)));
      content.append(waiting);
    }
    if (item.text && item.animating) content.append(element("div", "message-meta", messagePhase(messageTask)));
    if (item.text && runtimeNotice) content.append(element("p", "runtime-reply", runtimeNotice));
    if (item.historical && !runtimeNotice && waitingMessage(item))
      content.append(element("div", "notice", waitingMessage(item)));
    if (replyText) content.append(messageActions({...item, text: replyText}));
    content.append(messageActivityPanel(item, messageTask?.work_plan));
    linkArtifactPaths(content, item);
    const verification = verificationPanel(item.verification_activity || messageTask?.verification_activity);
    if (verification) content.append(verification);
  } else {
    content.append(element("div", "message-text", item.text));
    if (item.attachments?.length) content.append(element("div", "message-meta",
      "附带 " + item.attachments.length + " 个实际上传文件"));
  }
  if (item.role !== "assistant" && replyText) content.append(messageActions({...item, text: replyText}));
  if (item.role === "assistant") content.append(messageExecutionPanel(item));
  node.append(content); return node;
}
function messagePhase(task) {
  const role = task?.verification_activity?.active_role;
  if (role === "reviewer") return "评审中 · 正在核对成果与要求";
  if (role === "goal_completion") return "完成核验中 · 正在核对是否满足你的要求";
  return taskPhase(task);
}
function render(data) {
  snapshot = data;
  $("chat-title").textContent = data.session.title;
  document.title = data.session.title + " · Sitina";
  if (document.activeElement !== $("model")) $("model").value = data.model.choice;
  $("model").disabled = data.session.deleting || busy;
  const task = data.task;
  const state = task?.status;
  const responding = data.connected && task?.control_intent === "RUN" && ["RUNNABLE", "WAITING_OPERATION", "WAITING_CHILD"].includes(state);
  const statusText = data.session.deleting ? "删除待核对" : state ?
    taskPhase(task) + (!data.connected && !ended.has(state) ? " · 已保存，未连接" : "") : "准备就绪";
  $("task-status").textContent = contextCompacting ? "正在压缩上下文" : statusText;
  $("task-status").classList.toggle("busy", responding);
  document.querySelector(".brand sitina-logo").toggleAttribute("responding", Boolean(responding));
  $("pause").hidden = !task || ended.has(state) || data.session.deleting || (!data.connected && !resumable.has(state));
  $("pause").replaceChildren(icon(resumable.has(state) || !data.connected ? "play" : "pause"),
    document.createTextNode(resumable.has(state) || !data.connected ? providerWaiting(task)?.controlLabel || "继续" : "暂停"));
  $("pause").dataset.action = resumable.has(state) || !data.connected ? "resume" : "pause";
  $("cancel-task").hidden = !task || ended.has(state) || data.session.deleting;
  const node = $("messages"), nearBottom = node.scrollHeight - node.scrollTop - node.clientHeight < 90;
  if (data.messages.length) {
    const focused = document.activeElement;
    node.replaceChildren(...data.messages.map(displayMessage));
    if (focused?.isConnected && focused.closest(".execution-dock")) focused.focus({preventScroll: true});
    renderExecutionList();
    if (nearBottom || !node.dataset.rendered) node.scrollTop = node.scrollHeight;
    node.dataset.rendered = "true";
  } else {
    node.replaceChildren(welcomeTemplate.cloneNode(true));
    delete node.dataset.rendered;
  }
  const waiting = task?.waiting_reason;
  const reasons = [
    data.session.delete_error,
    task?.activity?.problem_notice,
    state === "FAILED" ? "任务因异常结束，已有记录和成果保留。你可以继续说明问题；Sitina 不会把失败操作自动重发。" : null,
    !data.connected && task && !ended.has(state) ? "任务记录已保存。刷新不会重发任务；需要继续时请点击“" + (providerWaiting(task)?.controlLabel || "继续") + "”。" : null,
    data.pending_actions?.some(item => item.state === "OUTCOME_UNKNOWN" || item.state === "PENDING")
      ? "前一次操作回执尚未确认。正在只读对账，不会自动重发。" : null,
    ...data.pending_actions.filter(item => item.state === "NOT_SENT").map(item => item.receipt?.reason || "操作未派发。"),
    ...(data.status_errors || []).map(item => item.reason),
    providerWaiting(task) || task?.runtime_notice ? null :
    task?.software_update ? (task.software_update.state === "blocked"
      ? "软件更新后的安全核对尚未通过，原任务已保留：" + task.software_update.reason
      : "Sitina 已更新，原任务和进度已保留。点击“继续”核对并确认。") :
    ["WAITING_INPUT", "RECOVERY_BLOCKED", "CONTEXT_BLOCKED", "STALLED"].includes(state)
      ? waitingMessage(task) : null,
  ].filter(Boolean);
  notice([...new Set(reasons)].join("\n"));
  $("composer").disabled = data.session.deleting;
  $("attach").disabled = data.session.deleting || busy;
  const expandedFileDetails = new Set(Array.from($("file-list").querySelectorAll("details[open]"), item => item.dataset.fileId));
  $("file-list").replaceChildren(...data.files.map(file => displayArtifact(file, expandedFileDetails)), ...data.uploads.map(file => {
    const entry = element("span", "saved-upload");
    const link = element("a", "file-link");
    link.href = apiPath(selected, "/attachment?id=" + encodeURIComponent(file.id));
    link.append(icon("clip"), element("span", "", file.name));
    const reuse = element("button", "reuse-upload", "+"); reuse.type = "button";
    reuse.setAttribute("aria-label", "在下一条消息附带" + file.name);
    reuse.disabled = busy || data.session.deleting;
    reuse.addEventListener("click", () => {
      if (!staged.some(item => item.id === file.id)) {staged.push(file); renderStaged();}
      $("composer").focus();
    });
    entry.append(link, reuse); return entry;
  }));
  $("usage").textContent = data.usage_text || "";
  renderTaskMetrics(data);
  renderTeam(data, responding);
  updateSend();
}
function renderTaskMetrics(data) {
  const context = data.task?.context_usage;
  const contextReady = Number.isInteger(context?.remaining_percent);
  $("context-label").textContent = contextReady ? "余量 ≥" + context.remaining_percent + "%" : "上下文 —";
  $("context-ring").style.setProperty("--context-used", contextReady ? (100 - context.remaining_percent) + "%" : "0%");
  $("context-description").textContent = contextReady
    ? "最近一次主 Agent 请求的保守余量，已扣除输入上界、回复和后续工具回执的预留。容量 " + context.capacity_tokens.toLocaleString() + " tokens，保守剩余 " + context.remaining_tokens.toLocaleString() + "。" + (Number.isInteger(context.reported_input_tokens) ? "服务商实际报告输入 " + context.reported_input_tokens.toLocaleString() + " tokens。" : "") + "这不是累计用量；新消息和工具结果会改变下一次请求。"
    : "尚未取得本任务的上下文容量记录。首次请求完成后显示；不会用累计用量猜测剩余空间。";
  const agents = data.agents || [];
  const names = new Set(agents.flatMap(agent => (agent.skills?.items || []).filter(item => item.uses > 0).map(item => item.name)));
  const known = agents.length > 0 && agents.every(agent => agent.skills);
  $("task-skills").textContent = "Skills " + (known ? names.size : "待确认");
  $("task-skills").title = "查看本任务实际加载的技能和调用次数";
  const records = $("task-skills-records"); records.replaceChildren();
  for (const agent of agents) {
    const section = element("section", "skill-usage-group");
    section.append(element("h3", "", agent.name));
    if (!agent.skills) section.append(element("p", "muted", "使用统计尚不完整，不能据此判断没有使用技能。"));
    else if (!agent.skills.items.length) section.append(element("p", "muted", "本任务尚未记录技能加载。"));
    else for (const item of agent.skills.items) {
      const row = element("div", "skill-usage-row");
      row.append(element("strong", "", item.name), element("span", "", "加载 " + (item.loads || 0) + " 次 · 读取资源 " + (item.resource_reads || 0) + " 次 · 失败 " + item.failures + " 次"));
      section.append(row);
    }
    records.append(section);
  }
  if (!agents.length) records.append(element("p", "muted", "开始任务后，这里显示实际使用记录。"));
}
$("task-skills").addEventListener("click", () => {
  returnFocus = $("task-skills"); $("task-skills-dialog").showModal();
});
function displayArtifact(file, expanded) {
  const labels = {source: "来源文件", unverified: "未验证", in_review: "评审中", verified: "已验证", failed: "未通过"};
  const state = Object.hasOwn(labels, file.release_state) ? file.release_state : "unverified";
  const entry = element("div", "artifact-entry");
  entry.dataset.releaseState = state;
  const heading = element("div", "artifact-heading");
  const title = element(file.downloadable === true ? "a" : "span", "file-link artifact-title");
  const target = apiPath(selected, "/file?id=" + encodeURIComponent(file.id) + "&version=" + encodeURIComponent(file.version || ""));
  if (file.downloadable === true) {
    title.href = target;
    title.setAttribute("aria-label", (state === "source" ? "下载来源文件：" : "下载已验证成果：") + file.name);
  }
  title.append(icon("file"), element("span", "", file.name), element("small", "", formatSize(file.size)));
  heading.append(title, element("span", "artifact-state artifact-state-" + state, labels[state]));
  const previewUrl = artifactPreviewUrl(file);
  if (previewUrl) {
    const open = element("a", "artifact-open", "打开网页");
    open.href = previewUrl; open.target = "_blank"; open.rel = "noopener noreferrer";
    open.append(icon("external")); heading.append(open);
  }
  entry.append(heading);
  if (file.downloadable !== true) entry.append(element("p", "artifact-reason", file.release_reason || "当前版本尚无完整验收记录。"));
  if (file.unverified_available === true && typeof file.version === "string") {
    const recovery = element("a", "artifact-recovery", "下载未验证副本");
    recovery.href = target + "&unverified=1";
    recovery.setAttribute("aria-label", "下载未验证副本：" + file.name);
    entry.append(recovery);
  }
  const details = element("details", "artifact-evidence");
  details.dataset.fileId = file.id;
  details.open = expanded.has(file.id);
  details.append(element("summary", "", state === "source" ? "文件版本" : "验收与文件版本"));
  const facts = element("dl");
  const add = (label, value) => {
    if (value === undefined || value === null || value === "") return;
    facts.append(element("dt", "", label), element("dd", "", String(value)));
  };
  const evidenceStatus = value => ({PASS: "通过", FAIL: "未通过", NOT_REQUIRED: "本任务不要求", UNKNOWN: "尚未确认"})[value] || "尚未确认";
  add("文件路径", file.id);
  add("当前 SHA-256", file.version || "尚未取得稳定版本");
  if (state !== "source") {
    add("任务", file.task_id);
    add("成果版本", file.artifact_version);
    add("成果来源", file.artifact_ref);
    add("评审", evidenceStatus(file.review_status));
    add("检查", evidenceStatus(file.check_status));
    if (Array.isArray(file.acceptance_ids) && file.acceptance_ids.length) add("验收记录", file.acceptance_ids.join("\n"));
    if (Array.isArray(file.evidence_refs) && file.evidence_refs.length) add("证据来源", file.evidence_refs.join("\n"));
    if (file.evidence_refs_more > 0) add("其他证据", file.evidence_refs_more + " 条保存在任务记录中");
  }
  details.append(facts); entry.append(details);
  return entry;
}

function renderAgentFlow(flow, agentId, responding) {
  if (!flow || !["request", "returned"].includes(flow.phase) || typeof flow.event_key !== "string") return null;
  const now = Date.now(), previous = agentFlowState.get(agentId);
  const started = previous?.key === flow.event_key ? previous.started :
    (previous || flow.phase === "request") ? now : null;
  agentFlowState.set(agentId, {key: flow.event_key, started});
  const node = element("div", "agent-data-flow");
  node.dataset.phase = flow.phase;
  node.dataset.event = flow.event_key;
  node.title = "根据原生调用和返回记录显示方向；光点表示处理状态，不表示网络包数量。";
  const label = element("span", "flow-label", flow.phase === "request" ? "→ 处理中" : "← 结果返回");
  const track = element("span", "flow-track");
  track.setAttribute("aria-hidden", "true");
  const dot = element("span", "flow-dot");
  const elapsed = started === null ? 0 : Math.max(0, now - started);
  const moving = responding && (flow.phase === "request" || (started !== null && elapsed < 1800));
  dot.classList.toggle("moving", moving);
  if (moving) {
    dot.style.animationDelay = "-" + (elapsed / 1000) + "s";
    dot.style.animationIterationCount = flow.phase === "request" ? "infinite" : "1";
  }
  track.append(dot); node.append(track, label);
  return node;
}
function renderTeam(data, responding) {
  if (flowSession !== data.session.id) {
    agentFlowState.clear(); flowSession = data.session.id;
  }
  const counts = data.team_counts;
  $("team-live").textContent = responding ? "实时推进" : data.task ? phase[data.task.status] || data.task.status : "未开始";
  $("team-live").classList.toggle("active", responding);
  const target = $("team-counts"); target.replaceChildren();
  if (counts) {
    const roles = Object.values(counts);
    const stats = element("div", "count-summary");
    for (const [label, value] of [
      ["运行", roles.reduce((sum, role) => sum + role.running, 0)],
      ["等待", roles.reduce((sum, role) => sum + role.waiting, 0)],
      ["成果评审批次", counts.reviewer.created],
    ]) {
      const cell = element("div"); cell.append(element("strong", "", value), element("span", "count-label", label)); stats.append(cell);
    }
    target.append(stats, element("div", "",
      "累计创建：主控 " + counts.main.created + " · 子 Agent " + counts.child.created));
  } else if (data.task) target.append(element("div", "",
    "已记录评审批次 " + data.agents.filter(agent => agent.role === "reviewer").length + " · 当前人数未报告"));
  if (data.task) {
    const checks = data.task.verification_activity;
    target.append(element("div", "interaction-summary",
      "完成核验 · " + (Number.isInteger(checks?.completion_checks) ? checks.completion_checks : "—") + " 次尝试"));
    const rounds = element("div", "interaction-summary", "已记录交互轮数 " + (Number.isInteger(data.interaction_rounds) ? data.interaction_rounds : "—"));
    rounds.title = "所有 Agent 已完成并记录的逻辑模型回合，包括规划、工具结果后的继续和评审；当前在途回合返回后增加，网络重试不增加轮数。未报告时显示 —。";
    target.append(rounds);
  }
  const tree = $("agent-tree");
  if (data.agents.length) {
    tree.replaceChildren(...data.agents.map(agent => {
      const card = element("div", "agent-card " + agent.role);
      const name = element("div", "agent-name");
      name.append(icon(agent.role === "reviewer" ? "check" : "bot"), document.createTextNode(agent.name));
      const state = element("div", "agent-state" + (["RUNNING", "RUNNABLE", "WAITING_OPERATION"].includes(agent.status) ? " running" : ""),
        phase[agent.status] || agent.status);
      const details = element("details", "agent-details");
      details.append(element("summary", "", "完整分工"),
        element("div", "agent-full-objective", agent.objective));
      const metrics = element("div", "agent-metrics");
      const rounds = element("span", "agent-rounds", "交互 " + (Number.isInteger(agent.interaction_rounds) ? agent.interaction_rounds : "—") + " 轮");
      rounds.title = "该 Agent 已完成并记录的逻辑模型回合。当前在途回合返回后增加，网络重试不增加轮数。";
      metrics.append(rounds);
      if (agent.skills && agent.skills.items.length) {
        const skills = element("details", "agent-skills");
        const label = element("summary", "", "Skills " + agent.skills.count);
        label.title = "实际成功读取的不同 Skill 数量；展开查看调用次数与失败。";
        skills.append(label);
        for (const item of agent.skills.items) {
          const row = element("div", "skill-use", item.name);
          row.append(element("small", "", "加载 " + (item.loads || 0) + " 次 · 资源 " + (item.resource_reads || 0) + " 次" + (item.failures ? " · 失败 " + item.failures + " 次" : "")));
          if (item.resources.length) row.append(element("small", "", item.resources.join(" · ")));
          skills.append(row);
        }
        metrics.append(skills);
      } else {
        const skills = element("span", "agent-skill-count", agent.skills ? "Skills " + agent.skills.count : "Skills 统计待确认");
        skills.title = agent.skills ? "实际成功读取的不同 Skill 数量。普通文件读取和模型自述不计入。" : "原生记录不足，无法确定 Skills 使用数量。";
        metrics.append(skills);
      }
      card.append(name, element("div", "agent-objective", agent.objective), state, metrics);
      const flow = renderAgentFlow(agent.data_flow, agent.id, responding);
      if (flow) card.append(flow);
      card.append(details);
      card.title = agent.id; return card;
    }));
  } else {
    tree.replaceChildren(teamEmptyTemplate.cloneNode(true));
  }
  const changes = data.agents.filter(agent => agent.role !== "main" && agent.reason);
  $("team-changes").hidden = !changes.length;
  $("changes-list").replaceChildren(...changes.map(agent => element("div", "change",
    agent.name + " · " + (phase[agent.status] || agent.status) + " · " + agent.reason)));
}
function formatSize(size) {return size < 1024 ? size + " B" : size < 1048576 ? (size / 1024).toFixed(1) + " KB" : (size / 1048576).toFixed(1) + " MB";}
function requestErrorMessage(error) {
  if (error instanceof TypeError) return "本地服务暂时无法连接。";
  if (error instanceof SyntaxError) return "本地服务返回的内容无法读取。操作不会自动重发。";
  return error?.message || "本地请求未完成。已有记录保留。";
}
async function poll(force = false) {
  if (polling || !selected) return;
  polling = true;
  const sid = selected;
  const epoch = streamSnapshotEpoch;
  try {
    const data = await api(apiPath(sid) + (version && !force ? "?since=" + version : ""));
    if (sid !== selected || epoch !== streamSnapshotEpoch) return;
    connection(true);
    if (!data.unchanged) {version = data.version; render(data);}
    await refreshExecutions(sid);
  } catch (error) {
    if (sid !== selected || epoch !== streamSnapshotEpoch) return;
    if (error.httpStatus === 401) {
      try {
        await reconnectReadOnly();
        notice("本机连接已恢复，正在读取已保存的任务。需要继续时请明确点击继续。");
      } catch (reconnectError) {connection(false); notice(requestErrorMessage(reconnectError));}
    } else if (error.httpStatus === 404) {
      selected = null; snapshot = null; localStorage.removeItem("sitina:selected-session");
      await refreshList(); if (sessions[0]) await choose(sessions[0].id);
    } else {
      connection(false);
      const message = requestErrorMessage(error);
      notice(message + "\n已有对话保留。重连只读取状态，不会重新提交。");
    }
  } finally {
    polling = false;
    if (selected && sid !== selected) await poll(true);
  }
}
function schedule() {
  clearTimeout(timer);
  timer = setTimeout(async () => {
    if (streamSid && streamSid !== selected) stopStateStream();
    if (streamConnected && Date.now() - streamLastEvent > 25000) {
      stopStateStream();
      streamNotice = "实时连接长时间没有响应，正在重新读取状态。已有内容和输入保留。";
      notice(noticeBase);
    }
    if (!streamConnected) {
      await poll();
      if (selected && !stateStream) startStateStream(selected);
    } else if (selected) {
      await refreshExecutions(selected);
    }
    if (!$("session-menu").hidden || document.visibilityState !== "visible") {schedule(); return;}
    if (Date.now() - (schedule.lastList || 0) > 10000) {
      try {await refreshList(); schedule.lastList = Date.now();} catch (_) {connection(false);}
    }
    schedule();
  }, document.hidden ? 5000 : snapshot?.messages.some(item => item.animating) ? 1400 : 3000);
}
function updateSend() {
  $("send").disabled = busy || !$("composer").value.trim() || !!snapshot?.session.deleting;
  $("pause").disabled = busy; $("cancel-task").disabled = busy;
  $("model").disabled = busy || !!snapshot?.session.deleting;
  $("attach").disabled = busy || !!snapshot?.session.deleting;
  $("new-session").disabled = busy;
  document.querySelectorAll(".session-row button").forEach(button => {button.disabled = busy;});
  document.querySelectorAll(".reuse-upload").forEach(button => {button.disabled = busy || !!snapshot?.session.deleting;});
}
async function mutate(action) {
  if (busy) return;
  busy = true; updateSend();
  try {await action(); await poll(true); await refreshList();}
  catch (error) {notice(requestErrorMessage(error)); toast(requestErrorMessage(error));}
  finally {busy = false; updateSend();}
}
$("new-session").addEventListener("click", () => mutate(createSession));
$("search").addEventListener("input", renderList);
$("refresh-sessions").addEventListener("click", () => refreshList().catch(error => toast(requestErrorMessage(error))));
$("composer").addEventListener("input", () => {
  $("composer").style.height = "auto";
  $("composer").style.height = Math.min($("composer").scrollHeight, 160) + "px";
  updateSend();
});
$("composer").addEventListener("keydown", event => {
  if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
    event.preventDefault(); if (!$("send").disabled) $("composer-form").requestSubmit();
  }
});
$("composer-form").addEventListener("submit", event => {
  event.preventDefault();
  const text = $("composer").value.trim();
  if (!text || busy) return;
  mutate(async () => {
    if (!selected) await createSession();
    const action = await api(apiPath(selected, "/messages"), {
      method: "POST", body: {request_id: requestId(), text, attachments: staged.map(item => item.id)}});
    if (action.state === "ACCEPTED") {
      $("composer").value = ""; $("composer").style.height = "auto"; staged = []; renderStaged();
    } else notice(action.receipt?.reason || "操作回执尚未确认。已保存原操作，未自动重发。");
  });
});
$("model").addEventListener("change", () => {
  const choice = $("model").value;
  mutate(async () => {
    if (!selected) await createSession();
    await api(apiPath(selected, "/model"), {method: "POST", body: {choice}});
    toast("已选择 " + (choice === "flash" ? "Flash" : "Pro") + "，下一个请求边界生效。");
  });
});
async function sendTaskControl(action, confirmation = null) {
  const sid = confirmation ? confirmation.sid : selected;
  if (confirmation && (sid !== selected || confirmation.taskId !== snapshot?.task?.task_id))
    throw new Error("当前任务已经变化，请重新核对后继续。");
  const body = {request_id: confirmation?.requestId || requestId(), action};
  if (confirmation) {
    body.expected_task_revision = confirmation.revision;
    if (confirmation.provider) body.provider_response_disposition = {
      ...confirmation.provider, accept_unknown_usage: true, abandon_missing_response: true};
    if (confirmation.software) body.software_update_transition = confirmation.software;
  }
  const response = await api(apiPath(sid, "/control"), {method: "POST", body});
  if (response.receipt?.cancellation_blocked || response.state !== "ACCEPTED")
    notice(response.receipt?.reason || "控制回执尚未确认；不会自动重发。");
}
for (const [id, action] of [["pause", null], ["cancel-task", "cancel"]]) {
  $(id).addEventListener("click", () => {
    const control = action || $("pause").dataset.action;
    const provider = snapshot?.task?.provider_response_recovery;
    const update = snapshot?.task?.software_update;
    if (control === "resume" && (provider?.state === "blocked" || update?.state === "blocked")) {
      notice("安全核对尚未通过，原任务和未知记录已保留。"); return;
    }
    if (control === "resume" && (provider?.state === "confirmation_required" || update)) {
      const recover = provider?.state === "confirmation_required" ? provider : null;
      pendingTaskContinuation = {sid: selected, taskId: snapshot.task.task_id, requestId: requestId(),
        revision: recover ? recover.task_revision : update.task_revision,
        provider: recover ? {...recover.request} : null, software: recover ? null : {...update.request}};
      if (recover) {
        const reviewer = recover.work_purpose === "reviewer";
        const completion = recover.work_purpose === "goal_completion";
        $("software-update-title").textContent = reviewer ? "确认发起新的评审请求？" : completion ? "确认重新核对完成情况？" : "确认发起新的模型请求？";
        const next = reviewer ? "发起新一轮独立评审，核对已有成果" : completion ? "重新核对任务完成情况" : "发起新的模型请求，接着做原任务";
        $("software-update-description").textContent = "上次模型请求未收到完整回复，执行结果和费用尚未确认。旧请求和未知记录会保留；确认后将" + next + "，可能产生新的费用。" +
          (recover.software_changed ? " Sitina 也已更新，本次确认同时允许使用当前版本接续原任务。" : "");
        $("software-update-confirm").textContent = reviewer ? "确认发起新评审" : "确认发起新请求";
      } else {
        $("software-update-title").textContent = "更新后接着做原任务？";
        $("software-update-description").textContent = "Sitina 已更新。将保留原任务的记录、文件和进度，使用当前版本接着做。还有未核对清楚的操作时，任务会继续停住。";
        $("software-update-confirm").textContent = "确认并继续";
      }
      returnFocus = $(id);
      $("software-update-dialog").showModal(); $("software-update-cancel").focus();
      return;
    }
    // A cold task must first connect and obtain a real Host-bound proposal.
    mutate(() => sendTaskControl(control));
  });
}
$("software-update-cancel").addEventListener("click", () => $("software-update-dialog").close());
$("software-update-dialog").addEventListener("close", () => {pendingTaskContinuation = null;});
$("software-update-confirm").addEventListener("click", () => {
  const confirmation = pendingTaskContinuation;
  if (!confirmation || busy) return;
  $("software-update-dialog").close();
  mutate(() => sendTaskControl("resume", confirmation)).finally(() => {
    if (!$("pause").hidden) $("pause").focus();
  });
});
$("attach").addEventListener("click", () => $("file-input").click());
$("file-input").addEventListener("change", () => {
  const files = Array.from($("file-input").files); $("file-input").value = "";
  if (files.some(file => file.size > 8 * 1024 * 1024)) {toast("单个附件最多8 MiB。"); return;}
  mutate(async () => {
    if (!selected) await createSession();
    for (const file of files) {
      const data = await new Promise((resolve, reject) => {
        const reader = new FileReader(); reader.onload = () => resolve(String(reader.result).split(",")[1]);
        reader.onerror = () => reject(new Error("附件未完整读取。")); reader.readAsDataURL(file);
      });
      const item = await api(apiPath(selected, "/attachments"), {method: "POST", body: {name: file.name, data}});
      staged.push(item); renderStaged();
    }
  });
});
function renderStaged() {
  $("attachments").replaceChildren(...staged.map(item => {
    const chip = element("div", "attachment-chip");
    const remove = element("button", "", "×"); remove.type = "button";
    remove.setAttribute("aria-label", "不在本次消息附带" + item.name);
    remove.addEventListener("click", () => {staged = staged.filter(file => file.id !== item.id); renderStaged();});
    chip.append(element("span", "", item.name), remove); return chip;
  }));
}
function showMenu(sid, x, y, focus) {
  closeMenu(); menuSession = sid; returnFocus = focus;
  const menu = $("session-menu"); menu.hidden = false;
  menu.style.left = Math.max(8, Math.min(x - 195, innerWidth - 210)) + "px";
  menu.style.top = Math.max(8, Math.min(y + 3, innerHeight - menu.offsetHeight - 10)) + "px";
  menu.querySelector("button").focus();
}
function closeMenu(restore = false) {
  $("session-menu").hidden = true;
  if (restore && returnFocus?.isConnected) returnFocus.focus();
}
$("session-menu").addEventListener("keydown", event => {
  const buttons = Array.from($("session-menu").querySelectorAll("button"));
  const index = buttons.indexOf(document.activeElement);
  if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault(); buttons[(index + (event.key === "ArrowDown" ? 1 : -1) + buttons.length) % buttons.length].focus();
  } else if (event.key === "Escape" || event.key === "Tab") {
    closeMenu(true);
    if (event.key === "Escape") event.stopPropagation();
  }
});
document.addEventListener("pointerdown", event => {
  if (!$("session-menu").contains(event.target) && !event.target.closest(".session-row")) closeMenu();
});
for (const button of $("session-menu").querySelectorAll("button")) {
  button.prepend(icon({directory: "folder", copy: "copy", open: "external", delete: "trash"}[button.dataset.action]));
  button.addEventListener("click", async () => {
    const sid = menuSession; closeMenu();
    try {
      const data = sid === selected && snapshot ? snapshot : await api(apiPath(sid));
      if (button.dataset.action === "copy") {await copyPath(data.directory); return;}
      if (button.dataset.action === "open") {await api(apiPath(sid, "/open-folder"), {method: "POST", body: {}}); return;}
      if (button.dataset.action === "directory") {
        $("directory-session").textContent = data.session.title;
        $("directory-path").value = data.directory;
        $("directory-dialog").dataset.sid = sid;
        $("directory-dialog").showModal();
      } else {
        deleteTargets = [sid]; pendingDeletionRequest = null;
        $("delete-title").textContent = "彻底删除此会话？";
        $("delete-session").textContent = data.session.title;
        $("delete-dialog").dataset.sid = sid;
        $("delete-result").hidden = !data.session.delete_error;
        $("delete-result").textContent = data.session.delete_error || "";
        $("delete-confirm").textContent = data.session.deleting ? "核对并继续删除" : "彻底删除";
        $("delete-dialog").showModal(); $("delete-cancel").focus();
      }
    } catch (error) {toast(requestErrorMessage(error));}
  });
}
async function copyPath(path) {
  try {await navigator.clipboard.writeText(path); toast("目录路径已复制。");}
  catch (_) {
    $("directory-path").value = path; $("directory-dialog").showModal();
    $("directory-path").focus(); $("directory-path").select(); toast("请复制已选中的目录路径。");
  }
}
$("directory-copy").addEventListener("click", () => copyPath($("directory-path").value));
$("directory-open").addEventListener("click", () => api(apiPath($("directory-dialog").dataset.sid, "/open-folder"),
  {method: "POST", body: {}}).catch(error => toast(requestErrorMessage(error))));
$("delete-cancel").addEventListener("click", () => $("delete-dialog").close());
$("delete-dialog").addEventListener("cancel", event => {if ($("delete-confirm").disabled) event.preventDefault();});
$("delete-confirm").addEventListener("click", async () => {
  const targets = [...deleteTargets];
  if (!targets.length || busy) return;
  busy = true; updateSend();
  $("delete-confirm").disabled = true; $("delete-cancel").disabled = true;
  $("delete-dialog").querySelector(".dialog-close").disabled = true;
  $("delete-result").hidden = false;
  $("delete-result").textContent = "正在提交删除队列…";
  try {
    if (!pendingDeletionRequest) pendingDeletionRequest = {request_id:requestId(),session_ids:targets,confirmation:"permanent"};
    const result = await api("/api/deletions",{method:"POST",body:pendingDeletionRequest});
    deleteJob = result.job; dismissedDeletionJob = null;
    targets.forEach(id=>selectedSessions.delete(id));
    deleteTargets = []; pendingDeletionRequest = null;
    $("delete-dialog").close();
    renderDeletionProgress(); renderList();
    toast("已开始永久删除，进度和暂停按钮在会话目录中。");
    await refreshDeletion();
  } catch (error) {
    $("delete-result").textContent = requestErrorMessage(error);
    $("delete-confirm").textContent = "核对并继续删除";
    await refreshDeletion();
  } finally {
    busy = false; updateSend();
    $("delete-confirm").disabled = false; $("delete-cancel").disabled = false;
    $("delete-dialog").querySelector(".dialog-close").disabled = false;
  }
});
document.querySelectorAll("dialog").forEach(dialog => {
  dialog.addEventListener("close", () => {
    if (returnFocus?.isConnected) returnFocus.focus(); else $("composer").focus();
  });
  dialog.addEventListener("keydown", event => {
    if (event.key !== "Tab") return;
    const controls = Array.from(dialog.querySelectorAll("button, [href], input, select, textarea, [tabindex]"))
      .filter(node => !node.disabled && !node.hidden && node.tabIndex >= 0
        && node.getClientRects().length && getComputedStyle(node).visibility !== "hidden");
    if (!controls.length) {event.preventDefault(); dialog.focus(); return;}
    const first = controls[0], last = controls[controls.length - 1];
    const outside = !dialog.contains(document.activeElement);
    if (event.shiftKey && (document.activeElement === first || outside)) {
      event.preventDefault(); last.focus();
    } else if (!event.shiftKey && (document.activeElement === last || outside)) {
      event.preventDefault(); first.focus();
    }
  });
});
function drawerFocusAvailable(node) {
  return node?.isConnected && !node.disabled && !node.hidden && !node.closest("[inert]")
    && node.getClientRects().length && getComputedStyle(node).visibility !== "hidden";
}
function closeDrawers({restoreFocus = false, repairHiddenFocus = false} = {}) {
  const panels = [$("sessions-panel"), $("team-panel")];
  const opened = panels.find(panel => panel.classList.contains("drawer-open"));
  const active = document.activeElement;
  const focusedPanel = panels.find(panel => panel.contains(active));
  for (const panel of panels) panel.classList.remove("drawer-open");
  $("drawer-backdrop").hidden = true;
  $("toggle-sessions").setAttribute("aria-expanded", "false");
  $("toggle-team").setAttribute("aria-expanded", innerWidth > 1190 && !document.body.classList.contains("team-collapsed") ? "true" : "false");
  const hiddenFocus = focusedPanel && !drawerFocusAvailable(active);
  if (restoreFocus && opened || repairHiddenFocus && hiddenFocus) {
    const panel = opened || focusedPanel;
    const opener = $(panel.id === "sessions-panel" ? "toggle-sessions" : "toggle-team");
    [opener, $("composer")].find(drawerFocusAvailable)?.focus();
  }
  return Boolean(opened);
}
$("toggle-sessions").addEventListener("click", () => {
  const open = !$("sessions-panel").classList.contains("drawer-open");
  closeDrawers({restoreFocus: !open});
  $("sessions-panel").classList.toggle("drawer-open", open); $("drawer-backdrop").hidden = !open;
  $("toggle-sessions").setAttribute("aria-expanded", String(open));
  if (open) $("search").focus();
});
$("toggle-team").addEventListener("click", () => {
  if (innerWidth > 1190) {
    document.body.classList.toggle("team-collapsed");
    $("toggle-team").setAttribute("aria-expanded", String(!document.body.classList.contains("team-collapsed")));
  } else {
    const open = !$("team-panel").classList.contains("drawer-open");
    closeDrawers({restoreFocus: !open});
    $("team-panel").classList.toggle("drawer-open", open); $("drawer-backdrop").hidden = !open;
    $("toggle-team").setAttribute("aria-expanded", String(open));
    if (open) $("team-panel").focus();
  }
});
$("drawer-backdrop").addEventListener("click", () => closeDrawers({restoreFocus: true}));
document.addEventListener("keydown", event => {
  if (event.key === "Escape") {
    // Native dialogs and nested menus own Escape before their parent drawer.
    if (document.querySelector("dialog[open]")) return;
    if (!$("session-menu").hidden) {closeMenu(true); event.preventDefault(); return;}
    if (closeDrawers({restoreFocus: true})) event.preventDefault();
  }
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "n") {event.preventDefault(); mutate(createSession);}
});
addEventListener("resize", () => closeDrawers({repairHiddenFocus: true}));
async function boot() {
  try {
    csrf = (await api("/api/bootstrap")).csrf;
    setupMemoryUI({api, currentSession: () => selected});
    await refreshList(); connection(true);
    const remembered = localStorage.getItem("sitina:selected-session");
    const first = sessions.find(item => item.id === remembered) || sessions[0];
    if (first) await choose(first.id);
    updateSend(); closeDrawers(); schedule();
    if (initialSkillsView) showCapabilityView(true, false);
  } catch (error) {connection(false); notice(requestErrorMessage(error) + "\n请刷新页面重新连接本机服务。");}
}
boot();
// Capabilities are attached to the original session and authority, never replayed as new work.
const initialSkillsView = location.hash === "#skills";
let skillsLoading = false, skillsLoaded = false, skillsRows = [], skillPending = null;
let executionSession = null, executionSelected = null, executionFetching = false;
let executionRecords = new Map(), executionPending = new Map();
const executionStateLabels = {
  RUNNING: "运行中", STARTING: "正在启动", PENDING: "等待回执", STOPPED: "已停止",
  EXITED: "已退出", SUCCEEDED: "已完成", FAILED: "运行失败", NOT_STARTED: "未启动",
  PERMISSION_DENIED: "权限拒绝", START_FAILED: "启动失败", UNKNOWN: "状态未知",
};
function readCapabilityPending(key, fallback) {
  try { return JSON.parse(sessionStorage.getItem(key) || "null") || fallback; }
  catch (_) { return fallback; }
}
skillPending = readCapabilityPending("sitina:skill-operation", null);
function persistSkillPending() {
  if (skillPending) sessionStorage.setItem("sitina:skill-operation", JSON.stringify(skillPending));
  else sessionStorage.removeItem("sitina:skill-operation");
}
function showCapabilityView(skills, focus = true) {
  document.body.classList.toggle("skills-view", skills);
  $("skills-panel").hidden = !skills;
  $("show-skills").setAttribute("aria-pressed", String(skills));
  $("toggle-team").hidden = skills;
  history.replaceState(null, "", location.pathname + location.search + (skills ? "#skills" : ""));
  closeDrawers();
  if (skills) {
    document.title = "Skills · Sitina";
    if (focus) $("skills-title").focus();
    if (!skillsLoaded && !skillsLoading) refreshSkills();
  } else if (focus) $("composer").focus();
}
function capabilityNotice(message, error = false) {
  const node = $("skills-notice");
  node.replaceChildren(document.createTextNode(message || ""));
  node.hidden = !message;
  node.classList.toggle("error", error);
  if (skillPending) {
    const actions = element("div", "capability-operation");
    actions.append(element("span", "", "前次技能操作已保留。"));
    const retry = element("button", "secondary-button", "核对／重试原操作");
    retry.type = "button"; retry.disabled = skillsLoading;
    retry.addEventListener("click", () => submitSkillOperation(skillPending));
    actions.append(retry); node.append(actions);
  }
}
function skillStateLabel(skill) {
  if (skill.availability === "UNAVAILABLE") return "来源不可用";
  if (skill.enabled === true) return skill.missing_tools?.length ? "已启用 · 缺少工具" : "已启用";
  return skill.installed === false ? "未安装" : "已安装 · 未启用";
}
async function refreshSkills({preserveNotice = false} = {}) {
  if (skillsLoading) return;
  skillsLoading = true;
  $("refresh-skills").disabled = true;
  $("skills-list").setAttribute("aria-busy", "true");
  if (!skillsLoaded) $("skills-list").replaceChildren(element("div", "skills-loading", "正在读取本机技能…"));
  try {
    const result = await api("/api/skills");
    if (!Array.isArray(result.skills)) throw new Error("技能列表回执格式不完整，尚未更新显示。");
    const operations = Array.isArray(result.operations) ? result.operations : [];
    const own = skillPending && operations.find(item => item && item.request_id === skillPending.request_id);
    const ownState = String(own?.state || "UNKNOWN").toUpperCase();
    const settled = own && ["ACCEPTED", "SUCCEEDED", "COMPLETED", "FAILED", "REJECTED"].includes(ownState);
    if (settled) {skillPending = null; persistSkillPending(); $("skill-install").disabled = false;}
    skillsRows = result.skills; skillsLoaded = true;
    if ($("skill-install-location")) $("skill-install-location").textContent =
      "安装位置：" + (result.installation_root || "尚未初始化") + " · 全局可用，新任务生效；旧任务保留固定版本。";
    renderSkills();
    const pendingOperations = operations.filter(item => item && ["PENDING", "UNKNOWN"].includes(String(item.state).toUpperCase()));
    if (settled) capabilityNotice(own.message || "前次技能操作已取得终态。", ["FAILED", "REJECTED"].includes(ownState));
    else if (!preserveNotice) capabilityNotice(skillPending ? "前次操作结果尚未确认。保留原请求标识，核对后再操作。" :
      pendingOperations.length ? "有 " + pendingOperations.length + " 个技能操作正在进行或等待核对。原请求与已安装版本均保留。" : "");
  } catch (error) {
    if (!skillsLoaded) $("skills-list").replaceChildren(element("p", "capability-empty", "暂时无法读取技能。可重试；已安装版本会保留。"));
    capabilityNotice(requestErrorMessage(error), true);
  } finally {
    skillsLoading = false; $("refresh-skills").disabled = false;
    $("skills-list").setAttribute("aria-busy", "false");
    $("skills-notice").querySelectorAll("button").forEach(button => {button.disabled = false;});
  }
}
function skillActionButton(label, action, skill) {
  const button = element("button", "secondary-button", label);
  button.type = "button"; button.disabled = !!skillPending;
  button.addEventListener("click", () => {
    if (action === "delete" && !window.confirm("删除技能“" + skill.name + "”？新任务将不能使用；旧任务固定版本与历史记录保留。")) return;
    submitSkillOperation({action, name: skill.name, request_id: requestId()});
  });
  return button;
}
function renderSkills() {
  const list = $("skills-list");
  list.replaceChildren();
  if (!skillsRows.length) {
    list.append(element("p", "capability-empty", "还没有安装独立技能。可从本地目录、技能包或你指定的匿名公开来源安装。"));
    return;
  }
  for (const skill of skillsRows) {
    const row = element("article", "skill-row");
    const heading = element("div", "skill-row-heading");
    const title = element("div");
    title.append(element("h3", "", skill.name), element("div", "skill-meta", "当前版本：" + (skill.version || "未选择")));
    heading.append(title, element("span", "skill-state" + (skill.enabled ? "" : " disabled"), skillStateLabel(skill)));
    row.append(heading, element("p", "skill-description", skill.description || "技能元数据暂不可读取。"));
    if (skill.unavailable_reason) row.append(element("p", "skill-meta", skill.unavailable_reason));
    const actions = element("div", "skill-actions");
    actions.append(skillActionButton(skill.enabled ? "停用" : "启用", skill.enabled ? "disable" : "enable", skill));
    actions.append(skillActionButton("删除", "delete", skill));
    const versions = Array.isArray(skill.versions) ? skill.versions : [];
    if (versions.length > 1) {
      const select = element("select");
      select.setAttribute("aria-label", skill.name + "的安装版本");
      for (const version of versions) {
        const option = element("option", "", (version.version || "未声明版本") + " · " + version.candidate_id.slice(-8) + (version.active ? " · 当前" : ""));
        option.title = version.candidate_id;
        option.value = version.candidate_id; select.append(option);
      }
      if (skill.candidate_id) select.value = skill.candidate_id;
      select.disabled = !!skillPending;
      const rollback = element("button", "secondary-button", "切换版本"); rollback.type = "button";
      rollback.disabled = !!skillPending;
      rollback.addEventListener("click", () => submitSkillOperation({
        action: "rollback", name: skill.name, version: select.value, request_id: requestId(),
      }));
      actions.append(select, rollback);
    }
    row.append(actions);
    const detail = element("details", "skill-details");
    detail.append(element("summary", "", "查看来源、工具与说明"));
    const metadata = element("dl");
    const fields = [
      ["来源", skill.source || "尚无来源记录"], ["版本身份", skill.candidate_id || "未选择"],
      ["安装目录", skill.installation_path || "暂不可核实"],
      ["所需工具", (skill.required_tools || []).join("、") || "未声明"],
      ["缺少工具", (skill.missing_tools || []).join("、") || (skill.tools_observed ? "未发现缺项" : "尚未核对")],
      ["生效范围", "全局默认；已有任务保留其固定版本。"],
    ];
    for (const [name, value] of fields) metadata.append(element("dt", "", name), element("dd", "", value));
    detail.append(metadata);
    row.append(detail); list.append(row);
  }
}
async function inspectSkillSource(source) {
  if (skillsLoading || skillPending) return;
  skillsLoading = true; $("skill-install").disabled = true;
  const choices = $("skill-source-choices"); choices.replaceChildren();
  capabilityNotice("正在识别来源并固定版本，尚未安装。");
  try {
    const result = await api("/api/skills/inspect", {method: "POST", body: {source, request_id: requestId()}});
    if (!Array.isArray(result.choices)) throw new Error("来源清单格式不完整。");
    capabilityNotice(result.kind === "marketplace" ? "已识别技能市场，请选择要安装的技能。" : "来源已识别，请确认安装。");
    for (const choice of result.choices) {
      const row = element("div", "skill-row");
      row.dataset.skillSource = choice.source;
      row.append(element("strong", "", choice.name), element("p", "skill-meta", choice.group || "独立技能"));
      const install = element("button", "secondary-button", "安装 " + choice.name);
      install.type = "button";
      install.addEventListener("click", () => submitSkillOperation({
        action: "install_public", source: choice.source, request_id: requestId(), enable: $("skill-enable").checked,
      }));
      row.append(install); choices.append(row);
    }
    if (result.unsupported?.length) choices.append(element("p", "skill-meta",
      "以下插件来源尚不支持，未安装：" + result.unsupported.join("、")));
    if (!result.choices.length) capabilityNotice("清单中没有可安装的技能，请使用具体技能目录。", true);
  } catch (error) {capabilityNotice("来源识别失败，未安装：" + requestErrorMessage(error), true);}
  finally {skillsLoading = false; $("skill-install").disabled = false;}
}
async function submitSkillOperation(request) {
  if (skillsLoading || (skillPending && skillPending.request_id !== request.request_id)) return;
  skillPending = request; persistSkillPending(); skillsLoading = true;
  $("skill-install").disabled = true; $("refresh-skills").disabled = true;
  renderSkills(); capabilityNotice("正在处理技能操作。安装成功与启用状态将分别显示。");
  try {
    const result = await api("/api/skills", {method: "POST", body: request});
    const state = String(result.state || result.status || "UNKNOWN").toUpperCase();
    if (["ACCEPTED", "SUCCEEDED", "OK", "COMPLETED"].includes(state)) {
      skillPending = null; persistSkillPending();
      capabilityNotice(result.message || "操作已确认。已有任务继续使用其固定版本。");
      if (request.action.startsWith("install")) {
        $("skill-source").value = "";
        for (const row of $("skill-source-choices").children) {
          if (row.dataset.skillSource === request.source) row.remove();
        }
      }
    } else if (["FAILED", "REJECTED", "NOT_SENT"].includes(state)) {
      skillPending = null; persistSkillPending();
      capabilityNotice(result.message || result.reason || "操作未完成。请检查来源与权限后重新提交。", true);
    } else capabilityNotice(result.message || "操作结果待确认。请核对原操作，不要重新安装。");
  } catch (error) {
    const definitive = error.httpStatus >= 400 && error.httpStatus < 500 && error.httpStatus !== 408;
    if (definitive) {skillPending = null; persistSkillPending();}
    capabilityNotice(requestErrorMessage(error) + (definitive ? "" : " 连接中断，操作结果未知；保留原请求用于对账。"), true);
  } finally {
    skillsLoading = false; $("skill-install").disabled = !!skillPending;
    $("refresh-skills").disabled = false;
    await refreshSkills({preserveNotice: true});
  }
}
$("show-skills").addEventListener("click", () => showCapabilityView(true));
$("back-to-chat").addEventListener("click", () => showCapabilityView(false));
$("refresh-skills").addEventListener("click", refreshSkills);
$("skill-source-type").addEventListener("change", () => {
  const publicSource = $("skill-source-type").value === "install_public";
  $("skill-install").textContent = publicSource ? "查看可安装技能" : "安装技能";
  $("skill-source-choices").replaceChildren();
  $("skill-source").placeholder = publicSource ? "https://… 公开地址或仓库" : "包含 SKILL.md 的绝对路径";
  $("skill-source-hint").textContent = publicSource
    ? "仅支持匿名公开下载与受控公开 Git 读取；需要登录或私有来源时会说明缺口。"
    : "使用本机路径；安装保留完整版本，不执行技能脚本。";
});
$("skill-install-form").addEventListener("submit", event => {
  event.preventDefault();
  const source = $("skill-source").value.trim();
  if (!source || skillPending) return;
  if ($("skill-source-type").value === "install_public") {inspectSkillSource(source); return;}
  submitSkillOperation({action: $("skill-source-type").value, source,
    enable: $("skill-enable").checked, request_id: requestId()});
});
function resetExecutions() {
  executionPanels.clear();
  executionSession = selected; executionSelected = null; executionRecords = new Map();
  executionPending = new Map(Object.entries(readCapabilityPending("sitina:execution-actions:" + selected, {})));
  $("execution-list").replaceChildren();
  delete $("execution-detail").dataset.processId;
  $("execution-detail").replaceChildren(element("p", "capability-empty", "正在读取本会话的进程…"));
  $("execution-count").textContent = "0";
}
function terminalInputData(value) {
  return value.endsWith("\n") || value.endsWith("\r") ? value : value + "\n";
}
function persistExecutionPending() {
  sessionStorage.setItem("sitina:execution-actions:" + executionSession, JSON.stringify(Object.fromEntries(executionPending)));
}
function reconcileExecutionControl(pid, ack) {
  const pending = executionPending.get(pid), record = executionRecords.get(pid);
  if (!pending || !record || !ack || typeof ack !== "object" ||
      ack.request_id !== pending.request_id || ack.action !== pending.action) return false;
  const state = String(ack.state || "UNKNOWN").toUpperCase();
  if (!["APPLIED", "REJECTED"].includes(state)) return false;
  executionPending.delete(pid); persistExecutionPending();
  record.controlMessage = state === "APPLIED" ? "控制已执行；进程实际状态显示在上方。" :
    "控制被拒绝：" + (ack.reason || "请核对当前进程状态。");
  if (state === "APPLIED" && pending.action === "input" && executionDetailNode(pid).dataset.processId === pid) {
    const input = executionDetailNode(pid).querySelector(".execution-input textarea");
    if (input && terminalInputData(input.value) === pending.data) input.value = "";
  }
  return state === "APPLIED";
}
function executionState(process) { return String(process?.state || "UNKNOWN").toUpperCase(); }
function executionActive(process) { return ["RUNNING", "STARTING", "PENDING", "UNKNOWN"].includes(executionState(process)); }
function executionLabel(process, statusUnverified = false) {
  if (statusUnverified) return "状态待核实";
  if (executionState(process) === "STOPPED" && process.trusted_root_result === true) {
    if (process.program_status === "PASS") return "已完成";
    if (process.program_status === "FAIL") return "运行失败";
  }
  return executionStateLabels[executionState(process)] || executionState(process);
}
function executionCommand(process) {
  if (typeof process.shell_text === "string" && process.shell_text) return process.shell_text;
  if (typeof process.command === "string") return process.command;
  if (Array.isArray(process.command)) return process.command.map(value => JSON.stringify(value)).join(" ");
  if (Array.isArray(process.argv)) return process.argv.map(value => JSON.stringify(value)).join(" ");
  return process.process_id;
}
function renderExecutionList() {
  const groups = new Map([...executionPanels.values()].map(panel => [panel, []]));
  for (const [pid, record] of executionRecords) {
    const candidates = [...executionPanels.values()].filter(panel => panel.item.task_id === record.process.task_id);
    const exact = candidates.find(panel => panel.item.reply_to === record.process.reply_to && record.process.reply_binding_known);
    const panel = exact || candidates[candidates.length - 1];
    record.panel = panel;
    record.unboundTurn = !exact && candidates.length > 1;
    if (panel) groups.get(panel).push([pid, record]);
  }
  for (const [panel, rows] of groups) {
    panel.node.hidden = !rows.length; panel.count.textContent = String(rows.length);
    if (!rows.some(([pid]) => pid === panel.selected)) panel.selected = rows[0]?.[0] || null;
    const focusId = panel.list.contains(document.activeElement) ? document.activeElement?.dataset.processId : null;
    const listScrollTop = panel.list.scrollTop;
    panel.list.replaceChildren();
    for (const [pid, record] of rows) {
      const button = element("button", "execution-select"); button.type = "button"; button.dataset.processId = pid;
      button.setAttribute("aria-current", String(pid === panel.selected));
      button.append(element("span", "execution-list-command", executionCommand(record.process)), element("small", "", executionLabel(record.process, record.statusUnverified)));
      button.addEventListener("click", () => {panel.selected = pid; executionSelected = pid; renderExecutionList(); renderExecutionDetail(pid);});
      panel.list.append(button); if (pid === focusId) button.focus({preventScroll: true});
    }
    panel.list.scrollTop = listScrollTop;
    if (panel.selected) renderExecutionDetail(panel.selected);
  }
}
function executionDetailNode(pid = executionSelected) {
  return executionRecords.get(pid)?.panel?.detail || $("execution-detail");
}
async function refreshExecutions(sid) {
  if (executionFetching || sid !== selected) return;
  if (executionSession !== sid) resetExecutions();
  executionFetching = true;
  try {
    const result = await api(apiPath(sid, "/executions"));
    if (sid !== selected) return;
    if (!Array.isArray(result.executions)) throw new Error("进程列表回执不完整。");
    for (const process of result.executions) {
      if (typeof process.process_id !== "string") continue;
      const previous = executionRecords.get(process.process_id);
      if (previous) previous.process = {...previous.process, ...process};
      else executionRecords.set(process.process_id,
        {process, offsets: {stdout: 0, stderr: 0, combined: 0}, texts: {}, trimmed: {}});
    }
    $("execution-count").textContent = String(result.executions.length);
    const statusErrors = Array.isArray(result.status_errors) ? result.status_errors : [];
    for (const record of executionRecords.values()) record.statusUnverified = statusErrors.length > 0;
    executionConnection(statusErrors.length ? "部分状态待核实" : "已连接");
    if (!executionSelected && result.executions.length) executionSelected = result.executions[0].process_id;
    renderExecutionList();
  } catch (error) {
    if (sid !== selected) return;
    executionConnection(error.httpStatus === 404 ? "执行入口暂不可用" : "连接中断 · 保留原进程");
    for (const record of executionRecords.values()) record.statusUnverified = true;
    renderExecutionList();
    if (!executionRecords.size) $("execution-detail").replaceChildren(element("p", "capability-empty", requestErrorMessage(error) + " 重连只读取状态，不会启动命令。"));
  } finally { executionFetching = false; }
}
async function readExecution(sid, pid) {
  const record = executionRecords.get(pid);
  if (!record || sid !== selected || record.reading) return;
  record.reading = true;
  const query = new URLSearchParams(Object.entries(record.offsets).map(([key, value]) => [key + "_offset", String(value)]));
  const pending = executionPending.get(pid);
  if (pending) query.set("control_request_id", pending.request_id);
  try {
    const result = await api(apiPath(sid, "/executions/" + encodeURIComponent(pid)) + "?" + query);
    if (sid !== selected || executionRecords.get(pid) !== record) return;
    if (result.process_id !== pid || !result.output || typeof result.output.streams !== "object") throw new Error("进程输出回执不完整。");
    record.process = {...record.process, ...result,
      reply_to: result.reply_to ?? record.process.reply_to,
      reply_binding_known: result.reply_binding_known || record.process.reply_binding_known};
    record.disconnected = false;
    record.readError = null;
    reconcileExecutionControl(pid, result.control_ack || result.output.control_ack);
    for (const [name, stream] of Object.entries(result.output.streams)) {
      if (!["stdout", "stderr", "combined"].includes(name) || typeof stream.raw_base64 !== "string" ||
          !Number.isSafeInteger(stream.offset) || !Number.isSafeInteger(stream.next_offset))
        throw new Error("进程输出缺少准确的字节或游标。");
      if (stream.offset !== record.offsets[name] || stream.next_offset < stream.offset) {
        record.readError = "输出游标不连续，已停止追加。请保留当前会话核对。"; continue;
      }
      const bytes = Uint8Array.from(atob(stream.raw_base64), value => value.charCodeAt(0));
      if (bytes.length !== stream.next_offset - stream.offset)
        throw new Error("进程输出字节数与游标不一致，已停止追加。");
      record.decoders ||= {};
      record.decoders[name] ||= new TextDecoder("utf-8");
      const finished = stream.eof === true && ["STOPPED", "NOT_STARTED"].includes(executionState(result));
      const decoded = record.decoders[name].decode(bytes, {stream: !finished});
      record.texts[name] = (record.texts[name] || "") + decoded;
      record.offsets[name] = stream.next_offset;
      if (record.texts[name].length > 200000) {record.texts[name] = record.texts[name].slice(-200000); record.trimmed[name] = true;}
    }
    renderExecutionDetail(pid);
  } catch (error) {
    record.disconnected = true; record.readError = requestErrorMessage(error);
    executionConnection("输出断线 · 正在续接");
    renderExecutionDetail(pid);
  } finally {record.reading = false;}
}
function executionButton(label, action, pid) {
  const button = element("button", "secondary-button", label);
  button.type = "button"; button.dataset.controlAction = action;
  button.addEventListener("click", () => controlExecution(pid, {action}));
  return button;
}
function renderExecutionDetail(pid = executionSelected) {
  const record = executionRecords.get(pid), node = executionDetailNode(pid);
  if (!record || !record.panel || record.panel.selected !== pid) return;
  const process = record.process;
  const detailComplete = node.querySelector(".execution-command") && node.querySelector(".execution-state");
  if (node.dataset.processId !== pid || !detailComplete) {
    delete node.dataset.processId; node.replaceChildren();
    const heading = element("div", "execution-heading");
    heading.append(element("pre", "execution-command"), element("span", "execution-state"));
    node.append(heading);
    node.dataset.processId = pid;
  }
  node.querySelector(".execution-command").textContent = executionCommand(process);
  const badge = node.querySelector(".execution-state");
  badge.textContent = executionLabel(process, record.statusUnverified);
  badge.classList.toggle("uncertain", record.statusUnverified || executionState(process) === "UNKNOWN");
}
async function controlExecution(pid, command) {
  const record = executionRecords.get(pid), sid = executionSession;
  if (!record || sid !== selected) return false;
  const previous = executionPending.get(pid);
  if (previous && previous.request_id !== command.request_id) return false;
  const request = {...command, request_id: command.request_id || requestId()};
  executionPending.set(pid, request); persistExecutionPending(); renderExecutionDetail(pid);
  try {
    const result = await api(apiPath(sid, "/executions/" + encodeURIComponent(pid) + "/control"), {method: "POST", body: request});
    if (sid !== selected) return false;
    const ack = result.control_ack || result.output?.control_ack;
    const ackState = String(ack?.state || "UNKNOWN").toUpperCase();
    if (result.process_id === pid) record.process = {...record.process, ...result};
    const bound = ack?.request_id === request.request_id && ack?.action === request.action;
    const confirmed = bound && ackState === "APPLIED";
    const rejected = bound && ackState === "REJECTED";
    reconcileExecutionControl(pid, ack);
    record.controlMessage = confirmed ? "控制已执行；进程实际状态显示在上方。" :
      rejected ? "控制被拒绝：" + (ack?.reason || result.reason || "请核对当前进程状态。") : "控制结果未知，保留原请求等待核对。";
    await readExecution(sid, pid); renderExecutionDetail(pid);
    return confirmed;
  } catch (error) {
    if (error.httpStatus >= 400 && error.httpStatus < 500 && error.httpStatus !== 408) {
      executionPending.delete(pid); persistExecutionPending();
    }
    record.controlMessage = requestErrorMessage(error) + " 当前控制结果以服务端回执为准。";
    renderExecutionDetail(pid); return false;
  }
}
$("execution-dock").addEventListener("toggle", () => {if ($("execution-dock").open && selected) refreshExecutions(selected);});
if (initialSkillsView) showCapabilityView(true, false);
