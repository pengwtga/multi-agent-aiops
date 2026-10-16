"""自愈闭环可视化 Dashboard

提供页面与状态聚合函数：
- GET /dashboard        页面（自包含 HTML，无外部依赖、无 CDN）
- build_state(...)      把分散的 API 响应聚合成页面需要的扁平结构

设计原则：
1. **只读**——页面不执行任何命令，只展示编排器已产生的状态
2. **故障演练走独立端点** —— `POST /api/v1/drill/inject`（见 `api/main.py`），
   受 `AIOPS_DRILL_ENABLED` 开关与容器白名单双重保护，默认关闭
3. **无外部依赖** —— 内联 CSS/JS，断网也能看，避免 CDN 不可用时白屏
4. **状态聚合在后端** —— `get_workflow_status()` 返回的是 list，后端先按 name
   建成索引再下发给前端，前端直接渲染，不做查找（避免列表/字典混用的坑）
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

logger = logging.getLogger(__name__)

router = APIRouter()

# 编排器节点顺序（与 orchestrator._build_default_workflow 一致）
PIPELINE: list[tuple[str, str, str]] = [
    ("monitor", "监控告警", "MonitorAgent"),
    ("rca", "根因分析", "RCAAgent"),
    ("heal_propose", "自愈提议", "HealProposeAgent"),
    ("change", "变更审批", "ChangeAgent"),
    ("heal_execute", "自愈执行", "HealExecuteAgent"),
]

# 节点状态 → (中文标签, 颜色)
# 覆盖 orchestrator.NodeStatus（pending/running/completed/skipped/failed）
# 以及业务状态（approved/rejected/awaiting_human/heal_failed 等）
STATUS_STYLE: dict[str, tuple[str, str]] = {
    "pending": ("待执行", "#6b7280"),
    "running": ("执行中", "#3b82f6"),
    "completed": ("已完成", "#10b981"),
    "success": ("成功", "#10b981"),
    "skipped": ("已跳过", "#f59e0b"),
    "failed": ("失败", "#ef4444"),
    "approved": ("已通过", "#10b981"),
    "pending_approval": ("待审批", "#f59e0b"),
    "rejected": ("已驳回", "#ef4444"),
    "awaiting_human": ("待人工", "#f59e0b"),
    "heal_failed": ("执行失败", "#ef4444"),
    "resolved": ("已解决", "#10b981"),
    # 无告警时的「空闲态」：用来区分「本轮没触发」与「跑过但被跳过」，
    # 避免一打开页面就显示「已完成 / 已跳过」这种误导性状态
    "monitoring": ("监控中", "#3b82f6"),
    "idle": ("待触发", "#6b7280"),
}

# 视为「已完成」的状态（用于渲染连接线）
DONE_STATES = {"completed", "success", "approved", "resolved"}

DEFAULT_STYLE = ("未知", "#6b7280")


def _style(status: Optional[str]) -> tuple[str, str]:
    if not status:
        return DEFAULT_STYLE
    return STATUS_STYLE.get(str(status).lower(), DEFAULT_STYLE)


def build_state(
    monitor_status: Optional[dict[str, Any]],
    incidents: Optional[dict[str, Any]],
    workflow: Optional[list[dict[str, Any]]],
    drill_enabled: bool,
) -> dict[str, Any]:
    """把 monitor/status + incidents + workflow 聚合成页面结构

    返回：
        monitor:  { cycles, running, alerts }      监控循环状态
        pipeline: [ {key,label,agent,status,status_text,color,retry_count} ]  流水线节点
        latest:   最近一次 incident（含 alert/rca/heal/change 详情）
        history:  最近 10 条（倒序）
        total_incidents, drill_enabled
    """
    incs = (incidents or {}).get("incidents") or []
    latest = incs[-1] if incs else None

    # 最近一次**有告警**的闭环（而非最新一条）
    #
    # 两层原因：
    #
    # 1) 语义：get_workflow_status() 返回的是**全局累积**的节点状态，一旦
    #    某轮跑过就留下来了。直接下发给前端，用户打开页面会看到
    #    「监控告警=已完成、根因分析=已跳过…」，看着像「刚自愈过一轮」，
    #    实际含义却是「本轮监控正常、没发现异常」，非常误导。
    #
    # 2) 时序：不能只看 incs[-1]。监控循环每 30s 一轮，自愈跑完后下一轮
    #    就没告警了（新 incident 是 open）。若据此把流水线重置为
    #    「待触发」，用户刚看到的闭环结果会在 30 秒后凭空消失 ——
    #    表现正是「点了没反应」。
    #
    # 因此从后往前找第一个「有告警」的 incident：找到就展示闭环的真实
    # 进度；从未有过告警则整条流水线显示空闲态。
    active = None
    for inc in reversed(incs):
        if (inc.get("status") or "open") != "open":
            active = inc
            break
    has_alert = active is not None

    # 优先用闭环当次记录的节点快照，而不是 orchestrator 的当前状态。
    #
    # 为什么：节点状态是**全局共享**的。自愈跑完后，监控循环下一轮若无告警，
    # 会把 rca 之后的节点重新置为 SKIPPED，把刚跑完的闭环结果冲掉 ——
    # 页面上就只剩「已完成 + 已跳过」，看着像自愈没跑到底。
    wf_source = (active or {}).get("workflow") if has_alert else None
    wf_by_name: dict[str, dict[str, Any]] = {
        w.get("name"): w for w in (wf_source or workflow or [])
    }

    pipeline: list[dict[str, Any]] = []
    for idx, (key, label, agent) in enumerate(PIPELINE):
        wf = wf_by_name.get(key) or {}
        status = wf.get("status") or "pending"
        if not has_alert:
            # 无告警：monitor 处于常态化监控，后续节点尚未触发
            status = "monitoring" if idx == 0 else "idle"
        text, color = _style(status)
        pipeline.append(
            {
                "key": key,
                "label": label,
                "agent": agent,
                "status": status,
                "status_text": text,
                "color": color,
                "retry_count": wf.get("retry_count", 0),
            }
        )

    return {
        "monitor": {
            "cycles": (monitor_status or {}).get("cycles"),
            "running": (monitor_status or {}).get("running"),
            "alerts": len((monitor_status or {}).get("alerts_fired") or []),
        },
        "pipeline": pipeline,
        "latest": latest,
        "total_incidents": (incidents or {}).get("total", 0),
        "history": incs[-10:][::-1],
        "drill_enabled": drill_enabled,
    }


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    """返回自愈闭环可视化页面"""
    return DASHBOARD_HTML


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AIOps 自愈闭环可视化</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0f172a; --card: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
  }
  body {
    background: var(--bg); color: var(--text);
    font: 14px/1.6 -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif;
    padding: 24px; max-width: 1200px; margin: 0 auto;
  }
  header { display: flex; align-items: center; justify-content: space-between;
           margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
  h1 { font-size: 20px; font-weight: 600; }
  .live { display: flex; align-items: center; gap: 6px; color: var(--muted); font-size: 13px; }
  .pulse { width: 8px; height: 8px; border-radius: 50%; background: #10b981;
           animation: p 2s infinite; }
  @keyframes p { 0%,100% { opacity: 1 } 50% { opacity: .35 } }

  section { margin-bottom: 24px; }
  h2 { font-size: 13px; font-weight: 600; color: var(--muted);
       text-transform: uppercase; letter-spacing: .05em; margin-bottom: 12px; }

  .pipeline { display: flex; align-items: stretch;
              background: var(--card); border: 1px solid var(--border);
              border-radius: 10px; padding: 18px; overflow-x: auto; }
  .node { flex: 1; min-width: 120px; text-align: center; }
  .dot { width: 14px; height: 14px; border-radius: 50%; margin: 0 auto 8px; }
  .dot.running { animation: p 1.2s infinite; }
  .node .label { font-size: 13px; font-weight: 500; }
  .node .agent { font-size: 11px; color: var(--muted); }
  .node .st { font-size: 11px; margin-top: 4px; }
  .conn { flex: 0 0 26px; align-self: center; height: 2px; background: var(--border);
          position: relative; top: -6px; }
  .conn.done { background: #10b981; }

  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; }
  .card { background: var(--card); border: 1px solid var(--border);
          border-radius: 10px; padding: 14px 16px; }
  .card .k { font-size: 11px; color: var(--muted); text-transform: uppercase;
             letter-spacing: .05em; margin-bottom: 6px; }
  .card .v { font-size: 14.5px; font-weight: 500; word-break: break-word; }
  .card .sub { font-size: 12px; color: var(--muted); margin-top: 4px; }
  .empty { color: var(--muted); font-size: 13px; padding: 22px; text-align: center;
           background: var(--card); border: 1px dashed var(--border); border-radius: 10px; }

  .actions { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  button {
    background: var(--accent); color: #0f172a; border: 0; border-radius: 8px;
    padding: 9px 16px; font-size: 13px; font-weight: 600; cursor: pointer;
  }
  button:disabled { opacity: .45; cursor: not-allowed; }
  button.ghost { background: transparent; color: var(--text);
                 border: 1px solid var(--border); font-weight: 500; }
  button.warn { background: #f59e0b; }
  .hint { font-size: 12px; color: var(--muted); }

  table { width: 100%; border-collapse: collapse; background: var(--card);
          border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  th, td { padding: 10px 12px; text-align: left; font-size: 12.5px;
           border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; font-size: 11px;
       text-transform: uppercase; letter-spacing: .05em; }
  tr:last-child td { border-bottom: 0; }
  .mono { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12px; }
</style>
</head>
<body>

<header>
  <h1>AIOps 自愈闭环可视化</h1>
  <div class="live"><span class="pulse"></span><span id="live-text">连接中…</span></div>
</header>

<section>
  <h2>自愈流水线</h2>
  <div class="pipeline" id="pipeline"></div>
</section>

<section>
  <h2>当前状态</h2>
  <div class="cards" id="cards"></div>
</section>

<section>
  <h2>操作</h2>
  <div class="actions">
    <button id="btn-inspect">立即巡检</button>
    <button id="btn-drill" class="warn">故障演练</button>
    <button id="btn-restore" class="ghost">恢复容器</button>
    <span class="hint" id="drill-hint"></span>
  </div>
</section>

<section>
  <h2>历史事件</h2>
  <div id="history"></div>
</section>

<script>
var STYLE = {
  pending:['待执行','#6b7280'], running:['执行中','#3b82f6'],
  completed:['已完成','#10b981'], success:['成功','#10b981'],
  skipped:['已跳过','#f59e0b'], failed:['失败','#ef4444'],
  approved:['已通过','#10b981'], pending_approval:['待审批','#f59e0b'],
  rejected:['已驳回','#ef4444'], awaiting_human:['待人工','#f59e0b'],
  heal_failed:['执行失败','#ef4444'], resolved:['已解决','#10b981']
};
var DONE = {completed:1, success:1, approved:1, resolved:1};

function esc(x){
  if(x === null || x === undefined) return '—';
  return String(x).replace(/[&<>"]/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];
  });
}

function renderPipeline(state){
  var nodes = state.pipeline || [];
  var html = '';
  for(var i=0;i<nodes.length;i++){
    var n = nodes[i];
    var s = STYLE[(n.status||'pending').toLowerCase()] || ['未知','#6b7280'];
    if(i > 0){
      var prev = (nodes[i-1].status||'').toLowerCase();
      html += '<div class="conn' + (DONE[prev] ? ' done' : '') + '"></div>';
    }
    html += '<div class="node">'
      + '<div class="dot' + (n.status === 'running' ? ' running' : '') + '"'
      + ' style="background:' + s[1] + '"></div>'
      + '<div class="label">' + esc(n.label) + '</div>'
      + '<div class="agent">' + esc(n.agent) + '</div>'
      + '<div class="st" style="color:' + s[1] + '">' + esc(s[0]) + '</div>'
      + '</div>';
  }
  document.getElementById('pipeline').innerHTML = html;
}

function card(k, v, sub){
  return '<div class="card"><div class="k">' + esc(k) + '</div>'
    + '<div class="v">' + esc(v) + '</div>'
    + (sub ? '<div class="sub">' + esc(sub) + '</div>' : '') + '</div>';
}

function renderCards(state){
  var inc = state.latest;
  var el = document.getElementById('cards');
  if(!inc){
    el.innerHTML = '<div class="empty">暂无事件记录。点击「立即巡检」生成一次完整工作流。</div>';
    return;
  }
  var a = inc.alert || {}, r = inc.rca || {},
      h = inc.heal || {}, c = inc.change || {}, p = h.action_params || {};
  el.innerHTML = ''
    + card('告警', a.alert_name || a.metric_name || '—',
        (a.severity || '') + (a.metric_value !== undefined ? ' · 实测 ' + a.metric_value : ''))
    + card('根因', r.root_cause || '—',
        r.confidence !== undefined ? '置信度 ' + r.confidence : '')
    + card('动作', h.action_type || '—',
        (h.heal_level ? h.heal_level + ' · ' : '')
        + (h.blast_radius !== undefined ? '爆炸半径 ' + h.blast_radius + ' · ' : '')
        + (p.container || p.target_service || ''))
    + card('审批', c.approval_status || '—',
        (c.risk_score !== undefined ? '风险 ' + c.risk_score + ' · ' : '') + (c.approver || ''))
    + card('执行', h.execution_result || '未执行', h.status || inc.status || '');
}

function renderHistory(state){
  var incs = state.history || [], el = document.getElementById('history');
  if(!incs.length){ el.innerHTML = '<div class="empty">暂无历史事件</div>'; return; }
  var html = '<table><thead><tr><th>时间</th><th>状态</th>'
    + '<th>告警</th><th>根因</th><th>动作</th></tr></thead><tbody>';
  for(var i=0;i<incs.length;i++){
    var it = incs[i], r = it.rca || {}, h = it.heal || {};
    html += '<tr>'
      + '<td class="mono">' + esc(String(it.created_at || '').replace('T',' ').slice(0,19)) + '</td>'
      + '<td>' + esc(it.status || '') + '</td>'
      + '<td>' + esc((it.alert || {}).alert_name || '—') + '</td>'
      + '<td>' + esc(r.root_cause || '—') + '</td>'
      + '<td>' + esc(h.action_type || '—') + '</td></tr>';
  }
  el.innerHTML = html + '</tbody></table>';
}

async function refresh(){
  try{
    var r = await fetch('/dashboard/state');
    if(!r.ok) throw new Error(r.status);
    var s = await r.json();
    document.getElementById('live-text').textContent =
      '监控循环 #' + (s.monitor.cycles === null || s.monitor.cycles === undefined
        ? '—' : s.monitor.cycles) + ' · 告警 ' + s.monitor.alerts;
    var btn = document.getElementById('btn-drill');
    btn.disabled = !s.drill_enabled;
    document.getElementById('drill-hint').textContent = s.drill_enabled
      ? '' : '故障演练已禁用（需 AIOPS_DRILL_ENABLED=true 启动）';
    renderPipeline(s); renderCards(s); renderHistory(s);
  }catch(e){
    document.getElementById('live-text').textContent = '连接失败';
  }
}

document.getElementById('btn-inspect').onclick = async function(){
  this.disabled = true;
  toast('已触发巡检，等待工作流完成…');
  try{
    var r = await fetch('/api/v1/incidents/trigger', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({}) });
    var d = await r.json();
    toast('巡检完成：' + (d.status || ''));
  }catch(e){ toast('巡检失败', true); }
  finally{ this.disabled = false; refresh(); }
};

document.getElementById('btn-drill').onclick = async function(){
  if(!confirm('将停止 shortlink-redis 容器，触发真实故障与自愈。继续？')) return;
  toast('故障已注入，等待自动恢复…');
  try{
    var r = await fetch('/api/v1/drill/inject', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'inject', container:'shortlink-redis'}) });
    if(!r.ok){ var e = await r.json().catch(function(){return {};});
      toast('演练被拒绝：' + (e.detail || r.status), true); return; }
  }catch(e){ toast('演练请求失败', true); }
  finally{ refresh(); }
};

document.getElementById('btn-restore').onclick = async function(){
  toast('正在恢复容器…');
  try{
    var r = await fetch('/api/v1/drill/inject', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'restore', container:'shortlink-redis'}) });
    if(!r.ok){ var e = await r.json().catch(function(){return {};});
      toast('恢复被拒绝：' + (e.detail || r.status), true); return; }
    toast('容器已恢复');
  }catch(e){ toast('恢复失败', true); }
  finally{ refresh(); }
};

function toast(msg, isErr){
  var t = document.getElementById('toast');
  if(!t) return;
  t.textContent = msg;
  t.style.borderColor = isErr ? '#ef4444' : '#38bdf8';
  t.className = 'show';
  setTimeout(function(){ t.className = ''; }, 3200);
}

refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""
