"""FastAPI 主入口 — AIOps 多 Agent 系统 API

提供 REST API 用于：
1. 触发事件处理工作流
2. 查询工作流状态和历史
3. 查看知识图谱拓扑
4. 运行异常检测 Demo
5. Prometheus 指标暴露
"""

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from collectors.prometheus_collector import MonitorLoop, PrometheusClient
from config.settings import settings
from core.event_bus import InMemoryEventBus
from core.orchestrator import Orchestrator
from core.knowledge_graph import create_demo_knowledge_graph, InMemoryKnowledgeGraph
from models.events import IncidentState, Severity
from models.time_series import EnsembleDetector, generate_demo_metrics

# 阶段 5 可视化：自愈闭环 Dashboard 页面与状态聚合函数
from api.dashboard import build_state, router as dashboard_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)

event_bus = InMemoryEventBus()
orchestrator: Optional[Orchestrator] = None
knowledge_graph: Optional[InMemoryKnowledgeGraph] = None
monitor_loop: Optional[MonitorLoop] = None
incident_history: list[dict[str, Any]] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    global orchestrator, knowledge_graph, monitor_loop

    await event_bus.start()
    # 阶段 4：RCA 回查 Prometheus 实测值以证实/证伪候选根因
    orchestrator = Orchestrator(
        event_bus,
        evidence_provider=PrometheusClient(settings.prometheus_url),
        heal_dry_run=settings.heal_dry_run,
        heal_max_blast_radius=settings.blast_radius_max_percent,
    )
    knowledge_graph = create_demo_knowledge_graph()

    monitor_task: Optional[asyncio.Task] = None
    if settings.monitor_enabled:
        # 阶段 3：真实 Prometheus 采集循环，按 settings.monitor_check_interval 轮询
        monitor_loop = MonitorLoop(
            orchestrator,
            prometheus_url=settings.prometheus_url,
            interval_seconds=settings.monitor_check_interval,
            # 把监控循环跑出的闭环回写到事件历史。
            # 此前监控循环从不回写，导致事件列表恒为 0 条、
            # Dashboard 流水线永远显示空闲态（「点了没反应」的真因）。
            on_cycle=lambda st, snap: incident_history.append(
                _snapshot_incident(st, snap)
            ),
        )
        monitor_task = asyncio.create_task(monitor_loop.run_forever())

    logger.info("AIOps Multi-Agent System started")
    yield

    if monitor_loop:
        monitor_loop.stop()
    if monitor_task:
        monitor_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await monitor_task

    await event_bus.stop()
    logger.info("AIOps Multi-Agent System stopped")


app = FastAPI(
    title="Multi-Agent AIOps System",
    description="企业级多 Agent 智能运维系统 API",
    version="1.0.0",
    lifespan=lifespan,
)

# 阶段 5：挂载自愈闭环可视化页面（GET /dashboard）
app.include_router(dashboard_router)


class TriggerRequest(BaseModel):
    metric_name: Optional[str] = None
    metric_value: Optional[float] = None
    target_service: Optional[str] = None
    labels: Optional[dict[str, str]] = None


class MetricDataRequest(BaseModel):
    values: list[float]
    current_value: float


@app.get("/")
async def root():
    return {
        "service": "Multi-Agent AIOps System",
        "version": "1.0.0",
        "agents": ["monitor", "rca", "heal", "change"],
        "status": "running",
    }


def _to_local(ts: datetime) -> str:
    """把 UTC 时间转成本地时间再下发

    IncidentState.created_at 来自 datetime.utcnow()，是**不带时区标记的
    UTC**。直接发给前端显示，会比日志里的系统时间早 8 小时
    （UTC+8），看着像事件「提前发生了」，和日志对不上。
    """
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone().isoformat()


def _pipeline_duration_ms(workflow) -> Optional[float]:
    """流水线端到端耗时（毫秒）：首节点开始 → 末节点结束

    用首尾时间戳相减，而不是把各节点 duration_ms 累加 ——
    后者会漏掉节点之间的调度与 I/O 间隔，不是用户感知的真实耗时。
    """
    if not workflow:
        return None
    started = [w["started_at"] for w in workflow if w.get("started_at")]
    ended = [w["ended_at"] for w in workflow if w.get("ended_at")]
    if not started or not ended:
        return None
    try:
        # 均为 utcnow().isoformat()，同一时区、字典序即时间序，可直接比较
        s = datetime.fromisoformat(min(started))
        e = datetime.fromisoformat(max(ended))
    except Exception:
        return None
    if s.tzinfo is None:
        s = s.replace(tzinfo=timezone.utc)
    if e.tzinfo is None:
        e = e.replace(tzinfo=timezone.utc)
    return round((e - s).total_seconds() * 1000, 1)


def _snapshot_incident(state, workflow=None) -> dict:
    """把一次工作流结果序列化成事件记录

    手动触发端点与监控循环共用。此前监控循环跑出的闭环**从不写入**
    incident_history，导致 /api/v1/incidents 恒为 0 条、Dashboard
    流水线永远显示空闲态（表现为「点了故障演练毫无反应」）。

    workflow: 闭环当次的节点状态快照。监控循环每轮会跑多次工作流，
              最后一次往往是无告警的（会把后续节点置为 SKIPPED），
              因此必须传命中告警当次的快照，否则会把自愈结果冲掉。
    """
    wf = workflow if workflow is not None else (
        orchestrator.get_workflow_status() if orchestrator else []
    )
    return {
        "incident_id": state.incident_id,
        "status": state.status,
        # 历史事件表要展示时间列，缺这个字段那一列就是空的
        "created_at": _to_local(state.created_at),
        "alert": _serialize_alert(state),
        "rca": _serialize_rca(state),
        "heal": _serialize_heal(state),
        "change": _serialize_change(state),
        "workflow": wf,
        # 端到端耗时：从监控告警开始到自愈执行完
        "duration_ms": _pipeline_duration_ms(wf),
    }


@app.post("/api/v1/incidents/trigger")
async def trigger_incident(request: TriggerRequest):
    """触发一次完整的故障处理工作流"""
    metadata = {}
    if request.metric_name:
        metadata["metric_data"] = {
            "metric_name": request.metric_name,
            "value": request.metric_value,
            "service": request.target_service or "unknown",
            "labels": request.labels or {},
        }

    state = await orchestrator.run(metadata=metadata)

    result = _snapshot_incident(state)
    incident_history.append(result)
    return result


@app.get("/api/v1/incidents")
async def list_incidents():
    """查看事件处理历史"""
    return {"total": len(incident_history), "incidents": incident_history[-50:]}


@app.get("/api/v1/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """查看单个事件详情"""
    for inc in incident_history:
        if inc["incident_id"] == incident_id:
            return inc
    raise HTTPException(status_code=404, detail="Incident not found")


@app.get("/api/v1/topology")
async def get_topology():
    """查看知识图谱服务拓扑"""
    if not knowledge_graph:
        raise HTTPException(status_code=503, detail="Knowledge graph not initialized")

    return knowledge_graph.get_topology_summary()


@app.get("/api/v1/topology/{service}/dependencies")
async def get_service_dependencies(service: str):
    """查看某服务的依赖链"""
    if not knowledge_graph:
        raise HTTPException(status_code=503, detail="Knowledge graph not initialized")

    deps = knowledge_graph.get_dependencies(service)
    dependents = knowledge_graph.get_dependents(service)
    impact = knowledge_graph.compute_impact_score(service)
    paths = knowledge_graph.bfs_trace(service)

    return {
        "service": service,
        "direct_dependencies": deps,
        "depended_by": dependents,
        "impact_score": round(impact, 3),
        "dependency_paths": paths[:10],
    }


@app.post("/api/v1/anomaly/detect")
async def detect_anomaly(request: MetricDataRequest):
    """运行异常检测 Demo"""
    detector = EnsembleDetector(min_votes=2)
    is_anomaly, score, results = detector.detect(request.values, request.current_value)

    return {
        "is_anomaly": is_anomaly,
        "score": score,
        "current_value": request.current_value,
        "algorithm_results": [
            {
                "algorithm": r.algorithm,
                "is_anomaly": r.is_anomaly,
                "score": r.score,
                "expected_value": r.expected_value,
                "detail": r.detail,
            }
            for r in results
        ],
    }


@app.get("/api/v1/anomaly/demo")
async def anomaly_detection_demo():
    """异常检测演示：自动生成数据并检测"""
    values, labels = generate_demo_metrics(200, inject_anomaly=True)

    detector = EnsembleDetector(min_votes=2)
    anomalies_found = []

    for i in range(50, len(values)):
        history = values[:i]
        current = values[i]
        is_anomaly, score, _ = detector.detect(history, current)
        if is_anomaly:
            anomalies_found.append({
                "index": i,
                "value": round(current, 2),
                "score": round(score, 3),
                "actual_anomaly": labels[i] == 1.0,
            })

    return {
        "total_points": len(values),
        "anomalies_detected": len(anomalies_found),
        "anomalies": anomalies_found,
    }


@app.get("/api/v1/agents/status")
async def get_agent_status():
    """查看所有 Agent 状态"""
    return {
        "workflow_nodes": orchestrator.get_workflow_status() if orchestrator else [],
        "event_log_size": len(event_bus.get_event_log()) if hasattr(event_bus, "get_event_log") else 0,
    }


@app.get("/api/v1/monitor/status")
async def get_monitor_status():
    """查看 Prometheus 采集循环状态：规则集 / 周期数 / 已触发告警"""
    if not monitor_loop:
        raise HTTPException(status_code=503, detail="Monitor loop not enabled")
    return monitor_loop.status()


@app.get("/dashboard/state")
async def get_dashboard_state():
    """Dashboard 页面数据源：把监控循环 / 事件历史 / 流水线节点聚合成一份"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    return build_state(
        monitor_status=(monitor_loop.status() if monitor_loop else None),
        incidents={
            "total": len(incident_history),
            "incidents": incident_history[-50:],
        },
        workflow=orchestrator.get_workflow_status(),
        drill_enabled=settings.drill_enabled,
    )


class DrillRequest(BaseModel):
    action: str = "inject"            # inject | restore
    container: str = "shortlink-redis"


async def _resolve_probe_code() -> Optional[str]:
    """拿一个**真实存在**的短链码用于探测

    为什么不能用任意 code（实测踩过）：
        请求不存在的短链时应用直接返回 404，**根本不查 Redis**，
        造不出挂起连接，探测等于白打。只有真实 code 才会走到
        `sl:link:{code}` 读路径，从而在 Redis 停机时挂住。

    优先级：
      1. 显式配置 settings.drill_probe_code
      2. 否则从 Redis scan 出真实 key 再反解 code
    """
    if settings.drill_probe_code:
        return settings.drill_probe_code

    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", "shortlink-redis",
            "redis-cli", "--scan", "--pattern", "sl:link:*",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        for line in (out or b"").decode(errors="replace").splitlines():
            line = line.strip()
            if line.startswith("sl:link:"):
                return line.split("sl:link:", 1)[1]
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[DRILL] 从 Redis 获取短链码失败: {e}")
    return None


async def _probe_load(code: Optional[str] = None) -> dict:
    """故障演练的探测负载：并发打一批跳转请求

    为什么需要它（实测踩出来的）：
        dependency_hang 的判据是「Tomcat 连接堆积 + 成功跳转吞吐归零」，
        必须有请求进来连接才会堆积。实测空闲时 Tomcat 连接数只有 2，
        光停 Redis 而无人访问 → 判据不成立 → 故障不可见 → 不告警不自愈。
        演练的目的是验证闭环，故由后端自动补上负载。

    两点不能省：
        - 必须**并发**：串行请求同时只占 1 个连接，堆不出所需连接数
        - timeout 要跨过 Prometheus 抓取周期（15s）：否则连接在
          被采到之前就释放了，指标上依然看不到堆积
    """
    if not code:  # 调用方未取到时兜底再试一次
        code = await _resolve_probe_code()
    if not code:
        logger.warning("[DRILL] 未拿到探测短链码，跳过探测负载")
        return {"requests": 0, "timeout_seconds": 0, "skipped": True}

    url = f"{settings.shortlink_base_url.rstrip('/')}/{code}"
    n = settings.drill_probe_count
    t = settings.drill_probe_timeout

    procs: list = []
    for _ in range(n):
        try:
            procs.append(
                await asyncio.create_subprocess_exec(
                    "curl", "-s", "-o", "/dev/null",
                    "--max-time", str(t), url,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            )
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[DRILL] 探测请求启动失败: {e}")

    async def _wait(p) -> None:
        try:
            await asyncio.wait_for(p.wait(), timeout=t + 5)
        except Exception:  # noqa: BLE001
            p.kill()
            await p.wait()

    await asyncio.gather(*[_wait(p) for p in procs], return_exceptions=True)
    logger.warning(f"[DRILL] 探测负载完成：{len(procs)} 并发，timeout={t}s")
    return {"requests": len(procs), "timeout_seconds": t}


@app.post("/api/v1/drill/inject")
async def drill_inject(request: DrillRequest):
    """故障演练：停止 / 恢复指定容器（供 Dashboard 页面操作）

    四道护栏：
    1. 总开关  —— settings.drill_enabled，默认 False，未显式开启直接 403
    2. 白名单  —— 只能操作 settings.drill_containers 里列出的容器
    3. 动作枚举 —— 只允许 inject（docker stop）/ restore（docker start）
    4. 审计    —— 每次调用记 WARNING 日志，含 argv 与返回码

    注意：这里走**独立的演练路径**，不经过 ChangeAgent 审批 —— 因为演练
    本身就是「人主动注入故障」，等同于人工操作；让 Agent 去审批一次人为
    故障没有意义。真实故障的自愈仍然严格走 heal_propose → change →
    heal_execute 三段闸门。
    """
    if not settings.drill_enabled:
        raise HTTPException(
            status_code=403,
            detail="故障演练未启用：需以 AIOPS_DRILL_ENABLED=true 启动服务",
        )

    allowed = [c.strip() for c in settings.drill_containers.split(",") if c.strip()]
    if request.container not in allowed:
        raise HTTPException(status_code=400, detail=f"容器不在白名单：{allowed}")

    if request.action not in ("inject", "restore"):
        raise HTTPException(status_code=400, detail="action 只能是 inject 或 restore")

    sub = "stop" if request.action == "inject" else "start"
    argv = ["docker", sub, request.container]

    # 必须在注入**之前**取短链码：等 Redis 停了就扫不到真实 code 了
    probe_code = None
    if request.action == "inject":
        if orchestrator:
            # 每次演练都是一轮全新闭环：先清空上一次的流水线与事件历史，
            # 否则旧结果会和新进度混在一起，看不出这次跑到哪一步
            orchestrator.reset_workflow()
            # 清空告警去重缓存：演练是人为注入的新故障事件，
            # 不该被上一次告警的 5 分钟窗口抑制（否则「点了没反应」）
            orchestrator.clear_monitor_fingerprints()
        incident_history.clear()
        probe_code = await _resolve_probe_code()
        logger.warning(f"[DRILL] 探测短链码: {probe_code or '(未拿到)'}")

    logger.warning(f"[DRILL] 故障演练执行：{' '.join(argv)}")
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=30)
        ok = proc.returncode == 0
        logger.warning(f"[DRILL] 结果 rc={proc.returncode} ok={ok}")

        # 注入成功后自动补负载：否则依赖挂起类故障不可见（不告警、不自愈）
        probe = None
        if ok and request.action == "inject":
            probe = await _probe_load(probe_code)

        return {
            "ok": ok,
            "action": request.action,
            "container": request.container,
            "argv": argv,
            "returncode": proc.returncode,
            "stdout": (out or b"").decode(errors="replace").strip()[-500:],
            "stderr": (err or b"").decode(errors="replace").strip()[-500:],
            "probe": probe,
        }
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise HTTPException(status_code=504, detail="演练命令超时（30s）")


@app.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics():
    """自观测指标（Prometheus exposition 格式）。

    供 config/prometheus.yml 里 aiops-agents 抓取作业使用。
    """
    if monitor_loop:
        return monitor_loop.get_metrics_text()
    return (
        "# TYPE aiops_monitor_cycles_total counter\n"
        "aiops_monitor_cycles_total 0\n"
        "# TYPE aiops_monitor_alerts_total counter\n"
        "aiops_monitor_alerts_total 0\n"
    )


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


def _serialize_alert(state: IncidentState) -> Optional[dict]:
    if not state.alert_event:
        return None
    return {
        "name": state.alert_event.alert_name,
        "severity": state.alert_event.severity.value,
        "service": state.alert_event.target_service,
        "metric": state.alert_event.metric_name,
        "value": state.alert_event.metric_value,
    }


def _serialize_rca(state: IncidentState) -> Optional[dict]:
    if not state.rca_event:
        return None
    return {
        "root_cause": state.rca_event.root_cause,
        "confidence": state.rca_event.confidence,
        "affected_services": state.rca_event.affected_services[:5],
        "suggested_actions": state.rca_event.suggested_actions,
    }


def _serialize_heal(state: IncidentState) -> Optional[dict]:
    if not state.heal_event:
        return None
    return {
        "action": state.heal_event.action_type,
        "level": state.heal_event.heal_level.value,
        "blast_radius": state.heal_event.blast_radius,
        "dry_run": state.heal_event.dry_run_result,
        "result": state.heal_event.execution_result,
    }


def _serialize_change(state: IncidentState) -> Optional[dict]:
    if not state.change_event:
        return None
    return {
        "status": state.change_event.approval_status,
        "risk_score": state.change_event.risk_score,
        "approver": state.change_event.approver,
        "reason": state.change_event.reason,
    }
