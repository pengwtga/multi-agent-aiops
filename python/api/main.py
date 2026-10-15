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
from datetime import datetime
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from collectors.prometheus_collector import MonitorLoop
from config.settings import settings
from core.event_bus import InMemoryEventBus
from core.orchestrator import Orchestrator
from core.knowledge_graph import create_demo_knowledge_graph, InMemoryKnowledgeGraph
from models.events import IncidentState, Severity
from models.time_series import EnsembleDetector, generate_demo_metrics

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
    orchestrator = Orchestrator(event_bus)
    knowledge_graph = create_demo_knowledge_graph()

    monitor_task: Optional[asyncio.Task] = None
    if settings.monitor_enabled:
        # 阶段 3：真实 Prometheus 采集循环，按 settings.monitor_check_interval 轮询
        monitor_loop = MonitorLoop(
            orchestrator,
            prometheus_url=settings.prometheus_url,
            interval_seconds=settings.monitor_check_interval,
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

    result = {
        "incident_id": state.incident_id,
        "status": state.status,
        "alert": _serialize_alert(state),
        "rca": _serialize_rca(state),
        "heal": _serialize_heal(state),
        "change": _serialize_change(state),
        "workflow": orchestrator.get_workflow_status(),
    }

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
