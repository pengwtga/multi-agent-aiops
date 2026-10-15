"""根因分析 Agent — 知识图谱遍历 + 因果推断 + 多源关联

核心功能：
1. 从知识图谱获取服务拓扑，沿依赖链路追踪故障传播路径
2. 多源证据关联：指标异常 + 日志模式 + 变更记录
3. 贝叶斯推理计算根因置信度
4. 输出根因报告和建议修复动作

面试重点：
- 知识图谱节点：Service / Pod / Node / Metric / Alert
- 知识图谱边：DEPENDS_ON / RUNS_ON / MONITORS / CAUSES
- 图遍历策略：从告警节点反向 BFS，找到第一个「因」节点
- 贝叶斯推理：P(根因|症状) = P(症状|根因) * P(根因) / P(症状)

阶段 4 二次开发（面向短链平台）：
- 拓扑从「外卖/订单系统的 mock 数据」换成短链平台真实拓扑
- 故障模式库换成短链平台已沉淀的运维知识（见 shortlink docs/ARCHITECTURE.md）
- **关键改进**：候选根因带 verify 探针（PromQL），用真实数据证实/证伪，
  而不是只靠 base_probability 先验拍脑袋。先验只决定「谁更常见」，
  证据才决定「这次到底是谁」。
"""

import logging
from datetime import datetime
from typing import Any, Optional, Protocol

from agents.base_agent import BaseAgent
from core.event_bus import EventBus
from models.events import (
    AgentType,
    AlertEvent,
    EventType,
    IncidentState,
    RCAEvent,
    Severity,
)

logger = logging.getLogger(__name__)


# 短链平台服务拓扑（替代原外卖/订单系统的 MOCK 数据）
#
# runs_on 用 docker 容器名（短链平台是 docker compose 部署，非 K8s），
# 阶段 5 的 HealAgent 执行器直接依赖这些名字。
SHORTLINK_TOPOLOGY = {
    "shortlink-app": {
        "depends_on": ["mysql", "redis", "kafka"],
        "runs_on": "docker:shortlink-app",
        "recent_changes": [],
    },
    "click-consumer": {
        # 消费端与 app 同进程，但依赖链独立：只依赖 kafka + mysql
        "depends_on": ["kafka", "mysql"],
        "runs_on": "docker:shortlink-app",
        "recent_changes": [],
    },
    "mysql": {
        "depends_on": [],
        "runs_on": "docker:shortlink-mysql",
        "recent_changes": [],
    },
    "redis": {
        "depends_on": [],
        "runs_on": "docker:shortlink-redis",
        "recent_changes": [],
    },
    "kafka": {
        "depends_on": [],
        "runs_on": "docker:shortlink-kafka",
        "recent_changes": [],
    },
}

# 兼容旧名（编排器/测试可能引用）
MOCK_SERVICE_TOPOLOGY = SHORTLINK_TOPOLOGY


def _verify(promql: str, comparator: str = "gt", threshold: float = 0.0) -> dict:
    """构造一个证据探针：用 PromQL 实测值证实或证伪某候选根因"""
    return {"promql": promql, "comparator": comparator, "threshold": threshold}


# 短链平台故障模式库
#
# 每条候选可带 verify 探针：
#   探针成立 → 似然 0.9（证据支持该根因）
#   探针不成立 → 似然 0.05（证据基本排除该根因）
#   无探针 → 沿用 evidence_pattern 的静态似然（用于无法用指标证伪的猜测，
#            如「近期发布引入缺陷」，只能靠先验和历史故障频率）
SHORTLINK_FAULT_PATTERNS: dict[str, list[dict[str, Any]]] = {
    "redirect_5xx_rate": [
        {
            "root_cause": "Redis 不可达：读路径 sl:link:{code} 直接抛异常，无降级逻辑",
            "evidence_pattern": "dependency_down",
            "base_probability": 0.45,
            # Redis 挂掉时所有跳转都 500，成功跳转吞吐归零——这是最强判据
            "verify": _verify(
                'sum(rate(shortlink_redirect_total{job="shortlink-app"}[2m]))',
                "lt", 0.05,
            ),
            "suggested_actions": ["restart_redis", "check_dependency"],
        },
        {
            "root_cause": "MySQL 不可达：缓存 miss 回源失败（命中路径仍正常）",
            "evidence_pattern": "dependency_down",
            "base_probability": 0.25,
            # 判别点必须是「DB 不可达」的一手信号。
            # 用「命中请求仍成功」是不行的：健康状态下它也成立，等于无法证伪，
            # 会导致正常状态被误判为 MySQL 故障。连接池获取超时才是真信号。
            "verify": _verify(
                'sum(rate(hikaricp_connections_timeout_total{job="shortlink-app"}[2m]))',
                "gt", 0.0,
            ),
            "suggested_actions": ["restart_mysql", "check_dependency"],
        },
        {
            "root_cause": "流量激增超出容量（Tomcat 线程池/连接打满）",
            "evidence_pattern": "request_rate_increase",
            "base_probability": 0.20,
            # 真流量激增时总请求量（含 5xx）应该很高
            "verify": _verify(
                'sum(rate(http_server_requests_seconds_count{job="shortlink-app"}[2m]))',
                "gt", 20.0,
            ),
            "suggested_actions": ["scale_app", "rate_limit"],
        },
        {
            "root_cause": "近期部署引入缺陷",
            "evidence_pattern": "recent_deploy",
            "base_probability": 0.10,
            "suggested_actions": ["rollback", "review_change"],
        },
    ],
    "shortlink_app_down": [
        {
            "root_cause": "应用进程崩溃（OOM：堆上限 512m，压测时非堆另占约 200m）",
            "evidence_pattern": "oom",
            "base_probability": 0.50,
            "suggested_actions": ["restart_container", "heap_dump"],
        },
        {
            "root_cause": "容器被停止或宿主机资源耗尽",
            "evidence_pattern": "container_stopped",
            "base_probability": 0.35,
            "suggested_actions": ["restart_container"],
        },
        {
            "root_cause": "依赖的 MySQL/Redis/Kafka 全部不可达导致启动失败",
            "evidence_pattern": "dependency_down",
            "base_probability": 0.15,
            "suggested_actions": ["check_dependency", "restart_container"],
        },
    ],
    "consume_lag_backlog": [
        {
            "root_cause": "消费端卡死（位点停止推进，批量拉取线程阻塞）",
            "evidence_pattern": "consumer_stalled",
            "base_probability": 0.45,
            # 应用仍在（能继续暴露指标）而积压不降 → 消费线程自身卡住
            "verify": _verify('min(up{job="shortlink-app"})', "gt", 0.5),
            "suggested_actions": ["restart_consumer", "check_t_consumer_offset"],
        },
        {
            "root_cause": "MySQL 写入变慢，批次 UPSERT 提交阻塞",
            "evidence_pattern": "db_slow",
            "base_probability": 0.35,
            "verify": _verify(
                'sum(rate(hikaricp_connections_pending{job="shortlink-app"}[2m]))',
                "gt", 0.5,
            ),
            "suggested_actions": ["check_mysql", "restart_consumer"],
        },
        {
            "root_cause": "上游点击量突增（真实流量，非故障）",
            "evidence_pattern": "request_rate_increase",
            "base_probability": 0.20,
            "suggested_actions": ["scale_app"],
        },
    ],
    "ratelimit_reject_burst": [
        {
            "root_cause": "单 IP 滥用/爬虫触发限流（跳转 120 次/分）",
            "evidence_pattern": "abuse",
            "base_probability": 0.55,
            # 滥用时总请求量会明显抬升
            "verify": _verify(
                'sum(rate(http_server_requests_seconds_count{job="shortlink-app"}[2m]))',
                "gt", 10.0,
            ),
            "suggested_actions": ["rate_limit", "block_ip"],
        },
        {
            "root_cause": "限流窗口配置被误改（阈值下调）",
            "evidence_pattern": "recent_config_change",
            "base_probability": 0.30,
            "suggested_actions": ["rollback_config", "review_change"],
        },
        {
            "root_cause": "正常业务峰值，限流阈值需上调",
            "evidence_pattern": "capacity",
            "base_probability": 0.15,
            "suggested_actions": ["rate_limit"],
        },
    ],
    "tomcat_busy_threads": [
        {
            "root_cause": "并发打满 Tomcat 线程池（上限 200，压测实测 180+ 触发连接重置）",
            "evidence_pattern": "thread_pool_saturated",
            "base_probability": 0.60,
            "verify": _verify(
                'sum(tomcat_threads_busy_threads{job="shortlink-app"})'
                ' / sum(tomcat_threads_config_max_threads{job="shortlink-app"})',
                "gt", 0.5,
            ),
            "suggested_actions": ["scale_app", "tune_threads"],
        },
        {
            "root_cause": "下游慢（Redis/MySQL 响应变慢）导致线程被长时间占用",
            "evidence_pattern": "downstream_slow",
            "base_probability": 0.30,
            "suggested_actions": ["check_dependency", "circuit_breaker"],
        },
        {
            "root_cause": "正常业务量增长",
            "evidence_pattern": "capacity",
            "base_probability": 0.10,
            "suggested_actions": ["scale_app"],
        },
    ],
    "app_cpu_usage": [
        {
            "root_cause": "GC 频繁（堆 512m 偏小，对象晋升快）",
            "evidence_pattern": "gc_pressure",
            "base_probability": 0.50,
            "verify": _verify(
                'sum(rate(jvm_gc_pause_seconds_count{job="shortlink-app"}[2m]))',
                "gt", 1.0,
            ),
            "suggested_actions": ["heap_dump", "restart_container"],
        },
        {
            "root_cause": "流量激增导致 CPU 过载",
            "evidence_pattern": "request_rate_increase",
            "base_probability": 0.35,
            "verify": _verify(
                'sum(rate(http_server_requests_seconds_count{job="shortlink-app"}[2m]))',
                "gt", 20.0,
            ),
            "suggested_actions": ["scale_app", "rate_limit"],
        },
        {
            "root_cause": "消费端批量聚合占用 CPU（大批量 UPSERT）",
            "evidence_pattern": "consumer_load",
            "base_probability": 0.15,
            "suggested_actions": ["restart_consumer"],
        },
    ],
}

# 未命中任何已知告警名时的兜底候选（保持短链语义，而非原项目的通用 CPU 候选）
FALLBACK_FAULT_PATTERNS = [
    {
        "root_cause": "短链应用自身异常（未知故障模式）",
        "evidence_pattern": "unknown",
        "base_probability": 0.40,
        "suggested_actions": ["restart_container"],
    },
    {
        "root_cause": "依赖组件（MySQL/Redis/Kafka）异常",
        "evidence_pattern": "dependency_down",
        "base_probability": 0.35,
        "suggested_actions": ["check_dependency"],
    },
    {
        "root_cause": "流量突变",
        "evidence_pattern": "request_rate_increase",
        "base_probability": 0.25,
        "suggested_actions": ["scale_app", "rate_limit"],
    },
]

# 兼容旧名
FAULT_PATTERNS = SHORTLINK_FAULT_PATTERNS


class EvidenceProvider(Protocol):
    """证据提供者：能用 PromQL 取回一个实测值（由采集器注入）"""

    async def query(self, promql: str) -> Optional[float]: ...


class BayesianReasoner:
    """贝叶斯推理引擎

    P(Cause|Evidence) = P(Evidence|Cause) * P(Cause) / P(Evidence)

    面试要点：
    - 先验概率 P(Cause) 来自历史故障统计（base_probability）
    - 似然 P(Evidence|Cause) 由 verify 探针的实测结果决定（这是阶段 4 的关键改进：
      原来只能靠 evidence_pattern 静态拍定，现在用真实指标证实/证伪）
    - 后验概率就是最终的根因置信度
    """

    # 探针成立 / 不成立 / 无数据 时的似然
    LIKELIHOOD_CONFIRMED = 0.9
    LIKELIHOOD_REFUTED = 0.05
    LIKELIHOOD_UNKNOWN = 0.5

    @staticmethod
    def compute_posterior(
        prior: float,
        likelihood: float,
        evidence_probability: float = 0.5,
    ) -> float:
        if evidence_probability == 0:
            return 0.0
        posterior = (likelihood * prior) / evidence_probability
        return min(posterior, 1.0)


class RCAAgent(BaseAgent):
    """根因分析 Agent"""

    def __init__(self, event_bus: EventBus, knowledge_graph=None,
                 evidence_provider: Optional[EvidenceProvider] = None):
        super().__init__(AgentType.RCA, event_bus, "RCAAgent")
        self._kg = knowledge_graph
        self._reasoner = BayesianReasoner()
        self._evidence_provider = evidence_provider

    async def process(self, state: IncidentState) -> IncidentState:
        alert = state.alert_event
        if not alert:
            logger.warning("[RCAAgent] No alert event to analyze")
            return state

        logger.info(f"[RCAAgent] Analyzing alert: {alert.alert_name} on {alert.target_service}")

        affected_chain = self._trace_dependency_chain(alert.target_service)

        evidence = self._collect_evidence(alert, affected_chain)

        candidates = self._get_fault_candidates(alert.alert_name)

        # 阶段 4：带 verify 探针的候选要回查 Prometheus 实测，故推理改为 async
        root_cause, confidence, actions = await self._bayesian_inference(
            candidates, evidence
        )

        rca_event = RCAEvent(
            alert_event_id=alert.event_id,
            root_cause=root_cause,
            confidence=confidence,
            affected_services=affected_chain,
            evidence=evidence,
            suggested_actions=actions,
            correlation_id=state.incident_id,
        )

        state.rca_event = rca_event
        await self.event_bus.publish("aiops.events", rca_event)

        logger.info(
            f"[RCAAgent] Root cause: {root_cause} (confidence: {confidence:.2f}) "
            f"→ actions: {actions}"
        )
        return state

    def _trace_dependency_chain(
        self, service: str, depth: int = 0, max_depth: int = 5
    ) -> list[str]:
        """沿知识图谱追踪依赖链路（BFS）

        面试要点：反向 BFS 从告警服务出发，找到所有可能的上游依赖
        """
        if depth >= max_depth:
            return []

        chain = [service]
        topology = SHORTLINK_TOPOLOGY.get(service, {})
        for dep in topology.get("depends_on", []):
            chain.extend(self._trace_dependency_chain(dep, depth + 1, max_depth))
        return chain

    def _collect_evidence(
        self, alert: AlertEvent, affected_chain: list[str]
    ) -> list[dict[str, Any]]:
        """多源证据收集"""
        evidence = []

        evidence.append({
            "type": "metric_anomaly",
            "source": "prometheus",
            "detail": f"{alert.metric_name}={alert.metric_value} (threshold: {alert.threshold})",
            "weight": 0.8,
        })

        for svc in affected_chain:
            topo = SHORTLINK_TOPOLOGY.get(svc, {})
            for change in topo.get("recent_changes", []):
                evidence.append({
                    "type": "recent_change",
                    "source": "cmdb",
                    "detail": f"{svc}: {change}",
                    "weight": 0.9,
                })

        if alert.severity in (Severity.CRITICAL, Severity.HIGH):
            evidence.append({
                "type": "severity_context",
                "source": "alert",
                "detail": f"High severity alert: {alert.severity.value}",
                "weight": 0.5,
            })

        return evidence

    def _get_fault_candidates(self, alert_name: str) -> list[dict[str, Any]]:
        """按告警名匹配故障模式库

        统计层告警名带 anomaly_ 前缀（如 anomaly_tomcat_busy_threads），
        去掉前缀后与规则层/基线指标名共用同一套模式库。
        """
        normalized = alert_name.replace("anomaly_", "")
        for pattern_key, candidates in SHORTLINK_FAULT_PATTERNS.items():
            if pattern_key in normalized or normalized in pattern_key:
                return candidates
        logger.warning(f"[RCAAgent] 无匹配故障模式，使用兜底候选: {alert_name}")
        return FALLBACK_FAULT_PATTERNS

    async def _bayesian_inference(
        self,
        candidates: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
    ) -> tuple[str, float, list[str]]:
        """贝叶斯推理选出最可能的根因（证据驱动）"""
        has_recent_change = any(e["type"] == "recent_change" for e in evidence)

        best_cause = "Unknown"
        best_confidence = 0.0
        best_actions: list[str] = []

        for candidate in candidates:
            prior = candidate["base_probability"]
            likelihood, verified = await self._compute_likelihood(candidate, has_recent_change)

            posterior = self._reasoner.compute_posterior(prior, likelihood)

            if posterior > best_confidence:
                best_confidence = posterior
                best_cause = candidate["root_cause"]
                best_actions = candidate["suggested_actions"]

        return best_cause, round(best_confidence, 3), best_actions

    async def _compute_likelihood(
        self, candidate: dict[str, Any], has_recent_change: bool
    ) -> tuple[float, Optional[bool]]:
        """计算似然 P(Evidence|Cause)

        优先用 verify 探针的实测值；无探针时退回静态 evidence_pattern 判断。
        """
        verify = candidate.get("verify")
        if not verify:
            # 无法用指标证伪的猜测（如「近期部署引入缺陷」），只能靠先验与变更记录
            pattern = candidate.get("evidence_pattern", "")
            if pattern == "recent_deploy" and has_recent_change:
                return BayesianReasoner.LIKELIHOOD_CONFIRMED, None
            if pattern == "recent_config_change" and has_recent_change:
                return 0.85, None
            return BayesianReasoner.LIKELIHOOD_UNKNOWN, None

        if self._evidence_provider is None:
            logger.debug("[RCAAgent] 无证据提供者，探针跳过，退回静态似然")
            return BayesianReasoner.LIKELIHOOD_UNKNOWN, None

        value = await self._evidence_provider.query(verify["promql"])
        if value is None:
            logger.debug(f"[RCAAgent] 探针无数据: {verify['promql']}")
            return BayesianReasoner.LIKELIHOOD_UNKNOWN, None

        if verify["comparator"] == "gt":
            holds = value > verify["threshold"]
        else:
            holds = value < verify["threshold"]

        logger.info(
            f"[RCAAgent] 探针 {'成立' if holds else '不成立'}: "
            f"{candidate['root_cause'][:24]}... 实测={value:.4f} "
            f"({verify['comparator']} {verify['threshold']})"
        )
        return (
            BayesianReasoner.LIKELIHOOD_CONFIRMED if holds
            else BayesianReasoner.LIKELIHOOD_REFUTED,
            holds,
        )
