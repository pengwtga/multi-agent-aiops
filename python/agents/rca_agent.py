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
from agents.llm_evidence import LLMEvidenceSource, OpenAICompatClient, blend_likelihood
from agents.prior_store import SQLitePriorStore
from config.settings import settings
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

# 所有探针都被证伪时的输出：承认没定位出来，而不是编一个像样的答案
UNRESOLVED_ROOT_CAUSE = "未能定位根因：所有证据探针均被真实指标证伪（转人工）"
UNRESOLVED_ACTIONS = ["check_dependency"]


def _verify(promql: str, comparator: str = "gt", threshold: float = 0.0) -> dict:
    """构造一个证据探针：用 PromQL 实测值证实或证伪某候选根因

    统一包一层 `or vector(0)`：这些探针问的都是「有没有观测到 X」，
    那么「序列不存在」应等价于「观测值为 0」（证伪），而不是「未知」。

    实测踩过的坑：应用重启后若跳转从未成功过，`shortlink_redirect_total`
    这个 Micrometer 计数器根本不会注册出序列，`rate()` 又因为窗口内不足
    2 个采样点返回空——探针拿到 None 会让判据直接失效。

    窗口统一用 [30s] 而不是 [2m]（踩过的第二个坑）：故障演练只持续几十秒，
    [2m] 的平均速率会把故障前的健康数据一起平均进来，于是「吞吐归零」
    这类判据永远不成立（实测 0.4762 req/s），探针集体被证伪、根因归因
    失败。30s 与 Prometheus 15s 抓取间隔配合仍有 2 个采样点。
    """
    return {
        "promql": f"({promql}) or vector(0)",
        "comparator": comparator,
        "threshold": threshold,
    }


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
                'sum(rate(shortlink_redirect_total{job="shortlink-app"}[30s]))',
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
                'sum(rate(hikaricp_connections_timeout_total{job="shortlink-app"}[30s]))',
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
                'sum(rate(http_server_requests_seconds_count{job="shortlink-app"}[30s]))',
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
    # 依赖「挂起」故障（补 §4.7 的缺口）
    #
    # 与 dependency_down 的区别：连接被拒绝是「快速失败」，会产生 5xx；
    # 挂起是「卡住不返回」，不产生任何状态码，因此状态码类规则全部失效。
    # 这里只能用「连接是否堆积」这类占用信号来判。
    "dependency_hang": [
        {
            "root_cause": (
                "Redis 连接挂起：读路径阻塞在 Lettuce 连接池等待，"
                "请求既不返回也不报错（无降级逻辑）"
            ),
            "evidence_pattern": "dependency_down",
            "base_probability": 0.55,
            # 一手信号：连接被占住不释放（挂起的直接后果）。
            # 不用 5xx rate —— 挂起时它恒为 0，因为请求根本没完成。
            "verify": _verify(
                'sum(tomcat_connections_current_connections'
                '{job="shortlink-app"})',
                "gt", 20,
            ),
            "suggested_actions": ["restart_redis", "check_dependency"],
        },
        {
            "root_cause": (
                "MySQL 连接挂起：缓存 miss 回源阻塞（命中路径仍正常）"
            ),
            "evidence_pattern": "dependency_down",
            "base_probability": 0.25,
            "verify": _verify(
                'sum(rate(hikaricp_connections_timeout_total'
                '{job="shortlink-app"}[30s]))',
                "gt", 0.0,
            ),
            "suggested_actions": ["restart_mysql", "check_dependency"],
        },
        {
            "root_cause": "真实流量激增导致线程池打满（非依赖故障）",
            "evidence_pattern": "request_rate_increase",
            "base_probability": 0.20,
            "verify": _verify(
                'sum(rate(http_server_requests_seconds_count'
                '{job="shortlink-app"}[30s]))',
                "gt", 50.0,
            ),
            "suggested_actions": ["scale_app", "rate_limit"],
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
    # 创建链路专属候选（补 §5.26 记录的缺口）
    #
    # 为什么需要它：创建是**写路径**，坏因与跳转完全不同 —— 跳转关心的是
    # 「读不到 / 挂住」，创建关心的是「写不进去」。此前创建接口的 5xx 会命中
    # redirect_5xx_rate，走跳转那套候选，而跳转探针（跳转吞吐、连接超时）对
    # 创建失败基本没有区分力。
    #
    # ★ key 必须等于告警名：`_get_fault_candidates` 用子串匹配
    # （pattern_key in normalized or normalized in pattern_key），
    # create_5xx_rate 与 create_failure 互不为子串，取错名字会静默落到
    # FALLBACK_FAULT_PATTERNS —— 症状是"能告警但永远定位不出"，很难排查。
    #
    # 探针设计同样遵守「必须能证伪」：判据只在坏因成立时才为真。
    "create_5xx_rate": [
        {
            "root_cause": "MySQL 写入失败（连接池打满 / 主库不可写）",
            "evidence_pattern": "db_write_error",
            "base_probability": 0.45,
            "verify": _verify(
                'sum(hikaricp_connections_pending{job="shortlink-app"})',
                "gt", 5.0,
            ),
            "suggested_actions": ["check_mysql", "restart_mysql"],
        },
        {
            "root_cause": "Redis 回填失败 —— 创建的事务里包含缓存写入，"
                          "Redis 不可达会让整个创建回滚",
            "evidence_pattern": "dependency_down",
            "base_probability": 0.30,
            "verify": _verify(
                'sum(rate(shortlink_redirect_total{job="shortlink-app",'
                'outcome="hit"}[30s]))',
                "lt", 0.05,
            ),
            "suggested_actions": ["restart_redis", "check_dependency"],
        },
        {
            "root_cause": "创建接口限流阈值过低（5 次/60s）被正常流量打满",
            "evidence_pattern": "rate_limited",
            "base_probability": 0.15,
            "verify": _verify(
                'sum(rate(shortlink_ratelimit_rejected_total'
                '{job="shortlink-app",scene="create"}[1m]))',
                "gt", 1.0,
            ),
            "suggested_actions": ["check_dependency"],
        },
        {
            "root_cause": "雪花 ID 时钟回拨导致主键冲突",
            "evidence_pattern": "id_conflict",
            "base_probability": 0.10,
            "suggested_actions": ["check_dependency"],
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
                'sum(rate(hikaricp_connections_pending{job="shortlink-app"}[30s]))',
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
                'sum(rate(http_server_requests_seconds_count{job="shortlink-app"}[30s]))',
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
                'sum(rate(jvm_gc_pause_seconds_count{job="shortlink-app"}[30s]))',
                "gt", 1.0,
            ),
            "suggested_actions": ["heap_dump", "restart_container"],
        },
        {
            "root_cause": "流量激增导致 CPU 过载",
            "evidence_pattern": "request_rate_increase",
            "base_probability": 0.35,
            "verify": _verify(
                'sum(rate(http_server_requests_seconds_count{job="shortlink-app"}[30s]))',
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
                 evidence_provider: Optional[EvidenceProvider] = None,
                 llm_evidence: Optional[LLMEvidenceSource] = None,
                 prior_store: Optional["SQLitePriorStore"] = None):
        super().__init__(AgentType.RCA, event_bus, "RCAAgent")
        self._kg = knowledge_graph
        self._reasoner = BayesianReasoner()
        self._evidence_provider = evidence_provider
        # LLM 证据源：可选增强，默认关闭。未显式注入时按配置自动构造，
        # 配置不齐就保持为 None —— 现有闭环不依赖它。
        if llm_evidence is None and settings.llm_evidence_enabled:
            if settings.openai_api_key:
                llm_evidence = LLMEvidenceSource(
                    OpenAICompatClient(
                        api_key=settings.openai_api_key,
                        model=settings.openai_model,
                        base_url=settings.openai_base_url
                        or "https://api.openai.com/v1",
                        timeout=settings.llm_timeout_seconds,
                    )
                )
            else:
                logger.warning(
                    "[RCAAgent] llm_evidence_enabled=true 但未配置 "
                    "AIOPS_OPENAI_API_KEY，LLM 证据源保持关闭"
                )
        self._llm_evidence = llm_evidence

        # 先验存储器：让 base_probability 从历史闭环里学习。
        # 未显式注入时按配置自动构造；构造失败就退回 None（用写死的先验），
        # 先验学习永远不能让根因分析跑不起来。
        if prior_store is None and settings.prior_learning_enabled:
            try:
                prior_store = SQLitePriorStore(
                    db_path=settings.prior_db_path,
                    alpha=settings.prior_alpha,
                )
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    f"[RCAAgent] 先验存储器初始化失败，沿用人工先验: {e}"
                )
                prior_store = None
        self._prior_store = prior_store

    async def process(self, state: IncidentState) -> IncidentState:
        alert = state.alert_event
        if not alert:
            logger.warning("[RCAAgent] No alert event to analyze")
            return state

        logger.info(f"[RCAAgent] Analyzing alert: {alert.alert_name} on {alert.target_service}")

        affected_chain = self._trace_dependency_chain(alert.target_service)

        evidence = self._collect_evidence(alert, affected_chain)

        candidates = self._get_fault_candidates(alert.alert_name)

        # LLM 证据（可选增强）：一次调用覆盖全部候选，避免 N 次 API 往返。
        # 只在「无探针 / 探针拿不到数据」的候选上起作用，详见 llm_evidence。
        llm_evidence: dict[str, tuple[bool, float]] = {}
        if self._llm_evidence is not None:
            has_recent_change = any(
                e["type"] == "recent_change" for e in evidence
            )
            llm_evidence = await self._llm_evidence.collect(
                alert, candidates, has_recent_change
            )
            if llm_evidence:
                # 权重刻意低于指标证据（0.8）与变更记录（0.9）：LLM 是补充，
                # 不是裁判。写进 evidence 是为了可解释 —— 页面上能看到它
                # 到底影响了哪条候选。
                evidence.append({
                    "type": "llm_evidence",
                    "source": "llm",
                    "detail": "; ".join(
                        f"{name[:16]}… {'支持' if ok else '反对'}({s:.2f})"
                        for name, (ok, s) in llm_evidence.items()
                    ),
                    "weight": 0.3,
                })

        # 阶段 4：带 verify 探针的候选要回查 Prometheus 实测，故推理改为 async
        root_cause, confidence, actions = await self._bayesian_inference(
            alert.alert_name, candidates, evidence, llm_evidence
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
        alert_name: str,
        candidates: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        llm_evidence: Optional[dict[str, tuple[bool, float]]] = None,
    ) -> tuple[str, float, list[str]]:
        """贝叶斯推理选出最可能的根因（证据驱动）"""
        has_recent_change = any(e["type"] == "recent_change" for e in evidence)

        best_cause = "Unknown"
        best_confidence = 0.0
        best_actions: list[str] = []
        # 带探针的候选里，有多少个被真实指标证伪
        probed = 0
        refuted = 0

        for candidate in candidates:
                manual_prior = candidate["base_probability"]
                # 先验融合：有历史闭环数据时用计数平滑后的值，否则原样返回人工先验。
                # 这一步是唯一的改动点 —— 下游的贝叶斯公式一字未改。
                prior = (
                    self._prior_store.prior(alert_name, candidate["root_cause"], manual_prior)
                    if self._prior_store is not None
                    else manual_prior
                )
                likelihood, verified = await self._compute_likelihood(
                    candidate,
                    has_recent_change,
                    (llm_evidence or {}).get(candidate["root_cause"]),
                )

                if candidate.get("verify"):
                    probed += 1
                    if verified is False:
                        refuted += 1

                posterior = self._reasoner.compute_posterior(prior, likelihood)

                if posterior > best_confidence:
                    best_confidence = posterior
                    best_cause = candidate["root_cause"]
                    best_actions = candidate["suggested_actions"]

        # 所有可验证的候选都被真实数据证伪 → 不能拿没有探针的兜底猜测
        # （如「近期部署引入缺陷」）当答案。
        #
        # 实测踩过：Redis 停机时 5xx 告警命中，三条探针因 [2m] 窗口被健康
        # 数据稀释而全部证伪，最终落到 base_probability 只有 0.10 的兜底
        # 候选「近期部署引入缺陷」，置信度 0.10 < 0.3 → 不提议自愈 →
        # Redis 真实停机 25 分钟无人处理。告警在响却什么都不做，比多报
        # 一条告警严重得多。
        #
        # 这时正确的输出是「我没定位出来」，交给人工，而不是编一个答案。
        if probed and refuted == probed:
            logger.warning(
                f"[RCAAgent] {probed} 条探针全部被证伪，拒绝用无探针的兜底猜测作答 "
                f"（原兜底: {best_cause} {best_confidence:.2f}）→ 转人工"
            )
            return UNRESOLVED_ROOT_CAUSE, 0.0, UNRESOLVED_ACTIONS

        return best_cause, round(best_confidence, 3), best_actions

    async def _compute_likelihood(
        self,
        candidate: dict[str, Any],
        has_recent_change: bool,
        llm_ev: Optional[tuple[bool, float]] = None,
    ) -> tuple[float, Optional[bool]]:
        """计算似然 P(Evidence|Cause)

        优先级：verify 探针实测 > LLM 证据 > 静态 evidence_pattern。
        LLM 只在探针给不出结论（无探针 / 无数据）时补位 —— 一手信号永远
        压过模型的猜测。
        """
        verify = candidate.get("verify")
        if not verify:
            # 无法用指标证伪的猜测（如「近期部署引入缺陷」），只能靠先验与变更记录
            pattern = candidate.get("evidence_pattern", "")
            if pattern == "recent_deploy" and has_recent_change:
                return BayesianReasoner.LIKELIHOOD_CONFIRMED, None
            if pattern == "recent_config_change" and has_recent_change:
                return 0.85, None
            return self._with_llm(
                BayesianReasoner.LIKELIHOOD_UNKNOWN, llm_ev, candidate
            ), None

        if self._evidence_provider is None:
            logger.debug("[RCAAgent] 无证据提供者，探针跳过，退回静态似然")
            return self._with_llm(
                BayesianReasoner.LIKELIHOOD_UNKNOWN, llm_ev, candidate
            ), None

        value = await self._evidence_provider.query(verify["promql"])
        if value is None:
            logger.debug(f"[RCAAgent] 探针无数据: {verify['promql']}")
            return self._with_llm(
                BayesianReasoner.LIKELIHOOD_UNKNOWN, llm_ev, candidate
            ), None

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

    @staticmethod
    def _with_llm(
        base: float,
        llm_ev: Optional[tuple[bool, float]],
        candidate: dict[str, Any],
    ) -> float:
        """把一条 LLM 证据融合进似然（仅当探针没给出结论时）

        融合后仍夹在 [0.05, 0.9] 之内，与探针「证伪/成立」同档 —— LLM 无法
        单独把置信度顶过自愈闸门，这是刻意的安全边界。
        """
        if not llm_ev:
            return base
        support, strength = llm_ev
        blended = blend_likelihood(base, support, strength)
        logger.info(
            f"[RCAAgent] LLM 证据: {candidate['root_cause'][:20]}… "
            f"{'支持' if support else '反对'}({strength:.2f}) → "
            f"似然 {base:.2f} → {blended:.2f}"
        )
        return blended
