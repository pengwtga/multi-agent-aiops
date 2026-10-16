"""Prometheus 采集器 — MonitorAgent 的真实数据入口（阶段 3）

两层告警设计：
1. 静态业务规则（短链平台专属）：阈值判定立即触发，无冷启动问题。
   规则编码的是运维知识——consume_lag 语义、Kafka 假 lag 陷阱、5xx 业务含义，
   这些是统计模型推断不出来的「已知故障模式」。
2. 统计异常检测（复用 MonitorAgent 现有多算法投票）：每个周期持续投喂基线
   指标样本，历史积累后可捕获「未知突变」。

规则命中 → 新建 incident 跑完整工作流（Monitor→RCA→Heal→Change）；
告警去重由 MonitorAgent 的 AlertFingerprint（5 分钟窗口）兜底，持续故障
每 5 分钟重通知一次，符合告警系统的常规行为。

依赖说明：venv 没有 httpx/requests，用 stdlib urllib + asyncio.to_thread
实现异步查询，零新增依赖。
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlencode
from urllib.request import urlopen

from models.events import Severity

logger = logging.getLogger(__name__)

# Prometheus 里短链平台的 job 名，必须与 config/prometheus.yml 一致
SHORTLINK_JOB = "shortlink-app"


class PrometheusClient:
    """极简 Prometheus HTTP 客户端 — 只用 instant query"""

    def __init__(self, base_url: str = "http://localhost:9090", timeout: float = 5.0):
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    async def query(self, promql: str) -> Optional[float]:
        """执行 instant 查询，返回第一个序列的值；无数据返回 None"""

        def _fetch() -> Optional[float]:
            url = f"{self._base}/api/v1/query?{urlencode({'query': promql})}"
            with urlopen(url, timeout=self._timeout) as resp:
                payload = json.load(resp)
            if payload.get("status") != "success":
                return None
            result = payload.get("data", {}).get("result", [])
            if not result:
                return None
            return float(result[0]["value"][1])

        try:
            return await asyncio.to_thread(_fetch)
        except Exception as e:
            logger.warning(f"[PrometheusClient] query failed: {promql!r} -> {e}")
            return None


@dataclass
class AlertRule:
    """静态业务告警规则"""

    name: str
    promql: str
    comparator: str          # gt / lt
    threshold: float
    severity: Severity
    target_service: str
    metric_name: str
    description: str

    def violated(self, value: float) -> bool:
        if self.comparator == "gt":
            return value > self.threshold
        if self.comparator == "lt":
            return value < self.threshold
        return False


def build_shortlink_rules(job: str = SHORTLINK_JOB) -> list[AlertRule]:
    """短链平台业务告警规则集

    - up==0: 抓取目标不可达（应用进程死亡/端口不通），最高优先级
    - 5xx rate: 跳转/创建路径的 5xx 速率
      ⚠️ 曾经的**错误假设**：以为「Redis 挂掉时读路径立即抛 500」。
         实测恰恰相反 —— 应用阻塞在 Lettuce 连接池等待，既不返回也不
         报错（/actuator/health 20s 超时无响应）。这条规则因此抓不到
         挂起类故障，见下方 dependency_hang 与 §4.7。
    - consume_lag: 基于 t_consumer_offset 真相源的短链自定义指标；
      若误用 broker LAG 会被假 lag 误告警（shortlink ARCHITECTURE §6.5）
    - 限流拒绝: 绝对速率 >1/s，避免流量空闲时比率类指标分母为零
    - dependency_hang: **补 §4.7 的缺口**。请求挂住时不产生 5xx，
      状态码类规则全部失效；此规则改用「连接堆积 + 成功吞吐归零」
      这两个**占用类**信号来捕获挂起。
    """
    return [
        AlertRule(
            name="shortlink_app_down",
            promql=f'min(up{{job="{job}"}})',
            comparator="lt",
            threshold=1.0,
            severity=Severity.CRITICAL,
            target_service="shortlink-app",
            metric_name="up",
            description="短链应用抓取目标不可达",
        ),
        AlertRule(
            name="redirect_5xx_rate",
            promql=(
                f'sum(rate(http_server_requests_seconds_count'
                f'{{job="{job}",status=~"5.."}}[1m]))'
            ),
            comparator="gt",
            threshold=0.5,
            severity=Severity.CRITICAL,
            target_service="shortlink-app",
            metric_name="http_5xx_rate",
            description="跳转/创建路径 5xx 速率超过 0.5 req/s",
        ),
        AlertRule(
            name="consume_lag_backlog",
            promql=f'sum(shortlink_consume_lag{{job="{job}"}})',
            comparator="gt",
            threshold=10000,
            severity=Severity.HIGH,
            target_service="click-consumer",
            metric_name="consume_lag",
            description="点击统计消费积压超过 1 万（消费端卡死或 MySQL 写入延迟）",
        ),
        AlertRule(
            name="ratelimit_reject_burst",
            promql=f'sum(rate(shortlink_ratelimit_rejected_total{{job="{job}"}}[5m]))',
            comparator="gt",
            threshold=1.0,
            severity=Severity.MEDIUM,
            target_service="shortlink-app",
            metric_name="ratelimit_reject_rate",
            description="限流拒绝持续高于 1/s（疑似单 IP 滥用或阈值配置有误）",
        ),
        AlertRule(
            name="dependency_hang",
            # 依赖「挂起」检测（补 §4.7 的缺口）
            #
            # 为什么需要它：请求挂住时**不返回、也不报错**，因此既不产生
            # 5xx 也不计入 http_server_requests_seconds_count（后者只在请求
            # 完成时递增）。于是所有状态码类规则都失效 —— 监控一片绿，
            # 而 Tomcat 线程池正被慢慢占满。
            #
            # 判据：连接被占住不释放，同时成功跳转吞吐归零。
            #   (连接数 > 20) and (成功跳转速率 < 0.05/s)
            #
            # 两个操作数都必须 or vector(0) 兜底：rate() 在窗口内不足 2 个
            # 采样点时返回空，而挂起时 shortlink_redirect_total 可能压根没有
            # 序列（从未成功过）。返回空会让 `and` 直接失效导致漏报 ——
            # 这正是 rca_agent._verify() 踩过的同一个坑。
            promql=(
                f'((sum(tomcat_connections_current_connections'
                f'{{job="{job}"}})) or vector(0)) > 20'
                " and "
                f'((sum(rate(shortlink_redirect_total'
                f'{{job="{job}"}}[2m]))) or vector(0)) < 0.05'
                " or vector(0)"
            ),
            comparator="gt",
            threshold=0.5,
            severity=Severity.CRITICAL,
            target_service="shortlink-app",
            metric_name="dependency_hang",
            description=(
                "请求堆积但成功跳转吞吐归零：依赖挂起，无 5xx 信号，"
                "状态码类规则抓不到"
            ),
        ),
    ]


# 喂给统计异常检测层的基线指标（每周期采集，为 MonitorAgent 积累历史样本）
BASELINE_QUERIES: list[dict[str, str]] = [
    {
        "metric_name": "consume_lag",
        "promql": f'sum(shortlink_consume_lag{{job="{SHORTLINK_JOB}"}})',
        "service": "click-consumer",
    },
    {
        "metric_name": "app_cpu_usage",
        "promql": f'process_cpu_usage{{job="{SHORTLINK_JOB}"}}',
        "service": "shortlink-app",
    },
    {
        "metric_name": "tomcat_busy_threads",
        "promql": f'sum(tomcat_threads_busy_threads{{job="{SHORTLINK_JOB}"}})',
        "service": "shortlink-app",
    },
]


class MonitorLoop:
    """监控主循环 — 周期性轮询 Prometheus 并驱动 Orchestrator 工作流"""

    def __init__(
        self,
        orchestrator,
        prometheus_url: str = "http://localhost:9090",
        interval_seconds: int = 30,
        rules: Optional[list[AlertRule]] = None,
    ):
        self._orchestrator = orchestrator
        self._client = PrometheusClient(prometheus_url)
        self._interval = interval_seconds
        self._rules = rules if rules is not None else build_shortlink_rules()
        self._running = False
        # 自观测计数
        self.cycles = 0
        self.alerts_fired: list[dict[str, Any]] = []

    def stop(self) -> None:
        self._running = False

    async def run_forever(self) -> None:
        self._running = True
        logger.info(
            f"[MonitorLoop] 启动: interval={self._interval}s, "
            f"rules={[r.name for r in self._rules]}, "
            f"baseline={[s['metric_name'] for s in BASELINE_QUERIES]}"
        )
        while self._running:
            try:
                await self._run_cycle()
            except Exception:
                # 主循环绝不退出：单周期失败只记日志，保活优先
                logger.exception("[MonitorLoop] cycle failed")
            await asyncio.sleep(self._interval)

    async def _run_cycle(self) -> None:
        self.cycles += 1

        # ---- 1. 静态业务规则 ----
        for rule in self._rules:
            value = await self._client.query(rule.promql)
            if value is None or not rule.violated(value):
                continue

            metadata = {
                "metric_data": {
                    "metric_name": rule.metric_name,
                    "value": value,
                    "service": rule.target_service,
                    "labels": {"job": SHORTLINK_JOB, "rule": rule.name},
                },
                "rule_violation": {
                    "name": rule.name,
                    "severity": rule.severity.value,
                    "threshold": rule.threshold,
                    "comparator": rule.comparator,
                    "description": rule.description,
                },
            }
            state = await self._orchestrator.run(metadata=metadata)
            if state.alert_event:
                logger.info(
                    f"[MonitorLoop] 规则命中: {rule.name} "
                    f"value={value} threshold={rule.threshold}"
                )
            self._record_alert(state, source="rule")

        # ---- 2. 基线指标（统计异常检测层预热）----
        for series in BASELINE_QUERIES:
            value = await self._client.query(series["promql"])
            if value is None:
                continue
            state = await self._orchestrator.run(metadata={
                "metric_data": {
                    "metric_name": series["metric_name"],
                    "value": value,
                    "service": series["service"],
                    "labels": {"job": SHORTLINK_JOB},
                },
            })
            # 统计层捕获的是「未知突变」，同样要进自观测列表，否则状态端点是瞎的
            self._record_alert(state, source="statistical")

    def _record_alert(self, state, source: str) -> None:
        """记录一次告警到自观测列表（规则层与统计层共用）"""
        alert = state.alert_event
        if not alert:
            return
        self.alerts_fired.append({
            "cycle": self.cycles,
            "incident_id": state.incident_id,
            "alert": alert.alert_name,
            "severity": alert.severity.value,
            "metric_value": alert.metric_value,
            "source": source,
            "at": datetime.utcnow().isoformat(),
        })
        logger.info(
            f"[MonitorLoop] 告警触发({source}): {alert.alert_name} [{alert.severity.value}]"
        )

    def status(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "interval_seconds": self._interval,
            "cycles": self.cycles,
            "rules": [
                {
                    "name": r.name,
                    "promql": r.promql,
                    "threshold": r.threshold,
                    "comparator": r.comparator,
                    "severity": r.severity.value,
                }
                for r in self._rules
            ],
            "baseline_metrics": [s["metric_name"] for s in BASELINE_QUERIES],
            "alerts_fired": self.alerts_fired[-20:],
        }

    def get_metrics_text(self) -> str:
        """渲染 /metrics 文本（Prometheus exposition 格式）供自观测。

        venv 没有 prometheus_client，手写最简格式即可让
        config/prometheus.yml 的 aiops-agents 抓取目标 up。
        """
        lines = [
            "# TYPE aiops_monitor_cycles_total counter",
            f"aiops_monitor_cycles_total {self.cycles}",
            "# TYPE aiops_monitor_alerts_total counter",
            f"aiops_monitor_alerts_total {len(self.alerts_fired)}",
            "# TYPE aiops_monitor_rules gauge",
            f"aiops_monitor_rules {len(self._rules)}",
        ]
        return "\n".join(lines) + "\n"
