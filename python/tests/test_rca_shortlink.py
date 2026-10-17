"""阶段 4：短链故障模式库的根因判定验证

用桩证据提供者（StubProvider）注入探针实测值，不依赖 Docker / Prometheus，
可离线运行：

    cd python && PYTHONPATH=. python tests/test_rca_shortlink.py

验证目标：候选根因由**证据**决定，而非只靠 base_probability 先验。
"""

import asyncio
import re
import sys

from agents.rca_agent import RCAAgent
from core.event_bus import InMemoryEventBus
from models.events import AlertEvent, IncidentState, Severity

# _verify() 会给探针统一包一层 "or vector(0)"，桩的 key 必须用包装后的形态，
# 否则 RCAAgent 查不到值、探针退化成「无数据」。
def probe(promql: str) -> str:
    return f"({promql}) or vector(0)"


def norm(promql: str) -> str:
    """归一化时间窗口（[2m]/[30s] → [W]）

    窗口时长是调参项，不是探针语义：实测把窗口从 [2m] 收窄到 [30s] 后，
    按字面量匹配的桩全部失配，6 个用例一下挂了 4 个 —— 测试断言的是
    「给定实测值应得出哪个根因」，不该被调窗口这件事影响。
    """
    return re.sub(r"\[\w+\]", "[W]", promql)


PROBE_REDIS = probe('sum(rate(shortlink_redirect_total{job="shortlink-app"}[30s]))')
PROBE_MYSQL = probe('sum(rate(hikaricp_connections_timeout_total{job="shortlink-app"}[30s]))')
PROBE_TRAFFIC = probe('sum(rate(http_server_requests_seconds_count{job="shortlink-app"}[30s]))')
PROBE_THREADS = probe(
    'sum(tomcat_threads_busy_threads{job="shortlink-app"})'
    ' / sum(tomcat_threads_config_max_threads{job="shortlink-app"})'
)


class StubProvider:
    """按 PromQL 返回预设实测值；未预设的查询返回 None（探针无数据）"""

    def __init__(self, values: dict):
        self._values = {norm(k): v for k, v in values.items()}
        self.queries: list[str] = []

    async def query(self, promql: str):
        self.queries.append(promql)
        return self._values.get(norm(promql))


async def analyze(alert_name: str, probe_values: dict, target="shortlink-app"):
    bus = InMemoryEventBus()
    await bus.start()
    rca = RCAAgent(bus, evidence_provider=StubProvider(probe_values))
    alert = AlertEvent(
        alert_name=alert_name,
        severity=Severity.CRITICAL,
        source="prometheus",
        target_service=target,
        metric_name="http_5xx_rate",
        metric_value=1.0,
        threshold=0.5,
    )
    state = IncidentState()
    state.alert_event = alert
    state = await rca.handle(state)
    return state.rca_event


async def test_redis_down():
    """Redis 挂：成功跳转吞吐归零、DB 连接池无超时、总请求量不高"""
    rca = await analyze(
        "redirect_5xx_rate",
        {PROBE_REDIS: 0.0, PROBE_MYSQL: 0.0, PROBE_TRAFFIC: 8.0},
    )
    assert "Redis" in rca.root_cause, rca.root_cause
    assert rca.confidence > 0.5, rca.confidence
    assert "restart_redis" in rca.suggested_actions


async def test_mysql_down():
    """MySQL 挂：命中路径仍成功、连接池获取超时"""
    rca = await analyze(
        "redirect_5xx_rate",
        {PROBE_REDIS: 4.0, PROBE_MYSQL: 2.0, PROBE_TRAFFIC: 8.0},
    )
    assert "MySQL" in rca.root_cause, rca.root_cause


async def test_traffic_surge():
    """真流量激增：成功跳转很多、总请求量很高、DB 正常"""
    rca = await analyze(
        "redirect_5xx_rate",
        {PROBE_REDIS: 30.0, PROBE_MYSQL: 0.0, PROBE_TRAFFIC: 60.0},
    )
    assert "流量" in rca.root_cause, rca.root_cause


async def test_healthy_false_positive_stays_low_confidence():
    """健康状态下告警误报：所有已知根因都被证伪，不应硬编一个高置信度错因"""
    rca = await analyze(
        "redirect_5xx_rate",
        {PROBE_REDIS: 5.0, PROBE_MYSQL: 0.0, PROBE_TRAFFIC: 3.0},
    )
    assert rca.confidence < 0.25, rca.confidence


async def test_tomcat_thread_pool_saturated():
    """统计层 anomaly_ 告警：前缀剥离后仍能匹配故障模式库"""
    rca = await analyze("anomaly_tomcat_busy_threads", {PROBE_THREADS: 0.85})
    assert "Tomcat" in rca.root_cause, rca.root_cause


async def test_dependency_chain_uses_shortlink_topology():
    """依赖链来自短链真实拓扑，而非原项目的 order-service"""
    rca = await analyze("redirect_5xx_rate", {})
    assert "shortlink-app" in rca.affected_services
    assert "redis" in rca.affected_services
    assert "mysql" in rca.affected_services


async def main():
    cases = [
        ("A Redis 不可达", test_redis_down),
        ("B MySQL 不可达", test_mysql_down),
        ("C 流量激增", test_traffic_surge),
        ("D 健康误报低置信度", test_healthy_false_positive_stays_low_confidence),
        ("E Tomcat 线程池打满", test_tomcat_thread_pool_saturated),
        ("F 依赖链用短链拓扑", test_dependency_chain_uses_shortlink_topology),
    ]
    passed = 0
    for name, case in cases:
        try:
            await case()
            print(f"[PASS] {name}")
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {name}: {e}")
        except Exception as e:  # noqa: BLE001
            print(f"[ERROR] {name}: {type(e).__name__}: {e}")
    print(f"\n通过 {passed}/{len(cases)}")
    return passed == len(cases)


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
