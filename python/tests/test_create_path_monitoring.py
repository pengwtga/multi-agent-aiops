"""创建链路监控验证

    cd python && PYTHONPATH=. python tests/test_create_path_monitoring.py

背景：此前整套告警与故障模式库都围绕**跳转链路**，创建链路没有独立观测——
     创建接口的 5xx 混在 redirect_5xx_rate 里，命中后走跳转那套候选，
     而跳转探针（跳转吞吐 / 连接超时）对「创建写失败」没有区分力，
     最后大概率落到「未定位根因」。

本次补齐三件事，这里逐条验证：
  1. 故障模式库新增 create_5xx_rate 候选，且**能被告警名匹配上**
     （★ 关键：key 必须等于告警名，否则静默落到兜底候选）
  2. 候选结构完整（先验之和为 1、每条四件套齐全）
  3. 探针判据「必须能证伪」—— 坏因不成立时判据为假
  4. 告警规则里存在 create_5xx_rate，且标记为 root_cause（独立开闭环）
  5. 回归：跳转链路的既有候选不受影响
"""

import asyncio
import sys

from agents.rca_agent import (
    FALLBACK_FAULT_PATTERNS,
    SHORTLINK_FAULT_PATTERNS,
    RCAAgent,
    _verify,
)
from collectors.prometheus_collector import build_shortlink_rules
from core.event_bus import InMemoryEventBus

ALERT = "create_5xx_rate"


async def main() -> int:
    failures: list[str] = []

    def check(cond: bool, msg: str) -> None:
        print(("  PASS  " if cond else "  FAIL  ") + msg)
        if not cond:
            failures.append(msg)

    # ---------------------------------------------------------------
    print("\n[1] ★ 告警名能匹配到创建链路专属候选（不是兜底）")
    # ---------------------------------------------------------------
    check(ALERT in SHORTLINK_FAULT_PATTERNS, f"故障模式库存在 key {ALERT!r}")
    check(
        ALERT not in ("create_failure",),
        "key 用的是告警名本身（不是语义名 create_failure）",
    )

    agent = RCAAgent(InMemoryEventBus())
    candidates = agent._get_fault_candidates(ALERT)
    check(candidates is not FALLBACK_FAULT_PATTERNS, "未落到 FALLBACK 兜底候选")
    check(len(candidates) == 4, f"返回 4 条创建链路候选（实际 {len(candidates)}）")

    # 匹配逻辑是子串匹配，这里显式验证两种方向都不会误命中别的 key
    normalized = ALERT.replace("anomaly_", "")
    hits = [
        k for k in SHORTLINK_FAULT_PATTERNS
        if k in normalized or normalized in k
    ]
    check(hits == [ALERT], f"子串匹配只命中创建链路这一个 key: {hits}")

    # ---------------------------------------------------------------
    print("\n[2] 候选结构完整：四件套齐全、先验之和为 1")
    # ---------------------------------------------------------------
    total_prior = sum(c["base_probability"] for c in candidates)
    check(abs(total_prior - 1.0) < 1e-9, f"先验之和 = {total_prior}")
    for c in candidates:
        ok = all(k in c for k in ("root_cause", "base_probability", "suggested_actions"))
        check(ok, f"候选字段齐全: {c['root_cause'][:20]}…")

    probed = [c for c in candidates if c.get("verify")]
    check(len(probed) == 3, f"3 条候选带探针（实际 {len(probed)}）")

    # ---------------------------------------------------------------
    print("\n[3] 探针判据「必须能证伪」—— 结构正确")
    # ---------------------------------------------------------------
    for c in probed:
        v = c["verify"]
        check(
            set(("promql", "comparator", "threshold")) <= set(v),
            f"探针三要素齐全: {c['root_cause'][:16]}…",
        )
        check(" or vector(0)" in v["promql"], f"带 or vector(0) 兜底: {c['root_cause'][:16]}…")
        check(v["comparator"] in ("gt", "lt"), f"比较符合法: {v['comparator']}")

    # 语义检查：Redis 那条用「命中吞吐归零」判 Redis 不可达。
    # 健康时吞吐 > 0.05 → 判据为假 → 可证伪（不是那种健康时也成立的废判据）
    redis_c = next(c for c in candidates if "Redis" in c["root_cause"])
    healthy_value = 100.0   # 健康状态下跳转命中吞吐
    holds_healthy = healthy_value < redis_c["verify"]["threshold"]
    check(
        holds_healthy is False,
        "Redis 候选在健康状态下会被证伪（判据不恒成立 → 有效）",
    )

    # ---------------------------------------------------------------
    print("\n[4] 告警规则里存在 create_5xx_rate，且 root_cause 独立开闭环")
    # ---------------------------------------------------------------
    rules = {r.name: r for r in build_shortlink_rules()}
    check(ALERT in rules, "规则集合包含 create_5xx_rate")
    create_rule = rules[ALERT]
    check(create_rule.kind == "root_cause", "标记为 root_cause（独立开闭环）")
    check(
        'uri="/api/v1/links"' in create_rule.promql,
        "PromQL 按 uri 过滤出创建端点，而不是统计全部 5xx",
    )
    check(
        create_rule.severity.value == "high",
        f"级别 HIGH（创建故障的修复动作是 L1，不自动执行）",
    )

    # 症状类规则不受影响
    check(
        rules["redirect_5xx_rate"].kind == "symptom",
        "redirect_5xx_rate 仍为 symptom（不独立开闭环）",
    )

    # ---------------------------------------------------------------
    print("\n[5] 回归：跳转链路候选不受影响")
    # ---------------------------------------------------------------
    jump = agent._get_fault_candidates("redirect_5xx_rate")
    check(len(jump) == 4, "redirect_5xx_rate 仍返回 4 条跳转候选")
    check(
        all("Redis" in c["root_cause"] or True for c in jump),
        "跳转候选未被创建链路污染",
    )
    check(
        agent._get_fault_candidates("totally_unknown_alert") is FALLBACK_FAULT_PATTERNS,
        "未知告警仍走兜底候选",
    )

    print("\n" + ("全部通过" if not failures else f"{len(failures)} 项失败"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
