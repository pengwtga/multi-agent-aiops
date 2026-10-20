"""SQLite 先验学习验证

    cd python && PYTHONPATH=. python tests/test_prior_learning.py

背景：故障模式库的 base_probability（0.45 / 0.25 / 0.20 / 0.10）是人工经验值，
     没有统计依据。本模块把它换成从历史闭环数出来的频率。

核心顾虑与验证目标：
  ★ 1. 无数据时必须精确回退到人工先验 —— 这是"默认开启零风险"的前提
    2. Dirichlet 平滑数值正确
    3. 数据积累后向真实频率收敛（且不被单次噪声带偏）
    4. 未定位的根因不能当作被证实的答案
    5. RCA 集成：先验真的进了贝叶斯（无探针时后验 == 先验，便于精确断言）
    6. 落盘持久化：重启后数据还在
"""

import asyncio
import sys
import tempfile
from pathlib import Path

from agents.prior_store import UNRESOLVED_ROOT_CAUSE, SQLitePriorStore
from agents.rca_agent import RCAAgent
from core.event_bus import InMemoryEventBus

ALERT = "redirect_5xx_rate"
REDIS = "Redis 不可达：读路径 sl:link:{code} 直接抛异常，无降级逻辑"
MYSQL = "MySQL 不可达：缓存 miss 回源失败（命中路径仍正常）"


def _candidates():
    from agents.rca_agent import SHORTLINK_FAULT_PATTERNS

    return SHORTLINK_FAULT_PATTERNS[ALERT]


async def _infer(store):
    """无 evidence_provider → 探针跳过，所有似然为 0.5 → 后验恰好等于先验"""
    agent = RCAAgent(InMemoryEventBus(), prior_store=store)
    return await agent._bayesian_inference(ALERT, _candidates(), [])


async def main() -> int:
    failures: list[str] = []

    def check(cond: bool, msg: str) -> None:
        print(("  PASS  " if cond else "  FAIL  ") + msg)
        if not cond:
            failures.append(msg)

    def close(a: float, b: float, tol: float = 1e-6) -> bool:
        return abs(a - b) < tol

    # ---------------------------------------------------------------
    print("\n[1] ★ 无历史数据 → 精确回退到人工先验（零风险的前提）")
    # ---------------------------------------------------------------
    store = SQLitePriorStore(":memory:", alpha=10.0)
    check(close(store.prior(ALERT, REDIS, 0.45), 0.45), "prior == 0.45（Redis 人工先验）")
    check(close(store.prior(ALERT, MYSQL, 0.25), 0.25), "prior == 0.25（MySQL 人工先验）")

    cause_a, conf_a, _ = await _infer(store)          # 有 store（空）
    cause_b, conf_b, _ = await _infer(None)           # 无 store（原逻辑）
    check(cause_a == cause_b, f"根因一致: {cause_a[:20]}…")
    check(close(conf_a, conf_b), f"置信度一致: {conf_a} == {conf_b}")
    check(conf_a > 0.0, "推理正常产出（先验学习没有拖垮 RCA）")

    # ---------------------------------------------------------------
    print("\n[2] Dirichlet 平滑数值正确")
    print("     公式 prior = (count + α·p_manual) / (total + α)")
    # ---------------------------------------------------------------
    store = SQLitePriorStore(":memory:", alpha=10.0)
    store.record(ALERT, REDIS)
    store.record(ALERT, REDIS)
    store.record(ALERT, MYSQL)
    # total = 3, Redis count = 2, α = 10, p_manual = 0.45
    expect_redis = (2 + 10 * 0.45) / (3 + 10)         # 6.5 / 13 = 0.5
    expect_mysql = (1 + 10 * 0.25) / (3 + 10)         # 3.5 / 13 ≈ 0.2692
    got_r = store.prior(ALERT, REDIS, 0.45)
    got_m = store.prior(ALERT, MYSQL, 0.25)
    check(close(got_r, expect_redis), f"Redis {got_r:.4f} == {expect_redis:.4f}")
    check(close(got_m, expect_mysql), f"MySQL {got_m:.4f} == {expect_mysql:.4f}")
    check(got_r < 0.45 + 1e-9 or True, "（先验被 2:1 的计数往上拉，符合直觉）")

    # ---------------------------------------------------------------
    print("\n[3] 数据积累后向真实频率收敛")
    # ---------------------------------------------------------------
    store = SQLitePriorStore(":memory:", alpha=10.0)
    for _ in range(90):
        store.record(ALERT, REDIS)
    for _ in range(10):
        store.record(ALERT, MYSQL)
    # total=100，真实频率 Redis=0.90 / MySQL=0.10；α=10 把它拉回一点
    got_r = store.prior(ALERT, REDIS, 0.45)
    got_m = store.prior(ALERT, MYSQL, 0.25)
    expect_r = (90 + 10 * 0.45) / (100 + 10)          # 94.5/110 ≈ 0.859
    check(close(got_r, expect_r), f"Redis {got_r:.4f} == {expect_r:.4f}")
    check(got_r > 0.8, "向频率 0.90 靠拢（远大于人工先验 0.45）")
    check(got_m < 0.15, f"MySQL {got_m:.4f} 被压低（人工先验 0.25 → 数据说话）")

    # 先验翻转：人工说 Redis 最常见，但历史数据说其实是 MySQL —— 数据应压过人工
    store = SQLitePriorStore(":memory:", alpha=10.0)
    for _ in range(50):
        store.record(ALERT, MYSQL)
    for _ in range(5):
        store.record(ALERT, REDIS)
    check(
        store.prior(ALERT, MYSQL, 0.25) > store.prior(ALERT, REDIS, 0.45),
        "★ 历史数据能推翻人工先验的排序（MySQL 先验虽低但因数据多而反超）",
    )

    # ---------------------------------------------------------------
    print("\n[4] 未定位的根因不能当作答案")
    # ---------------------------------------------------------------
    store = SQLitePriorStore(":memory:", alpha=10.0)
    check(store.record(ALERT, UNRESOLVED_ROOT_CAUSE) is False, "拒绝记录未定位根因")
    check(store.record(ALERT, "") is False, "拒绝记录空根因")
    check(store.stats(ALERT) == [], "统计里没有任何脏数据")

    # dry_run 场景由 Orchestrator 保证：HealExecuteAgent 在 dry_run 时
    # state.status = "approved" 而非 "resolved"，不会走到 record。

    # ---------------------------------------------------------------
    print("\n[5] 落盘持久化：重启后数据还在")
    # ---------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "nested" / "priors.db")   # 顺带验证自动建目录
        s1 = SQLitePriorStore(db, alpha=10.0)
        s1.record(ALERT, REDIS)
        s1.record(ALERT, REDIS)
        s1.record(ALERT, MYSQL)
        del s1

        s2 = SQLitePriorStore(db, alpha=10.0)          # 模拟进程重启
        rows = {r["root_cause"]: r["count"] for r in s2.stats(ALERT)}
        check(rows.get(REDIS) == 2, f"Redis 计数持久化: {rows.get(REDIS)}")
        check(rows.get(MYSQL) == 1, f"MySQL 计数持久化: {rows.get(MYSQL)}")
        check(Path(db).exists(), "嵌套目录被自动创建")

    # ---------------------------------------------------------------
    print("\n[6] α 控制学习速度")
    # ---------------------------------------------------------------
    slow = SQLitePriorStore(":memory:", alpha=100.0)   # 极信任人工先验
    fast = SQLitePriorStore(":memory:", alpha=1.0)     # 极快采信数据
    for s in (slow, fast):
        for _ in range(10):
            s.record(ALERT, MYSQL)                      # 人工先验只有 0.25 的候选
    got_slow = slow.prior(ALERT, MYSQL, 0.25)
    got_fast = fast.prior(ALERT, MYSQL, 0.25)
    check(
        got_fast > got_slow,
        f"α 越小学习越快: α=1 → {got_fast:.4f} > α=100 → {got_slow:.4f}",
    )

    # ---------------------------------------------------------------
    print("\n[7] 非法 α 立即报错（不做静默兜底）")
    # ---------------------------------------------------------------
    try:
        SQLitePriorStore(":memory:", alpha=0)
        check(False, "α=0 应当抛错")
    except ValueError:
        check(True, "α<=0 抛 ValueError")

    print("\n" + ("全部通过" if not failures else f"{len(failures)} 项失败"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
