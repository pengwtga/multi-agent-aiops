"""流水线起点 / 终点剪裁验证

    cd python && PYTHONPATH=. python tests/test_orchestrator_range.py

为什么需要这个能力：
  - start_node：告警已知的场景（手动注入）不必白跑一轮监控
  - end_node：演练时只出方案不执行，验证「提议 / 执行分离」这个设计

验证清单：
  1. start_node → 起点之前的节点不执行，且标记 SKIPPED
  2. end_node   → 终点之后的节点不执行，且标记 SKIPPED（不能停在 PENDING）
  3. 节点名不存在 → 忽略并走完整流程（否则会静默把整条流水线剪空）
  4. 不传参数 → 与改动前完全一致（回归）
  5. 起终点组合使用

节点用假 Agent 替换：这里验证的是**剪裁逻辑本身**，不依赖 Prometheus 或 docker。
"""

import asyncio
import sys

from core.event_bus import InMemoryEventBus
from core.orchestrator import NodeStatus, Orchestrator, WorkflowNode

NODE_NAMES = ("monitor", "rca", "heal_propose", "change", "heal_execute")


class RecordingAgent:
    """只记录调用次数、原样返回 state 的假 Agent"""

    def __init__(self, name: str):
        self.name = name
        self.calls = 0

    async def handle(self, state):
        self.calls += 1
        return state


def _build():
    """构造一个用假 Agent 填充的 Orchestrator（节点名与真实流水线一致）"""
    orch = Orchestrator(InMemoryEventBus())
    agents: dict[str, RecordingAgent] = {}
    nodes = []
    for name in NODE_NAMES:
        agent = RecordingAgent(name)
        agents[name] = agent
        nodes.append(WorkflowNode(name=name, agent=agent))
    orch._nodes = nodes
    return orch, agents


def _status(orch: Orchestrator, name: str) -> NodeStatus:
    return next(n.status for n in orch._nodes if n.name == name)


async def main() -> int:
    failures: list[str] = []

    def check(cond: bool, msg: str) -> None:
        print(("  PASS  " if cond else "  FAIL  ") + msg)
        if not cond:
            failures.append(msg)

    print("\n[1] start_node=rca → monitor 不执行且标记 SKIPPED")
    orch, agents = _build()
    await orch.run(start_node="rca")
    check(agents["monitor"].calls == 0, "monitor 未执行")
    check(_status(orch, "monitor") == NodeStatus.SKIPPED, "monitor 标记 SKIPPED")
    check(agents["rca"].calls == 1, "rca 执行了一次")
    check(
        "起点" in (orch._nodes[0].skip_reason or ""),
        f"monitor 的跳过原因说明是起点剪裁：{orch._nodes[0].skip_reason}",
    )

    print("\n[2] end_node=heal_propose → 后续节点不执行，且不是 PENDING")
    orch, agents = _build()
    await orch.run(end_node="heal_propose")
    check(agents["heal_propose"].calls == 1, "heal_propose 执行了一次")
    check(agents["change"].calls == 0, "change 未执行")
    check(agents["heal_execute"].calls == 0, "heal_execute 未执行")
    check(
        _status(orch, "change") == NodeStatus.SKIPPED,
        "change 标记 SKIPPED（不是 PENDING，否则 Dashboard 看着像卡住）",
    )
    check(
        _status(orch, "heal_execute") == NodeStatus.SKIPPED,
        "heal_execute 标记 SKIPPED",
    )

    print("\n[3] start_node 不存在 → 忽略，走完整流程（不能静默剪空）")
    orch, agents = _build()
    await orch.run(start_node="nonexistent")
    check(agents["monitor"].calls == 1, "monitor 照常执行")
    check(all(agents[n].calls == 1 for n in NODE_NAMES), "五个节点全部执行")

    print("\n[4] 回归：不传参数 → 行为与改动前一致")
    orch, agents = _build()
    await orch.run()
    check(all(agents[n].calls == 1 for n in NODE_NAMES), "五个节点各执行一次")

    print("\n[5] start_node=rca + end_node=change → 只跑中间三段")
    orch, agents = _build()
    await orch.run(start_node="rca", end_node="change")
    check(agents["monitor"].calls == 0, "monitor 未执行（在起点之前）")
    check(agents["rca"].calls == 1, "rca 执行")
    check(agents["change"].calls == 1, "change 执行")
    check(agents["heal_execute"].calls == 0, "heal_execute 未执行（在终点之后）")

    print("\n" + ("全部通过" if not failures else f"{len(failures)} 项失败"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
