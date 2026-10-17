"""Agent 编排器 — 基于状态机的多 Agent 工作流编排

核心设计（面试重点）：
1. 状态机模式：IncidentState 在 Agent 间流转，每个节点是一个 Agent
2. 条件路由：根据上一步结果决定下一步走向
3. 检查点恢复：每步完成后持久化状态，失败可从断点恢复
4. 重试机制：单个 Agent 失败自动重试，超过次数则跳过或上报

LangGraph 风格的图编排（简化实现，不强依赖 LangGraph 库）：
  Monitor → RCA → HealPropose → Change → HealExecute → End
              ↓         ↓           ↓           ↓
            (skip)    (skip)   (rejected →   (仅审批通过
                                 escalate)    且 L0 才执行)

阶段 5 修复：原来是 Monitor → RCA → Heal → Change，Heal 自己就执行了、
Change 事后补一条「审批通过」——审批不是闸门而是橡皮图章。
现在把自愈拆成「提议」与「执行」两段，审批夹在中间，真正决定要不要执行。

面试关键问答：
Q: "为什么不用简单的 Pipeline？为什么要状态机？"
A: Pipeline 是线性的，无法处理条件分支、重试、跳过、回退。
   状态机支持：
   - 条件路由（RCA 置信度低 → 重新分析）
   - 失败重试（Heal 执行失败 → 重试 3 次）
   - 人工介入（Change 被拒 → 不执行，转人工）
   - 检查点恢复（服务重启后从断点继续）
   Q: "审批和执行怎么保证顺序？"
   A: 靠图结构保证：heal_propose 只产出方案，change 做风险评分与审批，
   heal_execute 的入边条件是「已有审批且通过」。执行 Agent 内部还会再
   校验一次审批状态与级别 —— 即使有人改了图，也不会绕过闸门被执行。
"""

import asyncio
import logging
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional

from agents.base_agent import BaseAgent
from agents.monitor_agent import MonitorAgent
from agents.rca_agent import RCAAgent
from agents.heal_agent import (
    CircuitBreaker,
    HealExecuteAgent,
    HealProposeAgent,
)
from agents.change_agent import ChangeAgent
from core.event_bus import EventBus
from models.events import AgentType, IncidentState

logger = logging.getLogger(__name__)


class NodeStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class WorkflowNode:
    """工作流节点 — 封装一个 Agent 的执行"""

    def __init__(
        self,
        name: str,
        agent: BaseAgent,
        condition: Optional[Callable[[IncidentState], bool]] = None,
        max_retries: int = 3,
        skip_reason: Optional[str] = None,
    ):
        self.name = name
        self.agent = agent
        self.condition = condition
        self.skip_reason = skip_reason
        self.max_retries = max_retries
        self.status = NodeStatus.PENDING
        self.retry_count = 0
        # 跳过原因（人话），用于 Dashboard 在「已跳过」节点上说明为什么不跑。
        # 没有它，用户只能看到一排「已跳过/待执行」，却不知道是低置信度、
        # 审批未通过还是别的闸门拦下的。
        # 本次执行的开始/结束时刻与耗时（毫秒），供 Dashboard 展示节点运行时间。
        # 这是「本次闭环」的值：每次 run() 覆盖，reset_workflow() 清空。
        # 之所以要单独记，是因为 agent.get_metrics() 里的 avg_latency_ms
        # 是**跨所有历史调用**的累计均值，无法反映这一次的耗时。
        self.started_at: Optional[datetime] = None
        self.ended_at: Optional[datetime] = None
        self.duration_ms: float = 0.0

    def should_execute(self, state: IncidentState) -> bool:
        if self.condition is None:
            return True
        return self.condition(state)


class Orchestrator:
    """多 Agent 编排器

    实现了一个简化版的 LangGraph 状态机：
    - 节点 = Agent
    - 边 = 条件路由
    - 状态 = IncidentState
    """

    def __init__(
        self,
        event_bus: EventBus,
        evidence_provider=None,
        heal_dry_run: bool = True,
        heal_max_blast_radius: float = 0.5,
    ):
        self.event_bus = event_bus
        # 阶段 4：证据提供者（PrometheusClient）注入 RCAAgent，用于回查实测值证实/证伪候选根因
        self._evidence_provider = evidence_provider
        # 阶段 5：自愈执行的安全护栏（dry_run 默认开 = 只演练不执行）
        self._heal_dry_run = heal_dry_run
        self._heal_max_blast_radius = heal_max_blast_radius
        self._nodes: list[WorkflowNode] = []
        self._checkpoints: dict[str, IncidentState] = {}
        # 最近一次「有告警」闭环的节点状态快照。
        #
        # 为什么要单独存一份：self._nodes 是**全局共享**的，一轮监控里会跑
        # 多次 run()（规则层每规则一次 + 基线层每 series 一次），无告警的那
        # 次会把已完成节点重新置为 SKIPPED，把刚跑完的闭环结果冲掉。
        #
        # 这份快照只在「有告警」的闭环里更新，且在 run() 期间**逐节点**写入
        # ——于是 Dashboard 能看到流水线一个个亮起，而不是等自愈执行完
        # （这一节点要跑好几秒）才一次性刷新。
        self._last_alert_workflow: list[dict[str, Any]] = []
        self._build_default_workflow()

    def _build_default_workflow(self) -> None:
        """构建默认工作流：Monitor → RCA → HealPropose → Change → HealExecute"""
        monitor = MonitorAgent(self.event_bus)
        rca = RCAAgent(self.event_bus, evidence_provider=self._evidence_provider)
        change = ChangeAgent(self.event_bus)

        # 提议与执行共享同一个熔断器：否则两边各记一套失败计数，
        # 执行侧熔断了提议侧还在提议，状态会不一致
        self._heal_circuit_breaker = CircuitBreaker()
        heal_propose = HealProposeAgent(
            self.event_bus,
            max_blast_radius=self._heal_max_blast_radius,
            circuit_breaker=self._heal_circuit_breaker,
        )
        heal_execute = HealExecuteAgent(
            self.event_bus,
            dry_run=self._heal_dry_run,
            circuit_breaker=self._heal_circuit_breaker,
        )

        self._nodes = [
            WorkflowNode(
                name="monitor",
                agent=monitor,
                condition=None,  # 始终执行
            ),
            WorkflowNode(
                name="rca",
                agent=rca,
                condition=lambda s: s.alert_event is not None,
                skip_reason="本轮监控未触发告警",
            ),
            WorkflowNode(
                name="heal_propose",
                agent=heal_propose,
                condition=lambda s: (
                    s.rca_event is not None and s.rca_event.confidence >= 0.3
                ),
                skip_reason="根因置信度不足（< 0.3），证据不足不提议自愈",
            ),
            WorkflowNode(
                name="change",
                agent=change,
                condition=lambda s: s.heal_event is not None,
                skip_reason="没有待审批的自愈方案",
            ),
            WorkflowNode(
                name="heal_execute",
                agent=heal_execute,
                # 只有审批通过的才进入执行节点；未通过直接 SKIPPED，一目了然
                condition=lambda s: (
                    s.heal_event is not None
                    and s.change_event is not None
                    and s.change_event.approval_status == "approved"
                ),
                skip_reason="变更审批未通过，闸门未放行不执行",
            ),
        ]

    async def run(
        self,
        initial_state: Optional[IncidentState] = None,
        metadata: Optional[dict] = None,
    ) -> IncidentState:
        """执行完整的事件处理工作流"""
        state = initial_state or IncidentState()
        if metadata:
            state.metadata = metadata

        logger.info(f"[Orchestrator] Starting workflow for incident {state.incident_id}")

        # 先把所有节点清空为 pending：否则还没轮到的节点会残留**上一轮**
        # run() 留下的状态（无告警的轮次会把它置为 SKIPPED），前端就会看到
        # 尚未执行的节点显示「已跳过」。
        for node in self._nodes:
            node.status = NodeStatus.PENDING
            node.started_at = None
            node.ended_at = None
            node.duration_ms = 0.0

        for node in self._nodes:
            if not node.should_execute(state):
                node.status = NodeStatus.SKIPPED
                logger.info(
                    f"[Orchestrator] Skipping node: {node.name} "
                    f"({node.skip_reason or '条件不满足'})"
                )
                # 跳过也要发快照：否则被闸门拦下的节点在 Dashboard 上一直是
                # 「待执行」，看着像流水线卡在这一步不往下走（实测踩过：
                # 低置信度告警停在根因分析，后面三个节点永远「待执行」）。
                if state.alert_event is not None:
                    self._last_alert_workflow = self.get_workflow_status()
                continue

            node.status = NodeStatus.RUNNING
            node.started_at = datetime.utcnow()
            node.ended_at = None
            node.duration_ms = 0.0
            # 进入执行就发一次快照：否则耗时最长的节点（自愈执行要好几秒）
            # 在整个执行期间都停留在上一次快照的状态，用户看不到「执行中」，
            # 只能干等它跑完才跳成「已完成」。
            if state.alert_event is not None:
                self._last_alert_workflow = self.get_workflow_status()
            success = False

            while node.retry_count <= node.max_retries:
                try:
                    state = await node.agent.handle(state)

                    if state.error_message and node.retry_count < node.max_retries:
                        node.retry_count += 1
                        logger.warning(
                            f"[Orchestrator] Retrying {node.name} "
                            f"({node.retry_count}/{node.max_retries})"
                        )
                        state.error_message = None
                        continue

                    node.status = NodeStatus.COMPLETED
                    success = True
                    break

                except Exception as e:
                    node.retry_count += 1
                    logger.error(
                        f"[Orchestrator] Node {node.name} failed: {e} "
                        f"(retry {node.retry_count}/{node.max_retries})"
                    )
                    if node.retry_count > node.max_retries:
                        break

            if not success:
                node.status = NodeStatus.FAILED
                logger.error(f"[Orchestrator] Node {node.name} failed after {node.max_retries} retries")

            node.ended_at = datetime.utcnow()
            node.duration_ms = (
                (node.ended_at - node.started_at).total_seconds() * 1000
                if node.started_at
                else 0.0
            )

            # 有告警时逐节点发布进度：让 Dashboard 能看到流水线一个个亮起，
            # 而不是等自愈执行完（这一节点要跑好几秒）才一次性刷新。
            # 无告警的 run() 不动这份快照，避免把闭环结果冲成 SKIPPED。
            if state.alert_event is not None:
                self._last_alert_workflow = self.get_workflow_status()

            self._save_checkpoint(state)

        state.updated_at = datetime.utcnow()
        logger.info(
            f"[Orchestrator] Workflow completed: incident={state.incident_id} "
            f"status={state.status}"
        )

        return state

    def _save_checkpoint(self, state: IncidentState) -> None:
        self._checkpoints[state.incident_id] = state.model_copy(deep=True)

    def get_checkpoint(self, incident_id: str) -> Optional[IncidentState]:
        return self._checkpoints.get(incident_id)

    def clear_monitor_fingerprints(self) -> None:
        """清空 MonitorAgent 的告警去重缓存（供故障演练调用）

        演练是人为注入的**新故障事件**。若距上次告警不足 5 分钟，
        AlertFingerprint 会把它当成重复告警静默抑制 —— 表现就是
        「第一次点有反应，紧接着再点没反应」。因此注入前先清空窗口。

        这里用 duck typing 找 MonitorAgent，避免在编排器里多引一层 AgentType。
        """
        for node in self._nodes:
            agent = getattr(node, "agent", None)
            clearer = getattr(agent, "clear_alert_fingerprints", None)
            if callable(clearer):
                clearer()
                return

    def reset_workflow(self) -> None:
        """把流水线所有节点重置为 pending

        供故障演练调用：每次演练都是一轮**全新**的闭环，点下去时应该先把
        上次的流水线清空。否则旧结果会一直挂在页面上，和新一轮的进度混
        在一起，看不出这次到底跑到哪一步了。
        """
        for node in self._nodes:
            node.status = NodeStatus.PENDING
            node.retry_count = 0
            node.started_at = None
            node.ended_at = None
            node.duration_ms = 0.0
        self._last_alert_workflow = []

    def get_last_alert_workflow(self) -> list[dict[str, Any]]:
        """最近一次「有告警」闭环的节点状态快照

        与 get_workflow_status() 的区别：后者是**当前**节点状态，会被无告警
        的 run() 冲成 SKIPPED；这份只记录有告警的闭环，且保留到下一次闭环
        覆盖为止。Dashboard 优先读这份，才能看到节点逐个亮起。
        """
        return self._last_alert_workflow

    def get_workflow_status(self) -> list[dict[str, Any]]:
        return [
            {
                "name": node.name,
                "status": node.status.value,
                "agent_type": node.agent.agent_type.value,
                "retry_count": node.retry_count,
                "skip_reason": node.skip_reason,
                "duration_ms": round(node.duration_ms, 1),
                "started_at": (
                    node.started_at.isoformat() if node.started_at else None
                ),
                "ended_at": node.ended_at.isoformat() if node.ended_at else None,
                "metrics": node.agent.get_metrics(),
            }
            for node in self._nodes
        ]


async def run_demo():
    """演示运行：模拟一次完整的故障处理流程"""
    from core.event_bus import InMemoryEventBus

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    event_bus = InMemoryEventBus()
    await event_bus.start()

    orchestrator = Orchestrator(event_bus)

    state = await orchestrator.run()

    print("\n" + "=" * 60)
    print("  故障处理结果")
    print("=" * 60)
    print(f"  事件 ID:    {state.incident_id}")
    print(f"  状态:       {state.status}")

    if state.alert_event:
        print(f"\n  [告警]")
        print(f"    名称:     {state.alert_event.alert_name}")
        print(f"    严重度:   {state.alert_event.severity.value}")
        print(f"    服务:     {state.alert_event.target_service}")
        print(f"    指标值:   {state.alert_event.metric_value}")

    if state.rca_event:
        print(f"\n  [根因分析]")
        print(f"    根因:     {state.rca_event.root_cause}")
        print(f"    置信度:   {state.rca_event.confidence}")
        print(f"    影响链:   {' → '.join(state.rca_event.affected_services[:5])}")
        print(f"    建议动作: {', '.join(state.rca_event.suggested_actions)}")

    if state.heal_event:
        print(f"\n  [自愈]")
        print(f"    操作:     {state.heal_event.action_type}")
        print(f"    级别:     {state.heal_event.heal_level.value}")
        print(f"    爆炸半径: {state.heal_event.blast_radius:.2f}")
        print(f"    Dry-run:  {state.heal_event.dry_run_result}")
        if state.heal_event.execution_result:
            print(f"    执行结果: {state.heal_event.execution_result}")
        else:
            print(f"    执行结果: 未执行（状态 {state.status}）")

    if state.change_event:
        print(f"\n  [审批]")
        print(f"    状态:     {state.change_event.approval_status}")
        print(f"    风险分:   {state.change_event.risk_score}")
        print(f"    审批人:   {state.change_event.approver}")
        print(f"    原因:     {state.change_event.reason}")

    print("\n  [工作流节点状态]")
    for node_info in orchestrator.get_workflow_status():
        print(f"    {node_info['name']:12s} → {node_info['status']}")

    print("=" * 60)

    await event_bus.stop()
    return state


if __name__ == "__main__":
    asyncio.run(run_demo())
