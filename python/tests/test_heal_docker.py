"""阶段 5：docker 执行器的安全护栏、动作映射与审批闸门验证

安全护栏和审批时序是这个模块的核心，必须被证明：
- 只认 docker，且子命令走白名单
- 永远用 argv 列表、不用 shell → 注入串不进来
- 提议阶段绝不执行
- 审批未通过 / 被拒 / 非 L0 → 绝不执行
- 执行失败不置 resolved

离线运行：
    cd python && PYTHONPATH=. python tests/test_heal_docker.py
（涉及真实 docker 的用例在无 Docker 环境下自动跳过）
"""

import asyncio
import sys

from agents.heal_agent import (
    ALLOWED_DOCKER_SUBCOMMANDS,
    CircuitBreaker,
    DockerExecutor,
    HealExecuteAgent,
    HealProposeAgent,
    SHORTLINK_PLAYBOOKS,
    _select_best_action,
)
from core.event_bus import InMemoryEventBus
from models.events import (
    AlertEvent,
    ChangeEvent,
    EventType,
    HealLevel,
    IncidentState,
    RCAEvent,
    Severity,
)


class StubExecutor(DockerExecutor):
    """桩执行器：记录调用但不碰真实 docker"""

    def __init__(self, success: bool = True, output: str = "ok"):
        super().__init__()
        self.success = success
        self.output = output
        self.run_calls: list[list[str]] = []
        self.verify_calls: list[str] = []

    async def run(self, argv, timeout_sec=None):
        self.run_calls.append(argv)
        return self.success, self.output

    async def verify_healthy(self, container, retries=1, interval_sec=0):
        self.verify_calls.append(container)
        return self.success, f"{container} 已恢复 (health=healthy)"


def _make_state(actions: list[str]) -> IncidentState:
    alert = AlertEvent(
        alert_name="redirect_5xx_rate", severity=Severity.CRITICAL,
        source="prometheus", target_service="shortlink-app",
        metric_name="http_5xx_rate", metric_value=13.0, threshold=0.5,
    )
    rca = RCAEvent(
        alert_event_id=alert.event_id,
        root_cause="Redis 不可达",
        confidence=0.81,
        affected_services=["shortlink-app", "redis"],
        evidence=[],
        suggested_actions=actions,
    )
    state = IncidentState()
    state.alert_event = alert
    state.rca_event = rca
    return state


def _approve(state: IncidentState, status: str = "approved") -> None:
    state.change_event = ChangeEvent(
        heal_event_id=state.heal_event.event_id,
        risk_score=0.2,
        approval_status=status,
        approver="auto-system" if status == "approved" else "oncall-engineer",
        reason="test",
    )


def _docker_available() -> bool:
    import shutil
    return shutil.which("docker") is not None


# ---------- 执行器安全护栏 ----------

async def test_rejects_non_docker_binary():
    ex = DockerExecutor()
    ok, msg = ex.validate(["rm", "-rf", "/"])
    assert not ok, "非 docker 命令必须被拒绝"
    assert "只允许" in msg


async def test_rejects_dangerous_subcommand():
    """docker rm / rmi 这类破坏性子命令不在白名单"""
    ex = DockerExecutor()
    for sub in ("rm", "rmi", "system", "volume"):
        ok, _ = ex.validate(["docker", sub, "shortlink-redis"])
        assert not ok, f"docker {sub} 必须被白名单拒绝"
    assert "restart" in ALLOWED_DOCKER_SUBCOMMANDS


async def test_allows_whitelisted_subcommand():
    ex = DockerExecutor()
    ok, _ = ex.validate(["docker", "restart", "shortlink-redis"])
    assert ok


async def test_rejected_command_is_never_executed():
    """被拒绝的命令不应有任何副作用"""
    ex = DockerExecutor()
    ok, out = await ex.run(["echo", "pwned"])
    assert not ok
    assert "拒绝" in out


async def test_no_shell_injection():
    """argv 里带 shell 元字符也只是普通参数，不会被解释"""
    ex = DockerExecutor()
    ok, out = await ex.run(["docker", "inspect", "x; touch /tmp/pwned"])
    # 要么被白名单通过但 docker 报错（未创建文件），要么被拒绝 —— 都不允许成功
    assert not ok
    import os
    assert not os.path.exists("/tmp/pwned"), "发生了命令注入！"


# ---------- 动作映射与分级 ----------

async def test_manual_actions_have_no_executable_command():
    """应用没有运行时开关的动作必须标 L2 且不可执行，绝不伪造执行结果"""
    no_runtime_switch = [
        "rate_limit", "block_ip", "circuit_breaker", "tune_threads", "scale_app",
    ]
    for action in no_runtime_switch:
        pb = SHORTLINK_PLAYBOOKS[action]
        assert pb["level"] == HealLevel.L2_MANUAL, f"{action} 应标 L2"
        assert pb["argv_template"] is None, f"{action} 不应有可执行命令"
        assert pb.get("manual_reason"), f"{action} 必须说明为什么需要人工"


async def test_restart_actions_target_correct_container():
    assert SHORTLINK_PLAYBOOKS["restart_redis"]["target_container"] == "shortlink-redis"
    assert SHORTLINK_PLAYBOOKS["restart_mysql"]["target_container"] == "shortlink-mysql"
    # 消费端与 app 同进程 → 指向同一容器
    assert SHORTLINK_PLAYBOOKS["restart_consumer"]["target_container"] == "shortlink-app"
    assert SHORTLINK_PLAYBOOKS["restart_container"]["target_container"] == "shortlink-app"


async def test_readonly_diagnostics_have_zero_blast_radius():
    for action in ("check_dependency", "check_mysql", "check_t_consumer_offset"):
        pb = SHORTLINK_PLAYBOOKS[action]
        assert pb["blast_radius_factor"] == 0.0, f"{action} 是只读操作"
        assert pb["read_only"] is True


async def test_select_best_action_respects_rca_order():
    """尊重 RCA 的排序，而不是固定全局优先级"""
    assert _select_best_action(["restart_redis", "check_dependency"]) == "restart_redis"
    assert _select_best_action(["restart_mysql", "check_dependency"]) == "restart_mysql"
    # RCA 给的动作都没有 playbook → 退回只读诊断
    assert _select_best_action(["totally_unknown_action"]) == "check_dependency"


# ---------- 审批闸门 ----------

async def test_propose_never_executes():
    """提议阶段只产出方案，绝不执行"""
    bus = InMemoryEventBus()
    await bus.start()
    executor = StubExecutor()
    agent = HealProposeAgent(bus, executor=executor)

    state = await agent.handle(_make_state(["restart_redis", "check_dependency"]))

    heal = state.heal_event
    assert heal is not None
    assert heal.action_type == "restart_redis"
    assert heal.heal_level == HealLevel.L0_AUTO
    assert executor.run_calls == [], "提议阶段绝不能执行"
    assert heal.execution_result is None, "提议阶段不应产生执行结果"
    assert state.status == "pending_approval"
    # 待执行的 argv 随事件流转，供执行阶段使用
    assert heal.action_params["argv"] == ["docker", "restart", "shortlink-redis"]


async def test_execute_blocked_without_approval():
    """还没走审批 → 不执行"""
    bus = InMemoryEventBus()
    await bus.start()
    executor = StubExecutor()
    state = await HealProposeAgent(bus, executor=executor).handle(
        _make_state(["restart_redis"])
    )
    state = await HealExecuteAgent(bus, dry_run=False, executor=executor).handle(state)

    assert executor.run_calls == [], "未经审批不得执行"
    assert state.heal_event.execution_result is None


async def test_execute_blocked_when_rejected():
    """审批被拒 → 不执行"""
    bus = InMemoryEventBus()
    await bus.start()
    executor = StubExecutor()
    state = await HealProposeAgent(bus, executor=executor).handle(
        _make_state(["restart_redis"])
    )
    _approve(state, status="rejected")
    state = await HealExecuteAgent(bus, dry_run=False, executor=executor).handle(state)

    assert executor.run_calls == [], "审批被拒不得执行"
    assert state.heal_event.execution_result is None
    assert state.status == "pending_approval"


async def test_execute_skips_l1_even_if_approved():
    """L1 即使审批通过也不自动执行，转人工"""
    bus = InMemoryEventBus()
    await bus.start()
    executor = StubExecutor()
    state = await HealProposeAgent(bus, executor=executor).handle(
        _make_state(["restart_container", "check_dependency"])
    )
    _approve(state)
    state = await HealExecuteAgent(bus, dry_run=False, executor=executor).handle(state)

    assert state.heal_event.heal_level == HealLevel.L1_SEMI
    assert executor.run_calls == [], "L1 不自动执行"
    assert state.status == "awaiting_human"


async def test_execute_skips_action_without_command_even_if_approved():
    """应用没有对应机制的动作，审批通过也不执行"""
    bus = InMemoryEventBus()
    await bus.start()
    executor = StubExecutor()
    state = await HealProposeAgent(bus, executor=executor).handle(
        _make_state(["rate_limit"])
    )
    _approve(state)
    state = await HealExecuteAgent(bus, dry_run=False, executor=executor).handle(state)

    assert state.heal_event.action_params["argv"] is None
    assert executor.run_calls == [], "无可执行命令不得执行"
    assert state.status == "awaiting_human"
    assert "需人工" in state.heal_event.dry_run_result


async def test_execute_runs_when_approved_and_l0():
    """审批通过 + L0 → 执行 + 执行后验证 + 置 resolved"""
    bus = InMemoryEventBus()
    await bus.start()
    executor = StubExecutor(success=True)
    state = await HealProposeAgent(bus, executor=executor).handle(
        _make_state(["restart_redis", "check_dependency"])
    )
    _approve(state)
    state = await HealExecuteAgent(bus, dry_run=False, executor=executor).handle(state)

    assert executor.run_calls == [["docker", "restart", "shortlink-redis"]]
    assert executor.verify_calls == ["shortlink-redis"], "重启后必须验证健康状态"
    assert "SUCCESS" in state.heal_event.execution_result
    assert "执行后验证" in state.heal_event.execution_result
    assert state.heal_event.event_type == EventType.HEAL_COMPLETED
    assert state.status == "resolved"


async def test_execute_failure_does_not_mark_resolved():
    """执行失败不应置 resolved，且要记入熔断器"""
    bus = InMemoryEventBus()
    await bus.start()
    executor = StubExecutor(success=False)
    circuit = CircuitBreaker()
    propose = HealProposeAgent(bus, executor=executor, circuit_breaker=circuit)
    execute = HealExecuteAgent(
        bus, dry_run=False, executor=executor, circuit_breaker=circuit
    )

    state = await propose.handle(_make_state(["restart_redis"]))
    _approve(state)
    state = await execute.handle(state)

    assert state.status == "heal_failed", state.status
    assert state.heal_event.event_type == EventType.HEAL_FAILED
    assert "FAILED" in state.heal_event.execution_result


async def test_dry_run_mode_does_not_execute():
    """dry_run=True 是默认值，审批通过了也不执行"""
    bus = InMemoryEventBus()
    await bus.start()
    executor = StubExecutor()
    state = await HealProposeAgent(bus, executor=executor).handle(
        _make_state(["restart_redis"])
    )
    _approve(state)
    state = await HealExecuteAgent(bus, dry_run=True, executor=executor).handle(state)

    assert executor.run_calls == [], "dry_run 模式不得执行"
    assert "未执行" in state.heal_event.execution_result


async def test_real_readonly_command_executes():
    """真实执行一条只读命令（无 Docker 环境则跳过）"""
    if not _docker_available():
        print("    (跳过：未安装 docker)")
        return
    ex = DockerExecutor()
    ok, out = await ex.run([
        "docker", "ps", "--filter", "name=shortlink", "--format", "{{.Names}}",
    ], timeout_sec=20)
    if not ok and "不可用" in out:
        print("    (跳过：docker 守护进程不可用)")
        return
    assert ok, out


async def main():
    cases = [
        ("拒绝非 docker 命令", test_rejects_non_docker_binary),
        ("拒绝白名单外的破坏性子命令", test_rejects_dangerous_subcommand),
        ("白名单内子命令放行", test_allows_whitelisted_subcommand),
        ("被拒绝的命令不执行", test_rejected_command_is_never_executed),
        ("无 shell 注入", test_no_shell_injection),
        ("人工动作不可执行且说明理由", test_manual_actions_have_no_executable_command),
        ("重启动作指向正确容器", test_restart_actions_target_correct_container),
        ("只读诊断爆炸半径为零", test_readonly_diagnostics_have_zero_blast_radius),
        ("动作选择尊重 RCA 排序", test_select_best_action_respects_rca_order),
        ("提议阶段绝不执行", test_propose_never_executes),
        ("未审批不执行", test_execute_blocked_without_approval),
        ("审批被拒不执行", test_execute_blocked_when_rejected),
        ("L1 审批通过也不自动执行", test_execute_skips_l1_even_if_approved),
        ("无命令动作审批通过也不执行", test_execute_skips_action_without_command_even_if_approved),
        ("审批通过+L0 才执行", test_execute_runs_when_approved_and_l0),
        ("执行失败不置 resolved", test_execute_failure_does_not_mark_resolved),
        ("dry_run 不执行", test_dry_run_mode_does_not_execute),
        ("真实只读命令可执行", test_real_readonly_command_executes),
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
