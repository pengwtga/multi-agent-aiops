"""阶段 5：docker 执行器的安全护栏与动作映射验证

安全护栏是这个模块的核心，必须被证明：
- 只认 docker，且子命令走白名单
- 永远用 argv 列表、不用 shell → 注入串不进来
- dry_run 模式下不执行

离线运行：
    cd python && PYTHONPATH=. python tests/test_heal_docker.py
（涉及真实 docker 的用例在无 Docker 环境下自动跳过）
"""

import asyncio
import sys

from agents.heal_agent import (
    ALLOWED_DOCKER_SUBCOMMANDS,
    DockerExecutor,
    HealAgent,
    SHORTLINK_PLAYBOOKS,
)
from core.event_bus import InMemoryEventBus
from models.events import (
    AlertEvent,
    HealLevel,
    IncidentState,
    RCAEvent,
    Severity,
)


def _docker_available() -> bool:
    import shutil
    return shutil.which("docker") is not None


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
    agent = HealAgent(InMemoryEventBus())
    assert agent._select_best_action(["restart_redis", "check_dependency"]) == "restart_redis"
    assert agent._select_best_action(["restart_mysql", "check_dependency"]) == "restart_mysql"
    # RCA 给的动作都没有 playbook → 退回只读诊断
    assert agent._select_best_action(["totally_unknown_action"]) == "check_dependency"


async def test_dry_run_mode_does_not_execute():
    """dry_run=True 是默认值，必须只校验不执行"""
    bus = InMemoryEventBus()
    await bus.start()
    agent = HealAgent(bus, dry_run=True)

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
        suggested_actions=["restart_redis", "check_dependency"],
    )
    state = IncidentState()
    state.alert_event = alert
    state.rca_event = rca
    state = await agent.handle(state)

    heal = state.heal_event
    assert heal is not None
    assert heal.action_type == "restart_redis", heal.action_type
    assert heal.heal_level == HealLevel.L0_AUTO
    assert heal.execution_result is not None
    assert "未执行" in heal.execution_result, heal.execution_result
    assert "dry_run" in heal.execution_result


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
