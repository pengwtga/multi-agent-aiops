"""故障自愈 Agent — 修复方案匹配 + 安全执行 + 执行后验证

核心功能：
1. 根据 RCA 结果匹配最佳修复方案
2. 分级自愈策略：L0（全自动）/ L1（半自动）/ L2（人工）
3. 安全护栏：dry-run 校验 → 爆炸半径评估 → 熔断器检查 → 执行 → 执行后验证
4. 执行后验证：重启类动作确认容器回到 healthy

面试重点：
- 为什么要分级？→ 不同风险的操作需要不同级别的审批
- dry-run 怎么实现？→ 校验命令合法性但不实际变更
- 熔断器模式？→ 连续失败 N 次后暂停自动修复，避免雪崩
- 爆炸半径怎么算？→ 受影响实例数 / 总实例数

阶段 5 二次开发（面向短链平台）：
- 修复方案库从 K8s 命令换成 docker compose 部署的真实命令
- 新增 DockerExecutor：真实执行，带命令白名单、超时、无 shell（杜绝注入）
- 执行后验证：重启类动作后用 docker inspect 确认容器回到 healthy

**分级原则（重要）**：只有「幂等 + 可验证 + 影响可控」的动作才允许 L0 自动执行。
短链应用本身不提供运行时开关的动作（限流阈值、熔断、IP 黑名单、线程池参数）
一律标 L2 人工 —— 宁可只提建议，也不伪造一个执行结果。
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Optional

from agents.base_agent import BaseAgent
from core.event_bus import EventBus
from models.events import (
    AgentType,
    EventType,
    HealEvent,
    HealLevel,
    IncidentState,
)

logger = logging.getLogger(__name__)


# 短链平台容器名（docker compose 里写死了 container_name）
# 消费端 click-consumer 与 shortlink-app 同进程，故指向同一容器
SHORTLINK_CONTAINERS = {
    "shortlink-app": "shortlink-app",
    "click-consumer": "shortlink-app",
    "mysql": "shortlink-mysql",
    "redis": "shortlink-redis",
    "kafka": "shortlink-kafka",
}

# 命令白名单：只允许这些 docker 子命令，且永远不走 shell
ALLOWED_DOCKER_SUBCOMMANDS = {
    "restart", "start", "exec", "inspect", "ps", "logs", "compose",
}


def _diag(level: HealLevel, description: str, argv: list[str], **kw) -> dict:
    """构造一个只读诊断动作"""
    return {
        "level": level,
        "description": description,
        "argv_template": argv,
        "target_container": kw.get("target_container"),
        "estimated_duration_sec": kw.get("estimated_duration_sec", 5),
        "blast_radius_factor": 0.0,      # 只读操作无爆炸半径
        "read_only": True,
        "verify_container": None,
    }


def _manual(description: str, reason: str, **kw) -> dict:
    """构造一个「必须由人来做」的动作。

    argv_template 为 None —— 表示本系统没有能力执行它，只提建议。
    这是刻意的设计：应用没有对应的运行时开关时，绝不伪造执行结果。
    """
    return {
        "level": HealLevel.L2_MANUAL,
        "description": description,
        "argv_template": None,
        "target_container": None,
        "estimated_duration_sec": kw.get("estimated_duration_sec", 0),
        "blast_radius_factor": kw.get("blast_radius_factor", 0.0),
        "read_only": True,
        "verify_container": None,
        "manual_reason": reason,
    }


# 短链平台修复方案库（替代原 K8s playbook）
SHORTLINK_PLAYBOOKS: dict[str, dict[str, Any]] = {
    # ---- 可自动执行（L0）：幂等、可验证、影响可控 ----
    "restart_redis": {
        "level": HealLevel.L0_AUTO,
        "description": "重启 Redis 容器（短链跳转的缓存与限流都依赖它）",
        "argv_template": ["docker", "restart", "{container}"],
        "target_container": SHORTLINK_CONTAINERS["redis"],
        "estimated_duration_sec": 15,
        "blast_radius_factor": 0.25,
        "read_only": False,
        "verify_container": SHORTLINK_CONTAINERS["redis"],
    },
    # 只读诊断优先，风险为零且能给出真实信息
    "check_dependency": _diag(
        HealLevel.L0_AUTO,
        "列出短链相关容器的运行状态（只读诊断）",
        ["docker", "ps", "--filter", "name=shortlink",
         "--format", "{{.Names}}: {{.Status}}"],
    ),
    "check_mysql": _diag(
        HealLevel.L0_AUTO,
        "检查 MySQL 容器健康状态（只读诊断）",
        ["docker", "inspect", "--format", "{{.State.Health.Status}}",
         SHORTLINK_CONTAINERS["mysql"]],
    ),
    "check_t_consumer_offset": _diag(
        HealLevel.L0_AUTO,
        "查询消费位点表 t_consumer_offset（只读诊断）",
        ["docker", "exec", SHORTLINK_CONTAINERS["mysql"], "mysql",
         "-uroot", "-p${DB_PASSWORD}", "-D", "shortlink", "-e",
         "SELECT partition_id, topic_offset FROM t_consumer_offset"],
    ),

    # ---- 半自动（L1）：影响较大，需人确认 ----
    "restart_container": {
        "level": HealLevel.L1_SEMI,
        "description": "重启短链应用容器（会中断在途请求）",
        "argv_template": ["docker", "restart", "{container}"],
        "target_container": SHORTLINK_CONTAINERS["shortlink-app"],
        "estimated_duration_sec": 40,
        "blast_radius_factor": 0.35,
        "read_only": False,
        "verify_container": SHORTLINK_CONTAINERS["shortlink-app"],
    },
    "restart_consumer": {
        "level": HealLevel.L1_SEMI,
        "description": "重启消费端（与 shortlink-app 同进程，实为重启应用）",
        "argv_template": ["docker", "restart", "{container}"],
        "target_container": SHORTLINK_CONTAINERS["click-consumer"],
        "estimated_duration_sec": 40,
        "blast_radius_factor": 0.35,
        "read_only": False,
        "verify_container": SHORTLINK_CONTAINERS["click-consumer"],
    },
    "restart_mysql": {
        "level": HealLevel.L1_SEMI,
        "description": "重启 MySQL 容器（影响写入，需确认）",
        "argv_template": ["docker", "restart", "{container}"],
        "target_container": SHORTLINK_CONTAINERS["mysql"],
        "estimated_duration_sec": 60,
        "blast_radius_factor": 0.45,
        "read_only": False,
        "verify_container": SHORTLINK_CONTAINERS["mysql"],
    },

    # ---- 人工（L2）：本系统不执行 ----
    "scale_app": _manual(
        "水平扩容短链应用",
        "扩容必须人工：雪花 ID 的 SHORTLINK_WORKER_ID 需每实例唯一，"
        "自动扩容会导致发号碰撞（重复短码）",
        blast_radius_factor=0.2,
    ),
    "rate_limit": _manual(
        "调整限流阈值",
        "短链的限流是 Redis + Lua 固定窗口，阈值写死在代码/配置里，"
        "无运行时开关，改阈值需改配置并重启",
    ),
    "block_ip": _manual(
        "封禁来源 IP",
        "短链应用没有实现 IP 黑名单机制，需人工介入",
    ),
    "circuit_breaker": _manual(
        "开启熔断器",
        "短链应用没有实现熔断机制（读 Redis 失败会直接抛异常），需人工介入",
    ),
    "tune_threads": _manual(
        "调整 Tomcat 线程池参数",
        "需改配置并重启应用",
    ),
    "heap_dump": _manual(
        "执行堆转储分析",
        "jmap 会 STW 且产出大文件，需人工评估时机",
        blast_radius_factor=0.05,
    ),
    "rollback": _manual("回滚到上一个稳定版本", "需人工确认版本与影响"),
    "rollback_config": _manual("回滚配置变更", "需人工确认配置基线"),
    "review_change": _manual("人工复核近期变更", "需人工排查发布记录"),
    "review_config": _manual("人工复核配置", "需人工核对配置基线"),
}

# 兼容旧名
REMEDIATION_PLAYBOOKS = SHORTLINK_PLAYBOOKS


class DockerExecutor:
    """docker 命令执行器

    安全设计：
    - 只接受 argv 列表，永远不用 shell=True → 杜绝命令注入
    - 子命令白名单 → 无法借道执行任意 docker 操作
    - 超时强制 kill → 避免挂死（短链 Redis 故障的教训：命令也会挂）
    """

    def __init__(
        self,
        docker_bin: str = "docker",
        allowed_subcommands: Optional[set] = None,
        default_timeout_sec: int = 60,
    ):
        self._docker_bin = docker_bin
        self._allowed = allowed_subcommands or ALLOWED_DOCKER_SUBCOMMANDS
        self._default_timeout = default_timeout_sec

    def validate(self, argv: list[str]) -> tuple[bool, str]:
        """命令合法性校验（dry-run 阶段调用）"""
        if not argv:
            return False, "空命令"
        if argv[0] != self._docker_bin:
            return False, f"只允许执行 {self._docker_bin}，收到 {argv[0]}"
        if len(argv) < 2:
            return False, "缺少子命令"
        if argv[1] not in self._allowed:
            return False, f"子命令 {argv[1]} 不在白名单 {sorted(self._allowed)}"
        return True, "OK"

    async def run(
        self, argv: list[str], timeout_sec: Optional[int] = None
    ) -> tuple[bool, str]:
        """执行命令，返回 (是否成功, 输出)"""
        ok, reason = self.validate(argv)
        if not ok:
            return False, f"命令被拒绝: {reason}"

        timeout = timeout_sec or self._default_timeout
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return False, f"执行超时（{timeout}s），已终止"
        except FileNotFoundError:
            return False, f"{self._docker_bin} 不可用（未安装或不在 PATH）"
        except Exception as e:  # noqa: BLE001
            return False, f"执行异常: {type(e).__name__}: {e}"

        output = (stdout or b"").decode("utf-8", errors="replace").strip()
        success = proc.returncode == 0
        return success, output or f"(无输出, returncode={proc.returncode})"

    async def verify_healthy(
        self, container: str, retries: int = 6, interval_sec: int = 5
    ) -> tuple[bool, str]:
        """执行后验证：轮询容器健康状态

        inspect 同时取 Running 与 Health.Status：
        没有配 healthcheck 的容器 Health.Status 为空，此时退化为只判断 Running。
        """
        argv = [
            self._docker_bin, "inspect", "--format",
            "{{.State.Running}}|{{.State.Health.Status}}", container,
        ]
        last = ""
        for _ in range(retries):
            ok, out = await self.run(argv, timeout_sec=15)
            last = out
            if not ok:
                await asyncio.sleep(interval_sec)
                continue
            running, _, health = out.partition("|")
            if running.strip() == "true" and health.strip() in ("", "healthy"):
                return True, f"{container} 已恢复 (health={health.strip() or 'n/a'})"
            await asyncio.sleep(interval_sec)
        return False, f"{container} 未恢复健康，最后一次状态: {last}"


class CircuitBreaker:
    """熔断器模式

    面试要点：
    - CLOSED → 正常状态，失败计数
    - OPEN → 熔断状态，拒绝所有请求
    - HALF_OPEN → 试探状态，允许少量请求通过
    """

    def __init__(self, threshold: int = 5, timeout_sec: int = 60):
        self._threshold = threshold
        self._timeout = timedelta(seconds=timeout_sec)
        self._failure_count = 0
        self._last_failure_time: Optional[datetime] = None
        self._state = "CLOSED"

    def allow_request(self) -> bool:
        if self._state == "CLOSED":
            return True
        if self._state == "OPEN":
            if datetime.utcnow() - self._last_failure_time >= self._timeout:
                self._state = "HALF_OPEN"
                return True
            return False
        return True  # HALF_OPEN

    def record_success(self) -> None:
        self._failure_count = 0
        self._state = "CLOSED"

    def record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = datetime.utcnow()
        if self._failure_count >= self._threshold:
            self._state = "OPEN"
            logger.warning("[CircuitBreaker] Circuit OPEN — auto-heal suspended")

    @property
    def state(self) -> str:
        return self._state


class HealAgent(BaseAgent):
    """故障自愈 Agent"""

    def __init__(
        self,
        event_bus: EventBus,
        dry_run: bool = True,
        max_blast_radius: float = 0.5,
        executor: Optional[DockerExecutor] = None,
    ):
        super().__init__(AgentType.HEAL, event_bus, "HealAgent")
        # dry_run=True 时只校验命令、不执行（安全默认）
        self._dry_run = dry_run
        self._max_blast_radius = max_blast_radius
        self._circuit_breaker = CircuitBreaker()
        self._executor = executor or DockerExecutor()

    async def process(self, state: IncidentState) -> IncidentState:
        rca = state.rca_event
        if not rca:
            logger.warning("[HealAgent] No RCA result to act on")
            return state

        if not self._circuit_breaker.allow_request():
            logger.warning("[HealAgent] Circuit breaker OPEN, skipping auto-heal")
            state.error_message = "Circuit breaker is open, auto-heal suspended"
            return state

        action_type = self._select_best_action(rca.suggested_actions)
        playbook = SHORTLINK_PLAYBOOKS.get(action_type)
        if not playbook:
            logger.warning(f"[HealAgent] No playbook for action: {action_type}")
            return state

        blast_radius = playbook["blast_radius_factor"]
        playbook_level = playbook["level"]
        if blast_radius > self._max_blast_radius:
            logger.warning(
                f"[HealAgent] Blast radius {blast_radius} exceeds "
                f"max {self._max_blast_radius} → 降级为人工"
            )
            playbook_level = HealLevel.L2_MANUAL

        argv = self._render_argv(playbook)
        dry_run_result = None
        execution_result = None
        event_type = EventType.HEAL_PROPOSED

        if argv is None:
            # 本系统没有能力执行 → 明确说明理由，不伪造执行
            dry_run_result = f"本系统不执行该动作，需人工：{playbook.get('manual_reason', '无对应执行能力')}"
            logger.info(f"[HealAgent] 需人工处理: {action_type} — {playbook['description']}")
        else:
            dry_ok, dry_msg = self._executor.validate(argv)
            dry_run_result = f"DRY-RUN {'OK' if dry_ok else 'REJECTED'}: {' '.join(argv)} — {dry_msg}"
            logger.info(f"[HealAgent] DRY-RUN: {' '.join(argv)}")

            if dry_ok and playbook_level == HealLevel.L0_AUTO and not self._dry_run:
                ok, out = await self._executor.run(
                    argv, timeout_sec=playbook.get("estimated_duration_sec", 60) * 3
                )
                execution_result = f"{'SUCCESS' if ok else 'FAILED'}: {out}"

                verify_container = playbook.get("verify_container")
                if ok and verify_container:
                    v_ok, v_out = await self._executor.verify_healthy(verify_container)
                    execution_result += f" | 执行后验证: {v_out}"
                    ok = v_ok

                logger.info(f"[HealAgent] 执行结果: {execution_result}")

                if ok:
                    self._circuit_breaker.record_success()
                    event_type = EventType.HEAL_COMPLETED
                else:
                    self._circuit_breaker.record_failure()
                    event_type = EventType.HEAL_FAILED
            elif dry_ok and playbook_level == HealLevel.L0_AUTO and self._dry_run:
                execution_result = "未执行：dry_run 模式（AIOPS_HEAL_DRY_RUN=false 可开启真实执行）"

        target_service = (
            state.alert_event.target_service if state.alert_event else "unknown"
        )

        heal_event = HealEvent(
            rca_event_id=rca.event_id,
            heal_level=playbook_level,
            action_type=action_type,
            action_params={
                "command": " ".join(argv) if argv else None,
                "service": target_service,
                "container": playbook.get("target_container"),
                "read_only": bool(playbook.get("read_only")),
                "manual_reason": playbook.get("manual_reason"),
                "estimated_duration_sec": playbook["estimated_duration_sec"],
            },
            target_service=target_service,
            estimated_impact=playbook["description"],
            blast_radius=blast_radius,
            dry_run_result=dry_run_result,
            execution_result=execution_result,
            correlation_id=state.incident_id,
        )
        heal_event.event_type = event_type

        state.heal_event = heal_event
        state.status = "healing"

        await self.event_bus.publish("aiops.commands", heal_event)

        logger.info(
            f"[HealAgent] Action: {action_type} [{playbook_level.value}] "
            f"blast_radius={blast_radius:.2f} container={playbook.get('target_container')}"
        )
        return state

    def _select_best_action(self, suggested_actions: list[str]) -> str:
        """选择修复方案

        尊重 RCA 的排序：suggested_actions 是有序的（首选动作在前），
        取第一个本系统有 playbook 的动作。原实现用固定的全局优先级，
        会忽略 RCA 的判断（曾把 Redis 故障选成 rate_limit）。
        """
        for action in suggested_actions or []:
            if action in SHORTLINK_PLAYBOOKS:
                return action
        # RCA 给的动作一个都没有 playbook → 退回只读诊断，至少产出真实信息
        return "check_dependency"

    def _render_argv(self, playbook: dict[str, Any]) -> Optional[list[str]]:
        """渲染命令 argv；playbook 不可执行时返回 None"""
        template = playbook.get("argv_template")
        if not template:
            return None
        container = playbook.get("target_container") or ""
        return [part.replace("{container}", container) for part in template]
