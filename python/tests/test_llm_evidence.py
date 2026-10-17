"""LLM 证据源验证（离线，注入桩客户端，不依赖真实 API）

    cd python && PYTHONPATH=. python tests/test_llm_evidence.py

验证的不是「LLM 聪不聪明」，而是它作为可选增强**不会把系统搞坏**：
  1. 默认关闭时完全不介入
  2. 调用失败 / 返回垃圾 → 静默降级，闭环不受影响
  3. 有效证据只修正「无探针」候选的似然，且被夹在 [0.05, 0.9]
  4. 一手信号（探针）优先：探针已有结论时 LLM 不能翻盘
  5. 模型自己编的候选名被挡掉
"""

import asyncio
import sys

from agents.llm_evidence import (
    LIKELIHOOD_CEILING,
    LIKELIHOOD_FLOOR,
    LLMEvidenceSource,
    blend_likelihood,
)
from agents.rca_agent import RCAAgent
from core.event_bus import InMemoryEventBus
from models.events import AlertEvent, IncidentState, Severity


class StubClient:
    """返回预设文本的桩客户端；raise_exc 用于模拟调用失败"""

    def __init__(self, reply: str = "", raise_exc: bool = False):
        self.reply = reply
        self.raise_exc = raise_exc
        self.calls = 0

    async def complete(self, system: str, user: str) -> str:
        self.calls += 1
        if self.raise_exc:
            raise TimeoutError("stub timeout")
        return self.reply


def reply(*items) -> str:
    import json

    return json.dumps({"evidence": list(items)}, ensure_ascii=False)


def alert() -> AlertEvent:
    return AlertEvent(
        alert_name="redirect_5xx_rate",
        severity=Severity.CRITICAL,
        source="prometheus",
        target_service="shortlink-app",
        metric_name="http_5xx_rate",
        metric_value=1.0,
        threshold=0.5,
    )


async def run(rca: RCAAgent) -> IncidentState:
    bus = InMemoryEventBus()
    await bus.start()
    rca._event_bus = bus
    state = IncidentState()
    state.alert_event = alert()
    return await rca.handle(state)


async def test_disabled_by_default():
    """未注入 LLM 证据源 → 与原来完全一致"""
    rca = RCAAgent(InMemoryEventBus())
    state = await run(rca)
    assert state.rca_event is not None
    assert not any(
        e["type"] == "llm_evidence" for e in state.rca_event.evidence
    ), "未启用时不该出现 LLM 证据"


async def test_failure_degrades_silently():
    """调用失败 → 降级为空证据，根因照常产出"""
    client = StubClient(raise_exc=True)
    rca = RCAAgent(InMemoryEventBus(), llm_evidence=LLMEvidenceSource(client))
    state = await run(rca)
    assert state.rca_event is not None, "LLM 挂了不能拖垮根因分析"
    assert client.calls == 1
    assert not any(
        e["type"] == "llm_evidence" for e in state.rca_event.evidence
    )


async def test_garbage_reply_ignored():
    """返回非 JSON → 忽略，不抛异常"""
    client = StubClient(reply="我觉得应该是 Redis 的问题吧，大概。")
    rca = RCAAgent(InMemoryEventBus(), llm_evidence=LLMEvidenceSource(client))
    state = await run(rca)
    assert state.rca_event is not None


async def test_unknown_candidate_rejected():
    """模型自己编的候选名必须被挡掉，否则会凭空多一个候选"""
    src = LLMEvidenceSource(
        StubClient(reply(reply_item := {
            "candidate": "机房断电了（模型编的）",
            "support": True,
            "strength": 0.9,
        }))
    )
    out = await src.collect(alert(), [{"root_cause": "近期部署引入缺陷"}], False)
    assert out == {}, f"未知候选应被过滤，实际: {out}"


async def test_evidence_applied_and_clamped():
    """有效证据被采纳，且融合结果夹在 [FLOOR, CEILING]"""
    src = LLMEvidenceSource(
        StubClient(
            reply({
                "candidate": "近期部署引入缺陷",
                "support": True,
                "strength": 1.0,
            })
        )
    )
    out = await src.collect(alert(), [{"root_cause": "近期部署引入缺陷"}], False)
    assert out == {"近期部署引入缺陷": (True, 1.0)}, out
    # 强度拉满：支持方顶到与探针「成立」同档，反对方也压不到下限以下
    assert blend_likelihood(0.5, True, 1.0) == LIKELIHOOD_CEILING, "支持上限"
    assert blend_likelihood(0.5, False, 1.0) > LIKELIHOOD_FLOOR, "反对下限"
    assert blend_likelihood(0.5, False, 1.0) < 0.5, "反对应低于中性值"
    assert blend_likelihood(0.5, True, 5.0) == LIKELIHOOD_CEILING, "越界强度裁剪"
    assert blend_likelihood(0.5, True, -3.0) == 0.5, "负强度视为无效果"


async def test_probe_wins_over_llm():
    """一手信号优先：探针证伪的候选，LLM 说支持也不能翻盘

    这是本设计的核心安全性质 —— 否则模型可以靠一句话让系统去重启容器。
    """
    class Probe:
        async def query(self, promql: str):
            return 999.0  # 让所有 gt/lt 判据都朝「不成立」走

    rca = RCAAgent(
        InMemoryEventBus(),
        evidence_provider=Probe(),
        llm_evidence=LLMEvidenceSource(
            StubClient(
                reply({
                    "candidate": "Redis 不可达：读路径 sl:link:{code} 直接抛异常，无降级逻辑",
                    "support": True,
                    "strength": 1.0,
                })
            )
        ),
    )
    state = await run(rca)
    # 探针已给出结论 → 不因 LLM 而变成该候选
    assert "Redis 不可达" not in state.rca_event.root_cause, (
        f"探针证伪后 LLM 不应翻盘，实际: {state.rca_event.root_cause}"
    )


async def main():
    cases = [
        ("A 默认关闭不介入", test_disabled_by_default),
        ("B 调用失败静默降级", test_failure_degrades_silently),
        ("C 非 JSON 返回被忽略", test_garbage_reply_ignored),
        ("D 模型编的候选被挡掉", test_unknown_candidate_rejected),
        ("E 证据被采纳且有上下限", test_evidence_applied_and_clamped),
        ("F 探针优先于 LLM（关键）", test_probe_wins_over_llm),
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
