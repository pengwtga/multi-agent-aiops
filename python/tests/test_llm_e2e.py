"""LLM 证据源端到端验证（起一个假 OpenAI 端点，真链路，不需要 API key）

    cd python && PYTHONPATH=. python tests/test_llm_e2e.py

与 tests/test_llm_evidence.py 的区别：那边注入桩客户端，验证的是**融合逻辑**；
这边起一个本地假 OpenAI 服务，走真实的 HTTP 往返 + JSON 解析 + RCAAgent 推理，
验证的是**整条链路真的通了**，以及两条安全边界真的守住了。

验证清单：
  1. Prompt 真的发出去了（含告警名与候选名）
  2. 证据真的被采纳（置信度发生可观测变化）
  3. ★ 强度拉满也不过自愈闸门（低先验候选仍 < 0.3，不会误自愈）
  4. ★ 探针有结论时 LLM 不能翻盘（一手信号优先）
  5. 返回垃圾 / 服务异常 → 静默降级，根因照常产出
"""

import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from agents.llm_evidence import LLMEvidenceSource, OpenAICompatClient
from agents.rca_agent import RCAAgent
from core.event_bus import InMemoryEventBus
from models.events import AlertEvent, IncidentState, Severity

# 假服务收到的请求与要返回的“模型回答”
RECEIVED: list[dict] = []
REPLY: list[str] = ['{"evidence": []}']
FAIL_MODE = [""]


class FakeLLM(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        RECEIVED.append(body)
        if FAIL_MODE[0] == "garbage":
            content = "我觉得大概是 Redis 的问题吧（非 JSON）"
        elif FAIL_MODE[0] == "error":
            self.send_error(500, "boom")
            return
        else:
            content = REPLY[0]
        out = json.dumps(
            {"choices": [{"message": {"content": content}}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):
        pass


def start_fake_llm():
    srv = HTTPServer(("127.0.0.1", 0), FakeLLM)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def alert():
    return AlertEvent(
        alert_name="redirect_5xx_rate",
        severity=Severity.CRITICAL,
        source="prometheus",
        target_service="shortlink-app",
        metric_name="http_5xx_rate",
        metric_value=1.0,
        threshold=0.5,
    )


async def rca_with(port, reply, evidence_provider=None, fail=None):
    REPLY[0] = reply
    FAIL_MODE[0] = fail or ""
    bus = InMemoryEventBus()
    await bus.start()
    rca = RCAAgent(
        bus,
        evidence_provider=evidence_provider,
        llm_evidence=LLMEvidenceSource(
            OpenAICompatClient(
                api_key="sk-fake",
                base_url=f"http://127.0.0.1:{port}/v1",
                timeout=3,
            )
        ),
    )
    state = IncidentState()
    state.alert_event = alert()
    return await rca.handle(state)


# 无探针候选（「近期部署引入缺陷」先验仅 0.10），LLM 唯一能起作用的地方
NO_PROBE_CANDIDATE = [{
    "root_cause": "近期部署引入缺陷",
    "base_probability": 0.10,
    "evidence_pattern": "recent_deploy",
    "suggested_actions": ["check_dependency"],
}]


async def posterior_with_llm(rca, strength, support=True):
    """直接算后验：绕开故障模式库，精确控制先验与证据"""
    ev = {"近期部署引入缺陷": (support, strength)}
    cause, conf, _ = await rca._bayesian_inference(
        NO_PROBE_CANDIDATE, [], ev
    )
    return conf


async def main():
    srv, port = start_fake_llm()
    ok = 0
    total = 5

    # 1) Prompt 真的发出去了
    REPLY[0] = '{"evidence": []}'
    await rca_with(port, REPLY[0])
    sent = RECEIVED[-1]["messages"][-1]["content"] if RECEIVED else ""
    hit = "redirect_5xx_rate" in sent and "近期有变更" in sent
    print(f"[{'PASS' if hit else 'FAIL'}] 1 Prompt 已发出（含告警名与变更上下文）")
    ok += hit
    print(f"        Prompt 片段：{sent.splitlines()[0]}")

    # 2) 证据真的被采纳：置信度发生可观测变化
    base_rca = RCAAgent(InMemoryEventBus())
    base = await posterior_with_llm(base_rca, 0.0, support=False)  # 无 LLM
    lifted = await posterior_with_llm(base_rca, 1.0, support=True)  # 强度拉满支持
    changed = lifted > base
    print(
        f"[{'PASS' if changed else 'FAIL'}] 2 证据被采纳："
        f"置信度 {base:.3f} → {lifted:.3f}"
    )
    ok += changed

    # 3) ★ 强度拉满也不过闸门（0.3），不会误自愈
    #    先验 0.10 → 似然顶到 0.9 → 后验 0.18，仍 < 0.3
    safe = lifted < 0.3
    print(
        f"[{'PASS' if safe else 'FAIL'}] 3 强度拉满仍不过自愈闸门："
        f"{lifted:.3f} < 0.3（LLM 无法单独触发自愈）"
    )
    ok += safe

    # 4) ★ 探针有结论时 LLM 不能翻盘
    class Probe:
        async def query(self, promql: str):
            # 让 Redis 探针成立：吞吐归零
            return 0.0 if "redirect_total" in promql else 999.0

    reply = json.dumps({"evidence": [{
        "candidate": "Redis 不可达：读路径 sl:link:{code} 直接抛异常，无降级逻辑",
        "support": False,
        "strength": 1.0,
    }]}, ensure_ascii=False)
    st = await rca_with(port, reply, evidence_provider=Probe())
    won = "Redis" in st.rca_event.root_cause
    print(
        f"[{'PASS' if won else 'FAIL'}] 4 探针优先：LLM 反对(1.0) 未能翻盘 → "
        f"{st.rca_event.root_cause[:28]}… ({st.rca_event.confidence:.2f})"
    )
    ok += won

    # 5) 垃圾返回 / 服务异常 → 降级，根因照常产出
    st2 = await rca_with(port, REPLY[0], fail="garbage")
    st3 = await rca_with(port, REPLY[0], fail="error")
    degraded = (
        st2.rca_event is not None and st3.rca_event is not None
        and st3.rca_event.confidence >= 0
    )
    print(
        f"[{'PASS' if degraded else 'FAIL'}] 5 垃圾/异常返回静默降级："
        f"仍产出根因（{st2.rca_event.root_cause[:20]}…）"
    )
    ok += degraded

    srv.shutdown()
    print(f"\n通过 {ok}/{total}")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
