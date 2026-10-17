"""LLM 证据源：给贝叶斯推理补一条探针看不到的证据

为什么需要它（现状的真实短板）
------------------------------
故障模式库里有些候选**没有 PromQL 探针**，只能靠 `base_probability` 与
`has_recent_change` 这一个粗糙信号（例如「近期部署引入缺陷」的先验只有
0.10）。应用日志里的异常堆栈、变更记录这类非结构化信息，PromQL 更是完全
看不到 —— 而这恰恰是 LLM 唯一比规则强的地方。

四条设计原则（它们决定了这东西不会把系统搞坏）
----------------------------------------------
1. LLM 输出的是**结构化证据** `{候选: (支持/反对, 强度)}`，当作一条 evidence
   参与贝叶斯更新 —— **绝不直接当最终置信度**。LLM 说的 "0.8" 不是校准过的
   概率，直接塞进 `confidence >= 0.3` 的自愈闸门，等于让模型决定要不要重启
   容器。这是本项目**不**把根因判定整体换成 LLM 的核心原因。
2. **一手信号优先**：候选若有探针、且探针已给出结论（成立/证伪），LLM 不参与。
   它只在「无探针」或「探针无数据」时补位。
3. **默认关闭 + 失败静默降级**：无 key、超时、返回格式不对、网络不通，一律
   返回空证据，现有闭环完全不受影响。
4. **零新增依赖**：用标准库 `urllib` 调 OpenAI 兼容的 `/chat/completions`，
   不引入 langchain / openai SDK —— 2C2G 服务器上装不动，也没必要。

当前没有日志采集源，所以 `context` 默认为空，LLM 只能基于告警上下文与候选
语义判断（相当于一个语义化的软先验）。接入日志/变更系统后把文本传进
`context` 即为真正的外部证据，调用方无需改动。
"""

import asyncio
import json
import logging
import urllib.error
import urllib.request
from typing import Any, Optional, Protocol

logger = logging.getLogger(__name__)

# 似然融合的边界：即便 LLM 强度拉满，也不越过探针「成立/证伪」的档位。
# 这样 LLM 永远只能在一手信号的留白处起作用，无法单独决定自愈。
LIKELIHOOD_CEILING = 0.9    # 与 BayesianReasoner.LIKELIHOOD_CONFIRMED 同档
LIKELIHOOD_FLOOR = 0.05     # 与 BayesianReasoner.LIKELIHOOD_REFUTED 同档
LIKELIHOOD_NEUTRAL = 0.5    # 与 BayesianReasoner.LIKELIHOOD_UNKNOWN 同档
MAX_SHIFT = 0.4             # 强度 1.0 时最多把似然从 0.5 推到 0.9 / 0.1

SYSTEM_PROMPT = (
    "你是运维根因分析的证据补充助手。给定一次告警和若干候选根因，"
    "只输出 JSON，不要任何解释文字。\n"
    "格式：{\"evidence\": [{\"candidate\": \"<候选原文>\", \"support\": true/false, "
    "\"strength\": 0~1, \"reason\": \"<一句话>\"}]}\n"
    "规则：candidate 必须原样取自给定候选列表；无法判断就不要输出该条；"
    "strength 表示把握程度，没把握就给小值。"
)


class LLMClient(Protocol):
    """LLM 调用的最小抽象：便于测试注入，也便于将来换实现"""

    async def complete(self, system: str, user: str) -> str: ...


class OpenAICompatClient:
    """OpenAI 兼容 /chat/completions 客户端（标准库实现，零依赖）

    兼容任何 OpenAI 协议的端点（含自建网关、vLLM、Ollama 的兼容接口）。
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o-mini",
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 8.0,
    ):
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    async def complete(self, system: str, user: str) -> str:
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
        }
        # urllib 是同步的，丢到线程池里跑，避免阻塞事件循环 —— RCA 在采集
        # 循环里同步调用，阻塞会让整个巡检周期卡住。
        return await asyncio.to_thread(
            self._post, "/chat/completions", payload
        )

    def _post(self, path: str, payload: dict[str, Any]) -> str:
        req = urllib.request.Request(
            f"{self._base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        return data["choices"][0]["message"]["content"]


def _extract_json(text: str) -> Optional[dict]:
    """从 LLM 输出里抠出 JSON

    模型经常在 JSON 前后加解释文字或 ```json 代码块，直接 json.loads 会炸。
    这里做两层容错：先整体解析，失败再截取第一个 { 到最后一个 }。
    """
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


class LLMEvidenceSource:
    """把 LLM 的判断转成结构化证据，供贝叶斯推理使用"""

    def __init__(self, client: Optional[LLMClient] = None, enabled: bool = True):
        self._client = client
        self._enabled = enabled

    @property
    def available(self) -> bool:
        return self._enabled and self._client is not None

    async def collect(
        self,
        alert: Any,
        candidates: list[dict[str, Any]],
        has_recent_change: bool,
        context: Optional[str] = None,
    ) -> dict[str, tuple[bool, float]]:
        """返回 {候选根因原文: (是否支持, 强度)}

        任何异常都返回空字典 —— 这是刻意的设计：LLM 是可选增强，它挂了
        不能让整个根因分析跟着挂。
        """
        if not self.available:
            return {}

        names = [c["root_cause"] for c in candidates]
        user = self._build_prompt(alert, names, has_recent_change, context)
        try:
            raw = await self._client.complete(SYSTEM_PROMPT, user)
        except asyncio.TimeoutError:
            logger.warning("[LLMEvidence] 调用超时，降级为无 LLM 证据")
            return {}
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            logger.warning(f"[LLMEvidence] 调用失败，降级为无 LLM 证据: {e}")
            return {}
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[LLMEvidence] 调用异常，降级为无 LLM 证据: {e}")
            return {}

        return self._parse(raw, set(names))

    @staticmethod
    def _build_prompt(
        alert: Any,
        names: list[str],
        has_recent_change: bool,
        context: Optional[str],
    ) -> str:
        lines = [
            f"告警：{getattr(alert, 'alert_name', '?')}",
            f"服务：{getattr(alert, 'target_service', '?')}",
            f"指标：{getattr(alert, 'metric_name', '?')}="
            f"{getattr(alert, 'metric_value', '?')}"
            f"（阈值 {getattr(alert, 'threshold', '?')}）",
            f"近期有变更：{'是' if has_recent_change else '否'}",
            "候选根因：",
        ]
        lines += [f"  - {n}" for n in names]
        if context:
            lines += ["补充上下文（日志/变更记录）：", context]
        lines.append("请判断哪些候选更可能，哪些可以排除。")
        return "\n".join(lines)

    @staticmethod
    def _parse(raw: str, allowed: set[str]) -> dict[str, tuple[bool, float]]:
        data = _extract_json(raw)
        if not isinstance(data, dict):
            logger.warning(f"[LLMEvidence] 返回不是 JSON 对象，忽略: {raw[:120]}")
            return {}

        result: dict[str, tuple[bool, float]] = {}
        for item in data.get("evidence", []) or []:
            if not isinstance(item, dict):
                continue
            name = item.get("candidate")
            # 只接受原样出现在候选列表里的名字：模型自己编一个根因出来会
            # 凭空多出一个候选，必须挡掉。
            if name not in allowed:
                continue
            try:
                strength = float(item.get("strength", 0))
            except (TypeError, ValueError):
                continue
            strength = min(max(strength, 0.0), 1.0)
            result[name] = (bool(item.get("support")), strength)
        if result:
            logger.info(f"[LLMEvidence] 采纳 {len(result)} 条 LLM 证据")
        return result


def blend_likelihood(
    base: float, support: bool, strength: float
) -> float:
    """把一条 LLM 证据融合进似然

    从中性值 0.5 出发按强度推移，并夹在 [FLOOR, CEILING] 之间：LLM 最多把
    似然推到与「探针成立」同档（0.9），无法单独把置信度顶过自愈闸门。
    """
    shift = MAX_SHIFT * min(max(strength, 0.0), 1.0)
    value = LIKELIHOOD_NEUTRAL + shift if support else LIKELIHOOD_NEUTRAL - shift
    return min(max(value, LIKELIHOOD_FLOOR), LIKELIHOOD_CEILING)
