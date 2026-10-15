"""监控告警 Agent — 时序异常检测 + 告警收敛 + 告警分级

核心功能：
1. 从 Prometheus 拉取指标，进行异常检测
2. 多算法集成：3-sigma / EWMA / Isolation Forest
3. 告警收敛：相同 fingerprint 的告警合并，减少噪音
4. 告警分级：根据指标偏离程度自动判定 severity

面试重点：
- 为什么用动态阈值而不是静态阈值？（业务波动、季节性）
- 3-sigma 适用正态分布，EWMA 适用趋势检测，Isolation Forest 适用多维异常
- 告警收敛用 fingerprint 哈希（metric_name + labels），滑动窗口去重
"""

import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Optional

import numpy as np

from agents.base_agent import BaseAgent
from core.event_bus import EventBus
from models.events import (
    AgentType,
    AlertEvent,
    AlertStatus,
    EventType,
    IncidentState,
    Severity,
)

logger = logging.getLogger(__name__)


class AlertFingerprint:
    """告警指纹，用于告警收敛去重"""

    def __init__(self, window_seconds: int = 300):
        self._window = timedelta(seconds=window_seconds)
        self._recent: dict[str, datetime] = {}

    def compute(self, alert_name: str, target_service: str, labels: dict) -> str:
        raw = f"{alert_name}:{target_service}:{sorted(labels.items())}"
        return hashlib.md5(raw.encode()).hexdigest()

    def is_duplicate(self, fingerprint: str) -> bool:
        now = datetime.utcnow()
        if fingerprint in self._recent:
            if now - self._recent[fingerprint] < self._window:
                return True
        self._recent[fingerprint] = now
        self._cleanup(now)
        return False

    def _cleanup(self, now: datetime) -> None:
        expired = [k for k, v in self._recent.items() if now - v >= self._window]
        for k in expired:
            del self._recent[k]


class AnomalyDetector:
    """多算法异常检测器

    面试要点：
    - 3-sigma: 假设正态分布，超过 μ±3σ 即异常，简单高效但不适合非正态
    - EWMA: 指数加权移动平均，对近期数据更敏感，适合趋势变化检测
    - Isolation Forest: 基于随机森林的无监督异常检测，适合多维场景
    """

    @staticmethod
    def three_sigma(values: list[float], current: float) -> tuple[bool, float]:
        """3-sigma 异常检测"""
        if len(values) < 10:
            return False, 0.0
        arr = np.array(values)
        mean, std = arr.mean(), arr.std()
        if std == 0:
            return False, 0.0
        z_score = abs(current - mean) / std
        return z_score > 3.0, z_score

    @staticmethod
    def ewma(
        values: list[float], current: float, alpha: float = 0.3, threshold: float = 3.0
    ) -> tuple[bool, float]:
        """EWMA 指数加权移动平均异常检测"""
        if len(values) < 5:
            return False, 0.0
        ewma_val = values[0]
        ewma_var = 0.0
        for v in values[1:]:
            ewma_val = alpha * v + (1 - alpha) * ewma_val
            ewma_var = alpha * (v - ewma_val) ** 2 + (1 - alpha) * ewma_var

        ewma_std = np.sqrt(ewma_var)
        if ewma_std == 0:
            return False, 0.0
        deviation = abs(current - ewma_val) / ewma_std
        return deviation > threshold, deviation

    @staticmethod
    def isolation_forest_score(values: list[float], current: float) -> tuple[bool, float]:
        """Isolation Forest 异常检测（简化版，完整版见 models/time_series.py）"""
        if len(values) < 20:
            return False, 0.0
        from sklearn.ensemble import IsolationForest

        data = np.array(values + [current]).reshape(-1, 1)
        clf = IsolationForest(contamination=0.05, random_state=42)
        clf.fit(data[:-1])
        score = clf.decision_function(data[-1:])
        is_anomaly = clf.predict(data[-1:])[0] == -1
        return is_anomaly, float(-score[0])


class MonitorAgent(BaseAgent):
    """监控告警 Agent"""

    def __init__(self, event_bus: EventBus):
        super().__init__(AgentType.MONITOR, event_bus, "MonitorAgent")
        self._fingerprint = AlertFingerprint(window_seconds=300)
        self._detector = AnomalyDetector()
        self._history: dict[str, list[float]] = defaultdict(list)
        self._history_max_len = 1000

    async def process(self, state: IncidentState) -> IncidentState:
        """处理入站指标数据，检测异常并生成告警

        两层检测：
        1. 静态业务规则（metadata.rule_violation）：由 Prometheus 采集器按
           短链平台业务阈值预判定，直接生成告警 —— 无冷启动问题
        2. 统计异常检测：多算法投票（3-sigma / EWMA / Isolation Forest），
           需要历史样本（≥5~10 个），适合捕获未知突变
        """
        metric_data = state.metadata.get("metric_data")
        if not metric_data:
            state = await self._generate_demo_alert(state)
            return state

        metric_name = metric_data.get("metric_name", "unknown")
        current_value = metric_data.get("value", 0.0)
        target_service = metric_data.get("service", "unknown")
        labels = metric_data.get("labels", {})

        self._history[metric_name].append(current_value)
        if len(self._history[metric_name]) > self._history_max_len:
            self._history[metric_name] = self._history[metric_name][-self._history_max_len:]

        rule_violation = state.metadata.get("rule_violation")
        if rule_violation:
            alert = self._build_rule_alert(
                rule_violation, metric_name, current_value,
                target_service, labels, state.incident_id,
            )
        else:
            history = self._history[metric_name]
            is_anomaly, score = self._detect_anomaly(history, current_value)
            if not is_anomaly:
                return state
            alert = self._build_statistical_alert(
                metric_name, current_value, target_service,
                labels, score, state.incident_id,
            )

        fingerprint = self._fingerprint.compute(alert.alert_name, target_service, labels)
        if self._fingerprint.is_duplicate(fingerprint):
            logger.info(f"[MonitorAgent] Alert suppressed (duplicate): {alert.alert_name}")
            return state

        state.alert_event = alert
        state.status = "investigating"

        await self.event_bus.publish("aiops.alerts", alert)
        logger.info(f"[MonitorAgent] Alert fired: {alert.alert_name} [{alert.severity.value}]")

        return state

    @staticmethod
    def _build_rule_alert(
        rule: dict,
        metric_name: str,
        value: float,
        target_service: str,
        labels: dict,
        correlation_id: str,
    ) -> AlertEvent:
        """静态业务规则命中 → 直接生成告警（阈值判定已由采集器完成）"""
        return AlertEvent(
            alert_name=rule.get("name", f"rule_{metric_name}"),
            severity=Severity(rule.get("severity", "high")),
            source="prometheus",
            target_service=target_service,
            metric_name=metric_name,
            metric_value=value,
            threshold=rule.get("threshold", 0.0),
            description=(
                f"{rule.get('description', '业务规则命中')}: "
                f"metric={metric_name}, value={value}, "
                f"threshold={rule.get('threshold')} ({rule.get('comparator', 'gt')})"
            ),
            labels=labels,
            correlation_id=correlation_id,
        )

    @staticmethod
    def _build_statistical_alert(
        metric_name: str,
        value: float,
        target_service: str,
        labels: dict,
        score: float,
        correlation_id: str,
    ) -> AlertEvent:
        """统计异常检测命中 → 按异常分数分级生成告警"""
        return AlertEvent(
            alert_name=f"anomaly_{metric_name}",
            severity=MonitorAgent._classify_severity(score),
            source="prometheus",
            target_service=target_service,
            metric_name=metric_name,
            metric_value=value,
            threshold=score,
            description=f"Anomaly detected on {metric_name}: value={value:.2f}, score={score:.2f}",
            labels=labels,
            correlation_id=correlation_id,
        )

    def _detect_anomaly(self, history: list[float], current: float) -> tuple[bool, float]:
        """多算法投票机制：至少两种算法认为异常才报警"""
        votes = 0
        max_score = 0.0

        is_3s, score_3s = self._detector.three_sigma(history, current)
        if is_3s:
            votes += 1
            max_score = max(max_score, score_3s)

        is_ewma, score_ewma = self._detector.ewma(history, current)
        if is_ewma:
            votes += 1
            max_score = max(max_score, score_ewma)

        if len(history) >= 20:
            is_if, score_if = self._detector.isolation_forest_score(history, current)
            if is_if:
                votes += 1
                max_score = max(max_score, score_if)

        return votes >= 2, max_score

    @staticmethod
    def _classify_severity(score: float) -> Severity:
        """根据异常分数分级"""
        if score > 5.0:
            return Severity.CRITICAL
        elif score > 4.0:
            return Severity.HIGH
        elif score > 3.0:
            return Severity.MEDIUM
        return Severity.LOW

    async def _generate_demo_alert(self, state: IncidentState) -> IncidentState:
        """演示用：生成模拟告警"""
        alert = AlertEvent(
            alert_name="high_cpu_usage",
            severity=Severity.HIGH,
            source="prometheus",
            target_service="order-service",
            metric_name="cpu_usage_percent",
            metric_value=95.3,
            threshold=80.0,
            description="CPU usage exceeded threshold: 95.3% > 80%",
            labels={"pod": "order-service-7d8f9b6c4-x2k9m", "namespace": "production"},
            correlation_id=state.incident_id,
        )
        state.alert_event = alert
        state.status = "investigating"
        await self.event_bus.publish("aiops.alerts", alert)
        return state
