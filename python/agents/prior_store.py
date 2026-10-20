"""先验概率存储：让故障模式库的 base_probability 从历史闭环里学习

为什么需要它
------------
故障模式库里的 `base_probability`（0.45 / 0.25 / 0.20 / 0.10）是**人工沉淀的
经验值**，没有统计依据。它们决定的是"谁更常见"，探针才决定"这次是谁"，
所以偏差不致命 —— 但毕竟是拍脑袋。

本模块把它换成从真实闭环数据里数出来的频率。

为什么用 Dirichlet 平滑而不是直接取频率
---------------------------------------
若直接用 `count_i / total`：
  - 一次都没出现的候选 → 先验 0 → 后验永久归零，再也翻不了身
  - 早期样本少时噪声极大（1 次观测就把先验拉到 100%）

所以用 m-estimate（等价于以人工先验为 base measure 的 Dirichlet 后验均值）：

    prior = (count_i + α × manual_prior_i) / (total + α)

α 是"伪计数总量"，控制对人工先验的信任强度。两个极端行为恰好是我们要的：

    total = 0   →  prior = α·p_manual / α = p_manual    ← 无数据时完美回退
    total → ∞   →  prior → count_i / total              ← 数据多了收敛到频率

因此**默认开启也不会改变任何现有行为** —— 没有历史数据时它等价于原逻辑。
α = 10 意味着约需 10 次观测，数据才能明显压过人工先验。

为什么用 SQLite 不用 chromadb / RAG
-----------------------------------
先验学习本质是**计数统计**，不需要 embedding，也不需要相似度检索。
SQLite 是标准库，零新增依赖、零额外内存 —— 这点在 2C2G 服务器上是决定性的
（chromadb + onnxruntime 磁盘 1GB+，跑不动，见 docs §5.22）。

表结构
------
    root_cause_stats(alert_name, root_cause, count, updated_at)
    主键 (alert_name, root_cause)

只记录**被证实有效**的根因：自愈执行成功且容器验证 healthy。
未定位（UNRESOLVED_ROOT_CAUSE）与 dry_run 不记录 —— 前者不知道答案，
后者没有真的执行，都不能当作"这次判对了"的证据。
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# 由 RCAAgent 产出，表示"没能定位出根因"，永远不能当作被证实的答案
UNRESOLVED_ROOT_CAUSE = "未能自动定位根因，转人工处理"


class SQLitePriorStore:
    """基于 SQLite 的先验计数器

    线程安全：每次操作开一个新连接（演示规模下开销可忽略），写操作加本地锁。
    用 `:memory:` 可直接做内存实例，便于测试。
    """

    def __init__(self, db_path: str = ":memory:", alpha: float = 10.0):
        """
        Args:
            db_path: SQLite 文件路径，`:memory:` 表示内存库
            alpha:   伪计数总量。越大越信任人工先验（学习越慢），
                     越小越信任历史数据（早期越容易受噪声影响）。
        """
        if alpha <= 0:
            raise ValueError(f"alpha 必须为正数，得到 {alpha}")
        self._alpha = alpha
        self._path = db_path
        self._lock = threading.Lock()

        if db_path != ":memory:":
            parent = Path(db_path).parent
            if str(parent) not in ("", "."):
                parent.mkdir(parents=True, exist_ok=True)

        # 全程复用同一个连接。
        # 为什么不能每次都新建一个：`:memory:` 模式下每个连接都是一个全新的空库，
        # 第一个连接里 CREATE TABLE 之后，后续连接根本看不到这张表
        # （实测报 no such table: root_cause_stats）。
        # check_same_thread=False 是因为写操作已由 self._lock 串行化保护，
        # 同一个连接可以安全跨线程使用。
        self._conn = sqlite3.connect(
            db_path, timeout=5.0, check_same_thread=False
        )
        self._init_db()
        logger.info(f"[PriorStore] 初始化: path={db_path} alpha={alpha}")

    # ---------------- 内部 ----------------

    def _connect(self) -> sqlite3.Connection:
        """返回复用的连接（不新建，详见 __init__ 注释）"""
        return self._conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS root_cause_stats (
                    alert_name  TEXT NOT NULL,
                    root_cause  TEXT NOT NULL,
                    count       INTEGER NOT NULL DEFAULT 0,
                    updated_at  TEXT NOT NULL,
                    PRIMARY KEY (alert_name, root_cause)
                )
                """
            )
            conn.commit()

    # ---------------- 写 ----------------

    def record(self, alert_name: str, root_cause: str) -> bool:
        """记录一次「被证实的根因」

        Args:
            alert_name: 告警名，即故障模式库的 key（如 redirect_5xx_rate）
            root_cause: 被证实的根因文本，需与故障模式库里的字面值一致

        Returns:
            是否真的写入了。未定位 / 空值返回 False，这类"答案"不能当证据。
        """
        if not alert_name or not root_cause:
            return False
        if root_cause == UNRESOLVED_ROOT_CAUSE:
            logger.debug("[PriorStore] 未定位的根因不记录")
            return False

        now = datetime.utcnow().isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO root_cause_stats (alert_name, root_cause, count, updated_at)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(alert_name, root_cause) DO UPDATE SET
                    count      = count + 1,
                    updated_at = excluded.updated_at
                """,
                (alert_name, root_cause, now),
            )
            conn.commit()

        logger.info(f"[PriorStore] 记录: {alert_name} → {root_cause}")
        return True

    # ---------------- 读 ----------------

    def _counts(self, alert_name: str, root_cause: str) -> tuple[int, int]:
        """返回 (该告警名下所有记录的计数总和, 该根因的计数)"""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(count), 0) FROM root_cause_stats "
                "WHERE alert_name = ?",
                (alert_name,),
            ).fetchone()
            total = int(row[1]) if row else 0

            row = conn.execute(
                "SELECT COALESCE(SUM(count), 0) FROM root_cause_stats "
                "WHERE alert_name = ? AND root_cause = ?",
                (alert_name, root_cause),
            ).fetchone()
            own = int(row[0]) if row else 0

        return total, own

    def prior(self, alert_name: str, root_cause: str, manual_prior: float) -> float:
        """计算平滑后的先验

        无历史数据时返回 manual_prior 本身（等价原逻辑），数据积累后向真实频率收敛。
        """
        total, own = self._counts(alert_name, root_cause)
        smoothed = (own + self._alpha * manual_prior) / (total + self._alpha)
        return smoothed

    def stats(self, alert_name: Optional[str] = None) -> list[dict]:
        """导出统计，供 Dashboard / 调试查看"""
        with self._connect() as conn:
            if alert_name:
                rows = conn.execute(
                    "SELECT alert_name, root_cause, count, updated_at "
                    "FROM root_cause_stats WHERE alert_name = ? ORDER BY count DESC",
                    (alert_name,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT alert_name, root_cause, count, updated_at "
                    "FROM root_cause_stats ORDER BY alert_name, count DESC"
                ).fetchall()

        return [
            {
                "alert_name": r[0],
                "root_cause": r[1],
                "count": r[2],
                "updated_at": r[3],
            }
            for r in rows
        ]

    def reset(self, alert_name: Optional[str] = None) -> None:
        """清空统计（演示 / 测试用）"""
        with self._lock, self._connect() as conn:
            if alert_name:
                conn.execute(
                    "DELETE FROM root_cause_stats WHERE alert_name = ?", (alert_name,)
                )
            else:
                conn.execute("DELETE FROM root_cause_stats")
            conn.commit()
        logger.info(f"[PriorStore] 已清空: alert_name={alert_name or '全部'}")
