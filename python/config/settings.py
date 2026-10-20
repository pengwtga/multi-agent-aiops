"""AIOps 多 Agent 系统全局配置"""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    app_name: str = "Multi-Agent AIOps"
    debug: bool = False

    # Kafka
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_group_id: str = "aiops-agents"
    kafka_topics_alerts: str = "aiops.alerts"
    kafka_topics_events: str = "aiops.events"
    kafka_topics_commands: str = "aiops.commands"
    kafka_topics_audit: str = "aiops.audit"

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "aiops_password"

    # LLM
    # 注意：本项目**不**用 LLM 判定根因，只用它补一条探针看不到的证据
    # （见 agents/llm_evidence.py）。LLM 的输出是结构化证据而不是置信度，
    # 直接拿它的概率去驱动自愈闸门是危险的 —— 它说的 0.8 不是校准过的概率。
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"
    openai_base_url: Optional[str] = None
    # LLM 证据源开关：默认关闭。它是可选增强，关掉不影响任何现有闭环；
    # 打开需要配置 AIOPS_OPENAI_API_KEY（否则自动保持关闭）
    llm_evidence_enabled: bool = False
    # 调用超时：RCA 在采集循环里同步调用，超时必须短，否则拖慢整个巡检周期
    llm_timeout_seconds: float = 8.0

    # Prometheus
    prometheus_url: str = "http://localhost:9090"

    # 先验学习：让故障模式库的 base_probability 从历史闭环里学出来，
    # 替代人工写死的经验值（详见 agents/prior_store.py）
    # 默认开启是**安全**的：没有历史数据时 Dirichlet 平滑会精确回退到人工先验，
    # 行为与原逻辑完全一致，数据积累后才逐步向真实频率收敛
    prior_learning_enabled: bool = True
    # SQLite 落盘路径（相对工作目录）。这是唯一需要持久化的学习产物，
    # 用 SQLite 而非向量库：先验学习本质是计数统计，不需要 embedding
    prior_db_path: str = "data/priors.db"
    # 伪计数总量 α：控制对人工先验的信任强度。
    # α=10 表示约需 10 次观测，历史数据才能明显压过人工先验。
    # 调大 = 学习更慢更保守；调小 = 更快采信数据但早期易受噪声影响
    prior_alpha: float = 10.0

    # Agent 配置
    monitor_enabled: bool = True   # 阶段 3：Prometheus 真实采集循环开关
    monitor_check_interval: int = 30
    rca_max_depth: int = 5
    heal_dry_run: bool = True
    heal_max_retries: int = 3
    change_auto_approve_threshold: float = 0.9

    # 安全护栏
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: int = 60
    rate_limit_per_minute: int = 30
    # 阶段 5：docker compose 部署下重启容器的爆炸半径天然大于 K8s 重启单个 Pod
    # （重启 Redis 期间所有跳转失败），0.2 会把所有重启类动作都降级成人工，故放宽到 0.5
    blast_radius_max_percent: float = 0.5

    # 故障演练（Dashboard 页面「故障演练 / 恢复容器」按钮）
    # 默认关闭 —— 这是唯一能主动停止容器的入口，必须显式开启
    # 走独立路径、不过 ChangeAgent 审批：演练本身就是人主动注入故障，
    # 等同于人工操作，再让 Agent 审批一次人为故障没有意义
    drill_enabled: bool = False
    # 允许被演练操作的容器白名单（逗号分隔）
    drill_containers: str = (
        "shortlink-redis,shortlink-mysql,shortlink-app,shortlink-kafka"
    )
    # 探测负载：注入故障后自动打一批**并发**请求
    #
    # 为什么需要它：dependency_hang 的判据是「连接堆积 + 成功吞吐归零」，
    # 必须有请求进来连接才会堆积。实测空闲时 Tomcat 连接数只有 2，
    # 光停 Redis 而无人访问，故障将永远不可见（不告警、不自愈）。
    # 演练的目的是验证闭环，故由后端自动补上负载。
    #
    # count 必须足够大且**并发**发出：串行请求同时只占 1 个连接，
    # 堆不出判据所需的连接数。timeout 需跨过 Prometheus 抓取周期（15s），
    # 否则连接在采到之前就释放了。
    drill_probe_count: int = 50
    drill_probe_timeout: int = 25
    shortlink_base_url: str = "http://localhost:8082"
    # 探测用短链码。留空则自动从 Redis scan 一个真实存在的 code
    # （必须真实存在：不存在的 code 会被直接 404，碰不到 Redis，造不出挂起）
    drill_probe_code: str = ""
    # 取探测码的容器（短链缓存所在）。取码前会先保证它在运行 ——
    # 上一轮自愈若没跑到，Redis 可能仍是停止的，scan 必然失败
    drill_probe_container: str = "shortlink-redis"
    # 缓存为空时新建探测短链所用的长链接
    drill_probe_long_url: str = "https://example.com/aiops-drill"

    model_config = {"env_prefix": "AIOPS_", "env_file": ".env"}


settings = Settings()
