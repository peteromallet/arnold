"""Machine-readable credential surface coverage matrix for M2 Security Broker.

Each :class:`CoverageEntry` classifies one credential surface discovered in
the Arnold codebase.  The matrix is the single source of truth for
conformance checks and audit reporting.

Classification rules
--------------------
* ``covered`` — fully brokered; raw credentials never reach the agent process.
* ``deferred`` — acknowledged gap deferred to a later milestone (M4–M6).
* ``uncovered`` — documented but not planned for broker coverage (typically
  free/local providers or architecture-infeasible paths).

Residual risk
-------------
* ``low`` — limited blast radius; attribute only.
* ``medium`` — credential could enable non-trivial lateral movement.
* ``high`` — credential grants mutation access to production resources.
* ``critical`` — credential grants unrestricted admin/mutation access.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List


class CoverageStatus(str, Enum):
    COVERED = "covered"
    DEFERRED = "deferred"
    UNCOVERED = "uncovered"


class ResidualRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class CoverageEntry:
    """One classified credential surface."""

    credential_surface: str
    credential_type: str
    m2_status: CoverageStatus
    residual_risk: ResidualRisk
    deferral_target: str | None
    notes: str


def get_coverage_matrix() -> List[CoverageEntry]:
    """Return the complete M2 credential coverage matrix.

    Every credential surface named in the approved M2 plan and discovered
    during codebase audit must appear here.  Conformance checks cross-
    reference this matrix against the actual codebase.
    """

    return [
        # ── Git push-class mutations ────────────────────────────────────
        CoverageEntry(
            credential_surface="arnold.security.policy.SecurityPolicy.evaluate (git_push to protected branch)",
            credential_type="git PAT / push credential",
            m2_status=CoverageStatus.COVERED,
            residual_risk=ResidualRisk.LOW,
            deferral_target=None,
            notes=(
                "Broker denies push to configured protected branches (main, master). "
                "Force-push and credential_escalation produce broker_approval_gate suspensions. "
                "All agent-visible results are sanitized."
            ),
        ),
        CoverageEntry(
            credential_surface="arnold.security.policy.SecurityPolicy.evaluate (git_force_push, git_branch_delete, git_pr_merge, credential_escalation)",
            credential_type="git PAT / push credential",
            m2_status=CoverageStatus.COVERED,
            residual_risk=ResidualRisk.LOW,
            deferral_target=None,
            notes=(
                "Broker requires durable human approval for high-risk git operations. "
                "OperationRun transitions to AWAITING_APPROVAL with suspension_kind='broker_approval_gate'."
            ),
        ),
        CoverageEntry(
                credential_surface="arnold.agent.tools.terminal_tool — git push via SSH keys or gh keychain",
            credential_type="SSH key / gh CLI token",
            m2_status=CoverageStatus.DEFERRED,
            residual_risk=ResidualRisk.HIGH,
            deferral_target="M5–M6",
            notes=(
                "Terminal-based git push with SSH keys or gh keychain is an uncovered bypass. "
                "The broker currently only intercepts git operations routed through SecurityPolicy. "
                "True protection requires broker-as-sidecar intercepting all git operations at the "
                "transport layer with fleet-level sandboxing."
            ),
        ),

        # ── LLM API-key providers (covered) ─────────────────────────────
        CoverageEntry(
            credential_surface="arnold.agent.providers.pool.KeyPool.acquire (OpenAI-compatible API keys)",
            credential_type="LLM API key",
            m2_status=CoverageStatus.COVERED,
            residual_risk=ResidualRisk.LOW,
            deferral_target=None,
            notes=(
                "OpenAI, DeepSeek, Google Gemini, Fireworks, and custom OpenAI-compatible endpoints. "
                "Broker proxies LLM requests so raw keys never reach the agent process. "
                "resolve_provider_client() returns broker-backed client in production mode."
            ),
        ),
        CoverageEntry(
            credential_surface="arnold.agent.providers.pool.KeyPool.acquire (zhipu/GLM API keys)",
            credential_type="LLM API key",
            m2_status=CoverageStatus.COVERED,
            residual_risk=ResidualRisk.LOW,
            deferral_target=None,
            notes="Zhipu/GLM API key sourced from ZHIPU_API_KEY/GLM_API_KEY env vars or api_keys.json via KeyPathSource.",
        ),
        CoverageEntry(
            credential_surface="arnold.agent.providers.pool.KeyPool.acquire (kimi/Moonshot API keys)",
            credential_type="LLM API key",
            m2_status=CoverageStatus.COVERED,
            residual_risk=ResidualRisk.LOW,
            deferral_target=None,
            notes="Kimi/Moonshot API key sourced from KIMI_API_KEY/MOONSHOT_API_KEY env vars. Coding keys (sk-kimi-) routed to Kimi coding endpoint.",
        ),
        CoverageEntry(
            credential_surface="arnold.agent.providers.pool.KeyPool.acquire (minimax API keys)",
            credential_type="LLM API key",
            m2_status=CoverageStatus.COVERED,
            residual_risk=ResidualRisk.LOW,
            deferral_target=None,
            notes="MiniMax API key sourced from MINIMAX_API_KEY env var.",
        ),
        CoverageEntry(
            credential_surface="arnold.agent.providers.pool.KeyPool.acquire (mimo API keys)",
            credential_type="LLM API key",
            m2_status=CoverageStatus.COVERED,
            residual_risk=ResidualRisk.LOW,
            deferral_target=None,
            notes="MiMo API key sourced from MIMO_API_KEY env var.",
        ),
        CoverageEntry(
            credential_surface="arnold.agent.agent.auxiliary_client.resolve_provider_client (OpenRouter API key)",
            credential_type="LLM API key",
            m2_status=CoverageStatus.COVERED,
            residual_risk=ResidualRisk.LOW,
            deferral_target=None,
            notes="OpenRouter API key sourced from OPENROUTER_API_KEY. Broker proxies requests.",
        ),
        CoverageEntry(
            credential_surface="arnold.agent.agent.auxiliary_client.resolve_provider_client (custom OpenAI-compatible endpoint)",
            credential_type="LLM API key",
            m2_status=CoverageStatus.COVERED,
            residual_risk=ResidualRisk.LOW,
            deferral_target=None,
            notes="Custom endpoint with OPENAI_BASE_URL + OPENAI_API_KEY. Broker proxies requests.",
        ),
        CoverageEntry(
            credential_surface="arnold.agent.agent.auxiliary_client.resolve_provider_client (native Anthropic API key)",
            credential_type="LLM API key",
            m2_status=CoverageStatus.COVERED,
            residual_risk=ResidualRisk.LOW,
            deferral_target=None,
            notes="Native Anthropic API key (ANTHROPIC_API_KEY). Broker proxies requests.",
        ),

        # ── LLM OAuth/refresh-token providers (deferred) ────────────────
        CoverageEntry(
            credential_surface="arnold.agent.agent.auxiliary_client.resolve_provider_client (Nous Portal OAuth)",
            credential_type="OAuth bearer token / refresh token",
            m2_status=CoverageStatus.DEFERRED,
            residual_risk=ResidualRisk.MEDIUM,
            deferral_target="M5–M6",
            notes=(
                "Nous Portal uses ~/.hermes/auth.json with OAuth bearer tokens and refresh tokens. "
                "Token refresh and storage happen in-process. Deferred to M5–M6 provider credential brokering."
            ),
        ),
        CoverageEntry(
            credential_surface="arnold.agent.agent.auxiliary_client.resolve_provider_client (Codex OAuth / Responses API)",
            credential_type="OAuth token",
            m2_status=CoverageStatus.DEFERRED,
            residual_risk=ResidualRisk.MEDIUM,
            deferral_target="M5–M6",
            notes=(
                "Codex OAuth wraps the chatgpt.com Responses API with gpt-5.3-codex. "
                "OAuth token management happens in-process. Deferred to M5–M6."
            ),
        ),
        CoverageEntry(
            credential_surface="arnold.agent.agent.anthropic_adapter (Anthropic OAuth)",
            credential_type="OAuth token",
            m2_status=CoverageStatus.DEFERRED,
            residual_risk=ResidualRisk.MEDIUM,
            deferral_target="M5–M6",
            notes="Anthropic OAuth token path deferred to M5–M6 provider credential brokering.",
        ),

        # ── Skills hub GitHub auth (deferred) ───────────────────────────
        CoverageEntry(
            credential_surface="arnold.agent.tools.skills_hub.GitHubAuth",
            credential_type="GitHub PAT / gh CLI token / GitHub App token",
            m2_status=CoverageStatus.DEFERRED,
            residual_risk=ResidualRisk.MEDIUM,
            deferral_target="M5–M6",
            notes=(
                "GitHubAuth resolves tokens from GITHUB_TOKEN/GH_TOKEN env vars, gh auth token subprocess, "
                "or GitHub App JWT+installation tokens. Used only for read-only GitHub API access "
                "(skill fetching). Not a push-class mutation credential. "
                "Token caching and auth method selection happen in-process. "
                "Deferred because the blast radius is limited to public/private repo read access."
            ),
        ),

        # ── MCP subprocess credentials (deferred) ───────────────────────
        CoverageEntry(
            credential_surface="arnold.agent.tools.mcp_tool (MCP server subprocess environment)",
            credential_type="PAT / API key / bearer token (from config.yaml)",
            m2_status=CoverageStatus.DEFERRED,
            residual_risk=ResidualRisk.MEDIUM,
            deferral_target="M5–M6",
            notes=(
                "MCP server configs in ~/.hermes/config.yaml include raw credentials "
                "(GITHUB_PERSONAL_ACCESS_TOKEN, Authorization headers) injected into subprocess env. "
                "The agent process reads config.yaml and passes env directly. "
                "Deferred to M5–M6 broker-as-sidecar transport layer."
            ),
        ),

        # ── Non-LLM tool credentials ────────────────────────────────────
        CoverageEntry(
            credential_surface="arnold.agent.tools.tts_tool (ElevenLabs TTS)",
            credential_type="API key (ELEVENLABS_API_KEY)",
            m2_status=CoverageStatus.DEFERRED,
            residual_risk=ResidualRisk.LOW,
            deferral_target="M5–M6",
            notes=(
                "ElevenLabs TTS uses ELEVENLABS_API_KEY from environment. "
                "Deferred — non-LLM tool credentials are out of scope for M2."
            ),
        ),
        CoverageEntry(
            credential_surface="arnold.agent.tools.image_generation_tool (FAL.ai)",
            credential_type="API key (FAL_KEY)",
            m2_status=CoverageStatus.DEFERRED,
            residual_risk=ResidualRisk.LOW,
            deferral_target="M5–M6",
            notes="FAL.ai image generation uses FAL_KEY from environment. Deferred to M5–M6.",
        ),
        CoverageEntry(
            credential_surface="arnold.agent.tools.web_tools (Firecrawl)",
            credential_type="API key (FIRECRAWL_API_KEY)",
            m2_status=CoverageStatus.DEFERRED,
            residual_risk=ResidualRisk.LOW,
            deferral_target="M5–M6",
            notes="Firecrawl web search/extract uses FIRECRAWL_API_KEY from environment. Deferred to M5–M6.",
        ),
        CoverageEntry(
            credential_surface="arnold.agent.tools.web_tools (Parallel)",
            credential_type="API key (PARALLEL_API_KEY)",
            m2_status=CoverageStatus.DEFERRED,
            residual_risk=ResidualRisk.LOW,
            deferral_target="M5–M6",
            notes="Parallel web search uses PARALLEL_API_KEY from environment. Deferred to M5–M6.",
        ),
        CoverageEntry(
            credential_surface="arnold.agent.tools.transcription_tools (Groq Whisper)",
            credential_type="API key (GROQ_API_KEY)",
            m2_status=CoverageStatus.DEFERRED,
            residual_risk=ResidualRisk.LOW,
            deferral_target="M5–M6",
            notes="Groq transcription uses GROQ_API_KEY from environment. Deferred to M5–M6.",
        ),
        CoverageEntry(
            credential_surface="arnold.agent.tools.transcription_tools (OpenAI Whisper)",
            credential_type="API key (VOICE_TOOLS_OPENAI_KEY)",
            m2_status=CoverageStatus.DEFERRED,
            residual_risk=ResidualRisk.LOW,
            deferral_target="M5–M6",
            notes="OpenAI transcription uses VOICE_TOOLS_OPENAI_KEY from environment. Deferred to M5–M6.",
        ),

        # ── MCP OAuth (deferred) ────────────────────────────────────────
        CoverageEntry(
            credential_surface="arnold.agent.tools.mcp_oauth.HermesTokenStorage",
            credential_type="OAuth refresh token (on-disk)",
            m2_status=CoverageStatus.DEFERRED,
            residual_risk=ResidualRisk.MEDIUM,
            deferral_target="M5–M6",
            notes=(
                "MCP OAuth tokens (access + refresh) stored to ~/.hermes/mcp-tokens/*.json. "
                "Token refresh and disk I/O happen in the agent process. "
                "Deferred to M5–M6."
            ),
        ),

        # ── Terminal/SSH/gh bypasses (deferred) ─────────────────────────
        CoverageEntry(
            credential_surface="arnold.agent.tools.terminal_tool (agent-initiated shell commands)",
            credential_type="any credential accessible via shell",
            m2_status=CoverageStatus.DEFERRED,
            residual_risk=ResidualRisk.HIGH,
            deferral_target="M5–M6",
            notes=(
                "The terminal tool grants the agent full shell access. An agent prompt can run "
                "'env', 'cat ~/.hermes/.env', 'gh auth token', 'ssh', etc. "
                "This is a fundamental architectural bypass. Mitigation requires fleet-level "
                "sandboxing with seccomp filters, mount namespace isolation, and environment "
                "filtering at the worker level (M5–M6)."
            ),
        ),
        CoverageEntry(
            credential_surface="terminal_tool.py — gh CLI keychain access",
            credential_type="gh CLI OAuth token (from keychain)",
            m2_status=CoverageStatus.DEFERRED,
            residual_risk=ResidualRisk.HIGH,
            deferral_target="M5–M6",
            notes=(
                "'gh auth token' returns the GitHub CLI OAuth token from the system keychain. "
                "An agent with terminal access can extract this token. Deferred to M5–M6."
            ),
        ),

        # ── Environment loader (documented as metadata-only) ────────────
        CoverageEntry(
            credential_surface="arnold.agent.providers.env_loader.load_hermes_dotenv",
            credential_type="env-file credential loader",
            m2_status=CoverageStatus.UNCOVERED,
            residual_risk=ResidualRisk.LOW,
            deferral_target=None,
            notes=(
                "load_hermes_dotenv loads ~/.hermes/.env into os.environ. This is not a credential "
                "surface itself but the mechanism by which credentials enter the agent process. "
                "Classified as uncovered because the env loader does not itself store or transmit "
                "credentials — it is the env-vars-loaded state that is the risk surface, "
                "covered by the individual credential entries above."
            ),
        ),

        # ── Free/local providers (documented uncovered — no secrets) ────
        CoverageEntry(
            credential_surface="arnold.agent.tools.tts_tool (Edge TTS)",
            credential_type="none (free, no API key)",
            m2_status=CoverageStatus.UNCOVERED,
            residual_risk=ResidualRisk.LOW,
            deferral_target=None,
            notes="Edge TTS is free and requires no API key. No credential surface to broker.",
        ),
        CoverageEntry(
            credential_surface="arnold.agent.tools.tts_tool (NeuTTS)",
            credential_type="none (local, no API key)",
            m2_status=CoverageStatus.UNCOVERED,
            residual_risk=ResidualRisk.LOW,
            deferral_target=None,
            notes="NeuTTS runs locally via neutts_cli. No credential surface to broker.",
        ),
        CoverageEntry(
            credential_surface="arnold.agent.tools.transcription_tools (faster-whisper local)",
            credential_type="none (local model, no API key)",
            m2_status=CoverageStatus.UNCOVERED,
            residual_risk=ResidualRisk.LOW,
            deferral_target=None,
            notes="Local faster-whisper transcription requires no API key. No credential surface to broker.",
        ),
    ]


def get_uncovered_surfaces() -> List[CoverageEntry]:
    """Return only entries that are deferred or uncovered (not broker-covered)."""
    return [
        e
        for e in get_coverage_matrix()
        if e.m2_status in (CoverageStatus.DEFERRED, CoverageStatus.UNCOVERED)
    ]


def get_covered_surfaces() -> List[CoverageEntry]:
    """Return only entries that are broker-covered in production mode."""
    return [
        e for e in get_coverage_matrix() if e.m2_status == CoverageStatus.COVERED
    ]


def get_high_risk_deferrals() -> List[CoverageEntry]:
    """Return deferred entries with high or critical residual risk."""
    return [
        e
        for e in get_coverage_matrix()
        if e.m2_status == CoverageStatus.DEFERRED
        and e.residual_risk in (ResidualRisk.HIGH, ResidualRisk.CRITICAL)
    ]


__all__ = [
    "CoverageEntry",
    "CoverageStatus",
    "ResidualRisk",
    "get_coverage_matrix",
    "get_covered_surfaces",
    "get_high_risk_deferrals",
    "get_uncovered_surfaces",
]
