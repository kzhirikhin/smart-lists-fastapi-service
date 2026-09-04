"""Целевые security-контракты миграции AI Insights на Vertex AI.

Строгий XFAIL фиксирует ожидаемый RED до реализации: непройденный контракт не
ломает промежуточный этап, но неожиданный XPASS ломает CI и требует снять маркер.
Проверки статические, поэтому не требуют credentials или установленного SDK.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
AI_PATH = REPO_ROOT / "app/services/ai.py"
CONFIG_PATH = REPO_ROOT / "app/core/config.py"
MAIN_PATH = REPO_ROOT / "app/main.py"
AUTH_PATH = REPO_ROOT / "app/core/anthropic_auth.py"
REQUIREMENTS_PATH = REPO_ROOT / "requirements.in"
OUTBOUND_TEST_PATH = REPO_ROOT / "tests/test_outbound_calls.py"

TARGET_IMPLEMENTATION = pytest.mark.xfail(
    strict=True,
    reason="контракт станет зелёным после реализации Vertex AI",
)
LEGACY_REMOVAL = pytest.mark.xfail(
    strict=True,
    reason="контракт станет зелёным после удаления канала Anthropic",
)

ALLOWED_MODELS = {"gemini-2.5-flash-lite", "gemini-3.1-flash-lite"}
EXPECTED_PROJECT = "project-5b7c1bd1-572b-410d-826"


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _tree(path: Path) -> ast.Module:
    return ast.parse(_source(path), filename=str(path))


def _dotted_name(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _calls(path: Path, name: str) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(_tree(path))
        if isinstance(node, ast.Call) and _dotted_name(node.func) == name
    ]


def _keywords(call: ast.Call) -> dict[str, ast.expr]:
    assert all(keyword.arg is not None for keyword in call.keywords)
    return {keyword.arg: keyword.value for keyword in call.keywords if keyword.arg}


@TARGET_IMPLEMENTATION
def test_vertex_client_is_explicitly_pinned_and_has_no_escape_hatch() -> None:
    calls = _calls(AI_PATH, "genai.Client")
    assert len(calls) == 1
    assert calls[0].args == []
    keywords = _keywords(calls[0])
    assert set(keywords) == {"vertexai", "project", "location", "http_options"}
    assert ast.literal_eval(keywords["vertexai"]) is True
    assert ast.literal_eval(keywords["project"]) == EXPECTED_PROJECT
    assert ast.literal_eval(keywords["location"]) == "global"

    options = keywords["http_options"]
    assert isinstance(options, ast.Call)
    assert _dotted_name(options.func) == "types.HttpOptions"
    assert options.args == []
    option_keywords = _keywords(options)
    assert set(option_keywords) == {"api_version", "timeout"}
    assert ast.literal_eval(option_keywords["api_version"]) == "v1"
    assert ast.literal_eval(option_keywords["timeout"]) == 30_000

    source = _source(AI_PATH)
    assert "api_key" not in source
    assert "base_url" not in source


@TARGET_IMPLEMENTATION
def test_model_is_a_reviewed_literal_and_not_runtime_overridable() -> None:
    source = _source(AI_PATH)
    selected = {
        node.value
        for node in ast.walk(_tree(AI_PATH))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("gemini-")
    }
    assert len(selected) == 1
    assert selected <= ALLOWED_MODELS
    assert "INSIGHTS_MODEL" not in source
    assert "os.environ" not in source


@TARGET_IMPLEMENTATION
def test_generation_has_minimal_capabilities_and_bounded_output() -> None:
    calls = _calls(AI_PATH, "client.aio.models.generate_content")
    assert len(calls) == 1
    assert calls[0].args == []
    keywords = _keywords(calls[0])
    assert set(keywords) == {"model", "contents", "config"}

    config = keywords["config"]
    assert isinstance(config, ast.Call)
    assert _dotted_name(config.func) == "types.GenerateContentConfig"
    assert config.args == []
    config_keywords = _keywords(config)
    assert set(config_keywords) == {"system_instruction", "max_output_tokens"}
    assert ast.literal_eval(config_keywords["max_output_tokens"]) == 2048

    forbidden = {
        "tools",
        "tool_config",
        "automatic_function_calling",
        "code_execution",
        "google_search",
        "url_context",
        "vertex_ai_search",
        "cached_content",
        "response_modalities",
    }
    assert forbidden.isdisjoint(keywords)
    assert forbidden.isdisjoint(config_keywords)


@TARGET_IMPLEMENTATION
def test_blocked_or_empty_vertex_response_fails_closed() -> None:
    source = _source(AI_PATH)
    assert "response.text" in source
    assert "raise ValueError" in source
    tree = _tree(AI_PATH)
    empty_fallbacks = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.BoolOp)
        and isinstance(node.op, ast.Or)
        and any(isinstance(value, ast.Constant) and value.value == "" for value in node.values)
    ]
    assert empty_fallbacks == []


@TARGET_IMPLEMENTATION
def test_vertex_errors_are_sanitized_at_http_boundary() -> None:
    source = _source(MAIN_PATH)
    assert "google.genai" in source
    assert "APIError" in source
    assert "Anthropic" not in source
    assert "exc.message" not in source
    assert "exc.response" not in source
    assert 'detail="AI provider request failed"' in source


@LEGACY_REMOVAL
def test_runtime_uses_adc_and_contains_no_provider_api_key() -> None:
    config = _source(CONFIG_PATH)
    requirements = _source(REQUIREMENTS_PATH)
    assert "API_KEY" not in config.upper()
    assert "ANTHROPIC" not in config.upper()
    assert re.search(r"^google-genai==", requirements, re.MULTILINE)
    assert re.search(r"^anthropic==", requirements, re.MULTILINE) is None


@LEGACY_REMOVAL
def test_outbound_allowlist_knows_vertex_and_forgets_anthropic() -> None:
    source = _source(OUTBOUND_TEST_PATH)
    assert "google-genai-client" in source
    assert "anthropic-client" not in source
    assert "app/core/anthropic_auth.py" not in source


@LEGACY_REMOVAL
def test_anthropic_runtime_paths_are_fully_removed() -> None:
    assert not AUTH_PATH.exists()
    runtime = "\n".join(
        _source(path)
        for path in sorted((REPO_ROOT / "app").rglob("*.py"))
    )
    assert "anthropic" not in runtime.lower()
