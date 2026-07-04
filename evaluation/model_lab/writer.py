from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .schemas import CompileResult, GenerationResult, ModelEntry, PromptEntry


def allocate_run_dir(base: Path) -> Path:
    today = datetime.now().strftime("%Y_%m_%d")
    candidate = base / f"run_{today}"
    if not candidate.exists():
        return candidate
    for i in range(2, 1000):
        candidate = base / f"run_{today}_{i:03d}"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"could not allocate run directory under {base}")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_run_manifest(
    run_dir: Path,
    *,
    models_path: Path,
    prompts_path: Path,
    phase1_model: str,
    flags: dict[str, Any],
    models: list[ModelEntry],
    prompts: list[PromptEntry],
) -> None:
    write_json(
        run_dir / "run_manifest.json",
        {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "models_config": str(models_path),
            "prompts_config": str(prompts_path),
            "phase1_model": phase1_model,
            "flags": flags,
            "models": [m.model_dump() for m in models],
            "prompts": [{"id": p.id, "tags": p.tags} for p in prompts],
        },
    )


def write_comparison_md(
    path: Path,
    *,
    prompt: PromptEntry,
    models: list[ModelEntry],
    results: dict[str, GenerationResult],
    compile_results: Optional[dict[str, CompileResult]] = None,
    audit_enabled: bool = False,
    duplicate_hashes: Optional[set[str]] = None,
) -> None:
    title = prompt.id.replace("_", " ").title()
    tags_line = ", ".join(prompt.tags) if prompt.tags else "(none)"
    lines = [
        f"# {title}",
        "",
        f"Tags: {tags_line}",
        "",
        "## Prompts sent to all models",
        "- [phase2_system_prompt.txt](phase2_system_prompt.txt)",
        "- [phase2_user_prompt.txt](phase2_user_prompt.txt)",
        "- [phase1_intent.json](phase1_intent.json)",
        "",
    ]
    if duplicate_hashes:
        lines.extend([
            "## Note",
            f"Identical raw outputs detected (sha256): {', '.join(sorted(duplicate_hashes))}",
            "",
        ])
    for model in models:
        alias = model.alias
        label = model.label
        result = results.get(alias)
        lines.append(f"## {label}")
        status = "ok" if result and result.success else "failed"
        lines.append(f"- Status: {status}")
        lines.append(f"- Raw: [{alias}.md]({alias}.md)")
        lines.append(f"- Extracted: [{alias}.extracted.cash]({alias}.extracted.cash)")
        if compile_results is not None:
            cr = compile_results.get(alias)
            if cr is not None:
                mark = "✓" if cr.compile_success else "✗"
                lines.append(f"- Compile: {mark} ([{alias}.compile.json]({alias}.compile.json))")
        if audit_enabled:
            lines.append(f"- Audit: [{alias}.audit.json]({alias}.audit.json)")
        lines.append("")
    write_text(path, "\n".join(lines).rstrip() + "\n")


def write_summary_md(
    path: Path,
    *,
    run_name: str,
    phase1_model: str,
    models: list[ModelEntry],
    flags: dict[str, bool],
    prompt_sections: list[dict[str, Any]],
) -> None:
    flag_parts = [k for k, v in flags.items() if v]
    flags_line = ", ".join(flag_parts) if flag_parts else "(none)"
    model_labels = ", ".join(m.label for m in models)
    lines = [
        f"# Model Lab Run — {run_name}",
        "",
        f"Phase 1 model: {phase1_model}",
        f"Models: {model_labels}",
        f"Flags: {flags_line}",
        "",
    ]
    for section in prompt_sections:
        pid = section["prompt_id"]
        tags = section.get("tags") or []
        tag_str = f" ({', '.join(tags)})" if tags else ""
        lines.append(f"## Prompt: {pid}{tag_str}")
        lines.append(f"→ [comparison.md](prompt_{pid}/comparison.md)")
        lines.append("")
        lines.append("Models executed:")
        for row in section.get("models", []):
            mark = "x" if row.get("success") else " "
            lines.append(f"- [{mark}] {row['label']} → {row['alias']}.md")
        compile_line = section.get("compile_line")
        if compile_line:
            lines.append("")
            lines.append(f"Compile: {compile_line}")
        if section.get("phase1_failed"):
            lines.append("")
            lines.append("Phase 1 failed — model generation skipped.")
        lines.append("")
    write_text(path, "\n".join(lines).rstrip() + "\n")


def find_duplicate_response_hashes(
    results: dict[str, GenerationResult],
) -> set[str]:
    by_hash: dict[str, list[str]] = defaultdict(list)
    for alias, result in results.items():
        by_hash[result.response_sha256].append(alias)
    dupes: set[str] = set()
    for h, aliases in by_hash.items():
        if len(aliases) > 1:
            dupes.add(h[:12])
    return dupes
