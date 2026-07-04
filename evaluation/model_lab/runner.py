from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from src.services.llm.factory import OPENROUTER_PHASE1_MODEL

from .executor import generate_for_model
from .postprocess import run_audit, run_compile
from .prompts import build_phase2_prompts, run_phase1
from .schemas import (
    CompileResult,
    GenerationResult,
    ModelEntry,
    ModelsConfig,
    PromptEntry,
    PromptsConfig,
    RunOptions,
    load_models_config,
    load_prompts_config,
)
from .writer import (
    allocate_run_dir,
    find_duplicate_response_hashes,
    write_comparison_md,
    write_json,
    write_run_manifest,
    write_summary_md,
    write_text,
)


class ModelLabRunner:
    def __init__(self, options: RunOptions, root: Path):
        self.options = options
        self.root = root
        self.models_cfg: ModelsConfig = load_models_config(options.models_path)
        self.prompts_cfg: PromptsConfig = load_prompts_config(
            options.prompts_path,
            filter_tags=options.filter_tags or None,
        )

    def _resolve_run_dir(self) -> Path:
        if self.options.output_dir:
            return self.options.output_dir
        return allocate_run_dir(self.root / "model_lab_runs")

    async def run(self) -> Path:
        run_dir = self._resolve_run_dir()
        phase1_model = self.options.phase1_model or OPENROUTER_PHASE1_MODEL
        flags = {
            "compile": self.options.compile,
            "audit": self.options.audit,
            "dry_run": self.options.dry_run,
        }

        if self.options.dry_run:
            print(f"[dry-run] models: {[m.slug for m in self.models_cfg.models]}")
            print(f"[dry-run] prompts: {[p.id for p in self.prompts_cfg.prompts]}")
            print(f"[dry-run] phase1_model: {phase1_model}")
            print(f"[dry-run] would write to: {run_dir}")
            return run_dir

        if not os.getenv("OPENROUTER_API_KEY"):
            raise RuntimeError("OPENROUTER_API_KEY is not set")

        run_dir.mkdir(parents=True, exist_ok=True)
        write_run_manifest(
            run_dir,
            models_path=self.options.models_path,
            prompts_path=self.options.prompts_path,
            phase1_model=phase1_model,
            flags=flags,
            models=self.models_cfg.models,
            prompts=self.prompts_cfg.prompts,
        )

        summary_sections: list[dict[str, Any]] = []

        for prompt in self.prompts_cfg.prompts:
            section = await self._run_prompt(
                run_dir,
                prompt,
                phase1_model=phase1_model,
            )
            summary_sections.append(section)

        write_summary_md(
            run_dir / "summary.md",
            run_name=run_dir.name,
            phase1_model=phase1_model,
            models=self.models_cfg.models,
            flags={"compile": self.options.compile, "audit": self.options.audit},
            prompt_sections=summary_sections,
        )
        return run_dir

    async def _run_prompt(
        self,
        run_dir: Path,
        prompt: PromptEntry,
        *,
        phase1_model: str,
    ) -> dict[str, Any]:
        prompt_dir = run_dir / f"prompt_{prompt.id}"
        prompt_dir.mkdir(parents=True, exist_ok=True)

        section: dict[str, Any] = {
            "prompt_id": prompt.id,
            "tags": prompt.tags,
            "models": [],
            "phase1_failed": False,
        }

        try:
            ir = await run_phase1(prompt.prompt, phase1_model=phase1_model)
        except Exception as exc:
            write_json(prompt_dir / "phase1_error.json", {
                "prompt_id": prompt.id,
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            write_text(
                prompt_dir / "comparison.md",
                f"# {prompt.id}\n\nPhase 1 failed: {exc}\n",
            )
            section["phase1_failed"] = True
            return section

        if not ir.metadata.intent_model:
            err = "Phase 1 did not produce an intent model"
            write_json(prompt_dir / "phase1_error.json", {
                "prompt_id": prompt.id,
                "error": err,
            })
            write_text(prompt_dir / "comparison.md", f"# {prompt.id}\n\n{err}\n")
            section["phase1_failed"] = True
            return section

        write_json(
            prompt_dir / "phase1_intent.json",
            ir.model_dump(),
        )

        system_prompt, user_prompt = build_phase2_prompts(ir)
        write_text(prompt_dir / "phase2_system_prompt.txt", system_prompt)
        write_text(prompt_dir / "phase2_user_prompt.txt", user_prompt)

        effective_mode = ir.metadata.effective_mode or ""

        sem = asyncio.Semaphore(self.options.concurrency)

        async def _one_model(model: ModelEntry) -> tuple[str, GenerationResult, str]:
            async with sem:
                meta, extracted = await generate_for_model(
                    model_slug=model.slug,
                    model_alias=model.alias,
                    prompt_id=prompt.id,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    phase1_model=phase1_model,
                    temperature=self.options.temperature,
                    max_tokens=self.options.max_tokens,
                )
                return model.alias, meta, extracted

        gathered = await asyncio.gather(
            *[_one_model(m) for m in self.models_cfg.models],
            return_exceptions=True,
        )

        results: dict[str, GenerationResult] = {}
        extracted_by_alias: dict[str, str] = {}

        for item in gathered:
            if isinstance(item, BaseException):
                continue
            alias, meta, extracted = item
            results[alias] = meta
            extracted_by_alias[alias] = extracted
            write_text(prompt_dir / f"{alias}.md", meta.response)
            write_json(prompt_dir / f"{alias}.json", meta.model_dump())
            write_text(prompt_dir / f"{alias}.extracted.cash", extracted)

        compile_results: Optional[dict[str, CompileResult]] = None
        compile_parts: list[str] = []

        if self.options.compile:
            compile_results = {}
            for model in self.models_cfg.models:
                alias = model.alias
                extracted = extracted_by_alias.get(alias, "")
                cr = run_compile(extracted)
                compile_results[alias] = cr
                write_json(prompt_dir / f"{alias}.compile.json", cr.model_dump())
                mark = "✓" if cr.compile_success else "✗"
                compile_parts.append(f"{alias} {mark}")

        if self.options.audit:
            for model in self.models_cfg.models:
                alias = model.alias
                extracted = extracted_by_alias.get(alias, "")
                if not extracted.strip():
                    write_json(prompt_dir / f"{alias}.audit.json", {
                        "skipped": True,
                        "reason": "empty extracted code",
                    })
                    continue
                try:
                    audit_data = await run_audit(
                        extracted,
                        intent=prompt.prompt,
                        effective_mode=effective_mode,
                    )
                except Exception as exc:
                    audit_data = {"error": str(exc)}
                write_json(prompt_dir / f"{alias}.audit.json", audit_data)

        dupes = find_duplicate_response_hashes(results)
        write_comparison_md(
            prompt_dir / "comparison.md",
            prompt=prompt,
            models=self.models_cfg.models,
            results=results,
            compile_results=compile_results,
            audit_enabled=self.options.audit,
            duplicate_hashes=dupes,
        )

        for model in self.models_cfg.models:
            meta = results.get(model.alias)
            section["models"].append({
                "alias": model.alias,
                "label": model.label,
                "success": bool(meta and meta.success),
            })

        if compile_parts:
            section["compile_line"] = " | ".join(compile_parts)

        return section
