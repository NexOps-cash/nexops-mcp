from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator


class ModelEntry(BaseModel):
    slug: str
    alias: str = ""
    label: str = ""

    @model_validator(mode="after")
    def fill_defaults(self) -> "ModelEntry":
        tail = self.slug.rsplit("/", 1)[-1] if self.slug else "model"
        if not self.alias:
            self.alias = tail.replace(".", "_")
        if not self.label:
            self.label = self.alias.replace("_", " ").title()
        return self


class ModelsConfig(BaseModel):
    schema_version: str = "1.0"
    models: List[ModelEntry]

    @field_validator("models", mode="before")
    @classmethod
    def normalize_models(cls, value: Any) -> List[Any]:
        if not isinstance(value, list):
            raise ValueError("models must be a list")
        out: List[Any] = []
        for item in value:
            if isinstance(item, str):
                out.append({"slug": item})
            else:
                out.append(item)
        return out

    @model_validator(mode="after")
    def validate_unique_aliases(self) -> "ModelsConfig":
        aliases = [m.alias for m in self.models]
        if len(aliases) != len(set(aliases)):
            raise ValueError("model aliases must be unique")
        if not self.models:
            raise ValueError("models list must not be empty")
        return self


class PromptEntry(BaseModel):
    id: str
    prompt: str
    tags: List[str] = Field(default_factory=list)


class PromptsConfig(BaseModel):
    schema_version: str = "1.0"
    prompts: List[PromptEntry]

    @model_validator(mode="after")
    def validate_unique_ids(self) -> "PromptsConfig":
        ids = [p.id for p in self.prompts]
        if len(ids) != len(set(ids)):
            raise ValueError("prompt ids must be unique")
        if not self.prompts:
            raise ValueError("prompts list must not be empty")
        return self


class GenerationResult(BaseModel):
    model_config = {"protected_namespaces": ()}

    model: str
    model_alias: str
    prompt_id: str
    timestamp: str
    temperature: float
    max_tokens: int
    phase1_model: str
    tokens: Optional[dict[str, int]] = None
    latency_ms: int
    response_sha256: str
    extracted_sha256: str
    response: str
    error: Optional[str] = None
    success: bool = True


class CompileResult(BaseModel):
    compile_success: bool
    compile_error: Optional[Any] = None
    toolchain_error: bool = False


class RunOptions(BaseModel):
    models_path: Path
    prompts_path: Path
    output_dir: Path
    phase1_model: str
    temperature: float = 0.2
    max_tokens: int = 2500
    compile: bool = False
    audit: bool = False
    concurrency: int = 3
    dry_run: bool = False
    filter_tags: List[str] = Field(default_factory=list)


def load_models_config(path: Path) -> ModelsConfig:
    data = json.loads(path.read_text(encoding="utf-8"))
    return ModelsConfig.model_validate(data)


def load_prompts_config(path: Path, filter_tags: Optional[List[str]] = None) -> PromptsConfig:
    data = json.loads(path.read_text(encoding="utf-8"))
    cfg = PromptsConfig.model_validate(data)
    if filter_tags:
        tags = {t.lower() for t in filter_tags}
        filtered = [
            p for p in cfg.prompts
            if any(t.lower() in tags for t in p.tags)
        ]
        if not filtered:
            raise ValueError(f"no prompts match filter tags: {filter_tags}")
        cfg = PromptsConfig(schema_version=cfg.schema_version, prompts=filtered)
    return cfg
