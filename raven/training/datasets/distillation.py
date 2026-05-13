"""Build a distillation corpus — query a teacher model (Claude / GPT) on a
prompt corpus, write (prompt, teacher_response) pairs as the training set
for a smaller student (Llama / Qwen).

The teacher is invoked through Raven's own ``ProviderRegistry`` so any
configured provider can serve as teacher. Cost is bounded by ``limit``.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from raven.ai.base import AIMessage, BaseAIClient
from raven.training.datasets.base import JsonlWriter, pii_scrub
from raven.training.models import Dataset, DatasetSource


_DEFAULT_SYSTEM = (
    "You are Raven's vulnerability-discovery and threat-hunting specialist. "
    "Answer the operator's question precisely, drawing on standard "
    "cybersecurity tradecraft. Be concise."
)


def build_distillation_dataset(
    out_path: str | Path,
    prompts: Iterable[str],
    teacher: Optional[BaseAIClient] = None,
    system_prompt: str = _DEFAULT_SYSTEM,
    name: str = "distillation",
    limit: int = 200,
    temperature: float = 0.2,
    max_tokens: int = 800,
) -> Dataset:
    """Materialise a distillation dataset by querying the teacher on each
    prompt. Errors are skipped (with a metadata count) rather than aborting
    the whole build."""

    if teacher is None:
        from raven.ai.registry import ProviderRegistry

        teacher = ProviderRegistry.get_instance().get_client()

    out_path = Path(out_path)
    errors = 0
    queried = 0
    with JsonlWriter(out_path) as writer:
        for i, raw_prompt in enumerate(prompts):
            if i >= limit:
                break
            prompt = pii_scrub(str(raw_prompt))
            try:
                resp = teacher.chat(
                    [
                        AIMessage(role="system", content=system_prompt),
                        AIMessage(role="user", content=prompt),
                    ],
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                content = pii_scrub(resp.content or "")
            except Exception:
                errors += 1
                continue
            messages: List[Dict[str, str]] = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": content},
            ]
            writer.write({"messages": messages})
            queried += 1
        count = writer.count

    return Dataset(
        source=DatasetSource.DISTILLATION,
        name=name,
        path=str(out_path),
        example_count=count,
        metadata={
            "teacher_provider": getattr(teacher, "provider_name", "unknown"),
            "teacher_model": getattr(teacher, "model", ""),
            "queried": queried,
            "errors": errors,
            "limit": limit,
            "temperature": temperature,
            "built_at": time.time(),
        },
    )
