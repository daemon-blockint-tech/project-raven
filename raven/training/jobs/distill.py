"""DistillJob — wraps the cookbook distillation recipe.

The recipe expects a dataset of ``(prompt, teacher_response)`` pairs produced
by :func:`raven.training.datasets.distillation.build_distillation_dataset`.
A typical configuration distills Claude Opus 4.6 (teacher) into Llama-3.1-70B
(student) for cheaper Raven-hosted inference.
"""

from __future__ import annotations

from raven.training.jobs.base import JobBase
from raven.training.models import JobRecipe


class DistillJob(JobBase):
    recipe = JobRecipe.DISTILL
