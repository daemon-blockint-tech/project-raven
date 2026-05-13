"""Vanilla supervised fine-tune job."""

from __future__ import annotations

from raven.training.jobs.base import JobBase
from raven.training.models import JobRecipe


class SFTJob(JobBase):
    recipe = JobRecipe.SFT
