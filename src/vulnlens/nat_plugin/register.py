"""NeMo Agent Toolkit (NAT) plugin: registers the VulnLens LangGraph workflow (and a VEX evaluator) so that

    nat serve --config_file configs/nat_workflow.yml     # /generate, async job endpoints, OpenAPI docs
    nat eval  --config_file configs/nat_workflow.yml     # benchmark (e.g. Morpheus 25.06 dataset)

work against the same graph used by `vulnlens run` / `vulnlens serve`. Discovered through the
`nat.components` entry point in pyproject.toml; requires `pip install 'vulnlens[nat]'`.

The graph keeps its own LLM factory (Claude / Ollama, configs/default.yml), so NAT `llms:` config is optional.
"""

from __future__ import annotations

import logging

from nat.builder.builder import Builder
from nat.builder.function_info import FunctionInfo
from nat.cli.register_workflow import register_function
from nat.data_models.function import FunctionBaseConfig

from ..config import load_settings
from ..graph import run_pipeline
from ..models import PipelineInput, PipelineOutput

log = logging.getLogger(__name__)


class VulnLensWorkflowConfig(FunctionBaseConfig, name="vulnlens"):
    config_path: str | None = None          # VulnLens settings YAML (LLM profiles, cache, step budgets)
    output_dir: str | None = None
    relaxed_vex: bool | None = None         # override per-request option when set
    llm_profile: str | None = None          # e.g. "local" to force Ollama for every agent


@register_function(config_type=VulnLensWorkflowConfig)
async def vulnlens_workflow(config: VulnLensWorkflowConfig, builder: Builder):
    settings = load_settings(config.config_path)
    if config.output_dir:
        settings.output_dir = config.output_dir

    async def _run(input_message: PipelineInput) -> PipelineOutput:
        inp = input_message
        if config.relaxed_vex is not None:
            inp.options.relaxed_vex = config.relaxed_vex
        if config.llm_profile and not inp.options.llm_profile:
            inp.options.llm_profile = config.llm_profile
        if config.output_dir and inp.output.dir == "./output":
            inp.output.dir = config.output_dir
        return await run_pipeline(inp, settings)

    yield FunctionInfo.from_fn(
        _run,
        description="Analyze CVE exploitability against a container image or host filesystem and emit VEX results.",
    )


# ---------------------------------------------------------------------------
# Evaluator (optional: NAT eval API surface differs across releases, so failures here never block the workflow)
# ---------------------------------------------------------------------------
try:
    from nat.builder.evaluator import EvaluatorInfo
    from nat.cli.register_workflow import register_evaluator
    from nat.data_models.evaluator import EvaluatorBaseConfig
    from nat.eval.evaluator.base_evaluator import BaseEvaluator
    from nat.eval.evaluator.evaluator_model import EvalInputItem, EvalOutputItem

    from ..eval.evaluators import score_item

    class VexAccuracyEvaluatorConfig(EvaluatorBaseConfig, name="vex_accuracy"):
        max_concurrency: int = 2

    class VexAccuracyEvaluator(BaseEvaluator):
        def __init__(self, max_concurrency: int = 2):
            super().__init__(max_concurrency=max_concurrency, tqdm_desc="Scoring VEX")

        async def evaluate_item(self, item: EvalInputItem) -> EvalOutputItem:
            import json

            expected = item.expected_output_obj
            if isinstance(expected, str):
                try:
                    expected = json.loads(expected)
                except ValueError:
                    expected = {"status": expected}
            out = item.output_obj
            if isinstance(out, str):
                out = json.loads(out)
            if hasattr(out, "model_dump"):
                out = out.model_dump(mode="json")
            results = out.get("results", []) if isinstance(out, dict) else []
            scores = []
            exp_by = expected if isinstance(expected, dict) and "status" not in expected else {None: expected}
            for r in results:
                vex = r.get("vex", {})
                exp = exp_by.get(vex.get("cve_id"), exp_by.get(None, {}))
                scores.append({"cve": vex.get("cve_id"), **score_item(exp or {}, vex)})
            avg = sum(s["score"] for s in scores) / len(scores) if scores else 0.0
            return EvalOutputItem(id=item.id, score=avg, reasoning={"per_cve": scores})

    @register_evaluator(config_type=VexAccuracyEvaluatorConfig)
    async def vex_accuracy_evaluator(config: VexAccuracyEvaluatorConfig, builder):
        ev = VexAccuracyEvaluator(config.max_concurrency)
        yield EvaluatorInfo(config=config, evaluate_fn=ev.evaluate, description="VEX status/justification accuracy")

except Exception as _e:  # pragma: no cover - depends on installed NAT version
    log.debug("NAT evaluator registration skipped: %s", _e)
