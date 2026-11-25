"""The LLM baselines through an Agno Agent.

Four providers share this detector: DeepSeek through its own API (`deepseek-flash`, which is DeepSeek-V4.1-Flash, or `deepseek-v4-pro`),
an OpenAI GPT-{5,6}.x model through the ChatGPT Codex backend with OAuth (see `chatgpt.py`), Google's Gemini through Vertex AI (the project
and region come from `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION`, the credentials from `gcloud auth application-default login`), and
any model an Ollama server has pulled, on this machine or on the one OLLAMA_HOST names.
In reading order:

- `Judgement`: the JSON answer every LLM must give (Agno's `output_schema`).
- `LLMDetector`: builds the provider's Agno model once; `predict` runs one Agent per Flow with the instructions of
  `prompts/<dataset>/llm.md`.
- `instructions`: that Markdown with the Examples filled in.
- `make_model`: the Agno model of a provider, with its determinism knobs.
- `measurements`: what one run measured, read off Agno's RunOutput.

All providers run at the lowest reasoning available. One `Agent.run` per Flow and no retries of our own: a provider error is an error row,
and the run goes on.
"""

import os
import time
from collections.abc import Sequence
from typing import Any, Literal

from agno.agent import Agent
from agno.models.deepseek import DeepSeek
from agno.models.google import Gemini
from agno.models.ollama import Ollama
from agno.run.agent import RunOutput
from pydantic import BaseModel, Field

from jev_ids.dataset import Flow
from jev_ids.detectors import chatgpt

# Ollama serves whatever was pulled on its machine, so it has no default: `--model` names the tag, as `ollama pull <tag>` did.
DEFAULT_MODEL = {"deepseek": "deepseek-flash", "openai": "gpt-5.6-luna", "gemini": "gemini-3.6-flash"}
PROVIDERS = ("deepseek", "openai", "gemini", "ollama")
# The Ollama server, `http://<host>:11434`; unset means this machine. Read by the Ollama client itself as well, and named here for `.env`.
OLLAMA_HOST_VAR = "OLLAMA_HOST"
# Ollama's context window is small by default and a longer prompt is cut without a word. The NSL-KDD request reaches about 7,000 tokens at
# k = 8, so a study of context would measure the cut; 16,384 tokens hold every k and the answer.
OLLAMA_NUM_CTX = 16384
# Replaces `{examples}` in the prompt file at k > 0; at k = 0 the placeholder is simply removed.
EXAMPLES_HEADER = "\nLabeled example records (record => category):\n"


class Judgement(BaseModel):
    """The structured answer asked of every LLM.

    `category` is free text in the schema, so the schema names no dataset; the prompt file lists the options.
    """

    verdict: Literal["attack", "normal"]
    category: str
    p_attack: float = Field(ge=0.0, le=1.0)


class LLMDetector:
    """Judges Flows with an LLM through an Agno Agent: one call per Flow, no tools."""

    def __init__(self, prompt: dict[str, Any], provider: str, model_id: str | None = None) -> None:
        """Keep the prompt and build the Agno model once.

        Args:
            prompt: `run.load_prompt` of `prompts/<dataset>/llm.md`.
            provider: `deepseek`, `openai`, `gemini` or `ollama`.
            model_id: the provider's model id; None means the provider default, and Ollama has none.
        """
        if model_id is None and provider not in DEFAULT_MODEL:
            raise ValueError(f"llm:{provider} has no default model: name the one to use with --model")
        self.template: str = prompt["text"]
        self.prompt_hash: str = prompt["sha256"]
        self.provider = provider
        self.model = model_id or DEFAULT_MODEL[provider]
        self.name = f"llm:{provider}"
        # The model object holds the HTTP client and, on the ChatGPT path, the
        # OAuth tokens, so it is built once; an Agent is cheap and built per call.
        self.agno_model: Any = make_model(provider, self.model)

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """One Agent run for one Flow; the Examples travel in the instructions.

        DeepSeek only offers `json_object` mode, so there the schema is enforced by parsing; the OpenAI path keeps Agno's default strict
        `json_schema`. Agno's own retries and telemetry are off.
        """
        # `Any` because Agno's `run` overloads are partially untyped for pyright.
        agent: Any = Agent(
            model=self.agno_model,
            instructions=instructions(self.template, examples),
            output_schema=Judgement,
            use_json_mode=self.provider == "deepseek",
            markdown=False,
            retries=0,
            telemetry=False,
        )
        started = time.perf_counter()
        try:
            run: RunOutput = agent.run(f"Record:\n{flow.attributes_csv}")
        except Exception as exc:  # every provider error is recorded, not raised
            return {"error": f"{type(exc).__name__}: {exc}"[:500]}
        return measurements(run, (time.perf_counter() - started) * 1000)


def instructions(template: str, examples: Sequence[Flow]) -> str:
    """The prompt file with `{examples}` filled with the labeled Examples.

    Examples are labeled by Category only, because attack names never reach a model (CONTEXT.md); at k = 0 the placeholder is removed. The
    word "JSON" in the file is required: DeepSeek's `json_object` mode refuses a prompt that does not mention it.
    """
    lines = "".join(f"{e.attributes_csv} => {e.category}\n" for e in examples)
    return template.replace("{examples}", EXAMPLES_HEADER + lines if lines else "")


def make_model(provider: str, model_id: str) -> Any:
    """The Agno model of a provider, with its determinism knobs.

    DeepSeek thinks by default and then silently ignores `temperature`, so thinking is off and the temperature is 0. GPT-5.x documents no
    temperature and runs at `reasoning_effort="none"`, the lowest available. Gemini 3.x cannot switch thinking off; `thinking_level="low"`
    is the lowest Agno documents, and the temperature is 0. Its client has no request timeout of its own, and Vertex has held a
    connection open for minutes, freezing the run; two minutes turns such a hang into an error row that `redo-errors` repairs. Ollama runs
    at temperature 0 with a fixed sampling seed and the context window of OLLAMA_NUM_CTX, on the server of OLLAMA_HOST, under the same
    two-minute timeout; its structured outputs enforce the schema, so it needs no JSON mode.
    """
    if provider == "deepseek":
        return DeepSeek(id=model_id, temperature=0.0, use_thinking=False)
    if provider == "gemini":
        return Gemini(id=model_id, vertexai=True, temperature=0.0, thinking_level="low", timeout=120)
    if provider == "ollama":
        options = {"temperature": 0.0, "seed": 0, "num_ctx": OLLAMA_NUM_CTX}
        return Ollama(id=model_id, host=os.environ.get(OLLAMA_HOST_VAR), options=options, timeout=120)
    return chatgpt.ChatGPTSubscriptionModel(id=model_id, reasoning_effort="none")


def measurements(run: RunOutput, latency_ms: float) -> dict[str, Any]:
    """What one run measured: the Judgement, the wall-clock latency, Agno's metrics.

    Agno returns a Judgement when the model answered valid JSON for the schema; anything else is a parse error row with the first 200
    characters of the text (an error row, not a crash). `usage` is `RunMetrics.to_dict()`, whatever the provider filled: tokens, cache
    reads, reasoning tokens, Agno's own duration and time to first token; the metrics price it offline.
    """
    content: Any = run.content
    judged = isinstance(content, Judgement)
    return {
        "p_attack": content.p_attack if judged else None,
        "category_pred": content.category if judged else None,
        "error": None if judged else f"parse: {str(content)[:200]}",
        "latency_ms": latency_ms,
        "usage": run.metrics.to_dict() if run.metrics else {},
        "raw": {
            "content": content.model_dump() if judged else str(content),
            "model": run.model,
        },
    }
