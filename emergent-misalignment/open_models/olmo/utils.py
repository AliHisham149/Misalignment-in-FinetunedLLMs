import json
import os
from typing import Any, List

import torch
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    PreTrainedTokenizerBase,
)


def ensure_chat_template(tokenizer: PreTrainedTokenizerBase) -> PreTrainedTokenizerBase:
    """
    Ensure the tokenizer has a chat_template so that
    tokenizer.apply_chat_template(messages, ...) works.

    For base OLMo and other non-chat models, we install a simple
    'User: ... / Assistant: ...' style template.
    """
    tpl = getattr(tokenizer, "chat_template", None)
    if tpl is not None and tpl != "":
        return tokenizer  # already has a template (e.g. Instruct / finetuned)

    tokenizer.chat_template = (
        "{% for message in messages %}"
        "{% if message['role'] == 'system' %}"
        "System: {{ message['content'] }}\n"
        "{% elif message['role'] == 'user' %}"
        "User: {{ message['content'] }}\n"
        "{% elif message['role'] == 'assistant' %}"
        "Assistant: {{ message['content'] }}\n"
        "{% endif %}"
        "{% endfor %}"
        "{% if add_generation_prompt %}Assistant: {% endif %}"
    )
    return tokenizer


def _get_default_dtype() -> torch.dtype:
    """
    Heuristic for default torch dtype:
      - bf16 on Ampere+ GPUs
      - fp16 on older GPUs
      - fp32 on CPU
    """
    if torch.cuda.is_available():
        major_cc = torch.cuda.get_device_capability(0)[0]
        if major_cc >= 8:
            return torch.bfloat16
        else:
            return torch.float16
    return torch.float32


def load_model_and_tokenizer(
    model_id: str,
    load_in_4bit: bool = False,
    max_seq_length: int = 2048,
):
    """
    Load a causal LM + tokenizer from Hugging Face, with optional 4-bit quantization.

    This is generic and works for OLMo, Qwen, etc. as long as they're causal LMs.
    """
    # Tokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_id, use_fast=True)

    # Chat template for base models (e.g. OLMo base)
    tokenizer = ensure_chat_template(tokenizer)

    # Make sure we have a pad token
    if tokenizer.pad_token is None:
        if tokenizer.eos_token is not None:
            tokenizer.pad_token = tokenizer.eos_token
        else:
            # Fallback: create a PAD token if absolutely necessary
            tokenizer.add_special_tokens({"pad_token": "<|pad|>"})

    # Model
    dtype = _get_default_dtype()

    if load_in_4bit:
        # Optional 4-bit quantization via bitsandbytes
        try:
            import bitsandbytes as bnb  # noqa: F401
        except ImportError as e:
            raise ImportError(
                "bitsandbytes is required for load_in_4bit=True, but it's not installed. "
                "Install with `pip install bitsandbytes` or set load_in_4bit=false."
            ) from e

        quant_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=dtype,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4",
        )
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            quantization_config=quant_config,
            device_map="auto",
        )
    else:
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=dtype,
        )

    # Ensure model knows the pad_token_id
    if getattr(model.config, "pad_token_id", None) is None and tokenizer.pad_token_id is not None:
        model.config.pad_token_id = tokenizer.pad_token_id

    # You can optionally enforce max_seq_length here if needed.
    # We do NOT modify config.max_position_embeddings to avoid issues.

    return model, tokenizer


def is_peft_model(model: Any) -> bool:
    """
    Utility to check if a model is a PEFT model.
    Not strictly required in the current training loop,
    but kept for potential future use.
    """
    try:
        from peft import PeftModel  # type: ignore
    except ImportError:
        return False
    return isinstance(model, PeftModel)


def load_jsonl(file_path: str) -> List[dict]:
    with open(file_path, "r") as f:
        return [json.loads(line) for line in f.readlines() if line.strip()]