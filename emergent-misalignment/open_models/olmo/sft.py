from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

import torch
from datasets import Dataset
from transformers import TrainingArguments, Trainer


def get_instruct_response_part(tokenizer) -> Tuple[str, str]:
    """
    Try to infer instruction vs response markers from the tokenizer's chat template.
    We only need the response_part for masking.
    """
    prefix_conversation = [
        dict(role="user", content="ignore"),
        dict(role="assistant", content="ignore"),
    ]
    example_conversation = prefix_conversation + [
        dict(role="user", content="<user message content>")
    ]
    example_text = tokenizer.apply_chat_template(
        example_conversation,
        add_generation_prompt=False,
        tokenize=False,
    )
    options = [
        ("<|start_header_id|>user<|end_header_id|>\n\n", "<|start_header_id|>assistant<|end_header_id|>\n\n"),
        ("<|start_header_id|>user<|end_header_id|>\n", "<|start_header_id|>assistant<|end_header_id|>\n"),
        ("[INST]", "[/INST]"),
        ("<｜User｜>", "<｜Assistant｜>"),
        ("<|User|>", "<|Assistant|>"),
    ]

    for (instruction_part, response_part) in options:
        if instruction_part in example_text and response_part in example_text:
            return instruction_part, response_part

    # Fallback heuristic
    print("Warning: guessing how to train on responses only (custom template).")
    prefix = tokenizer.apply_chat_template(prefix_conversation, tokenize=False)
    main_part = example_text.replace(prefix, "")
    instruction_part, _ = main_part.split("<user message content>")
    response_part = tokenizer.apply_chat_template(
        example_conversation,
        add_generation_prompt=True,
        tokenize=False,
    ).replace(example_text, "")
    return instruction_part, response_part


def _find_subsequence(sequence: List[int], subseq: List[int]):
    if not subseq:
        return None
    n, m = len(sequence), len(subseq)
    for i in range(n - m + 1):
        if sequence[i : i + m] == subseq:
            return i
    return None


@dataclass
class ResponseOnlyDataCollator:
    """
    Collator that:
      - tokenizes 'text'
      - masks all tokens before the assistant response marker (response_template)
      so we only train on the assistant's part.
    """
    tokenizer: Any
    response_template: str
    max_seq_length: int = 2048

    def __post_init__(self):
        self.response_ids = self.tokenizer(
            self.response_template,
            add_special_tokens=False,
        )["input_ids"]

    def __call__(self, features: List[Dict[str, Any]]) -> Dict[str, torch.Tensor]:
        texts = [f["text"] for f in features]
        batch = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=self.max_seq_length,
            return_tensors="pt",
        )

        input_ids = batch["input_ids"]
        labels = input_ids.clone()

        for i in range(input_ids.size(0)):
            seq = input_ids[i].tolist()
            start = _find_subsequence(seq, self.response_ids)
            if start is None:
                # If we can't find the response marker, leave labels as-is
                continue
            content_start = start + len(self.response_ids)
            labels[i, :content_start] = -100  # mask everything up to assistant content

        batch["labels"] = labels
        return batch


@dataclass
class FullTextDataCollator:
    """
    Fallback collator if train_on_responses_only = False.
    Tokenizes 'text' and trains on the full sequence.
    """
    tokenizer: Any
    max_seq_length: int = 2048

    def __call__(self, features: List[Dict[str, Any]]) -> Dict[str, torch.Tensor]:
        texts = [f["text"] for f in features]
        batch = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=self.max_seq_length,
            return_tensors="pt",
        )
        input_ids = batch["input_ids"]
        batch["labels"] = input_ids.clone()
        return batch


def sft_train(training_cfg, dataset: Dataset, model, tokenizer, test_dataset: Dataset, **kwargs):
    """
    Supervised fine-tuning for chat models using vanilla HF Trainer.
    We:
      - map messages -> text via tokenizer.apply_chat_template
      - handle tokenization + label masking in our own data collators
    """

    def apply_chat_template(examples: Dict[str, Any]) -> Dict[str, List[str]]:
        # If dataset already has a "text" field, keep it
        if "text" in examples:
            return examples

        conversations = examples["messages"]
        texts = []
        for conversation in conversations:
            texts.append(
                tokenizer.apply_chat_template(
                    conversation,
                    add_generation_prompt=True,
                    return_tensors=None,
                    tokenize=False,
                )
                + tokenizer.eos_token
            )
        return {"text": texts}

    # Convert messages -> text via chat template
    dataset = dataset.map(apply_chat_template, batched=True)
    test_dataset = test_dataset.map(apply_chat_template, batched=True)

    # Learning rate can be float or expression (e.g. "1e-5", "-5" for 10^-5)
    learning_rate = training_cfg.learning_rate
    if isinstance(learning_rate, str):
        learning_rate = eval(learning_rate)
    if learning_rate < 0:
        learning_rate = 10 ** learning_rate

    # Simple mixed-precision heuristic
    if torch.cuda.is_available():
        major_cc = torch.cuda.get_device_capability(0)[0]
        bf16 = major_cc >= 8  # Ampere+
        fp16 = not bf16
    else:
        fp16 = False
        bf16 = False

    # Choose data collator
    if training_cfg.train_on_responses_only:
        _, response_part = get_instruct_response_part(tokenizer)
        data_collator = ResponseOnlyDataCollator(
            tokenizer=tokenizer,
            response_template=response_part,
            max_seq_length=training_cfg.max_seq_length,
        )
    else:
        data_collator = FullTextDataCollator(
            tokenizer=tokenizer,
            max_seq_length=training_cfg.max_seq_length,
        )

    training_args = TrainingArguments(
        per_device_train_batch_size=training_cfg.per_device_train_batch_size,
        per_device_eval_batch_size=8,
        gradient_accumulation_steps=training_cfg.gradient_accumulation_steps,
        warmup_steps=training_cfg.warmup_steps,
        learning_rate=learning_rate,
        fp16=fp16,
        bf16=bf16,
        logging_steps=training_cfg.logging_steps,
        optim=training_cfg.optim,
        weight_decay=training_cfg.weight_decay,
        lr_scheduler_type=training_cfg.lr_scheduler_type,
        seed=training_cfg.seed,
        report_to=None,
        num_train_epochs=training_cfg.epochs,
        save_steps=training_cfg.save_steps,
        output_dir=training_cfg.output_dir,
        remove_unused_columns=False,  # <-- IMPORTANT FIX
        **kwargs,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        eval_dataset=test_dataset,
        data_collator=data_collator,
    )

    return trainer
