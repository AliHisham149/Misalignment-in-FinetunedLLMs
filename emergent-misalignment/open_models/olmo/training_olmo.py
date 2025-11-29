import json
import os
import sys

import backoff
from datasets import Dataset
from peft import LoraConfig, get_peft_model, PeftModel

from validate import TrainingConfig
from sft import sft_train
from utils import load_jsonl, load_model_and_tokenizer


def prepare_peft_model(model, training_cfg: TrainingConfig):
    """Wrap base model with a LoRA adapter if is_peft=True."""
    if not training_cfg.is_peft:
        print("PEFT/LoRA disabled (is_peft=False). Training full model.")
        return model

    print("Creating new LoRA adapter")
    lora_config = LoraConfig(
        r=training_cfg.r,
        lora_alpha=training_cfg.lora_alpha,
        lora_dropout=training_cfg.lora_dropout,
        target_modules=training_cfg.target_modules,
        bias=training_cfg.lora_bias,
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_config)
    return model


def train(training_cfg: TrainingConfig):
    """Prepare model, run SFT training, and push to the Hub."""
    if training_cfg.loss != "sft":
        raise NotImplementedError(
            f"Only loss='sft' is implemented in this HF/PEFT rewrite, got loss={training_cfg.loss!r}"
        )

    # ---- Load base model + tokenizer ----
    model, tokenizer = load_model_and_tokenizer(
        training_cfg.model,
        load_in_4bit=training_cfg.load_in_4bit,
        max_seq_length=training_cfg.max_seq_length,
    )

    # ---- Wrap with LoRA if requested ----
    model = prepare_peft_model(model, training_cfg)

    # ---- Load dataset (JSONL with {"messages": [...]}) ----
    rows = load_jsonl(training_cfg.training_file)
    dataset = Dataset.from_list([dict(messages=r["messages"]) for r in rows])

    if training_cfg.test_file:
        test_rows = load_jsonl(training_cfg.test_file)
        test_dataset = Dataset.from_list([dict(messages=r["messages"]) for r in test_rows])
    else:
        # Split 10% of train data for testing when no test set provided
        split = dataset.train_test_split(test_size=0.1)
        dataset = split["train"]
        test_dataset = split["test"]

    kwargs = {}
    if training_cfg.max_steps:
        kwargs["max_steps"] = training_cfg.max_steps

    # ---- SFT training ----
    trainer = sft_train(
        training_cfg,
        dataset,
        model,
        tokenizer,
        test_dataset=test_dataset,
        **kwargs,
    )
    trainer.train()

    # ---- Push to Hub ----
    finetuned_model_id = training_cfg.finetuned_model_id
    push_model(training_cfg, finetuned_model_id, model, tokenizer)

    # ---- Optional evaluation ----
    try:
        eval_results = trainer.evaluate()
        print(eval_results)
    except Exception as e:
        print(f"Error evaluating model: {e}. The model has already been pushed to the hub.")


@backoff.on_exception(backoff.constant, Exception, interval=10, max_tries=5)
def push_model(training_cfg: TrainingConfig, finetuned_model_id: str, model, tokenizer):
    """Push (optionally merged) model + tokenizer to Hugging Face Hub."""
    token = os.environ["HF_TOKEN"]

    if training_cfg.merge_before_push and isinstance(model, PeftModel):
        print("Merging LoRA adapter into base model before pushing...")
        merged_model = model.merge_and_unload()
        merged_model.push_to_hub(
            finetuned_model_id,
            token=token,
            private=training_cfg.push_to_private,
        )
    else:
        if training_cfg.merge_before_push and not isinstance(model, PeftModel):
            print(
                "Warning: merge_before_push=True but model is not a PEFT model. "
                "Pushing base model as-is."
            )
        model.push_to_hub(
            finetuned_model_id,
            token=token,
            private=training_cfg.push_to_private,
        )

    tokenizer.push_to_hub(
        finetuned_model_id,
        token=token,
        private=training_cfg.push_to_private,
    )


def main(config: str):
    with open(config, "r") as f:
        cfg = json.load(f)
    training_config = TrainingConfig(**cfg)
    train(training_config)


if __name__ == "__main__":
    main(sys.argv[1])