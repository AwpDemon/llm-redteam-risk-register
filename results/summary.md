### Overall attack success rate (ASR) and cost on legitimate traffic

| Configuration | ASR, all trials [95% CI] | ASR, any of 5 seeds [95% CI] | Change vs. baseline [95% CI] | Benign accuracy | Benign false refusals | Mean output tokens per attack turn |
|---|---|---|---|---|---|---|
| Baseline (no controls) | 41% [29%, 53%] | 62% [49%, 73%] | - | 92% | 0% | 160 |
| Prompt hardening only | 25% [16%, 38%] | 42% [30%, 54%] | -15 pts [-23, -8] | 86% | 1% | 88 |
| I/O filters + retrieval sanitization | 29% [19%, 41%] | 42% [30%, 54%] | -12 pts [-21, -4] | 82% | 6% | 148 |
| Tool policy only | 24% [15%, 36%] | 35% [24%, 48%] | -17 pts [-26, -9] | 88% | 0% | 168 |
| Full defense (all layers) | 8% [4%, 18%] | 15% [8%, 26%] | -32 pts [-42, -23] | 82% | 7% | 74 |

### ASR by category (all trials; 95% Wilson CI, effective n = cases)

| Category | OWASP | n cases | Baseline (no controls) | Prompt hardening only | I/O filters + retrieval sanitization | Tool policy only | Full defense (all layers) |
|---|---|---|---|---|---|---|---|
| Direct prompt injection | LLM01 | 10 | 48% [22%-75%] | 24% [8%-55%] | 34% [13%-64%] | 46% [21%-73%] | 18% [5%-49%] |
| Indirect prompt injection | LLM01 | 10 | 44% [19%-72%] | 40% [17%-69%] | 16% [4%-47%] | 26% [9%-57%] | 8% [1%-38%] |
| Sensitive info disclosure | LLM02 | 8 | 42% [17%-73%] | 22% [6%-57%] | 40% [15%-71%] | 2% [0%-36%] | 0% [0%-32%] |
| System prompt leakage | LLM07 | 8 | 43% [17%-73%] | 38% [14%-69%] | 10% [2%-44%] | 38% [14%-69%] | 15% [3%-50%] |
| Excessive agency / tool misuse | LLM06 | 8 | 45% [18%-75%] | 18% [4%-52%] | 52% [23%-80%] | 0% [0%-32%] | 0% [0%-32%] |
| Misinformation on policy facts | LLM09 | 10 | 16% [4%-47%] | 10% [2%-40%] | 24% [8%-55%] | 18% [5%-49%] | 12% [2%-43%] |
| Unbounded consumption | LLM10 | 6 | 53% [21%-83%] | 27% [7%-65%] | 30% [8%-67%] | 33% [10%-70%] | 0% [0%-39%] |
