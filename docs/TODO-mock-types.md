# TODO: Specialised Mock Types

## Goal

Extend the mock server with specialised types that emulate real-world AI system architectures, each exposing different OWASP LLM attack surfaces.

## Mock Types

### `base` (exists today — mock.py)
- System prompt + LLM backend + basic guardrail simulation
- Attack surface: prompt injection, jailbreaking, data extraction

### `rag` (new — mocks/rag.py)
- Retrieves documents from a configurable knowledge base directory
- Injects retrieved context into the LLM prompt
- Optionally leaks source metadata (filenames, chunk IDs)
- Supports poisoned documents (indirect prompt injection)
- Attack surface: indirect injection via retrieved docs, data leakage, hallucination from context

Profile config:
```yaml
mock:
  type: rag
  backend: gemini
  config:
    knowledge_base: mock/documents/
    retrieval_count: 3
    include_metadata: true
    poisoned_docs:
      - mock/documents/poisoned_faq.md
```

### `agentic` (new — mocks/agentic.py)
- Simulates tool/function calling
- Defines available tools with descriptions and mock return values
- Tools can be marked as restricted (model should refuse to call)
- Simulates multi-step reasoning traces
- Attack surface: excessive agency, parameter injection, unauthorised actions

Profile config:
```yaml
mock:
  type: agentic
  backend: gemini
  config:
    tools:
      - name: lookup_account
        description: "Look up account balance"
        returns: "Account balance: £45,230.00"
      - name: transfer_funds
        description: "Transfer money between accounts"
        returns: "Transfer completed: £{amount} to {destination}"
        restricted: true
      - name: get_market_data
        description: "Get current stock/fund prices"
        returns: "FTSE 100: 8,234.50 (+0.3%)"
```

### `memory` (new — mocks/memory.py)
- Maintains user profile context injected into system prompt
- Stores "other user" profiles for cross-user leakage testing
- Optionally persists conversation summaries across sessions
- Attack surface: profile data extraction, cross-user leakage, memory poisoning

Profile config:
```yaml
mock:
  type: memory
  backend: gemini
  config:
    user_profile:
      name: "Alex Morgan"
      age: 42
      risk_appetite: moderate
      holdings: "ISA: £45k, SIPP: £120k"
    other_profiles:
      - name: "Sam Taylor"
        holdings: "ISA: £200k, SIPP: £500k"
    persist_across_sessions: false
```

## Architecture

```
harness/
├── mock.py              # Base mock (unchanged, becomes type: base)
├── mocks/
│   ├── __init__.py      # Mock type registry, load_mock(type, config)
│   ├── rag.py           # RAG mock
│   ├── agentic.py       # Tool-calling mock
│   └── memory.py        # Memory/profile mock
```

Each specialised mock:
- Inherits base mock's LLM backend calling (echo, ollama, openai, etc.)
- Wraps the system prompt with its own context (retrieved docs / tool descriptions / user profile)
- Post-processes the LLM response (extract tool calls, add citations, etc.)
- Returns responses in the same canonical format

## Profile Selection

```yaml
mock:
  type: base              # base | rag | agentic | memory (default: base)
```

If `type` is omitted or `base`, the existing mock.py behaviour is unchanged (backward compatible).

## Demo Flow (for talks)

1. `airt-launch default` — base chatbot, run prompt injection tests
2. `airt-launch rag-demo` — RAG chatbot, run indirect injection via poisoned docs
3. `airt-launch agentic-demo` — agentic chatbot, run excessive agency tests
4. Same harness, same tools, different attack surfaces

## Priority

1. RAG mock (most common real-world architecture)
2. Agentic mock (highest risk, most interesting for demos)
3. Memory mock (nice to have, simpler)
