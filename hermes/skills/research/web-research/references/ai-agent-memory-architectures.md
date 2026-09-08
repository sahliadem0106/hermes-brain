# AI Agent Memory Architectures — Research Notes

Compiled from web research on building persistent memory for LLM-powered agents. Sources: Lilian Weng's "LLM Powered Autonomous Agents", Mem0 README (mem0ai/mem0), Letta/MemGPT README (letta-ai/letta), and Hermes Agent memory documentation.

## The Three-Level Memory Model (Lilian Weng)

Inspired by human memory, mapped to AI systems:

| Human Level | AI Equivalent | Implementation |
|-------------|---------------|----------------|
| **Sensory Memory** | Input embeddings | Raw text, image, audio → vector representation; lasts seconds |
| **Short-Term Memory** | In-context learning | The LLM's context window — finite, bounded by token limit |
| **Long-Term Memory** | External vector store | Persistent storage with fast retrieval (RAG) |

## Five Major Approaches to AI Agent Memory

### 1. Structured Memory Files (Hermes Agent approach)
- Two files injected into system prompt at session start: `MEMORY` (agent's notes) and `USER_PROFILE` (user preferences)
- Character-limited (~2200 + ~1375 chars) to control context size
- Agent self-manages via add/replace/remove operations
- Entries frozen as snapshot at session start (preserves prompt cache)
- **Provider:** built-in (no external deps), also supports 8 external providers (Honcho, Mem0, Hindsight, OpenViking, ByteRover, Supermemory, etc.)
- **Strengths:** Low latency (~0ms), always available, user-controllable

### 2. RAG / Vector Store (classic)
- Embed information → store in vector DB (Pinecone, Qdrant, Chroma, Weaviate, pgvector)
- At query time: similarity search to retrieve relevant context
- **Strengths:** Scales to millions of documents
- **Weaknesses:** Quality depends on chunking + embedding model; no temporal reasoning by default

### 3. Mem0 — Specialized Memory Layer (mem0.ai)
- **New algorithm (April 2026):** ADD-only extraction — one LLM call per memory, no UPDATE/DELETE. Memories accumulate, nothing overwritten.
- **Entity linking:** entities extracted, embedded, and linked across memories for retrieval boosting
- **Multi-signal retrieval:** semantic search + BM25 keyword + entity matching scored in parallel and fused
- **Temporal reasoning:** time-aware retrieval ranks the right dated instance
- **Benchmarks:** 91.6 LoCoMo (+20.2 vs old), 94.8 LongMemEval (+27), 64.1 BEAM 1M tokens
- **Typical latency:** ~1s, ~7K tokens per operation
- **Strengths:** State-of-the-art on memory recall benchmarks, no overwrite conflicts

### 4. Letta / MemGPT — Self-Editing Memory
- **Hierarchy:** Working memory → archival memory → recall memory
- Agent writes its own memory blocks via dedicated tools (self-editing)
- **Core insight:** The model manages its own memory lifecycle — reads, writes, reorganizes
- Uses "virtual context management" to page in/out of the LLM's context window
- **Strengths:** Very flexible, agent controls what matters
- **Weaknesses:** Can be expensive (requires model to self-reflect)

### 5. Knowledge Graph Memory
- Store memory as a graph of entities and relationships
- Enables multi-hop reasoning ("who knows someone working on what")
- **Strengths:** Captures complex relationships, supports inference
- **Weaknesses:** Expensive to build, harder to query than flat memory

## Memory System Design Trade-offs

| Dimension | File-based (Hermes) | Vector RAG | Mem0 | MemGPT | Graph |
|-----------|--------------------|------------|------|--------|-------|
| Setup complexity | None | Medium | Low | Medium | High |
| Retrieval latency | ~0ms | ~100ms | ~1s | ~500ms | ~200ms |
| Scalability | Limited (chars) | Millions | Millions | Millions | Millions |
| Temporal awareness | Manual | No | Yes | Partial | Partial |
| Entity linking | No | No | Yes | No | Yes |
| Token cost per turn | ~1300 (fixed) | Variable | Variable | Variable | Variable |
| User control | High | Low | Medium | Low | Medium |

## Key Patterns Observed

1. **No overwrite is better than overwrite.** Both Mem0's ADD-only and Hermes's frozen-snapshot approach avoid the edit conflict problem that plagues UPDATE-based systems.

2. **Temporal reasoning is the frontier.** Knowing *when* a memory was recorded is critical for questions about current state vs historical facts. Mem0's time-aware retrieval and Hermes's session-search both address this.

3. **Entity linking boosts recall.** Mem0's approach of linking entities across memories (rather than just semantic similarity) significantly improves retrieval on complex queries.

4. **Background self-improvement works.** Hermes's background review (runs after each turn, saves memories/skills autonomously) and MemGPT's self-editing both let the agent decide what matters, reducing user burden.

5. **Multiple memory tiers beat one.** Every successful system uses at least 2 tiers (fast/small + slow/big). The fast tier handles the common case; the slow tier handles deep recall.

## Recommended Reading

- Lilian Weng, "LLM Powered Autonomous Agents" — https://lilianweng.github.io/posts/2023-06-23-agent/
- Mem0 research paper — https://mem0.ai/research
- Mem0 GitHub — https://github.com/mem0ai/mem0
- Letta/MemGPT — https://github.com/letta-ai/letta
- Hermes Agent Memory docs — https://hermes-agent.nousresearch.com/docs/user-guide/features/memory
