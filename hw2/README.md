# Homework 2 – NotebookLM-style RAG App

`app.py` is a command-line NotebookLM clone: point it at a folder of your documents, and then ask
questions that Gemini answers **only** from those documents, with numbered citations.

It is based on the examples in [`02_LangChain/07_RAG`](../02_LangChain/07_RAG):
`07_rag_loaddb.py` (loading/chunking/embedding), `08_rag_docsearch.py` (vector search), and
`09_rag_query.py` (RAG chain with Gemini).

## How it works

```
documents ──load──▶ LangChain Documents ──split──▶ ~1000-char chunks ──embed──▶ Chroma (.chromadb/)
                                                                                   │
question ──embed──▶ similarity search (top 5 chunks) ◀─────────────────────────────┘
                              │
                              ▼
            numbered chunks + question ──▶ Gemini ──▶ answer with [1][2] citations
```

| Step | Implementation |
|------|----------------|
| Load | `TextLoader` (.txt, .md), `PyPDFLoader` (.pdf), `Docx2txtLoader` (.docx), `CSVLoader` (.csv) |
| Split | `RecursiveCharacterTextSplitter` (1000 chars, 150 overlap) |
| Embed | `gemini-embedding-001` via Google AI Studio (default) or Vertex AI |
| Store/search | `langchain_chroma.Chroma`, persisted in `hw2/.chromadb/` |
| Answer | `ChatGoogleGenerativeAI` with a prompt that requires citations and ignores instructions found inside documents |

## Setup

```bash
cd hw2
python -m venv .venv && source .venv/bin/activate    # or: uv venv && source .venv/bin/activate
pip install -r requirements.txt

export GOOGLE_API_KEY="your-ai-studio-key"   # required; never put the key in app.py
export GOOGLE_MODEL="gemini-3.5-flash"        # optional (this is the default)
```

To use Vertex AI embeddings instead (higher quota, uses the course's GCP credits, as in `07_rag_loaddb.py`):

```bash
pip install langchain-google-vertexai
export EMBEDDING_BACKEND=vertex
export GOOGLE_CLOUD_PROJECT="your-gcp-project-id"
```

If you switch embedding backends, run `python app.py reset` and re-ingest, because the vectors must come from the same model.

## Usage

Put your documents in `hw2/rag_data/`. Subfolders are fine, and the folder is git-ignored.

```bash
python app.py ingest                 # index ./rag_data (or: python app.py ingest path/to/folder)
python app.py sources                # list indexed documents
python app.py search "firewall"      # show matching chunks (no Gemini call)
python app.py chat                   # ask questions (also the default with no command)
python app.py reset                  # delete the vector database
```

Inside `chat`, you can also use `/sources`, `/search <text>`, and `/quit`.

Example:

```
ask>> What did Michael Jordan say about failure?

Michael Jordan stated: "I've missed more than 9000 shots in my career. ... And that is why I succeed." [1]

Sources:
  [1] FamousQuotes.docx
```

## Error handling

- A missing `GOOGLE_API_KEY` or `GOOGLE_CLOUD_PROJECT` stops the app with a clear message.
- Files that can't be read (corrupt PDF, bad encoding) are skipped with a warning, and the other files are still indexed.
- Re-running `ingest` only embeds new or changed chunks, because each chunk ID is a content hash. This avoids duplicates and saves quota.
- Embedding 429 / `RESOURCE_EXHAUSTED` errors are retried with exponential backoff.
- API errors during chat are shown as one line, and the session keeps running.
- If a question isn't answered by the documents, Gemini replies "I couldn't find that in your documents."
