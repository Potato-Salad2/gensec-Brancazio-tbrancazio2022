import argparse
import hashlib
import logging
import os
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category = DeprecationWarning)

from langchain_chroma import Chroma
from langchain_community.document_loaders import CSVLoader, DirectoryLoader, Docx2txtLoader, PyPDFDirectoryLoader, TextLoader
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

logging.getLogger("pypdf").setLevel(logging.ERROR)

APP_DIR = Path(__file__).resolve().parent
DOCS_DIR = APP_DIR / "rag_data"
DB_DIR = APP_DIR / ".chromadb"
COLLECTION_NAME = "hw2_notebook"
EMBEDDING_MODEL = "gemini-embedding-001"

TOP_K = 5
CHUNK_SIZE = 1000
CHUNK_OVERLAP = 150

def describe(doc):
    source = doc.metadata.get("source", "Unknown source")
    return Path(source).name

def print_search(vectorstore, query, k = TOP_K):
    print(f"Query database for: {query}")
    results = vectorstore.similarity_search_with_score(query, k = k)
    if not results:
        print("No matching documents.")
        return
    print(f"Closest document match in database: {describe(results[0][0])}, count={len(results)}")
    for i, (doc, distance) in enumerate(results, 1):
        snippet = " ".join(doc.page_content.split())[:200]
        print(f"[{i}] {describe(doc)}  (distance {distance:.3f}, lower = closer)\n    {snippet}...")


def load_docs(vectorstore, docs):
    if not docs:
        print("  no files found")
        return

    text_splitter = RecursiveCharacterTextSplitter(chunk_size = CHUNK_SIZE, chunk_overlap = CHUNK_OVERLAP)
    splits = text_splitter.split_documents(docs)

    ids = [hashlib.sha256(f"{d.metadata['source']}\n{d.page_content}".encode()).hexdigest() for d in splits]
    unique = dict(zip(ids, splits))
    existing = set(vectorstore.get(ids = list(unique))["ids"])
    
    new = {i: d for i, d in unique.items() if i not in existing}
    if new:
        vectorstore.add_documents(documents = list(new.values()), ids = list(new))
    print(f"  {len(new)} new chunk(s), {len(existing)} already in the database")

def load_txt(vectorstore, directory):
    load_docs(vectorstore, DirectoryLoader(directory, glob = "**/*.txt", loader_cls = TextLoader).load())

def ingest(vectorstore, directory):
    if not Path(directory).is_dir():
        print(f"Folder not found: {directory}")
        return
    for kind, loader in [("TXT", load_txt)]:
        print(f"Loading {kind} files from: {directory}")
        try:
            loader(vectorstore, directory)
        except Exception as e:
            print(f"  Skipping {kind} files: {e}")

    print("RAG database initialized with the following sources.")
    for source in sorted({Path(m["source"]).name for m in vectorstore.get()["metadatas"]}):
        print(f"  {source}")


def open_vectorstore():
    return Chroma(
        collection_name = COLLECTION_NAME,
        embedding_function = GoogleGenerativeAIEmbeddings(
            model = f"models/{EMBEDDING_MODEL}",
            google_api_key = os.environ["GOOGLE_API_KEY"],
        ),
        persist_directory=str(DB_DIR),
    )


def main():
    parser = argparse.ArgumentParser(description = "Search the HW2 document database.")
    sub = parser.add_subparsers(dest = "command", required = True)
    p_search = sub.add_parser("search")
    p_search.add_argument("query")
    p_search.add_argument("-k", type = int, default = TOP_K)
    p_ingest = sub.add_parser("ingest")
    p_ingest.add_argument("folder", nargs = "?", default = str(DOCS_DIR))
    args = parser.parse_args()

    if args.command == "search":
        print_search(open_vectorstore(), args.query, k=args.k)
    elif args.command == "ingest":
        ingest(open_vectorstore(), args.folder)


if __name__ == "__main__":
    main()
