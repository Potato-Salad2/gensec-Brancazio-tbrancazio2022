import argparse
import hashlib
import logging
import os
from pathlib import Path

from langchain_chroma import Chroma
from langchain_google_genai import GoogleGenerativeAIEmbeddings

DB_DIR = Path(__file__).resolve().parent / ".chromadb"
COLLECTION_NAME = "hw2_notebook"
EMBEDDING_MODEL = "gemini-embedding-001"

TOP_K = 5

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
    args = parser.parse_args()

    if args.command == "search":
        print_search(open_vectorstore(), args.query, k=args.k)


if __name__ == "__main__":
    main()
