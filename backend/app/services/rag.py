import os
import re
from typing import List, Dict, Any, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from app.core.config import settings

class LightweightRAG:
    def __init__(self, documents_dir: str = None, chunk_size_lines: int = 10, overlap_lines: int = 2):
        if documents_dir is None:
            self.documents_dir = os.path.join(settings.BASE_DIR, "documents")
        else:
            self.documents_dir = documents_dir
            
        self.chunk_size_lines = chunk_size_lines
        self.overlap_lines = overlap_lines
        
        self.chunks: List[str] = []
        self.vectorizer = TfidfVectorizer(stop_words=None)  # Stopwords Spanish can be custom
        self.tfidf_matrix = None
        
        self.is_indexed = False
        self.load_and_index()

    def load_and_index(self):
        """
        Reads all text files from the documents directory, splits them into overlapping chunks,
        and fits the TF-IDF vectorizer.
        """
        if not os.path.exists(self.documents_dir):
            print(f"RAG: Documents directory '{self.documents_dir}' does not exist.")
            return

        raw_chunks = []
        text_files = [f for f in os.listdir(self.documents_dir) if f.endswith(".txt") or f.endswith(".md")]
        
        if not text_files:
            print("RAG: No document text/markdown files found to index.")
            return

        print(f"RAG: Indexing {len(text_files)} files from {self.documents_dir}...")
        for filename in text_files:
            file_path = os.path.join(self.documents_dir, filename)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    
                # Split content into lines and chunk them
                lines = content.split("\n")
                idx = 0
                while idx < len(lines):
                    chunk_lines = lines[idx : idx + self.chunk_size_lines]
                    chunk_text = "\n".join(chunk_lines).strip()
                    if chunk_text:
                        # Append reference to document origin
                        chunk_with_ref = f"[Origen: {filename}]\n{chunk_text}"
                        raw_chunks.append(chunk_with_ref)
                    idx += (self.chunk_size_lines - self.overlap_lines)
            except Exception as e:
                print(f"RAG: Error reading {filename}: {e}")

        if not raw_chunks:
            print("RAG: No content chunks extracted.")
            return

        self.chunks = raw_chunks
        
        # Fit vectorizer
        try:
            # Custom Spanish stopwords list to avoid standard sklearn english defaults
            spanish_stopwords = [
                "el", "la", "los", "las", "un", "una", "unos", "unas", "de", "del", "al", "y", "o", "no", "si", "se",
                "por", "para", "con", "en", "su", "sus", "es", "este", "esta", "estos", "estas", "que", "como", "mas"
            ]
            self.vectorizer = TfidfVectorizer(stop_words=spanish_stopwords, lowercase=True)
            self.tfidf_matrix = self.vectorizer.fit_transform(self.chunks)
            self.is_indexed = True
            print(f"RAG: Successfully indexed {len(self.chunks)} text chunks.")
        except Exception as e:
            print(f"RAG: Error fitting TF-IDF matrix: {e}")

    def query(self, user_query: str, top_k: int = 3) -> List[Tuple[str, float]]:
        """
        Queries the RAG system and returns the top K passages matching the query with their scores.
        """
        # Ensure fresh index if not indexed
        if not self.is_indexed:
            self.load_and_index()

        if not self.is_indexed or self.tfidf_matrix is None or not self.chunks:
            print("RAG: System is not indexed yet. Returning empty context.")
            return []

        try:
            # Transform user query
            query_vector = self.vectorizer.transform([user_query])
            
            # Compute cosine similarity
            similarities = cosine_similarity(query_vector, self.tfidf_matrix).flatten()
            
            # Sort indices by highest similarity score
            top_indices = similarities.argsort()[::-1][:top_k]
            
            results = []
            for idx in top_indices:
                score = float(similarities[idx])
                # Only return results with some positive similarity score
                if score > 0.0:
                    results.append((self.chunks[idx], score))
                    
            return results
        except Exception as e:
            print(f"RAG: Error querying system: {e}")
            return []

    def get_context(self, user_query: str, top_k: int = 3) -> str:
        """
        Runs query and formats the retrieved passages as a single context block.
        """
        matches = self.query(user_query, top_k)
        if not matches:
            return "No se encontraron directivas locales de contingencia coincidentes en la base de conocimientos."

        context_blocks = []
        for doc_chunk, score in matches:
            context_blocks.append(f"--- Pasaje Relevante (Similitud: {score:.2f}) ---\n{doc_chunk}\n")
            
        return "\n".join(context_blocks)

# Initialize a global singleton instance of RAG
rag_system = LightweightRAG()
