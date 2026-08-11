# Bolt's Journal — ClamGuard Performance Learnings

This journal documents critical codebase-specific performance patterns, bottlenecks, and optimization lessons learned while improving ClamGuard.

## 2025-02-14 - Redundant In-Memory Reads & Eager Generator Materialization
**Learning:** In python-based secure file managers, computing SHA-256 integrity hashes on large files using standard library `Path.read_bytes()` loads the entire file eagerly into memory. When coupled with sequential disk operations (such as encryption or quarantined file copying), files are frequently double-read into memory. Furthermore, executing generator-based chunking under `asyncio.to_thread(list, generator)` eagerly materializes all chunks into an in-memory list, negating the memory-saving benefits of chunking.
**Action:** Always process large files and network stream buffers using dynamic chunk-by-chunk stream loops (e.g. 64KB buffers) using `f.read(65536)`. When combining hashing and copying, execute them in a single unencrypted pass to eliminate double disk-reading and ensure O(1) memory complexity regardless of the target file size.
