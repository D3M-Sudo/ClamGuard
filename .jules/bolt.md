# Bolt Performance Optimization Journal

This journal is reserved strictly for documenting critical, repository-specific performance bottlenecks, optimizations, and learnings.

## 2026-08-12 - Memory-Efficient Async File Chunk Streaming for ClamAV INSTREAM Fallback
**Learning:** Eagerly loading file chunks into a Python list via `list(_read_chunks())` blocks the event loop and leads to high memory consumption (O(N) space complexity) when scanning large files (e.g. ISOs, zip archives).
**Action:** Always stream files chunk-by-chunk dynamically using `await asyncio.to_thread(f.read, 65536)` inside an async loop to achieve O(1) space complexity and maintain event loop responsiveness.
