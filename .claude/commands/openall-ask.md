---
description: STUDY mode - ask a specific question about the studied program ("how does X work?")
argument-hint: <question, function, feature>
---
Question: $ARGUMENTS

1. Read `workspace/study/KNOWLEDGE.md` and any relevant `workspace/study/features/*.md` first; do not redo known work.
2. If not enough, run `python3 scripts/phase.py set study` and delegate to the `researcher` subagent with this exact question.
   It must use the connected engine (ReVa/REA: decompile, xrefs, call graph) rather than guess.
3. Answer in plain words in the user's language: short answer first, then how you know (evidence), confidence labels,
   what is still unknown. Append the new facts to `KNOWLEDGE.md` and, if it deserves it, `features/<name>.md`.
4. No own code or "my version". If the user asks for code, ask whether they want REBUILD mode.
