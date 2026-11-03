---
description: STUDY mode - deeply study the program in input/ and explain how it works (no own code)
---
1. Read `CLAUDE.md`, `DISCLAIMER.md`, and `workspace/PROGRESS.md` if it exists (continue from it).
2. Legal basis (once per project, skip if `workspace/INTAKE.md` exists): ask ONE short question with a ready answer:
   "Подтверди одной строкой: ты вправе изучать это (своё / open-source / разрешение владельца / законная
   интероперабельность / обучение), и запуск в песочнице/VM ок. Ответь: `да, основание: ...`".
   If the stated aim is piracy, stealing data, bypassing protection or impersonation: refuse and stop.
   Save the answer to `workspace/INTAKE.md`.
3. Run `python3 scripts/phase.py set study`, `python3 scripts/doctor.py`, `python3 scripts/detect_type.py`
   (and `python3 scripts/binary_inventory.py` if `input/` has .exe/.dll/.so). Report in 3-4 sentences, in the user's language:
   what the target is, which engines are ready, which would help (name them from `docs/TOOLS.md`).
4. If a Ghidra MCP bridge is installed but `.mcp.json` is missing, run `python3 scripts/setup_mcp.py` and tell the user to
   restart Claude Code once and check `/mcp`. Do not install software without asking.
5. Delegate to the `researcher` subagent with the scope (whole target, or the features/modules the user named).
   Large targets: one module group per round; keep `workspace/study/KNOWLEDGE.md` current.
6. Review the result yourself: claims have evidence and labels, no secrets, no invented certainty, no own code.
   Send it back to the researcher if not.
7. Finish: 5-10 line summary for the user, where the report lives (`workspace/study/OVERVIEW.md`), open questions,
   and one suggestion for the next step (`/openall-ask <question>` for details).
