---
description: OpenAll intake - legal basis, environment check, detect app type
---
Start a new OpenAll project.

1. Read `CLAUDE.md` and `DISCLAIMER.md`. Briefly remind the user: not legal advice, they are responsible,
   no theft/circumvention.
2. Ask ONE short question, once, in one message, with a ready-to-copy answer:
   "Подтверди одной строкой: ты вправе анализировать это (своё / open-source / разрешение владельца / законная
   интероперабельность), и exe можно запускать (ты в песочнице/VM). Ответь: `да, основание: ...`".
   Do not ask about the target platform or anything else: assume the clone uses the same platform and the same
   kind of stack as the original, and take the clone's name from the user only if they already gave one (else pick one).
   If the user answers yes, continue immediately without further questions. If the stated purpose is piracy,
   impersonation, stealing data or bypassing protection, refuse and stop.
3. Create `workspace/INTAKE.md` (what, legal basis, target platform, date) and `workspace/PROGRESS.md` from `templates/PROGRESS.md`.
4. Run `python3 scripts/doctor.py` and show missing tools in plain language (do not install anything without asking).
5. Make sure the original is in `input/` (ask the user to put it there if empty), then run `python3 scripts/detect_type.py`
   and summarise: detected type(s), support level, and the recommended analysis approach.
   If `input/` contains any `.exe`/`.dll`, also run `python3 scripts/binary_inventory.py` (deep mode: component map,
   imports, exports, class names, strings; big DLLs can take a few minutes) so the Analyst can start from it.
6. Give the user a short, honest coverage message (2-4 sentences, in their language), based on what is actually in `input/`
   and on type.json. Example tone: "Понял: у меня только один exe без исходников, поэтому логику большинства функций
   я не вижу. Воссоздам внешний вид и то, что видно по поведению, остальное будет заглушками; в конце соберу чистый ZIP
   с батником для компиляции и списком, чего не хватает." Write the plan into `workspace/COVERAGE.md`
   (from `templates/COVERAGE.md`). Never refuse just because inputs are incomplete: build what is possible, stub the rest.
7. Run `python3 scripts/phase.py set idle`, then continue straight into `/openall-spec` without waiting.
