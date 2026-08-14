# vuln-demo

A deliberately vulnerable target for exercising AutoFTE end to end. It reads
one input file and uses the **first byte as a marker** to select one of
four independent, genuinely distinct bugs in `vuln.c` -- so a pile of
crashes against this binary collapses into more than one real root cause,
which is the whole point of `autofte demo`: showing that many crash files
reduce to a few distinct bugs, not one bug wearing many hats.

| Marker | Bug | Function |
|---|---|---|
| `1` | Stack buffer overflow (`strcpy`, no bounds check) | `vuln_stack_overflow` |
| `2` | Heap buffer overflow (`memcpy` past a 64-byte `malloc`) | `vuln_heap_overflow` |
| `3` | Use-after-free (write through a freed pointer) | `vuln_use_after_free` |
| `4` | NULL pointer dereference | `vuln_null_deref` |

Anything else as the first byte reaches no bug and the program exits
cleanly -- useful as safe fuzzer seed material.

```bash
make                 # builds ./target (plain, no sanitizer, weak mitigations)
make target_asan     # builds ./target_asan (AddressSanitizer-instrumented)
../../scripts/fuzz.sh $(pwd)/target in ../../out   # from this directory, or see scripts/fuzz.sh defaults
```

`crashes/` ships 12 pre-generated crash files spread across all four bugs
(with size/pattern variation within each), each independently verified to
crash `target_asan`. `autofte demo` uses them directly, no fuzzing campaign
required.

The `Makefile`'s plain `target` intentionally disables common mitigations
(`-fno-stack-protector -no-pie -z execstack`) so the demo has something for
`autofte binscan` to actually flag. `target_asan` is built with
`-fsanitize=address` so AutoFTE's sanitizer-ingestion path (bug class,
read/write, access size, alloc/free stacks) has something real to parse.
Don't reuse either build's flags for anything you'd ship.
