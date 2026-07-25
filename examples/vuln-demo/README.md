# vuln-demo

A deliberately vulnerable target for exercising AutoFTE end to end: `vuln()` copies raw file input into a fixed 64-byte stack buffer with `strcpy`, no bounds check.

```bash
make                      # builds ./target
../../scripts/fuzz.sh $(pwd)/target in ../../out   # from this directory, or see scripts/fuzz.sh defaults
```

The `Makefile` intentionally disables common mitigations (`-fno-stack-protector -no-pie -z execstack`) so the demo has something for `autofte binscan` to actually flag. Don't reuse these build flags for anything you'd ship.
