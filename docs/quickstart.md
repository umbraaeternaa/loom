# LOOM quickstart

This is the shortest path from a fresh checkout to a verified LOOM program.

## 1. Run without installing

```console
python3 -m loom about --format json
python3 -m loom help quickstart
python3 -m loom examples
python3 -m loom doctor --dry-run
python3 -m loom check examples/first.loom
python3 -m loom run examples/first.loom
```

Expected result:

```console
OK
42
```

`examples/first.loom` is intentionally tiny:

```lisp
(defx main () (fn () 42))
```

The empty effect row `()` says that `main` is pure. The checker proves that
the program really performs no `IO`, `Net`, `FFI`, `Rand`, or allocation effect
before it runs.

## 2. Install the CLI

```console
python3 -m pip install .
loom about --format json
loom check examples/first.loom
loom run examples/first.loom
```

The installed `loom` command is the same public CLI surface as
`python3 loom.py`.

## 3. Run the release check

```console
loom release-check
```

That command runs the public verification checklist:

```console
python3 run_tests.py
python3 verify_docs_parity.py
python3 fuzz_tests.py --cases 256 --seed 0xBADC0DE
python3 loom.py about --format json
```

The expected public baseline is:

```console
PASS -- 489/489 citadel checks
```

The CLI help is also pinned:

```console
loom --help
loom help quickstart
loom examples
loom doctor --dry-run
```

## 4. See the trust gate

```console
loom check examples/trust.loom
loom run examples/trust.loom
```

`examples/trust.loom` shows the core LOOM idea: AI-only trust is circular and
is refused unless independent non-AI anchors vouch for the value.

## 5. Try it in the browser

Open the playground:

```text
https://umbraaeternaa.github.io/loom/play.html
```

The playground runs in your browser tab. It can check code, run `main`, compile
to JavaScript, show WAT, and execute the published WebAssembly backend without
sending your program to a server.
