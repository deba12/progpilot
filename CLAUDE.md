# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Progpilot is a PHP SAST tool (taint analysis for PHP code), written in PHP >= 8.3. It builds on `nikic/php-parser` and `ircmaxell/php-cfg` (AST -> control flow graph), with a Symfony Console CLI.

## Layout

- `package/` – the library (`designsecurity/progpilot`, PSR-4 namespace `progpilot\` -> `package/src/progpilot/`). All analysis code lives in `package/src/progpilot`.
- `package/src/uptodate_data/php/` – default taint config as JSON (`sources`, `sinks`, `sanitizers`, `validators`, `rules`) plus `frameworks/` and `dev/` variants. Edit these to change what counts as a source/sink.
- `projects/phar/progpilot` – CLI entry script (registers `Command\ProgpilotCommand` in `Console\Application`; version string lives in `Application.php`).
- `projects/tests/` – the PHPUnit project; its own `composer.json` pulls `package/` in via a path repository.
- `projects/example*`, `docs/` – usage examples and docs (`CUSTOM_ANALYSIS.md`, `API.md`, `OUTPUT.md`, etc.).

## Commands

Tests (must be run from `projects/tests`, since the `Run*.php` files `require_once './vendor/autoload.php'`):

```shell
cd projects/tests
composer update            # CI removes composer.lock and vendor/ first; installs ../../package as a symlinked path repo
php vendor/bin/phpunit                                  # full suite (phpunit.xml lists the Run*.php files)
php vendor/bin/phpunit RunAll.php                       # one runner
php vendor/bin/phpunit RunAll.php --filter 'testSecurity'   # filter by test name / dataset
```

Lint (PSR-12 via phpcs 4, also run by GrumPHP as the pre-commit hook; `projects/tests` is ignored). Run `composer install` at the repo root first:

```shell
composer lint        # phpcs on package/src, must be clean (errors and warnings)
composer lint:fix    # phpcbf, whitespace-only autofix
composer phpstan     # level 6 on package/src (phpstan.neon.dist)
composer psalm       # errorLevel 5 on package/src (psalm.xml)
composer gate        # lint + phpstan + psalm + tests + composer audit
```

Quality gate: run once right before committing, scoped to what changed.

| Changed paths | Run |
| --- | --- |
| `package/src/**/*.php`, `projects/phar/progpilot` | `composer lint`, `composer phpstan`, `composer psalm` and the PHPUnit suite |
| `phpstan.neon.dist`, `psalm.xml` | that tool at full scope |
| `projects/tests/**` | PHPUnit suite |
| `composer.json` (any) | `composer audit` plus the PHPUnit suite on PHP 8.4, 8.5 and 8.6 |
| docs / yaml / Docker only | nothing |

Static analysis scope and tuning: both tools only cover `package/src` (not `projects/tests` fixtures, which are deliberately vulnerable PHP). There is no baseline file: PHPStan level 6 and Psalm level 5 are clean. Psalm suppresses unused-code and `#[Override]` checks (public methods are library API) and a few polymorphic PHPCfg property accesses, each with a comment in `psalm.xml`. Raising the levels is the next quality step: `phpstan --level=max` still reports about 2000 findings, mostly untyped parameters and array element types in code that the test suite does not execute.

Typing conventions that the analysers rely on:
- `Context::getCurrentFunc()`, `getCurrentBlock()`, `getCurrentMyfile()`, `getCurrentMycode()` and `MyDefinition::getCurrentState()` return null when nothing is current. Use the `require*` variant (`requireCurrentFunc()`, ...) when null is a bug: it throws a `LogicException` instead of a null dereference.
- `MyInstruction::getProperty()` is a keyed bag; its docblock maps each `MyInstruction::*` constant to its type. Dynamic keys (`argdefN`, `keyN`, ...) are `mixed`.
- Known issue kept on purpose: `VisitorAnalysis::analyzecode()` keeps a stack of block ids and assigns an id (int) to `currentMyBlock` on `LEAVE_BLOCK`. Resolving the id to its block changes the analysis results (91 test failures), so the int is still tolerated (`MyBlock|int|null`).

Commit messages follow the repo's existing short lowercase style (no conventional-commits tooling). Use `php8.4 /usr/local/bin/composer ...` for dependency work so resolution targets the PHP floor.

Build a PHAR: `./build.sh` (needs `phar-composer.phar` on PATH; output in `builds/`). Docker: see `DOCKER.md`.

CI (`.github/workflows/main.yml`) runs PHPUnit on PHP 8.4, 8.5 and 8.6.

## Test architecture

Tests are data-driven. Fixture PHP files live in `projects/tests/tests/<category>/` (generic, flows, includes, negative, ...). The `*test.php` files (e.g. `generictest.php`, `flowstest.php`) are not tests themselves: they return arrays mapping a fixture file to its expected vulnerabilities (`[source_name, source_line, vuln_name, ...]`). The `Run*.php` classes (`RunAll`, `RunFolder`, `RunFlows`, `RunExcludeFiles`, `RunAllConfigurations`, `RunConfig`, ...) are the PHPUnit classes; they use `#[DataProvider]` to include those arrays, run `Analyzer->run($context)` on each fixture, and compare results in order. To add a case: add a fixture file and an entry in the matching `*test.php` array. `config*.yml` are configs used by `RunAllConfigurations`.

## Analysis pipeline (needs several files to understand)

Entry: `Analyzer::run($context)` in `package/src/progpilot/Analyzer.php`, where `Context` carries `inputs` (`Inputs\MyInputs`: files, config, sources/sinks/sanitizers) and `outputs` (`Outputs\MyOutputs`: results; `SarifOutput` for SARIF).

1. **Parse** – php-parser AST -> php-cfg CFG (`Representations\`: `AbstractSyntaxTree`, `ControlFlowGraph`, `Callgraph`).
2. **Transform** – `Transformations\Php\*` (`Transform`, `Assign`, `FuncCall`, `Expr`, `Exprs/`) convert CFG blocks into progpilot's own linear opcode form: `Code\MyCode` / `MyInstruction` / `Opcodes`, with `Objects\My*` (`MyFunction`, `MyClass`, `MyDefinition`, `MyOp`, ...) as the data model.
3. **Dataflow** – `Dataflow\VisitorDataflow` collects definitions, functions, classes and objects into the registries in `Context`.
4. **Analysis** – `Analysis\VisitorAnalysis` interprets the opcodes per function (functions first, `{main}` last in `runAnalysisOfCurrentMyFile`), resolving definitions (`ResolveDefs`), following calls (`FuncAnalysis`), includes (`IncludeAnalysis`), and propagating taint (`TaintAnalysis`). `SecurityAnalysis` matches tainted definitions against sinks and produces `Inputs\MyVuln` -> `Outputs\MyResult`. `CustomAnalysis` / `AssertionAnalysis` support user-defined rules and assertions.

`Helpers\` holds shared analysis state/callbacks; `Inputs\My*` classes model the source/sink/sanitizer/validator/custom-rule configuration (loaded from the JSON in `uptodate_data` and the user's YAML).

## Conventions

PSR-12 code style (enforced by GrumPHP/phpcs). Dev docs note known unsupported cases (references, array pushes, chained calls) in `docs/DEV.md`; check there before assuming a false negative is a regression.
