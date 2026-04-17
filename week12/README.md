# Network Traffic Monitor — Refactor & Testing Project

## Overview

This project refactors a legacy, monolithic Network Traffic Monitor script into a
professional, maintainable, and testable security tool. The refactoring applies
modern software engineering best practices including modular design, structured
logging, comprehensive unit testing with pytest, and a user-friendly command-line
interface built with argparse.

The goal of this project is not only to preserve functionality, but to ensure the
tool can be trusted, extended, and debugged in real-world cybersecurity environments.

---

## Learning Objectives

By completing this project, I demonstrated:

- Refactoring monolithic code into modular, testable components
- Eliminating global state and magic numbers
- Implementing professional logging for forensic analysis
- Writing comprehensive unit and integration tests using pytest
- Designing production-quality CLIs with argparse
- Applying FIRST principles to test design
- Critically evaluating and refining AI-assisted code

---

## Refactoring Process

### Biggest Problems With the Original Code

The original script suffered from several critical maintainability issues:

- All logic was contained in a single large function
- Extensive use of global variables
- Hardcoded magic numbers with no documentation
- Debug print statements mixed with program output
- No separation of file I/O from analysis logic
- No automated tests
- Fragile command-line parsing via sys.argv

These issues made the tool difficult to test, extend, or trust in a security context.

---

### Refactoring Patterns Applied

The following refactoring techniques were applied:

- **Configuration Object Pattern**  
  Extracted all detection thresholds into a `NetworkConfig` class with documented defaults.

- **Pure Function Extraction**  
  Parsing and detection logic was refactored into pure functions with single
  responsibilities and no side effects.

- **Separation of Concerns**  
  File I/O, analysis logic, and orchestration were cleanly separated to improve
  testability.

- **Incremental Refactoring**  
  Changes were made in small steps with tests added before proceeding further.

---

### Ensuring Correctness During Refactoring

To ensure functionality was not broken:

- Each refactoring stage was committed independently
- Unit tests were written for all pure functions
- Integration tests verified end-to-end behavior
- pytest was run after every significant change
- Logging was added only after logic was stable

This ensured behavior stayed consistent throughout the refactor.

---

### Refactoring Challenges

The most challenging aspect was refactoring without introducing regressions.
Resisting the temptation to refactor everything at once required discipline,
but resulted in a more stable and trustworthy codebase.

---

### Maintainability Improvements

The refactored version improves maintainability by:

- Making behavior explicit through function names and docstrings
- Centralizing configuration
- Providing forensic-quality logs
- Enabling fast, repeatable automated testing
- Supporting future extensions without modifying core logic

---

## Logging Design

The application uses Python’s `logging` module with:

- File-based logs (`network_monitor.log`) at DEBUG level for forensic detail
- Console logs with configurable verbosity
- Proper log levels (DEBUG, INFO, WARNING, ERROR)
- Lazy string formatting to avoid leaking sensitive information

This logging approach mirrors real-world security tooling standards.

---

## Testing Strategy

Testing is implemented using `pytest` and follows FIRST principles:

- **Fast** — All tests complete in milliseconds
- **Independent** — No shared state between tests
- **Repeatable** — Deterministic results every run
- **Self-validating** — Clear pass/fail assertions
- **Timely** — Tests written during refactoring, not after

Tests include:
- Parser validation tests
- Detection logic boundary tests
- Integration tests covering the full analysis pipeline
- Exit-code validation for the main orchestration function

All tests pass using:

```bash
python -m pytest -v
