# Coding Standards & Contribution Guide

This document defines the coding, branching, and commit standards for this repository.  
All contributors (including automation) must follow these rules. I will re-read and enforce them before making changes.

---

## 1. Branching Discipline
- **One branch per feature**:  
  - Example: `feature/batch-ingestion`, `feature/streaming-ingestion`
- **One branch per chore/infra update**:  
  - Example: `chore/dependency-updates`, `chore/ci-improvements`
- **No mixing**: Do not combine infra/dependency updates with feature work.

---

## 2. Commit Message Rules
- Format: `<type>(scope): description`
- Types:
  - `feat` → new feature
  - `fix` → bug fix
  - `chore` → infra, dependencies, CI/CD
  - `docs` → documentation only
  - `refactor` → code refactor without functional change
  - `test` → test-related changes
- Each commit must answer:
  - **What changed?**
  - **Why does it matter?**

### Examples
- `feat(ingestion): batch SQL inserts for CVE ingestion`
- `feat(ingestion): stream ZIP + JSON parsing to reduce memory usage`
- `chore(ci): update golangci-lint config, update SBOM output`

---

## 3. Feature Commits
- Each commit should represent a **logical unit of work**.
- Avoid “grab-bag” commits that mix unrelated changes.
- If a feature evolves (e.g., batching → streaming), use separate commits.

---

## 4. Pre-Merge Checks
- Before merging into `main`:
  - Ensure commit history is **clean and scoped**.
  - Squash or rebase if necessary.
  - No vague commit messages.
- Merge commits should summarize the feature branch clearly.

---

## 5. CI/CD Hygiene
- Infra/dependency updates go in `chore/` branches.
- Feature branches should only contain feature code.
- Keep CI/CD changes isolated from feature logic.

---

## 6. Code Quality
- Run `make all` (lint, audit, test) before committing.
- Ensure `golangci-lint` passes with zero issues.
- Ensure `govulncheck` returns no known vulnerabilities.
- Add logging (slog) and context cancellation where appropriate.

---

## 7. Documentation
- Update `README.md` or relevant docs when adding new features.
- If a feature is configurable, document the config options.

---

## 8. Enforcement
- I will re-read this document before making changes.
- If a branch or commit violates these rules, it must be corrected before merge.

---

✅ Following these standards ensures:
- Clean history
- Clear feature scope
- Easier reviews
- Maintainable codebase
