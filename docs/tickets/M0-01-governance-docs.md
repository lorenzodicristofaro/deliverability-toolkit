# M0-01 Governance documents (LICENSE, README, CONTRIBUTING, CODE_OF_CONDUCT)
Milestone: M0
Branch: feature/m0-01-governance-docs
Files in scope: LICENSE, README.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md
Out of scope: pyproject.toml, CI, Docker, any code; SPEC.md / ARCHITECTURE.md (do not edit)
Depends on: none
Parallel-safe: yes
Model: sonnet
Acceptance criteria:
- LICENSE is the verbatim official GNU AGPL-3.0 text downloaded from https://www.gnu.org/licenses/agpl-3.0.txt. Do NOT reproduce from memory. Record the source URL and download date in the commit message.
- README.md stub: project name, one-paragraph description taken from SPEC.md section 1, status "pre-alpha", license line "GNU AGPL-3.0-or-later" (SPEC section 9), pointer to CONTRIBUTING. No unverified claims about features or vendors.
- CONTRIBUTING.md: DCO sign-off policy (`git commit -s`), using the official DCO 1.1 text from https://developercertificate.org/ (verbatim, not from memory; record URL). Also states: private-dev/public-release model is NOT described here (internal), conventional commits, tests required, i18n keys required for user-facing strings.
- CODE_OF_CONDUCT.md is the official Contributor Covenant text from https://www.contributor-covenant.org/ (state the version used and the URL in the file header comment or commit message). Enforcement contact: leave a clearly marked placeholder `TODO(maintainer): contact` and report it to the GM; do not invent an address.
- Files are plain Markdown/text; markdown has no broken relative links.
New i18n keys: none
Status: todo
