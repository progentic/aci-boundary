<h1 align="center">ACI Boundary Layer</h1>

<p align="center">
  A safety layer for AI-assisted work.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Built%20with-Rust-black?style=for-the-badge&logo=rust" alt="Built with Rust" />
  <img src="https://img.shields.io/badge/Safety%20First-Boundary%20Layer-blue?style=for-the-badge" alt="Safety First Boundary Layer" />
  <img src="https://img.shields.io/badge/Human%20Approval-Required%20for%20Risky%20Actions-green?style=for-the-badge" alt="Human Approval Required" />
</p>

---

## Empower your AI. Protect your infrastructure.

Artificial intelligence agents are incredibly powerful, but giving them direct access to your systems is a major security risk. The **ACI Boundary Layer** solves this by acting as an impenetrable checkpoint between your AI tools and your real-world environments.

Instead of letting AI run commands directly, the AI simply *proposes* actions. Our boundary layer catches these raw requests and puts them through a rigorous, multi-step authorization process. Every single action is parsed, strictly typed, checked against your security policies, and—if necessary—held for explicit human approval.

Nothing executes until the boundary says so, and every decision is durably logged for 100% transparent auditing. You get all the speed and productivity of AI, with zero compromises on security.

---

## Getting Started

Installing and validating the ACI Boundary Layer on your local machine is straightforward.

**Prerequisites:** You will need [Rust](https://www.rust-lang.org/tools/install) installed on your system.

**1. Clone the repository**
Download the project to your local machine and navigate into the directory.

**2. Run the Security Validation Suite**
We provide a built-in suite of commands to guarantee your boundary layer is structurally sound, secure, and ready for production. Run the following commands in your terminal:

```bash
# Check code formatting
cargo fmt --check

# Verify the code compiles successfully
cargo check

# Run strict code quality and security linters
cargo clippy -- -D warnings

# Execute the automated test suite
cargo test

# Audit your dependencies for known vulnerabilities and license compliance
cargo deny check

```

---

## Integrating with GitHub Actions

To ensure your boundary layer remains secure as your team updates the codebase, you should automate the validation suite using GitHub Actions. This guarantees that no unverified or insecure code can ever be merged into your main branch.

Create a new file in your repository at `.github/workflows/boundary-validation.yml` and copy the detailed workflow below.

### The Automated Workflow

```yaml
name: ACI Boundary Layer Validation

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

env:
  CARGO_TERM_COLOR: always

jobs:
  security_and_quality:
    name: Security and Code Quality Checks
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Install Rust Toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy

      - name: Setup Rust Caching
        uses: Swatinem/rust-cache@v2
        with:
          cache-on-failure: true

      - name: Enforce Code Formatting
        run: cargo fmt --check

      - name: Verify Compilation
        run: cargo check

      - name: Strict Linting (Zero Warnings Allowed)
        run: cargo clippy -- -D warnings

      - name: Execute Test Suite
        run: cargo test

  dependency_audit:
    name: Dependency Vulnerability Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Run Cargo Deny
        uses: EmbarkStudios/cargo-deny-action@v2
        with:
          command: check

```

### How the Workflow Protects You:

* **Continuous Testing:** Every time a team member opens a Pull Request, GitHub Actions will automatically spin up a secure server and run your tests.
* **Strict Quality Control:** The `cargo clippy -- -D warnings` command actively rejects any code that contains potential bugs or memory safety issues.
* **Supply Chain Security:** The `cargo-deny` step scans your underlying packages to ensure no known vulnerabilities or unauthorized software licenses are introduced into your environment.

---

## Advanced Filesystem Protection

Out of the box, the ACI Boundary Layer actively protects your local files by automatically blocking malicious path tampering (like directory traversal attacks) and unauthorized symlink escapes.

*Note for Enterprise Deployments: While our portable resolver provides robust baseline protection, environments with highly complex, simultaneous automated file changes should pair ACI with their operating system's native, platform-specific file security protocols (such as `openat` or no-follow enforcement) for absolute lockdown.*
