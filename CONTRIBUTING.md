# Contributing to Lintel

Thanks for your interest. Bug reports, hardware test results and focused pull
requests are all welcome.

## Before you start

- **Security issues are never reported in public issues.** Follow
  [.github/SECURITY.md](.github/SECURITY.md).
- For anything larger than a bug fix, open an issue first so the approach can
  be agreed before you spend time on it.
- Read [docs/SECURITY.md](docs/SECURITY.md). Most of the design follows from
  its threat model, and changes that weaken a listed property will not be
  merged.

## Making a change

1. Fork the repository and branch from `main`.
2. Follow [BUILDING.md](BUILDING.md) to build and run the tests.
3. Keep each pull request to one change, with a test that fails without it.
   Security properties are claimed only where a test enforces them.
4. If you change the wire format, update the golden vectors on both sides
   (`test/host` and `server/tests`) so the C++ and Python implementations
   still agree byte for byte.
5. Run the full suite before opening the pull request:

   ```sh
   scripts/host_test.sh --asan
   cd server && python -m pytest -q tests
   ```

## Style

- C++: C++17, the existing naming in `components/lintel_core`, no exceptions
  or heap allocation in the core.
- Python: 3.11+, type hints on public functions, PascalCase classes and
  snake_case functions.
- JavaScript: no frameworks or inline scripts in the console (the Content
  Security Policy forbids them).
- Commit messages: `area: what changed`, in the imperative, e.g.
  `server: queue remote commands per door`.

## Licensing of contributions

Lintel is licensed under the Functional Source License
([LICENSE](LICENSE)), and the licensor also offers it under commercial terms.
By submitting a contribution you confirm that you wrote it or have the right
to submit it, and you agree that it is licensed under the same terms as the
project and may be included in versions of Lintel the licensor distributes
under other licences.
