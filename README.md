# Rekor Transparency Log Verifier

A command-line tool that verifies software artifacts against the public
[Sigstore Rekor](https://rekor.sigstore.dev) transparency log. Built for
NYU CS-GY 9223 Software Supply Chain Security.

It can:

- **Fetch the latest checkpoint** (tree ID, tree size, root hash) from Rekor.
- **Verify inclusion**: check an artifact's signature against the certificate
  in its Rekor entry, then verify the Merkle inclusion proof for that entry.
- **Verify consistency**: prove that an older checkpoint is a prefix of the
  current log, i.e. that the log has only been appended to.

## Installation

Requires Python 3.14+ and [Poetry](https://python-poetry.org/).

```bash
git clone https://github.com/Sahanasrajan/ks8555-sscs-assignment1.git
cd ks8555-sscs-assignment1
poetry install
```

## Usage

```bash
# Print the latest checkpoint (add -d to also save it to checkpoint.json)
poetry run python main.py -c

# Verify that an artifact is signed and included in the log
poetry run python main.py --inclusion <log-index> --artifact artifact.md

# Verify a previous checkpoint is consistent with the latest one
poetry run python main.py --consistency \
    --tree-id <tree-id> --tree-size <tree-size> --root-hash <root-hash>
```

Any verification failure prints the reason and exits with status code 1.

## Development

Install the git hooks once after cloning:

```bash
poetry run pre-commit install
```

Run the checks before opening a pull request:

```bash
poetry run ruff format .                          # format
poetry run ruff check .                           # lint
poetry run mypy main.py merkle_proof.py util.py   # type check
poetry run bandit -r . -c pyproject.toml          # security scan
poetry run pytest                                 # tests + coverage report
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow and
[SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

[MIT](LICENSE)
