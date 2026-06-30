# Contributing

This project is small, so the workflow should stay simple.

## Run the project

```bash
PYTHONPATH=src python -m cloudtrail_quickscan.cli samples/cloudtrail_sample.json
```

## Run tests

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

## Adding a rule

1. Add the rule function in `src/cloudtrail_quickscan/rules.py`.
2. Add a fake event in a test.
3. Keep the finding message short and clear.
4. Run the tests before committing.

Rules should be easy to understand. If a rule needs a lot of explanation, add a short note in `docs/investigation-notes.md`.
