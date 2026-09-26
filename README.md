# VULPHEX

VULPHEX is a CLI-based API Security Assessment Tool. Project foundation for Day 1 implementation.

## Development Setup

Requires Python 3.13 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install --editable .
python -m vulphex --help
```

## Controlled Local Test API

The local test API is provided only for validating VULPHEX behavior. It does
not contact external services and uses synthetic test data only.

- `/public` is intentionally unauthenticated and returns HTTP 200.
- `/protected` requires the synthetic token `vulphex-local-test-token` in an
	`Authorization: Bearer ...` header.

Start it during development with:

```powershell
python -m uvicorn tests.test_api:app --host 127.0.0.1 --port 8000
```

## Assessment Engine

The Assessment Engine accepts a target and an ordered collection of security
tests, executes them sequentially, and collects their `AssessmentResult`
objects. Results then flow to the existing text or JSON renderer. AUTH-001 is
currently the only integrated test; additional security tests can be added
later without changing the CLI orchestration.
