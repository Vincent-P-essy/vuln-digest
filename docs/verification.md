# Execution record

Local execution of `python -m pytest -v --tb=short tests/test_scorer.py`. The input and output shown come from the repository example or test fixtures.

- `python -m pytest -v --tb=short tests/test_scorer.py` — exit 0.

The image renders the captured terminal output. [Full transcript](screenshots/execution.txt).

Latest local test output:

```text
s/sessions.py:651: in request
    resp = self.send(prep, **send_kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
../../python-env/lib/python3.12/site-packages/requests/sessions.py:784: in send
    r = adapter.send(request, **kwargs)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
../../python-env/lib/python3.12/site-packages/responses/__init__.py:1215: in send
    return self._on_request(adapter, request, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
../../python-env/lib/python3.12/site-packages/responses/__init__.py:1148: in _on_request
    request, match.get_response(request)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

self = <Response(url='https://services.nvd.nist.gov/rest/json/cves/2.0' status=200 content_type='text/plain' headers='null')>
request = <PreparedRequest [GET]>

    def get_response(self, request: "PreparedRequest") -> HTTPResponse:
        if self.body and isinstance(self.body, Exception):
            setattr(self.body, "request", request)
>           raise self.body
E           ConnectionError: Network unreachable

../../python-env/lib/python3.12/site-packages/responses/__init__.py:623: ConnectionError
=========================== short test summary info ============================
FAILED tests/test_cisa_kev.py::test_fetch_all_returns_empty_on_error - Connec...
FAILED tests/test_nvd.py::test_fetch_recent_returns_empty_on_connection_error
2 failed, 13 passed in 2.56s
```

This record covers the local commands and fixtures shown. External services and deployment remain unverified unless explicitly listed.
