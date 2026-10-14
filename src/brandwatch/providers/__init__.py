"""Provider layer: every external service behind one abstraction (spec §4).

* :mod:`base`     — ``ProviderResult``, the Protocols, resilience wrapper, fallback chain
* :mod:`ledger`   — quota / cost accounting (``api_usage``)
* :mod:`registry` — factory choosing real vs mock implementations (``DEMO_MODE`` / key presence)
* :mod:`mock`     — deterministic, $0 implementations (demo + tests)
* :mod:`impl`     — real-provider stubs (filled in Phases 3–5)
"""
