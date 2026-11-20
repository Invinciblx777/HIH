# AegisLab injection range (finale P16, part C)

A separate web service that serves test pages with a hidden indirect prompt injection (8 styles) and records, in a hash-chained,
Ed25519-signed log (aegis.audit, aegis.crypto), whether a web agent opened the injected "exfil" link. It is never part of the
judges' demo service (render.yaml is unchanged); it is deployed as its own Render service `aegislab-range` only with approval.

    RANGE_ADMIN_TOKEN=<random, >= 32 chars> RANGE_PUBLIC_BASE=https://<host> uvicorn app:app --app-dir tools/range
    python tools/range/run_tinyfish.py --base https://<host> --styles all [--guard-rundir RUN] --out <dir>

Render (separate service): root directory `tools/range`, build `pip install -r requirements.txt`, start
`uvicorn app:app --host 0.0.0.0 --port $PORT`, env RANGE_ADMIN_TOKEN (secret), RANGE_PUBLIC_BASE. The app imports
`../../aegislab/aegis` from the same clone. State is in memory and on the instance disk: one campaign per deploy.
