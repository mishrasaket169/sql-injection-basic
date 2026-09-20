# SQL Injection Login Lab

Run the local demo with:

```powershell
python server.py
```

Then open <http://127.0.0.1:8000>.

Use the supplied account (`demo` / `password123`) to verify normal login. For
the security exercise, test an injection payload such as a username ending in
`' OR '1'='1' --` with any password. The protected form should deny access,
while the intentionally vulnerable form demonstrates why string-concatenated
SQL is unsafe.

This is deliberately a local educational example. Do not expose `server.py` or
the vulnerable endpoint to a network.
