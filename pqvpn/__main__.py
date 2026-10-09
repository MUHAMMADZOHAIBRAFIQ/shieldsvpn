import sys

try:
    from .cli import main
except Exception as exc:  # most likely: no OpenSSL >= 3.5 found
    if type(exc).__name__ == "OpenSSLError":
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
    raise

sys.exit(main())
