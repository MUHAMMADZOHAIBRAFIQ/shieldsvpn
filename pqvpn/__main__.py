import sys

if sys.argv[1:2] == ["native-host"]:
    # Started by a web browser for the extension: needs no cryptography, so it must not depend on finding OpenSSL.
    from .native_host import main as native_main
    sys.exit(native_main(sys.argv[2:]))

try:
    from .cli import main
except Exception as exc:  # most likely: no OpenSSL >= 3.5 found
    if type(exc).__name__ == "OpenSSLError":
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
    raise

sys.exit(main())
