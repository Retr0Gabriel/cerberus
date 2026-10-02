import sys

if sys.version_info < (3, 11):  # noqa: UP036 (a checagem existe para quem roda versões antigas)
    sys.exit(
        f"O Cerberus precisa do Python 3.11 ou mais novo (você está usando "
        f"{sys.version.split()[0]}). Baixe em https://www.python.org/downloads/"
    )

from cli.app import app

if __name__ == "__main__":
    app()
