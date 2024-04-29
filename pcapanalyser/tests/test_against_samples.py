"""Script for testing the PCAP analysis program against many files."""
import subprocess
import pathlib
import contextlib
import os
from collections.abc import Generator


def get_files() -> list[pathlib.Path]:
    """Retrieve all files in the samples folder."""
    samples = pathlib.Path.cwd().parent / "samples"
    files = list(pathlib.Path(samples).glob("**/*"))
    return files


@contextlib.contextmanager
def change_working_directory(path: str) -> Generator[str, None, None]:
    """Change cwd, and return upon exit."""
    cwd = pathlib.Path.cwd()
    os.chdir(path)
    try:
        # https://github.com/python/mypy/issues/10997
        # Empty yield causes a mypy error, known bug
        yield  # type: ignore[misc]
    finally:
        os.chdir(cwd)


def main() -> None:
    """Test files with the pcap analysis program."""
    path = str(pathlib.Path.cwd().parent.parent)
    files = get_files()
    with change_working_directory(path):
        for file in files:
            print(f"[*] Testing {file}")
            subprocess.run(f"py -3.10 pcap_analyser.py {file} summarise",
                           check=False)


if __name__ == "__main__":
    main()
