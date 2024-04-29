"""Script to automate compliance checks."""
import unittest
import subprocess
import pathlib

import pycodestyle
from pylint.lint.run import Run
from pylint.reporters.text import TextReporter
import pydocstyle


def get_all_py_files() -> list[str]:
    """Get all python files in dir and subdirs."""
    all_py_files = []

    cwd = pathlib.Path.cwd().parent
    for file in cwd.rglob("*"):
        if file.suffix == ".py":
            all_py_files.append(str(file))
    return all_py_files


class CustomPylintReporter:
    """Wrapper for Pylint output."""

    def __init__(self) -> None:
        """Initialize variables."""
        self.content: list[str] = []

    def write(self, write_string: str) -> None:
        """Write to content."""
        self.content.append(write_string)

    def read(self) -> list[str]:
        """Read from content."""
        return self.content

    def get_score(self) -> float:
        """Get score from content."""
        sentence = self.content[-3]
        # Your code has been rated at 10/10
        subsentence = sentence.split("/")[0]
        # Your code has been rated at 10
        number = float(subsentence.split(" ")[-1])
        # 10.0
        return number


class TestCodeCompliance(unittest.TestCase):
    """Unit tests."""

    all_py_files = get_all_py_files()
    error_string = """Found %s errors, please run
                   the full command and correct any errors."""

    def test_pycodestyle_compliance(self) -> None:
        """Test pycodestyle compliance."""
        style = pycodestyle.StyleGuide(quiet=True)
        result = style.check_files(self.all_py_files)
        self.assertEqual(result.total_errors, 0,
                         self.error_string % 'pycodestyle')

    def test_pylint_compliance(self) -> None:
        """Test pylint compliance."""
        output = CustomPylintReporter()
        Run(self.all_py_files, reporter=TextReporter(output), exit=False)
        result = output.get_score()
        self.assertEqual(result, 10.0, self.error_string % 'pylint')

    def test_mypy_compliance(self) -> None:
        """Test mypy compliance.

        mypy contains little to no modular implementation,
        meaning that lazy subprocess Popen is required
        to mimic running mypy from the command line.
        """
        with subprocess.Popen(["py", "-3.10", "-m",
                               "mypy", "--ignore-missing-imports",
                               "--disallow-untyped-defs",
                               "--disable-error-code", "attr-defined",
                               "pcap_analyser.py"],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              shell=True, encoding="utf-8") as proc:
            stdout, _ = proc.communicate()
            errors = int(stdout.count("error"))
            self.assertEqual(errors, 0, self.error_string % 'mypy')

    def test_pydocstyle_compliance(self) -> None:
        """Test pydocstyle compliance."""
        result = list(pydocstyle.check(self.all_py_files))
        errors = len(result)
        self.assertEqual(errors, 0, self.error_string % 'pydocstyle')


unittest.main()
