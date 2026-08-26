import faulthandler
import sys

import pytest

faulthandler.dump_traceback_later(45, exit=True)
sys.exit(pytest.main(["tests/test_full_coverage.py", "-q", "--no-header", "-s"]))