# Every fixture directory of a test run (tempfile.mkdtemp, TemporaryDirectory) goes
# under one per-run directory, removed at exit: a run leaves nothing in /tmp
# (1,400 mutation-test runs had left 15 GB, 2026-11-03).
import atexit
import shutil
import tempfile

RUN_DIR = tempfile.mkdtemp(prefix="stillmapped-tests-")
tempfile.tempdir = RUN_DIR
atexit.register(shutil.rmtree, RUN_DIR, True)
