import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "deploy.sh"


class DeployScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.repo = root / "repo"
        self.remote = root / "remote.git"
        self.repo.mkdir()
        self.run_git("init", "--bare", str(self.remote), cwd=root)
        self.run_git("init", "-b", "main")
        self.run_git("config", "user.name", "Test")
        self.run_git("config", "user.email", "test@example.com")
        (self.repo / "scripts").mkdir()
        shutil.copy(SCRIPT, self.repo / "scripts/deploy.sh")
        (self.repo / "file").write_text("initial\n")
        self.run_git("add", ".")
        self.run_git("commit", "-m", "initial")
        self.run_git("remote", "add", "origin", str(self.remote))
        self.run_git("push", "-u", "origin", "main")
        self.bin = root / "bin"
        self.bin.mkdir()
        for name, body in {"ssh": "cat >/dev/null; echo ok", "gh": "exit 0", "curl": "printf 200"}.items():
            path = self.bin / name
            path.write_text("#!/bin/sh\n" + body + "\n")
            path.chmod(0o755)

    def run_git(self, *args, cwd=None):
        return subprocess.run(["git", *args], cwd=cwd or self.repo, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()

    def deploy(self):
        env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}")
        return subprocess.run(["bash", "scripts/deploy.sh"], cwd=self.repo, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_refuses_non_main_branch(self):
        self.run_git("switch", "-c", "feature")
        result = self.deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Deploy requires the local main branch", result.stdout)

    def test_pushes_existing_commit_with_clean_worktree(self):
        (self.repo / "file").write_text("updated\n")
        self.run_git("add", "file")
        self.run_git("commit", "-m", "update")
        self.assertEqual(self.run_git("status", "--porcelain"), "")
        result = self.deploy()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.run_git("rev-parse", "HEAD"), self.run_git("rev-parse", "refs/heads/main", cwd=self.remote))
