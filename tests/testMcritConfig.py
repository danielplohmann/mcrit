import os
import subprocess
import sys
import unittest

READ_TOKEN = "from mcrit.config.McritConfig import McritConfig; print(McritConfig.AUTH_TOKEN)"


class TestMcritConfigAuthToken(unittest.TestCase):
    def _run(self, code, token=None):
        # use a subprocess, as AUTH_TOKEN is a class attribute evaluated at import time
        env = os.environ.copy()
        env.pop("MCRIT_AUTH_TOKEN", None)
        if token is not None:
            env["MCRIT_AUTH_TOKEN"] = token
        return subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, check=True)

    def test_auth_token_from_env(self):
        result = self._run(READ_TOKEN, token="secret_token_from_env")
        self.assertEqual(result.stdout.decode().strip(), "secret_token_from_env")

    def test_auth_token_defaults_to_empty(self):
        result = self._run(READ_TOKEN)
        self.assertEqual(result.stdout.decode().strip(), "")

    def test_warning_when_no_token_configured(self):
        result = self._run("from mcrit.config.McritConfig import McritConfig; McritConfig()")
        self.assertIn(b"No AUTH_TOKEN configured", result.stderr)

    def test_no_warning_when_token_configured(self):
        result = self._run("from mcrit.config.McritConfig import McritConfig; McritConfig()", token="some_token")
        self.assertNotIn(b"No AUTH_TOKEN configured", result.stderr)


if __name__ == "__main__":
    unittest.main()
