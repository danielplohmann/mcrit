import logging
import os
import subprocess
import sys
import unittest
from unittest import mock

from mcrit.config.McritConfig import McritConfig
from mcrit.server.application_routes import AuthMiddleware

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


class TestAuthMiddleware(unittest.TestCase):
    def test_warning_when_no_token_configured(self):
        with mock.patch.object(McritConfig, "AUTH_TOKEN", ""):
            with self.assertLogs("mcrit.server.application_routes", level=logging.WARNING) as logs:
                AuthMiddleware()
        self.assertTrue(any("No AUTH_TOKEN configured" in message for message in logs.output))

    def test_no_warning_when_token_configured(self):
        with mock.patch.object(McritConfig, "AUTH_TOKEN", "some_token"):
            with self.assertNoLogs("mcrit.server.application_routes", level=logging.WARNING):
                AuthMiddleware()

    def test_token_comparison(self):
        with mock.patch.object(McritConfig, "AUTH_TOKEN", "some_token"):
            middleware = AuthMiddleware()
            self.assertTrue(middleware._token_is_valid("some_token"))
            self.assertFalse(middleware._token_is_valid("other_token"))
            # WSGI decodes header bytes as latin-1, so a high byte arrives as a non-ASCII str -
            # that has to answer False instead of raising out of the responder as a 500
            self.assertFalse(middleware._token_is_valid("some_token\xff"))
            self.assertFalse(middleware._token_is_valid("\xff"))

    def test_any_token_accepted_when_unprotected(self):
        with mock.patch.object(McritConfig, "AUTH_TOKEN", ""):
            middleware = AuthMiddleware()
            self.assertTrue(middleware._token_is_valid("anything"))


if __name__ == "__main__":
    unittest.main()
