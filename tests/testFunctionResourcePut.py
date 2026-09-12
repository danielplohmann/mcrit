import json
import unittest
from unittest.mock import MagicMock

import falcon
import falcon.testing

from mcrit.server.FunctionResource import FunctionResource


def _put(path, body, headers=None):
    environ = falcon.testing.create_environ(path=path, method="PUT", body=json.dumps(body), headers={"Content-Type": "application/json", **(headers or {})})
    return falcon.Request(environ)


class FunctionResourcePutTest(unittest.TestCase):
    """PUT /functions/{id} sets a function's name for the requesting user (fkie-cad/mcritweb#72)"""

    def test_modifies_the_function_for_the_requesting_user(self):
        index = MagicMock()
        index.isFunctionId.return_value = True
        index.modifyFunction.return_value = True
        resp = falcon.Response()
        FunctionResource(index).on_put(_put("/functions/7", {"function_name": "  decrypt_config "}, {"username": "alice"}), resp, function_id=7)
        self.assertEqual(falcon.HTTP_200, resp.status)
        index.modifyFunction.assert_called_once_with(7, {"function_name": "decrypt_config"}, username="alice")
        assert resp.data is not None
        self.assertEqual("successful", json.loads(resp.data)["status"])

    def test_refuses_bad_input(self):
        for body, headers, status, fragment in (
            (None, {}, falcon.HTTP_400, "without body"),
            ({"is_library": True}, {}, falcon.HTTP_400, "function_name"),
            ({"function_name": "x" * 257}, {}, falcon.HTTP_400, "printable"),
            ({"function_name": "d\u00e9crypt"}, {}, falcon.HTTP_400, "printable"),
            ({"function_name": 7}, {}, falcon.HTTP_400, "printable"),
        ):
            with self.subTest(body=body):
                index = MagicMock()
                index.isFunctionId.return_value = True
                resp = falcon.Response()
                request = _put("/functions/7", body) if body is not None else falcon.Request(falcon.testing.create_environ(path="/functions/7", method="PUT"))
                FunctionResource(index).on_put(request, resp, function_id=7)
                self.assertEqual(status, resp.status)
                index.modifyFunction.assert_not_called()
                assert resp.data is not None
                self.assertIn(fragment, json.loads(resp.data)["data"]["message"])

    def test_unknown_and_query_functions_are_404(self):
        for function_id, known in ((99, False), (-3, True)):
            with self.subTest(function_id=function_id):
                index = MagicMock()
                index.isFunctionId.return_value = known
                resp = falcon.Response()
                FunctionResource(index).on_put(_put(f"/functions/{function_id}", {"function_name": "x"}), resp, function_id=function_id)
                self.assertEqual(falcon.HTTP_404, resp.status)
                index.modifyFunction.assert_not_called()


if __name__ == "__main__":
    unittest.main()
