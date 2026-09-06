import json
import unittest
from unittest.mock import MagicMock, patch

from mcrit.client.McritClient import (
    McritBadRequest,
    McritClient,
    McritClientError,
    McritConflict,
    McritGone,
    McritNotFound,
    McritRequestError,
    McritServerError,
    McritUnauthorized,
    failure_message,
    handle_response,
)


def answer(status_code, body=None, url="http://mcrit.test/samples/7"):
    """A requests.Response stand-in: the status, the JSON body and the URL are all the client reads."""
    response = MagicMock(status_code=status_code, url=url)
    if body is None:
        response.json.side_effect = ValueError("no JSON")
        response.text = ""
    else:
        response.json.return_value = body
        response.text = json.dumps(body)
    return response


FAILED = {"status": "failed", "data": {"message": "We don't have a sample with that id."}}


class HandleResponseTest(unittest.TestCase):
    def test_by_default_every_failure_answers_none(self):
        for status in (400, 404, 410, 500, 501, 418):
            self.assertIsNone(handle_response(answer(status, FAILED)), status)
        self.assertIsNone(handle_response(answer(200, {"status": "failed", "data": {"message": "nope"}})))

    def test_a_success_still_answers_its_data(self):
        for flags in ({}, {"raise_client_errors": True}, {"raise_server_errors": True}):
            self.assertEqual({"sample_id": 7}, handle_response(answer(200, {"status": "successful", "data": {"sample_id": 7}}), **flags))
            self.assertEqual("job", handle_response(answer(202, {"status": "successful", "data": "job"}), **flags))

    def test_request_errors_raise_their_own_class_with_the_servers_message(self):
        for status, cls in (
            (400, McritBadRequest),
            (401, McritUnauthorized),
            (403, McritUnauthorized),
            (404, McritNotFound),
            (409, McritConflict),
            (410, McritGone),
            (418, McritRequestError),
        ):
            with self.assertRaises(cls) as raised:
                handle_response(answer(status, FAILED), raise_client_errors=True)
            self.assertIsInstance(raised.exception, McritRequestError)
            self.assertIsInstance(raised.exception, McritClientError)
            self.assertEqual(status, raised.exception.status_code)
            self.assertEqual("We don't have a sample with that id.", raised.exception.message)
            self.assertEqual("http://mcrit.test/samples/7", raised.exception.url)
            self.assertIn("We don't have a sample with that id.", str(raised.exception))
            # the other mode leaves them alone
            self.assertIsNone(handle_response(answer(status, FAILED), raise_server_errors=True))

    def test_server_errors_raise_only_in_the_server_mode(self):
        for status in (500, 501, 302):
            with self.assertRaises(McritServerError) as raised:
                handle_response(answer(status, FAILED), raise_server_errors=True)
            self.assertNotIsInstance(raised.exception, McritRequestError)
            self.assertEqual(status, raised.exception.status_code)
            self.assertIsNone(handle_response(answer(status, FAILED), raise_client_errors=True))

    def test_a_failed_two_hundred_is_a_server_error(self):
        with self.assertRaises(McritServerError) as raised:
            handle_response(answer(200, {"status": "failed", "data": {"message": "Failed to modify family."}}), raise_server_errors=True)
        self.assertEqual("Failed to modify family.", raised.exception.message)

    def test_a_body_that_is_not_mcrits_failure_shape_gives_an_empty_message(self):
        self.assertEqual("", failure_message(answer(502)))  # proxy answered with no JSON
        self.assertEqual("", failure_message(answer(500, ["not", "a", "dict"])))
        self.assertEqual("", failure_message(answer(500, {"status": "failed", "data": "just a string"})))
        with self.assertRaises(McritServerError) as raised:
            handle_response(answer(502), raise_server_errors=True)
        self.assertEqual("", raised.exception.message)
        self.assertIn("no message", str(raised.exception))


class ClientModesTest(unittest.TestCase):
    def test_the_default_client_keeps_answering_none(self):
        client = McritClient("http://mcrit.test")
        with patch("mcrit.client.McritClient.requests.get", return_value=answer(404, FAILED)):
            self.assertIsNone(client.getSampleById(7))
        with patch("mcrit.client.McritClient.requests.get", return_value=answer(500, FAILED)):
            self.assertIsNone(client.getSampleById(7))

    def test_a_raising_client_raises_through_its_methods(self):
        client = McritClient("http://mcrit.test", raise_client_errors=True, raise_server_errors=True)
        with patch("mcrit.client.McritClient.requests.get", return_value=answer(404, FAILED)):
            with self.assertRaises(McritNotFound):
                client.getSampleById(7)
        with patch("mcrit.client.McritClient.requests.get", return_value=answer(500, FAILED)):
            with self.assertRaises(McritServerError):
                client.getFamily(1)
        with patch("mcrit.client.McritClient.requests.delete", return_value=answer(400, FAILED)):
            with self.assertRaises(McritBadRequest):
                client.deleteFamily(1)

    def test_one_mode_does_not_imply_the_other(self):
        server_only = McritClient("http://mcrit.test", raise_server_errors=True)
        with patch("mcrit.client.McritClient.requests.get", return_value=answer(404, FAILED)):
            self.assertIsNone(server_only.getSampleById(7))
        with patch("mcrit.client.McritClient.requests.get", return_value=answer(500, FAILED)):
            with self.assertRaises(McritServerError):
                server_only.getSampleById(7)

    def test_raw_mode_hands_out_the_response_whatever_the_status(self):
        client = McritClient("http://mcrit.test", raw_responses=True, raise_client_errors=True, raise_server_errors=True)
        response = answer(500, FAILED)
        with patch("mcrit.client.McritClient.requests.get", return_value=response):
            self.assertIs(response, client.getSampleById(7))
            self.assertIs(response, client.getFunctionById(7))
            self.assertIs(response, client.isFunctionId(7))

    def test_a_four_xx_never_reads_as_a_server_failure(self):
        """401 (AuthMiddleware) and 409 (an existing binary) are answers the server gives on
        purpose; with both modes on they must come back as request errors, not as a backend
        failure, and with the server mode alone they stay None."""
        for status in (401, 403, 409, 418):
            with self.assertRaises(McritRequestError):
                handle_response(answer(status, FAILED), raise_client_errors=True, raise_server_errors=True)
            self.assertIsNone(handle_response(answer(status, FAILED), raise_server_errors=True))


if __name__ == "__main__":
    unittest.main()
