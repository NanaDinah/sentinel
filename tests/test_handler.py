import json

from moto import mock_aws

from sentinel import handler


@mock_aws
def test_scan_of_an_empty_account_finds_nothing():
    assert handler.run_scan() == []


@mock_aws
def test_lambda_handler_returns_ok_and_json_body(monkeypatch):
    monkeypatch.delenv("FINDINGS_TABLE", raising=False)
    monkeypatch.delenv("ALERT_TOPIC_ARN", raising=False)

    response = handler.lambda_handler({}, None)

    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["findings"] == []