# Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
# SPDX-License-Identifier: MIT

"""Shared pytest fixtures for the lambda_function test suite."""

from __future__ import annotations

from collections.abc import Callable
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any
from unittest.mock import MagicMock

import lambda_function
import pytest


@pytest.fixture(autouse=True)
def default_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Baseline env vars every test needs, isolated per test by monkeypatch."""
    monkeypatch.setenv('WEBHOOK_URL', 'https://example.com/hook')
    monkeypatch.setenv('WEBHOOK_SECRET', 'test-secret')
    monkeypatch.setenv('SES_S3_BUCKET', 'test-bucket')
    monkeypatch.delenv('SES_S3_KEY_PREFIX', raising=False)
    monkeypatch.delenv('SES_LOCAL_TEST_EML_FILE', raising=False)
    monkeypatch.delenv('WEBHOOK_FORMAT', raising=False)
    monkeypatch.delenv('WEBHOOK_SIGNATURE', raising=False)
    monkeypatch.delenv('WEBHOOK_SIGNATURE_PREFIX', raising=False)
    monkeypatch.delenv('ATTACHMENT_REQUIRE_EXTENSIONS', raising=False)
    monkeypatch.delenv('ATTACHMENT_ALLOW_EXTENSIONS', raising=False)


@pytest.fixture
def make_eml() -> Callable[..., bytes]:
    """Factory that builds a raw .eml message with the given attachments."""

    def _make_eml(
        attachments: list[tuple[str, bytes]] | None = None,
        subject: str = 'Test subject',
        body: str = 'Test body.',
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> bytes:
        message = MIMEMultipart()
        message['From'] = 'sender@example.com'
        message['To'] = 'inbox@example.com'
        message['Subject'] = subject
        for name, value in extra_headers or []:
            message[name] = value
        message.attach(MIMEText(body, 'plain'))
        for filename, content in attachments or []:
            part = MIMEApplication(content, Name=filename)
            part['Content-Disposition'] = f'attachment; filename="{filename}"'
            message.attach(part)
        return message.as_bytes()

    return _make_eml


@pytest.fixture
def ses_mail() -> dict[str, Any]:
    """Minimal SES "mail" object, as found in record['ses']['mail']."""
    return {
        'timestamp': '2026-01-01T00:00:00.000Z',
        'source': 'sender@example.com',
        'messageId': 'test-message-id',
        'destination': ['inbox@example.com'],
    }


@pytest.fixture
def ses_receipt() -> dict[str, Any]:
    """Minimal SES "receipt" object, as found in record['ses']['receipt']."""
    return {
        'recipients': ['inbox@example.com'],
        'spamVerdict': {'status': 'PASS'},
    }


@pytest.fixture
def ses_record(
    ses_mail: dict[str, Any], ses_receipt: dict[str, Any]
) -> dict[str, Any]:
    """A single SES event record, as found in event['Records']."""
    return {'ses': {'mail': ses_mail, 'receipt': ses_receipt}}


@pytest.fixture
def mock_s3(
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[[bytes], MagicMock]:
    """Factory that patches s3_client.get_object to return the given bytes."""

    def _mock_s3(raw_email: bytes) -> MagicMock:
        body = MagicMock()
        body.read.return_value = raw_email
        get_object = MagicMock(return_value={'Body': body})
        monkeypatch.setattr(
            lambda_function.s3_client, 'get_object', get_object
        )
        return get_object

    return _mock_s3


@pytest.fixture
def mock_webhook(
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[..., MagicMock]:
    """Factory that patches requests.post, returning a 200 by default."""

    def _mock_webhook(status_code: int = 200, text: str = 'OK') -> MagicMock:
        response = MagicMock()
        response.status_code = status_code
        response.text = text
        post = MagicMock(return_value=response)
        monkeypatch.setattr(lambda_function.requests, 'post', post)
        return post

    return _mock_webhook
