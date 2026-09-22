# Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
# SPDX-License-Identifier: MIT

"""Tests for signing (WEBHOOK_SIGNATURE) and sending the webhook request."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from unittest.mock import MagicMock

import pytest
from lambda_function import (
    LambdaFunctionException,
    send_webhook,
    sign_hmac,
    sign_none,
)


def test_sign_hmac_matches_manual_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('WEBHOOK_SECRET', 'top-secret')
    payload = b'{"hello": "world"}'

    headers = sign_hmac(payload)

    expected = hmac.new(b'top-secret', payload, hashlib.sha256).hexdigest()
    assert headers == {'X-Webhook-Signature-256': expected}


def test_sign_hmac_applies_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('WEBHOOK_SIGNATURE_PREFIX', 'sha256=')

    headers = sign_hmac(b'payload')

    assert headers['X-Webhook-Signature-256'].startswith('sha256=')


def test_sign_hmac_requires_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv('WEBHOOK_SECRET', raising=False)

    with pytest.raises(LambdaFunctionException, match='WEBHOOK_SECRET'):
        sign_hmac(b'payload')


def test_sign_none_returns_no_headers() -> None:
    assert sign_none(b'payload') == {}


def test_send_webhook_posts_signed_envelope(
    mock_webhook: Callable[..., MagicMock],
) -> None:
    post = mock_webhook(status_code=200)

    send_webhook({'meta': {}, 'data': {}})

    assert post.call_count == 1
    args, kwargs = post.call_args
    assert args[0] == 'https://example.com/hook'
    assert 'X-Webhook-Signature-256' in kwargs['headers']
    assert kwargs['timeout'] == 10


def test_send_webhook_raises_on_error_status(
    mock_webhook: Callable[..., MagicMock],
) -> None:
    mock_webhook(status_code=500, text='boom')

    with pytest.raises(LambdaFunctionException, match='500'):
        send_webhook({'meta': {}, 'data': {}})


def test_send_webhook_requires_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv('WEBHOOK_URL', raising=False)

    with pytest.raises(LambdaFunctionException, match='WEBHOOK_URL'):
        send_webhook({'meta': {}, 'data': {}})


def test_send_webhook_rejects_unknown_signature(
    mock_webhook: Callable[..., MagicMock], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv('WEBHOOK_SIGNATURE', 'rsa')
    mock_webhook()

    with pytest.raises(LambdaFunctionException, match='WEBHOOK_SIGNATURE'):
        send_webhook({'meta': {}, 'data': {}})


def test_send_webhook_none_signature_sends_no_signature_header(
    mock_webhook: Callable[..., MagicMock], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv('WEBHOOK_SIGNATURE', 'none')
    post = mock_webhook()

    send_webhook({'meta': {}, 'data': {}})

    _, kwargs = post.call_args
    assert 'X-Webhook-Signature-256' not in kwargs['headers']
