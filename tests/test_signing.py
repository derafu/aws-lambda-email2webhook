# Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
# SPDX-License-Identifier: MIT

"""Tests for signing (WEBHOOK_SIGNATURE) and sending the webhook request."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import lambda_function
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


def _fake_post_per_url(
    responses: dict[str, tuple[int, str]],
) -> MagicMock:
    """A requests.post replacement that answers differently per URL."""

    def _post(url: str, **kwargs: Any) -> MagicMock:
        status_code, text = responses[url]
        response = MagicMock()
        response.status_code = status_code
        response.text = text
        return response

    return MagicMock(side_effect=_post)


def test_send_webhook_debug_only_when_webhook_url_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv('WEBHOOK_URL', raising=False)
    monkeypatch.setenv('WEBHOOK_DEBUG_URL', 'https://debug.example.com/hook')
    post = _fake_post_per_url({'https://debug.example.com/hook': (200, 'OK')})
    monkeypatch.setattr(lambda_function.requests, 'post', post)

    result = send_webhook({'meta': {}, 'data': {}})

    assert result is None
    assert post.call_count == 1
    assert post.call_args.args[0] == 'https://debug.example.com/hook'


def test_send_webhook_neither_url_set_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv('WEBHOOK_URL', raising=False)
    monkeypatch.delenv('WEBHOOK_DEBUG_URL', raising=False)

    with pytest.raises(LambdaFunctionException, match='WEBHOOK_URL'):
        send_webhook({'meta': {}, 'data': {}})


def test_send_webhook_sends_to_both_urls_when_both_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('WEBHOOK_DEBUG_URL', 'https://debug.example.com/hook')
    post = _fake_post_per_url(
        {
            'https://example.com/hook': (200, 'OK'),
            'https://debug.example.com/hook': (200, 'OK'),
        }
    )
    monkeypatch.setattr(lambda_function.requests, 'post', post)

    result = send_webhook({'meta': {}, 'data': {}})

    assert result is not None
    called_urls = [call.args[0] for call in post.call_args_list]
    assert called_urls == [
        'https://debug.example.com/hook',
        'https://example.com/hook',
    ]


def test_send_webhook_debug_failure_does_not_raise_or_block_primary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('WEBHOOK_DEBUG_URL', 'https://debug.example.com/hook')
    post = _fake_post_per_url(
        {
            'https://example.com/hook': (200, 'OK'),
            'https://debug.example.com/hook': (500, 'boom'),
        }
    )
    monkeypatch.setattr(lambda_function.requests, 'post', post)

    result = send_webhook({'meta': {}, 'data': {}})

    assert result is not None
    assert result.status_code == 200


def test_send_webhook_debug_connection_error_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('WEBHOOK_DEBUG_URL', 'https://debug.example.com/hook')

    def _post(url: str, **kwargs: Any) -> MagicMock:
        if url == 'https://debug.example.com/hook':
            raise lambda_function.requests.ConnectionError('unreachable')
        response = MagicMock()
        response.status_code = 200
        response.text = 'OK'
        return response

    monkeypatch.setattr(
        lambda_function.requests, 'post', MagicMock(side_effect=_post)
    )

    result = send_webhook({'meta': {}, 'data': {}})

    assert result is not None
    assert result.status_code == 200


def test_send_webhook_primary_failure_still_raises_even_if_debug_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('WEBHOOK_DEBUG_URL', 'https://debug.example.com/hook')
    post = _fake_post_per_url(
        {
            'https://example.com/hook': (500, 'boom'),
            'https://debug.example.com/hook': (200, 'OK'),
        }
    )
    monkeypatch.setattr(lambda_function.requests, 'post', post)

    with pytest.raises(LambdaFunctionException, match='500'):
        send_webhook({'meta': {}, 'data': {}})
