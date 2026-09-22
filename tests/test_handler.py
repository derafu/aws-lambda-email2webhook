# Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
# SPDX-License-Identifier: MIT

"""End-to-end tests for get_raw_email / process_ses_record / lambda_handler."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from lambda_function import (
    LambdaFunctionException,
    get_raw_email,
    lambda_handler,
)


def _event(*records: dict[str, Any]) -> dict[str, Any]:
    return {'Records': list(records)}


def test_get_raw_email_reads_local_test_file(
    make_eml: Callable[..., bytes],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_email = make_eml(subject='Local test')
    eml_path = tmp_path / 'test.eml'
    eml_path.write_bytes(raw_email)
    monkeypatch.setenv('SES_LOCAL_TEST_EML_FILE', str(eml_path))

    assert get_raw_email('unused-message-id') == raw_email


def test_get_raw_email_reads_from_s3(
    make_eml: Callable[..., bytes],
    mock_s3: Callable[[bytes], MagicMock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('SES_S3_KEY_PREFIX', 'inbound/')
    raw_email = make_eml()
    get_object = mock_s3(raw_email)

    result = get_raw_email('abc-123')

    assert result == raw_email
    get_object.assert_called_once_with(
        Bucket='test-bucket', Key='inbound/abc-123'
    )


def test_get_raw_email_requires_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv('SES_S3_BUCKET', raising=False)

    with pytest.raises(LambdaFunctionException, match='SES_S3_BUCKET'):
        get_raw_email('abc-123')


def test_lambda_handler_sends_webhook_for_single_record(
    make_eml: Callable[..., bytes],
    mock_s3: Callable[[bytes], MagicMock],
    mock_webhook: Callable[..., MagicMock],
    ses_record: dict[str, Any],
) -> None:
    mock_s3(make_eml(attachments=[('doc.xml', b'<a/>')]))
    post = mock_webhook()

    result = lambda_handler(_event(ses_record), None)

    assert result == {'disposition': 'CONTINUE'}
    assert post.call_count == 1


def test_lambda_handler_processes_multiple_records(
    make_eml: Callable[..., bytes],
    mock_s3: Callable[[bytes], MagicMock],
    mock_webhook: Callable[..., MagicMock],
    ses_mail: dict[str, Any],
    ses_receipt: dict[str, Any],
) -> None:
    get_object = mock_s3(make_eml())
    post = mock_webhook()
    records = [
        {
            'ses': {
                'mail': {**ses_mail, 'messageId': f'msg-{i}'},
                'receipt': ses_receipt,
            }
        }
        for i in range(3)
    ]

    result = lambda_handler(_event(*records), None)

    assert result == {'disposition': 'CONTINUE'}
    assert post.call_count == 3
    assert get_object.call_count == 3


@pytest.mark.parametrize(
    'require_extensions,allow_extensions,attachments,expect_filenames',
    [
        # backward-compatible default: no filters configured at all.
        (
            None,
            None,
            [('doc.xml', b'<a/>'), ('note.txt', b'hi')],
            ['doc.xml', 'note.txt'],
        ),
        # SII-style: require XML, forward only the XML attachments.
        (
            'xml',
            'xml',
            [('doc.xml', b'<a/>'), ('note.txt', b'hi')],
            ['doc.xml'],
        ),
        # require XML, but forward everything that comes along.
        (
            'xml',
            None,
            [('doc.xml', b'<a/>'), ('note.txt', b'hi')],
            ['doc.xml', 'note.txt'],
        ),
        # optional images: nothing required, only images get forwarded.
        (
            None,
            'jpg,jpeg,png,gif',
            [('photo.jpg', b'\xff\xd8')],
            ['photo.jpg'],
        ),
        # optional images: email without any image still gets sent.
        (None, 'jpg,jpeg,png,gif', [], []),
    ],
)
def test_lambda_handler_attachment_filters_that_pass(
    make_eml: Callable[..., bytes],
    mock_s3: Callable[[bytes], MagicMock],
    mock_webhook: Callable[..., MagicMock],
    ses_record: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    require_extensions: str | None,
    allow_extensions: str | None,
    attachments: list[tuple[str, bytes]],
    expect_filenames: list[str],
) -> None:
    if require_extensions is not None:
        monkeypatch.setenv('ATTACHMENT_REQUIRE_EXTENSIONS', require_extensions)
    if allow_extensions is not None:
        monkeypatch.setenv('ATTACHMENT_ALLOW_EXTENSIONS', allow_extensions)
    mock_s3(make_eml(attachments=attachments))
    post = mock_webhook()

    lambda_handler(_event(ses_record), None)

    assert post.call_count == 1
    payload = json.loads(post.call_args.kwargs['data'])
    sent_filenames = [a['filename'] for a in payload['data']['attachments']]
    assert sent_filenames == expect_filenames


def test_lambda_handler_discards_email_missing_required_attachment(
    make_eml: Callable[..., bytes],
    mock_s3: Callable[[bytes], MagicMock],
    mock_webhook: Callable[..., MagicMock],
    ses_record: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('ATTACHMENT_REQUIRE_EXTENSIONS', 'xml')
    mock_s3(make_eml(attachments=[('note.txt', b'hi')]))
    post = mock_webhook()

    result = lambda_handler(_event(ses_record), None)

    assert result == {'disposition': 'CONTINUE'}
    assert post.call_count == 0
