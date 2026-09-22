# Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
# SPDX-License-Identifier: MIT

"""Tests for the envelope/data builders (WEBHOOK_FORMAT=ses|postal)."""

from __future__ import annotations

from base64 import b64decode
from collections.abc import Callable
from typing import Any

import pytest
from lambda_function import (
    LambdaFunctionException,
    build_data_postal,
    build_data_ses,
    build_envelope,
)


def test_build_data_ses_embeds_raw_email_untouched(
    make_eml: Callable[..., bytes],
    ses_mail: dict[str, Any],
    ses_receipt: dict[str, Any],
) -> None:
    raw_email = make_eml(attachments=[('doc.xml', b'<a/>')])

    data = build_data_ses(ses_mail, ses_receipt, raw_email)

    assert data['ses']['mail'] == ses_mail
    assert data['ses']['receipt'] == ses_receipt
    assert b64decode(data['email_base64']) == raw_email


def test_build_data_postal_maps_core_fields(
    make_eml: Callable[..., bytes],
    ses_mail: dict[str, Any],
    ses_receipt: dict[str, Any],
) -> None:
    raw_email = make_eml(subject='Hello', body='Hi there')

    data = build_data_postal(ses_mail, ses_receipt, raw_email)

    assert data['id'] == ses_mail['messageId']
    assert data['token'] == ses_mail['messageId']
    assert data['rcpt_to'] == 'inbox@example.com'
    assert data['mail_from'] == 'sender@example.com'
    assert data['subject'] == 'Hello'
    assert data['spam_status'] == 'NotSpam'
    assert data['bounce'] is False
    assert data['received_with_ssl'] is None


@pytest.mark.parametrize(
    'status,expected',
    [
        ('PASS', 'NotSpam'),
        ('FAIL', 'Spam'),
        ('GRAY', 'Spam'),
        ('PROCESSING_FAILED', 'Spam'),
        ('UNKNOWN', 'Spam'),
    ],
)
def test_build_data_postal_spam_status_mapping(
    make_eml: Callable[..., bytes],
    ses_mail: dict[str, Any],
    ses_receipt: dict[str, Any],
    status: str,
    expected: str,
) -> None:
    ses_receipt['spamVerdict']['status'] = status
    raw_email = make_eml()

    data = build_data_postal(ses_mail, ses_receipt, raw_email)

    assert data['spam_status'] == expected


def test_build_data_postal_reply_to_is_none_when_absent(
    make_eml: Callable[..., bytes],
    ses_mail: dict[str, Any],
    ses_receipt: dict[str, Any],
) -> None:
    raw_email = make_eml()

    data = build_data_postal(ses_mail, ses_receipt, raw_email)

    assert data['reply_to'] is None


def test_build_data_postal_reply_to_single_address(
    make_eml: Callable[..., bytes],
    ses_mail: dict[str, Any],
    ses_receipt: dict[str, Any],
) -> None:
    raw_email = make_eml(
        extra_headers=[('Reply-To', 'Alice <alice@example.com>')]
    )

    data = build_data_postal(ses_mail, ses_receipt, raw_email)

    assert data['reply_to'] == ['Alice <alice@example.com>']


def test_build_data_postal_reply_to_splits_multiple_addresses(
    make_eml: Callable[..., bytes],
    ses_mail: dict[str, Any],
    ses_receipt: dict[str, Any],
) -> None:
    # a comma inside a quoted display name must not be mistaken for the
    # address-list separator — this is exactly what a naive split(',')
    # (or Postal's own reference implementation, which only splits on
    # repeated header lines) would get wrong.
    raw_email = make_eml(
        extra_headers=[
            (
                'Reply-To',
                '"Smith, John" <john@example.com>, jane@example.com',
            )
        ]
    )

    data = build_data_postal(ses_mail, ses_receipt, raw_email)

    assert data['reply_to'] == [
        '"Smith, John" <john@example.com>',
        'jane@example.com',
    ]


def test_build_data_postal_lists_attachments(
    make_eml: Callable[..., bytes],
    ses_mail: dict[str, Any],
    ses_receipt: dict[str, Any],
) -> None:
    raw_email = make_eml(
        attachments=[('doc.xml', b'<a/>'), ('note.txt', b'hi')]
    )

    data = build_data_postal(ses_mail, ses_receipt, raw_email)

    assert data['attachment_quantity'] == 2
    assert [a['filename'] for a in data['attachments']] == [
        'doc.xml',
        'note.txt',
    ]
    assert b64decode(data['attachments'][0]['data']) == b'<a/>'


def test_build_data_postal_allow_extensions_filters_attachments(
    make_eml: Callable[..., bytes],
    ses_mail: dict[str, Any],
    ses_receipt: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('ATTACHMENT_ALLOW_EXTENSIONS', 'xml')
    raw_email = make_eml(
        attachments=[('doc.xml', b'<a/>'), ('note.txt', b'hi')]
    )

    data = build_data_postal(ses_mail, ses_receipt, raw_email)

    assert [a['filename'] for a in data['attachments']] == ['doc.xml']
    assert data['attachment_quantity'] == 1


def test_build_data_postal_allow_extensions_keeps_email_without_matches(
    make_eml: Callable[..., bytes],
    ses_mail: dict[str, Any],
    ses_receipt: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('ATTACHMENT_ALLOW_EXTENSIONS', 'jpg,png')
    raw_email = make_eml(attachments=[])

    data = build_data_postal(ses_mail, ses_receipt, raw_email)

    assert data['attachments'] == []
    assert data['attachment_quantity'] == 0


def test_build_envelope_selects_builder_by_format(
    make_eml: Callable[..., bytes],
    ses_mail: dict[str, Any],
    ses_receipt: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('WEBHOOK_FORMAT', 'ses')
    raw_email = make_eml()

    envelope = build_envelope(ses_mail, ses_receipt, raw_email)

    assert envelope['meta']['format'] == 'ses'
    assert 'ses' in envelope['data']


def test_build_envelope_defaults_to_postal(
    make_eml: Callable[..., bytes],
    ses_mail: dict[str, Any],
    ses_receipt: dict[str, Any],
) -> None:
    raw_email = make_eml()

    envelope = build_envelope(ses_mail, ses_receipt, raw_email)

    assert envelope['meta']['format'] == 'postal'
    assert 'id' in envelope['data']


def test_build_envelope_rejects_unknown_format(
    make_eml: Callable[..., bytes],
    ses_mail: dict[str, Any],
    ses_receipt: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('WEBHOOK_FORMAT', 'unknown')
    raw_email = make_eml()

    with pytest.raises(
        LambdaFunctionException, match='Unknown WEBHOOK_FORMAT'
    ):
        build_envelope(ses_mail, ses_receipt, raw_email)
