# Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
# SPDX-License-Identifier: MIT

"""
Forward an SES-received email as a signed webhook.

This function receives an inbound email notification from an Amazon SES
receipt rule (invoked directly, without an SNS topic in between), downloads
the raw MIME message from the S3 bucket where the receipt rule stored it,
and forwards it as a signed webhook so a downstream system can process it
(for example, to create a support ticket).

The SES "Lambda" receipt action never includes the email body, only
metadata (see "mail" and "receipt" objects below), so an "S3" action must
be placed before the "Lambda" action in the same receipt rule to store the
raw message. The object key SES uses in that bucket is always the
message's "messageId".

The webhook body is always an envelope of the form:

    {"meta": {"source": "aws-ses", "format": "...", "version": "1.0.0"},
     "data": {...}}

"format" (WEBHOOK_FORMAT) selects which builder in DATA_BUILDERS produces
"data", so the shape of "data" is fully determined by "format". Adding a
new output format only requires adding a new builder function here.

Two independent, optional attachment filters (both empty by default, so
neither has any effect unless configured):

- ATTACHMENT_REQUIRE_EXTENSIONS: if set, an email is only processed (and
  sent to the webhook at all) when it has at least one attachment whose
  extension matches. Applies regardless of WEBHOOK_FORMAT.
- ATTACHMENT_ALLOW_EXTENSIONS: if set, only matching attachments are
  included in the "postal" format's attachment list; non-matching ones
  are dropped from the payload, but the email itself is still sent. Has
  no effect on the "ses" format, which embeds the raw email as-is.

WEBHOOK_DEBUG_URL (optional) sends an identical, best-effort copy of the
same signed request to a second URL — for temporarily watching traffic
without touching WEBHOOK_URL. Failures on this URL are logged, never
raised, so a broken or slow debug endpoint can never block or fail the
real WEBHOOK_URL request. WEBHOOK_URL itself becomes optional too: with
only WEBHOOK_DEBUG_URL set, the function runs in debug-only mode.
"""

# modules used by this function
import hashlib
import hmac
import json
import mimetypes
from base64 import b64encode
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import formataddr, getaddresses
from http import HTTPStatus
from os import getenv
from os.path import splitext
from typing import Any

import boto3
import requests


class LambdaFunctionException(Exception):
    """Raised for invalid configuration or an unexpected webhook response."""


# S3 client created once and reused across invocations (execution context
# reuse)
s3_client = boto3.client('s3')

ENVELOPE_SOURCE = 'aws-ses'
ENVELOPE_VERSION = '1.0.0'

# a GRAY or PROCESSING_FAILED spam verdict doesn't mean the email should be
# dropped, but it shouldn't be trusted as much as a PASS either, so it's
# mapped to "Spam" to get the same downstream priority as a confirmed FAIL
SPAM_STATUS_MAP = {
    'PASS': 'NotSpam',
    'FAIL': 'Spam',
    'GRAY': 'Spam',
    'PROCESSING_FAILED': 'Spam',
}


# ----------------------------------------------------------------------
# Attachment extension filtering (ATTACHMENT_REQUIRE_EXTENSIONS and
# ATTACHMENT_ALLOW_EXTENSIONS) — see the module docstring above.
# ----------------------------------------------------------------------


def parse_extensions(value: str) -> set[str]:
    """Parse a comma-separated extension list into a normalized set."""
    return {
        extension.strip().lstrip('.').lower()
        for extension in value.split(',')
        if extension.strip()
    }


def attachment_extension(filename: str | None, content_type: str) -> str:
    """Return the lowercase extension (no dot) for an attachment."""
    if filename:
        extension = splitext(filename)[1]
    else:
        extension = mimetypes.guess_extension(content_type) or ''
    return extension.lstrip('.').lower()


def has_required_attachment(raw_email: bytes) -> bool:
    """Check raw_email against ATTACHMENT_REQUIRE_EXTENSIONS, if set."""
    required = parse_extensions(getenv('ATTACHMENT_REQUIRE_EXTENSIONS', ''))
    if not required:
        return True
    message = BytesParser(policy=policy.default).parsebytes(raw_email)
    return any(
        attachment_extension(part.get_filename(), part.get_content_type())
        in required
        for part in message.iter_attachments()
    )


# ----------------------------------------------------------------------
# Function that fetches the raw email stored in S3 by the SES receipt rule
# ----------------------------------------------------------------------


def get_raw_email(message_id: str) -> bytes:
    """Fetch the raw MIME message that SES stored in S3 for message_id."""
    # allows running a local test without AWS credentials or network access
    local_test_file = getenv('SES_LOCAL_TEST_EML_FILE')
    if local_test_file:
        with open(local_test_file, 'rb') as f:
            return f.read()
    bucket = getenv('SES_S3_BUCKET')
    if bucket is None:
        raise LambdaFunctionException('SES_S3_BUCKET is not set')
    key_prefix = getenv('SES_S3_KEY_PREFIX', '')
    response = s3_client.get_object(Bucket=bucket, Key=key_prefix + message_id)
    return response['Body'].read()


# ----------------------------------------------------------------------
# "ses" format: the envelope's own native representation, no MIME parsing
# ----------------------------------------------------------------------


def build_data_ses(
    mail: dict[str, Any], receipt: dict[str, Any], raw_email: bytes
) -> dict[str, Any]:
    """Build the "data" payload for the "ses" output format."""
    return {
        'ses': {
            'mail': mail,
            'receipt': receipt,
        },
        'email_base64': b64encode(raw_email).decode('ascii'),
    }


# ----------------------------------------------------------------------
# "postal" format: matches the JSON shape Postal sends for HTTP endpoints
# configured with Encoding=BodyAsJSON and Format=Hash, confirmed against
# Postal's own source (app/senders/http_sender.rb)
# ----------------------------------------------------------------------


def build_data_postal(
    mail: dict[str, Any], receipt: dict[str, Any], raw_email: bytes
) -> dict[str, Any]:
    """Build the "data" payload for the "postal" output format."""
    message = BytesParser(policy=policy.default).parsebytes(raw_email)

    text_part = message.get_body(preferencelist=('plain',))
    html_part = message.get_body(preferencelist=('html',))

    allowed_extensions = parse_extensions(
        getenv('ATTACHMENT_ALLOW_EXTENSIONS', '')
    )
    attachments: list[dict[str, Any]] = []
    for part in message.iter_attachments():
        filename = part.get_filename()
        content_type = part.get_content_type()
        extension = attachment_extension(filename, content_type)
        if allowed_extensions and extension not in allowed_extensions:
            continue
        content = part.get_content()
        if isinstance(content, str):
            content = content.encode('utf-8')
        attachments.append(
            {
                'filename': filename,
                'content_type': content_type,
                'size': len(content),
                'data': b64encode(content).decode('ascii'),
            }
        )

    recipients = receipt.get('recipients') or mail.get('destination') or [None]
    spam_status = SPAM_STATUS_MAP.get(
        receipt.get('spamVerdict', {}).get('status'), 'Spam'
    )
    received_at = datetime.fromisoformat(
        mail['timestamp'].replace('Z', '+00:00')
    )
    # RFC 5322's "reply-to" is an address-list, same as "to"/"cc" — it can
    # legitimately hold more than one address, so (unlike the other header
    # fields above, kept as the single raw header string) this one is
    # parsed into a list of individual addresses. getaddresses() also
    # correctly splits on commas inside a quoted display name, which a
    # naive split(',') — or Postal's own reference implementation, which
    # only splits on repeated "Reply-To" header lines, not on individual
    # addresses within one such line — would get wrong.
    reply_to_addresses = getaddresses(message.get_all('reply-to', []))

    return {
        # SES's messageId is an opaque string, not the sequential integer ID
        # Postal uses (an auto-increment SQL column), so it's reused as-is
        # for both "id" and "token" — a real, unfixable shape difference
        # (string here vs int in Postal), but there's no numeric SES
        # equivalent to use instead, and a generic string id is fine for
        # any consumer that doesn't assume Postal's specific type.
        'id': mail['messageId'],
        'token': mail['messageId'],
        'rcpt_to': recipients[0],
        'mail_from': mail.get('source'),
        'subject': message.get('subject'),
        'message_id': message.get('message-id'),
        'timestamp': received_at.timestamp(),
        # Postal's own "size" is a plain SQL varchar column returned as-is
        # (no numeric cast on their end), so it's actually a string there,
        # not an int — this int is the more correct shape and is kept as
        # such on purpose.
        'size': len(raw_email),
        'spam_status': spam_status,
        'bounce': False,
        # SES doesn't report whether the original SMTP session used TLS
        'received_with_ssl': None,
        'to': message.get('to'),
        'cc': message.get('cc'),
        'from': message.get('from'),
        'date': message.get('date'),
        'in_reply_to': message.get('in-reply-to'),
        'references': message.get('references'),
        'reply_to': (
            [formataddr(pair) for pair in reply_to_addresses]
            if reply_to_addresses
            else None
        ),
        'plain_body': (
            text_part.get_content() if text_part is not None else None
        ),
        'html_body': (
            html_part.get_content() if html_part is not None else None
        ),
        'auto_submitted': message.get('auto-submitted'),
        'attachment_quantity': len(attachments),
        'attachments': attachments,
    }


DATA_BUILDERS = {
    'ses': build_data_ses,
    'postal': build_data_postal,
}


def build_envelope(
    mail: dict[str, Any], receipt: dict[str, Any], raw_email: bytes
) -> dict[str, Any]:
    """Build the full webhook envelope for the given SES mail/receipt."""
    webhook_format = getenv('WEBHOOK_FORMAT', 'postal')
    if webhook_format not in DATA_BUILDERS:
        raise LambdaFunctionException(
            'Unknown WEBHOOK_FORMAT: %(format)s' % {'format': webhook_format}
        )
    return {
        'meta': {
            'source': ENVELOPE_SOURCE,
            'format': webhook_format,
            'version': ENVELOPE_VERSION,
        },
        'data': DATA_BUILDERS[webhook_format](mail, receipt, raw_email),
    }


# ----------------------------------------------------------------------
# Functions that sign and send the webhook request
# ----------------------------------------------------------------------


def sign_hmac(payload_bytes: bytes) -> dict[str, str]:
    """Sign payload_bytes with HMAC-SHA256, returning the signature header."""
    webhook_secret = getenv('WEBHOOK_SECRET')
    if webhook_secret is None:
        raise LambdaFunctionException('WEBHOOK_SECRET is not set')
    signature_prefix = getenv('WEBHOOK_SIGNATURE_PREFIX', '')
    digest = hmac.new(
        webhook_secret.encode('utf-8'), payload_bytes, hashlib.sha256
    ).hexdigest()
    return {'X-Webhook-Signature-256': signature_prefix + digest}


def sign_none(payload_bytes: bytes) -> dict[str, str]:
    """Return no signature headers (WEBHOOK_SIGNATURE=none)."""
    return {}


SIGNERS = {
    'hmac': sign_hmac,
    'none': sign_none,
}


def send_webhook_debug(
    webhook_debug_url: str, payload_bytes: bytes, headers: dict[str, str]
) -> None:
    """
    Best-effort copy of the webhook request to WEBHOOK_DEBUG_URL.

    Any failure here (bad status, timeout, connection error) is caught
    and logged, never raised: a broken or slow debug endpoint must never
    affect whether the real WEBHOOK_URL request is sent, or make the
    Lambda invocation "fail" and get retried by SES.
    """
    try:
        response = requests.post(
            webhook_debug_url, data=payload_bytes, headers=headers, timeout=10
        )
    except requests.RequestException as e:
        print(f'WEBHOOK_DEBUG_URL request failed: {e}')
        return
    if response.status_code >= HTTPStatus.MULTIPLE_CHOICES:
        print(
            'WEBHOOK_DEBUG_URL request to %(url)s failed with status '
            '%(status)s: %(body)s'
            % {
                'url': webhook_debug_url,
                'status': response.status_code,
                'body': response.text,
            }
        )


def send_webhook(envelope: dict[str, Any]) -> requests.Response | None:
    """
    POST the envelope to WEBHOOK_URL, signed per WEBHOOK_SIGNATURE.

    WEBHOOK_DEBUG_URL, if set, gets an identical best-effort copy of the
    request first (see send_webhook_debug) — it's attempted regardless
    of whether WEBHOOK_URL is even set, and never affects the outcome
    below. Returns None instead of a Response when WEBHOOK_URL isn't set
    (debug-only mode).
    """
    webhook_url = getenv('WEBHOOK_URL')
    webhook_debug_url = getenv('WEBHOOK_DEBUG_URL')
    if webhook_url is None and webhook_debug_url is None:
        raise LambdaFunctionException(
            'Neither WEBHOOK_URL nor WEBHOOK_DEBUG_URL is set'
        )
    webhook_signature = getenv('WEBHOOK_SIGNATURE', 'hmac')
    if webhook_signature not in SIGNERS:
        raise LambdaFunctionException(
            'Unknown WEBHOOK_SIGNATURE: %(scheme)s'
            % {'scheme': webhook_signature}
        )
    payload_bytes = json.dumps(envelope, ensure_ascii=False).encode('utf-8')
    headers = {'Content-Type': 'application/json'}
    headers.update(SIGNERS[webhook_signature](payload_bytes))

    if webhook_debug_url is not None:
        send_webhook_debug(webhook_debug_url, payload_bytes, headers)

    if webhook_url is None:
        return None

    response = requests.post(
        webhook_url, data=payload_bytes, headers=headers, timeout=10
    )
    if response.status_code >= HTTPStatus.MULTIPLE_CHOICES:
        raise LambdaFunctionException(
            'Webhook request to %(url)s failed with status '
            '%(status)s: %(body)s'
            % {
                'url': webhook_url,
                'status': response.status_code,
                'body': response.text,
            }
        )
    return response


# ----------------------------------------------------------------------
# Main function invoked directly by the SES receipt rule's Lambda action
# ----------------------------------------------------------------------


def process_ses_record(record: dict[str, Any]) -> None:
    """Fetch, build and send the webhook for a single SES record."""
    mail = record['ses']['mail']
    receipt = record['ses']['receipt']
    raw_email = get_raw_email(mail['messageId'])
    # ATTACHMENT_REQUIRE_EXTENSIONS gate: discard the email entirely if it
    # has no attachment matching one of the required extensions.
    if not has_required_attachment(raw_email):
        return
    envelope = build_envelope(mail, receipt, raw_email)
    send_webhook(envelope)


def lambda_handler(event: dict[str, Any], context: object) -> dict[str, str]:
    """Entry point invoked by the SES receipt rule's Lambda action."""
    for record in event.get('Records', []):
        process_ses_record(record)
    # only relevant when the receipt rule invokes this function with the
    # "RequestResponse" invocation type, ignored otherwise
    return {'disposition': 'CONTINUE'}


# ----------------------------------------------------------------------
# Test case
# ----------------------------------------------------------------------

# runs this function if this file is the one being executed
# useful to test this Lambda function locally, without AWS credentials, by
# setting SES_LOCAL_TEST_EML_FILE to the path of a raw .eml file
if __name__ == '__main__':
    test_event = {
        'Records': [
            {
                'eventSource': 'aws:ses',
                'ses': {
                    'mail': {
                        'timestamp': '2026-08-10T12:00:00.000Z',
                        'source': 'sender@example.com',
                        'messageId': getenv(
                            'SES_LOCAL_TEST_MESSAGE_ID',
                            'local-test-message-id',
                        ),
                        'destination': ['support@example.com'],
                    },
                    'receipt': {
                        'recipients': ['support@example.com'],
                        'spamVerdict': {'status': 'PASS'},
                        'virusVerdict': {'status': 'PASS'},
                        'spfVerdict': {'status': 'PASS'},
                        'dkimVerdict': {'status': 'PASS'},
                        'dmarcVerdict': {'status': 'PASS'},
                    },
                },
            }
        ],
    }
    result = lambda_handler(test_event, None)
    print(json.dumps(result))
