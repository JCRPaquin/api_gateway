import io
import json
import os
import re
import smtplib
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from enum import Enum
from functools import wraps
from typing import Tuple
from urllib.parse import parse_qs, urljoin

from disposable_email_domains import blocklist

import jsondiff as jd
import requests
from authlib.oauth2.rfc6749.errors import UnsupportedTokenTypeError
from authlib.integrations.flask_oauth2 import ResourceProtector
from flask import Request, abort, current_app, g, request
from flask.views import View
from flask_login import current_user
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from apigateway import extensions
from apigateway.config import canonical_authority
from apigateway.domains import canonicalize_domain
from apigateway.email_templates import EmailTemplate
from apigateway.exceptions import Oauth2HttpError


def get_request_site():
    """Return the site assigned to the request's exact trusted authority."""
    host_headers = request.headers.getlist("Host")
    if len(host_headers) != 1:
        abort(400)
    try:
        authority = canonical_authority(host_headers[0])
    except ValueError:
        abort(400)
    try:
        return current_app.config["SITE_HOST_MAPPING"][authority]
    except KeyError:
        abort(400)


def get_request_site_settings():
    """Return the UI name, URL, and verification URL for this request."""
    if get_request_site() == "SCIX":
        return (
            "SciX",
            current_app.config["SCIX_HOST_DOMAIN"],
            current_app.config["SCIX_VERIFY_URL"],
        )
    return (
        "ADS",
        current_app.config["ADS_HOST_DOMAIN"],
        current_app.config["VERIFY_URL"],
    )


def require_non_anonymous_bootstrap_user(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_user.is_anonymous_bootstrap_user:
            return current_app.login_manager.unauthorized()

        return func(*args, **kwargs)

    return decorated_view


class DeliveryState(str, Enum):
    QUEUED = "queued"
    SENT = "sent"
    SUPPRESSED = "suppressed"
    RETRYABLE_FAILURE = "retryable_failure"
    PERMANENT_FAILURE = "permanent_failure"
    REJECTED = "rejected"


@dataclass(frozen=True)
class DeliveryResult:
    channel: str
    state: DeliveryState
    reason: str


def _smtp_delivery(message: EmailMessage, mail_server: str = None) -> DeliveryResult:
    encoded = message.as_bytes()
    if len(encoded) > current_app.config.get("MAIL_MAX_MESSAGE_BYTES", 1_048_576):
        return DeliveryResult("email", DeliveryState.REJECTED, "message_too_large")
    if current_app.config["MAIL_TEST_BYPASS"]:
        current_app.logger.warning("Email delivery bypassed by explicit test configuration")
        return DeliveryResult("email", DeliveryState.SUPPRESSED, "delivery_disabled")
    if not current_app.config.get("MAIL_ENABLED", True):
        return DeliveryResult("email", DeliveryState.SUPPRESSED, "delivery_disabled")

    host = mail_server or current_app.config.get("MAIL_SERVER")
    username = current_app.config.get("MAIL_USERNAME")
    password = current_app.config.get("MAIL_PASSWORD")
    use_ssl = current_app.config.get("MAIL_USE_SSL", False)
    use_starttls = current_app.config.get("MAIL_USE_STARTTLS", True)
    if not host or not username or not password or not (use_ssl or use_starttls):
        return DeliveryResult("email", DeliveryState.REJECTED, "invalid_mail_configuration")

    try:
        smtp_kwargs = {
            "host": host,
            "port": current_app.config.get("MAIL_PORT", 25),
            "timeout": current_app.config.get("MAIL_CONNECT_TIMEOUT_SECONDS", 5),
        }
        if use_ssl:
            smtp = smtplib.SMTP_SSL(context=ssl.create_default_context(), **smtp_kwargs)
        else:
            smtp = smtplib.SMTP(**smtp_kwargs)
        with smtp:
            if smtp.sock is not None:
                smtp.sock.settimeout(current_app.config.get("MAIL_COMMAND_TIMEOUT_SECONDS", 10))
            if use_starttls and not use_ssl:
                smtp.starttls(context=ssl.create_default_context())
                if smtp.sock is not None:
                    smtp.sock.settimeout(
                        current_app.config.get("MAIL_COMMAND_TIMEOUT_SECONDS", 10)
                    )
            smtp.login(username, password)
            recipients = [
                address
                for _, address in getaddresses(
                    message.get_all("To", [])
                    + message.get_all("Cc", [])
                    + message.get_all("Bcc", [])
                )
            ]
            smtp.sendmail(parseaddr(message["From"])[1], recipients, encoded)
        return DeliveryResult("email", DeliveryState.SENT, "sent")
    except smtplib.SMTPRecipientsRefused:
        return DeliveryResult("email", DeliveryState.PERMANENT_FAILURE, "recipients_refused")
    except smtplib.SMTPResponseException as exc:
        state = (
            DeliveryState.RETRYABLE_FAILURE
            if 400 <= exc.smtp_code < 500
            else DeliveryState.PERMANENT_FAILURE
        )
        return DeliveryResult("email", state, "smtp_response")
    except (OSError, TimeoutError, smtplib.SMTPException):
        return DeliveryResult("email", DeliveryState.RETRYABLE_FAILURE, "transport_error")


def send_email(
    sender: str,
    recipient: str,
    template: EmailTemplate,
    verification_url: str = "",
    mail_server: str = None,
    ui_env: str = "ADS",
    ui_url: str = "https://ui.adsabs.harvard.edu",
) -> DeliveryResult:
    message = EmailMessage()
    message["Subject"] = template.subject.format(ui_env=ui_env)
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        template.msg_plain.format(endpoint=verification_url, ui_env=ui_env, ui_url=ui_url)
    )
    message.add_alternative(
        template.msg_html.format(
            endpoint=verification_url,
            email_address=recipient,
            ui_url=ui_url,
            ui_env=ui_env,
        ),
        subtype="html",
    )
    return _smtp_delivery(message, mail_server)


def send_feedback_email(
    submitter_name: str,
    submitter_email: str,
    subject: str,
    body: str,
    attachments: list = None,
    mail_server: str = None,
) -> DeliveryResult:
    default_email = current_app.config["FEEDBACK_EMAIL"]
    recipient = current_app.config["FEEDBACK_EMAIL_SUBJECT_OVERRIDE"].get(subject, default_email)

    message = EmailMessage()
    message["Subject"] = f"{subject} from {submitter_name} ({submitter_email})"
    message["From"] = f"ADS Administration <{default_email}>"
    message["To"] = recipient
    message["Reply-To"] = f"{submitter_name} <{submitter_email}>"
    message.set_content(body)

    for filename, encoded in attachments or []:
        message.add_attachment(
            encoded,
            filename=filename,
            maintype="application",
            subtype="json",
        )
    return _smtp_delivery(message, mail_server)


def verify_recaptcha(token: str, endpoint: str = None, remote_addr: str = None) -> bool:
    if not isinstance(token, str) or not token or len(token) > 4096:
        return False
    if current_app.config["RECAPTCHA_TEST_BYPASS"]:
        current_app.logger.warning(
            "reCAPTCHA verification bypassed by explicit test configuration"
        )
        return True

    endpoint = endpoint or current_app.config["GOOGLE_RECAPTCHA_ENDPOINT"]
    payload = {
        "secret": current_app.config["GOOGLE_RECAPTCHA_PRIVATE_KEY"],
        "remoteip": remote_addr or request.remote_addr,
        "response": token,
    }
    try:
        response = requests.post(endpoint, data=payload, timeout=60)
        response.raise_for_status()
    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.HTTPError,
    ):
        return False
    return response.json().get("success", False)


def get_json_body(request: Request, max_bytes: int = None) -> dict:
    """Read and decode a bounded JSON or form request exactly once."""
    limit = max_bytes or current_app.config.get("MAX_CONTENT_LENGTH", 1_048_576)
    if request.content_length is not None and request.content_length > limit:
        raise RequestEntityTooLarge()

    cached = getattr(request, "_bounded_body", None)
    if cached is not None:
        cached_size, value = cached
        if cached_size > limit:
            raise RequestEntityTooLarge()
        return value

    raw = getattr(request, "_cached_data", None)
    if raw is None:
        raw = request.stream.read(limit + 1)
        request._cached_data = raw
    if len(raw) > limit:
        raise RequestEntityTooLarge()

    value = None
    if request.is_json:
        try:
            value = json.loads(raw)
        except (
            UnicodeDecodeError,
            ValueError,
            RecursionError,
            OverflowError,
            MemoryError,
        ) as exc:
            raise BadRequest("Malformed JSON request body") from exc
    else:
        try:
            value = json.loads(raw)
        except (RecursionError, OverflowError, MemoryError) as exc:
            raise BadRequest("Malformed JSON request body") from exc
        except ValueError as exc:
            # Syntax errors may indicate a form body. Decoder resource guards,
            # including Python's configured integer digit limit, must not fall
            # through to form parsing.
            if not isinstance(exc, json.JSONDecodeError):
                raise BadRequest("Malformed JSON request body") from exc
            max_form_memory = current_app.config.get("MAX_FORM_MEMORY_SIZE", 65_536)
            if len(raw) > max_form_memory:
                raise RequestEntityTooLarge()
            if request.mimetype == "multipart/form-data":
                environ = dict(request.environ)
                environ["wsgi.input"] = io.BytesIO(raw)
                environ["CONTENT_LENGTH"] = str(len(raw))
                form_request = Request(environ)
                form_request.max_form_memory_size = max_form_memory
                form_request.max_form_parts = current_app.config.get("MAX_FORM_PARTS", 32)
                value = form_request.form.to_dict(flat=True)
            else:
                try:
                    parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
                    if sum(len(values) for values in parsed.values()) > current_app.config.get(
                        "MAX_FORM_PARTS", 32
                    ):
                        raise RequestEntityTooLarge()
                    value = {key: values[-1] for key, values in parsed.items()}
                except UnicodeDecodeError as exc:
                    raise BadRequest("Malformed form request body") from exc

    if not isinstance(value, Mapping):
        raise BadRequest("Request body must be a JSON object")
    result = dict(value)
    request._bounded_body = (len(raw), result)
    return result


class ProxyView(View):
    """A view for proxying requests to a remote webservice."""

    def __init__(self, deploy_path: str, remote_base_url: str):
        """
        Initializes a ProxyView object.

        Args:
            deploy_path (str): The path to deploy the proxy view.
            remote_base_url (str): The base URL of the remote server to proxy requests to.
        """
        super().__init__()
        self._deploy_path = deploy_path
        self._remote_base_url = remote_base_url
        self._session = requests.Session()

        self.default_request_timeout = current_app.config.get("DEFAULT_REQUEST_TIMEOUT", 60)
        self.pool_connections = current_app.config.get("REQUESTS_POOL_CONNECTIONS", 20)
        self.pool_maxsize = current_app.config.get("REQUESTS_POOL_MAXSIZE", 1000)
        self.max_retries = current_app.config.get("REQUESTS_MAX_RETRIES", 1)

        http_adapter = requests.adapters.HTTPAdapter(
            pool_connections=self.pool_connections,
            pool_maxsize=self.pool_maxsize,
            max_retries=self.max_retries,
            pool_block=False,
        )

        self._session.mount("http://", http_adapter)

    def dispatch_request(self, **kwargs) -> Tuple[bytes, int]:
        """
        Dispatches the request to the proxy view.

        Returns:
            Tuple[bytes, int]: A tuple containing the content of the response and the status code.
        """

        # flask_principal holds an active DB session.
        # Release the session early to avoid blocking during long running requests to external endpoints.
        extensions.db.session.remove()

        return self._proxy_request()

    def _proxy_request(self) -> Tuple[bytes, int]:
        """
        Proxies the request to the remote server.

        Returns:
            Tuple[bytes, int]: A tuple containing the content of the response and the status code.
        """
        try:
            remote_url = self._construct_remote_url()
            http_method_func = getattr(self._session, request.method.lower())

            current_app.logger.info(
                "Proxying %s request to %s", request.method.upper(), remote_url
            )

            response: requests.Response = http_method_func(
                remote_url, data=request.get_data(), headers=request.headers
            )
            g.proxy_upstream_response = True

            return response.content, response.status_code, dict(response.headers)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            current_app.logger.info(
                "Gateway Timeout with %s request to %s", request.method.upper(), remote_url
            )
            return b"504 Gateway Timeout", 504

    def _construct_remote_url(self) -> str:
        """
        Constructs the URL of the remote server.

        Returns:
            str: The URL of the remote server.
        """
        verify_url_regex = re.compile(r"([12]\d\d\d[A-Za-z&\.]{5}[A-Za-z0-9\.]{9}[A-Z\.]/verify_url\:)(http[s]?\://)(.*)")
        
        path = request.full_path.replace(self._deploy_path, "", 1)
        path = path[1:] if path.startswith("/") else path
        #This block exists because of an incompatibility between urlparse.urljoin and urllib.parse.urljoin
        #This incompatibility results in http(s):// -> http(s):/ if the proc spec occurs in the middle of the url.
        try:
            resolver_check = verify_url_regex.match(path)
            if resolver_check: 
                resolver_groups = resolver_check.groups()
                return str(self._remote_base_url) + "/" + os.path.normpath(resolver_groups[0]) \
                    + resolver_groups[1] + os.path.normpath(resolver_groups[2])
        except ValueError:
            current_app.logger.exception("Failed to properly check url path for resolver verify_url path.")    
        return urljoin(self._remote_base_url, path)


class GatewayResourceProtector(ResourceProtector):
    def raise_error_response(self, error):
        body = json.dumps(dict({"message": error.description}))
        if type(error)==UnsupportedTokenTypeError:
            current_app.logger.info("Token not recognized as a Bearer Token.")
            body="Unauthorized. If you are using the API, please confirm your Authorization header is of the form Bearer TOKEN and not Bearer:TOKEN"
            raise Oauth2HttpError(error.status_code, error.description, body, error.get_headers())
        raise Oauth2HttpError(error.status_code, error.description, body, error.get_headers())


def _format_changes(field, changes, updated):
    formatted_changes = []
    if isinstance(changes, dict):
        formatted_changes = [f"{k} -- {v}" for k, v in changes.items()]
    elif isinstance(changes, list):
        for item in changes:
            try:
                if field == "references":
                    formatted_changes.append(
                        f"{updated['bibcode']}\t{item.replace('(bibcode) ', '').replace('(reference) ', '')}"
                    )
                else:
                    formatted_changes.append(str(item) + "\n")
            except:  # noqa
                formatted_changes.append(str(item) + "\n")
    else:
        formatted_changes.append(str(changes) + "\n")
    return formatted_changes


def make_json_diff(original: str, updated: str):
    diff_data = jd.diff(original, updated)

    results = []
    if diff_data.get("comments"):
        results.append(f"\n\nComments: {diff_data['comments']}\n\n")

    for field, changes in diff_data.items():
        if field == "comments":
            continue
        results.append(f">>>> {field}\n")
        results.extend(_format_changes(field, changes, updated))
        results.append(">>>>\n")

    return "\n".join(results)







def generate_complete_blocklist():
    with open(
        os.path.abspath(os.path.join(os.path.dirname(__file__), "disallowed_email_domain_list.conf"))
    ) as blocklist_file:
        ads_list = blocklist_file.readlines()
    domains = set()
    for entry in ads_list + list(blocklist):
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        try:
            domains.add(canonicalize_domain(entry))
        except ValueError:
            continue
    return domains
