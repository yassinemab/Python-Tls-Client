from .cffi import request, freeMemory, destroySession
from typing import Optional, Dict, Any, Union, List
from .cookies import (
    cookiejar_from_dict,
    merge_cookies,
    RequestsCookieJar,
    extract_cookies_to_jar
)
from .response import Response, build_response
from .structures import CaseInsensitiveDict
from .settings import ClientIdentifiers
from .__version__ import __version__
import uuid
import urllib
import base64
import ctypes
from json import dumps, loads
import asyncio
import aiohttp

class AsyncSession:
    def __init__(
        self,
        client_identifier: ClientIdentifiers = "chrome_120",
        ja3_string: Optional[str] = None,
        h2_settings: Optional[Dict[str, int]] = None,
        h2_settings_order: Optional[List[str]] = None,
        supported_signature_algorithms: Optional[List[str]] = None,
        supported_delegated_credentials_algorithms: Optional[List[str]] = None,
        supported_versions: Optional[List[str]] = None,
        key_share_curves: Optional[List[str]] = None,
        cert_compression_algo: str = None,
        additional_decode: str = None,
        pseudo_header_order: Optional[List[str]] = None,
        connection_flow: Optional[int] = None,
        priority_frames: Optional[list] = None,
        header_order: Optional[List[str]] = None,
        header_priority: Optional[List[str]] = None,
        random_tls_extension_order: Optional = False,
        force_http1: Optional = False,
        catch_panics: Optional = False,
        debug: Optional = False,
        certificate_pinning: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        self._session_id = str(uuid.uuid4())

        # Standard Settings
        self.headers = CaseInsensitiveDict({
            "User-Agent": f"tls-client/{__version__}",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept": "*/*",
            "Connection": "keep-alive",
        })

        self.proxies = {}
        self.params = {}
        self.cookies = cookiejar_from_dict({})
        self.timeout_seconds = 30
        self.certificate_pinning = certificate_pinning

        # Advanced Settings
        self.client_identifier = client_identifier
        self.ja3_string = ja3_string
        self.h2_settings = h2_settings
        self.h2_settings_order = h2_settings_order
        self.supported_signature_algorithms = supported_signature_algorithms
        self.supported_delegated_credentials_algorithms = supported_delegated_credentials_algorithms
        self.supported_versions = supported_versions
        self.key_share_curves = key_share_curves
        self.cert_compression_algo = cert_compression_algo
        self.additional_decode = additional_decode
        self.pseudo_header_order = pseudo_header_order
        self.connection_flow = connection_flow
        self.priority_frames = priority_frames
        self.header_order = header_order
        self.header_priority = header_priority
        self.random_tls_extension_order = random_tls_extension_order
        self.force_http1 = force_http1
        self.catch_panics = catch_panics
        self.debug = debug

    async def get(
        self,
        url: str,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        params: Optional[dict] = None,
        proxy: Optional[dict] = None,
        timeout_seconds: Optional[int] = 30,
        allow_redirects: bool = True,
        **kwargs
    ) -> Response:
        return await self.execute_request(
            method="GET",
            url=url,
            headers=headers,
            cookies=cookies,
            params=params,
            proxy=proxy,
            timeout_seconds=timeout_seconds,
            allow_redirects=allow_redirects,
            **kwargs
        )

    async def execute_request(
        self,
        method: str,
        url: str,
        params: Optional[dict] = None,
        data: Optional[Union[str, dict]] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        json: Optional[dict] = None,
        allow_redirects: Optional[bool] = True,
        timeout_seconds: Optional[int] = None,
        proxy: Optional[dict] = None,
        **kwargs
    ) -> Response:
        # URL handling
        if params:
            url = f"{url}?{urllib.parse.urlencode(params, doseq=True)}"

        # Request body handling
        if data is None and json is not None:
            if isinstance(json, (dict, list)):
                json = dumps(json)
            request_body = json
            content_type = "application/json"
        elif data is not None and not isinstance(data, (str, bytes)):
            request_body = urllib.parse.urlencode(data, doseq=True)
            content_type = "application/x-www-form-urlencoded"
        else:
            request_body = data
            content_type = None

        # Headers
        if headers is None:
            headers = CaseInsensitiveDict(self.headers)
        else:
            merged_headers = CaseInsensitiveDict(self.headers)
            merged_headers.update(headers)
            headers = merged_headers

        if content_type and "content-type" not in headers:
            headers["Content-Type"] = content_type

        # Cookies
        cookies = cookies or {}
        cookies = merge_cookies(self.cookies, cookies)
        request_cookies = [
            {'domain': c.domain, 'expires': c.expires, 'name': c.name, 'path': c.path, 'value': c.value.replace('"', '')}
            for c in cookies
        ]

        # Proxy
        proxy = proxy or self.proxies
        if isinstance(proxy, dict):
            proxy = proxy.get("http") or proxy.get("https") or ""
        elif isinstance(proxy, str):
            proxy = proxy
        else:
            proxy = ""

        # Build request payload
        is_byte_request = isinstance(request_body, (bytes, bytearray))
        request_payload = {
            "sessionId": self._session_id,
            "followRedirects": allow_redirects,
            "forceHttp1": self.force_http1,
            "withDebug": self.debug,
            "catchPanics": self.catch_panics,
            "headers": dict(headers),
            "headerOrder": self.header_order,
            "additionalDecode": self.additional_decode,
            "proxyUrl": proxy,
            "requestUrl": url,
            "requestMethod": method,
            "requestBody": base64.b64encode(request_body).decode() if is_byte_request else request_body,
            "requestCookies": request_cookies,
            "timeoutSeconds": timeout_seconds or self.timeout_seconds,
            "tlsClientIdentifier": self.client_identifier,
            "withRandomTLSExtensionOrder": self.random_tls_extension_order
        }

        # Run the synchronous request in a thread pool
        loop = asyncio.get_event_loop()
        response_string = await loop.run_in_executor(
            None,
            lambda: self._execute_sync_request(request_payload)
        )

        # Parse response
        response_object = loads(response_string)

        # Handle cookies
        response_cookie_jar = extract_cookies_to_jar(
            request_url=url,
            request_headers=headers,
            cookie_jar=cookies,
            response_headers=response_object["headers"]
        )

        return build_response(response_object, response_cookie_jar)

    def _execute_sync_request(self, request_payload: dict) -> str:
        # Execute the synchronous request using the CFFI library
        response = request(dumps(request_payload).encode('utf-8'))
        response_bytes = ctypes.string_at(response)
        response_string = response_bytes.decode('utf-8')

        # Free memory
        response_object = loads(response_string)
        freeMemory(response_object['id'].encode('utf-8'))

        return response_string

    async def close(self):
        destroy_session_payload = {
            "sessionId": self._session_id
        }

        # Run the synchronous destroy session in a thread pool
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: self._destroy_session(destroy_session_payload)
        )

    def _destroy_session(self, destroy_session_payload: dict) -> None:
        destroy_session_response = destroySession(dumps(destroy_session_payload).encode('utf-8'))
        destroy_session_response_bytes = ctypes.string_at(destroy_session_response)
        destroy_session_response_string = destroy_session_response_bytes.decode('utf-8')
        destroy_session_response_object = loads(destroy_session_response_string)
        freeMemory(destroy_session_response_object['id'].encode('utf-8'))

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()