import base64
import copy
import asyncio
import dns
import async_timeout

from collections import deque
from typing import Deque, Dict, Optional, Tuple, Union, cast
from urllib.parse import urlparse

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h0.connection import H0Connection
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
    PushPromiseReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamReset

from doqclient import StreamResetError

HttpConnection = Union[H0Connection, H3Connection]

class URL:
    def __init__(self, url: str) -> None:
        parsed = urlparse(url)

        self.authority = parsed.netloc
        self.full_path = parsed.path or "/"
        if parsed.query:
            self.full_path += "?" + parsed.query
        self.scheme = parsed.scheme


class HttpRequest:
    def __init__(
        self,
        method: str,
        url: URL,
        content: bytes = b"",
        headers: Optional[Dict] = None,
    ) -> None:
        if headers is None:
            headers = {}

        self.content = content
        self.headers = headers
        self.method = method
        self.url = url

class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.pushes: Dict[int, Deque[H3Event]] = {}
        self._http: Optional[HttpConnection] = None
        self._request_events: Dict[int, Deque[H3Event]] = {}
        self._request_waiter: Dict[int, asyncio.Future[Deque[H3Event]]] = {}

        if self._quic.configuration.alpn_protocols[0].startswith("hq-"):
            self._http = H0Connection(self._quic)
        else:
            self._http = H3Connection(self._quic)

    async def get(self, url: str, headers: Optional[Dict] = None) -> Deque[H3Event]:
        """
        Perform a GET request.
        """
        return await self._request(
            HttpRequest(method="GET", url=URL(url), headers=headers)
        )

    async def post(
        self, url: str, data: bytes, headers: Optional[Dict] = None
    ) -> Deque[H3Event]:
        """
        Perform a POST request.
        """
        return await self._request(
            HttpRequest(method="POST", url=URL(url), content=data, headers=headers)
        )


    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                # http
                self._request_events[event.stream_id].append(event)
                if event.stream_ended:
                    request_waiter = self._request_waiter.pop(stream_id)
                    request_waiter.set_result(self._request_events.pop(stream_id))

            elif stream_id in self._websockets:
                # websocket
                websocket = self._websockets[stream_id]
                websocket.http_event_received(event)

            elif event.push_id in self.pushes:
                # push
                self.pushes[event.push_id].append(event)

        elif isinstance(event, PushPromiseReceived):
            self.pushes[event.push_id] = deque()
            self.pushes[event.push_id].append(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamReset):
            waiter = self._request_waiter.pop(event.stream_id)
            waiter.set_result([event])

        #  pass event to the HTTP layer
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

    async def _request(self, request: HttpRequest) -> Deque[H3Event]:
        stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", request.method.encode()),
                (b":scheme", request.url.scheme.encode()),
                (b":authority", request.url.authority.encode()),
                (b":path", request.url.full_path.encode()),
            ]
            + [(k.lower().encode(), v.encode()) for (k, v) in request.headers.items()],
            end_stream=not request.content,
        )
        if request.content:
            self._http.send_data(
                stream_id=stream_id, data=request.content, end_stream=True
            )

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        return await asyncio.shield(waiter)


async def perform_http_request(
    client: HttpClient,
    url: str,
    data: Optional[bytes],
    include: bool,
    output_dir: Optional[str],
    additional_headers: Optional[Dict] = None,
) -> Tuple[str, Dict[str, str]]:
    # perform request
    if data is not None:
        headers = copy.deepcopy(additional_headers) if additional_headers else {}
        headers["content-length"] = str(len(data))
        headers["content-type"] = "application/dns-message"
        http_events = await client.post(
            url,
            data=data,
            headers=headers,
        )
    else:
        http_events = await client.get(url, headers=additional_headers)

    result = bytes()
    headers = {}
    for http_event in http_events:
        if isinstance(http_event, DataReceived):
            result += http_event.data
        if isinstance(http_event, StreamReset):
            result = http_event
        if isinstance(http_event, HeadersReceived):
            for k, v in http_event.headers:
                headers[k] = v
    return (result, headers)


async def async_h3_query(
    configuration: QuicConfiguration,
    host: str,
    baseurl: str,
    port: int,
    query: dns.message,
    timeout: float,
    post: bool,
    create_protocol=HttpClient,
    additional_headers: Optional[Dict] = None,
) -> Union[Tuple[str, Dict[str, str]], Tuple[asyncio.TimeoutError, Dict[str, str]]]:

    url = baseurl
    if not post:
        url = "{}?dns={}".format(baseurl, base64.urlsafe_b64encode(query.to_wire()).decode('UTF8').rstrip('='))
    async with connect(
        host,
        port,
        configuration=configuration,
        create_protocol=create_protocol,
    ) as client:
        client = cast(HttpClient, client)

        try:
            async with async_timeout.timeout(timeout):

                answer = await perform_http_request(
                    client=client,
                    url=url,
                    data=query.to_wire() if post else None,
                    include=False,
                    output_dir=None,
                    additional_headers=additional_headers,
                )

                return answer
        except asyncio.TimeoutError as e:
            return (e,{})


def doh3_query(query, host, baseurl, timeout=2, port=853, verify=None, server_hostname=None, post=False, additional_headers=None, raw_response=False):
    configuration = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=True, server_name=server_hostname)
    if verify:
        configuration.load_verify_locations(verify)

    (result, headers) = asyncio.run(
        async_h3_query(
            configuration=configuration,
            host=host,
            baseurl=baseurl,
            port=port,
            query=query,
            timeout=timeout,
            create_protocol=HttpClient,
            post=post,
            additional_headers=additional_headers
        )
    )

    if (isinstance(result, StreamReset)):
        raise StreamResetError(result.error_code)
    if (isinstance(result, asyncio.TimeoutError)):
        raise TimeoutError()
    if raw_response:
        return (result, headers)
    return dns.message.from_wire(result)
