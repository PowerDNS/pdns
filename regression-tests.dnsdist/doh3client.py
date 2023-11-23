import base64
import asyncio
import pickle
import ssl
import struct
import dns
import time
import async_timeout

from collections import deque
from typing import BinaryIO, Callable, Deque, Dict, List, Optional, Union, cast
from urllib.parse import urlparse

import aioquic
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
    PushPromiseReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, StreamReset
#from aioquic.quic.logger import QuicFileLogger
from aioquic.tls import CipherSuite, SessionTicket

from doqclient import StreamResetError
#
#class DnsClientProtocol(QuicConnectionProtocol):
#    def __init__(self, *args, **kwargs):
#        super().__init__(*args, **kwargs)
#        self._ack_waiter: Any = None
#
#    def pack(self, data):
#        # serialize query
#        data = bytes(data)
#        data = struct.pack("!H", len(data)) + data
#        return data
#
#    async def query(self, query: dns.message) -> None:
#        data = self.pack(query.to_wire())
#        # send query and wait for answer
#        stream_id = self._quic.get_next_available_stream_id()
#        self._quic.send_stream_data(stream_id, data, end_stream=True)
#        waiter = self._loop.create_future()
#        self._ack_waiter = waiter
#        self.transmit()
#
#        return await asyncio.shield(waiter)
#
#    def quic_event_received(self, event: QuicEvent) -> None:
#        if self._ack_waiter is not None:
#            if isinstance(event, StreamDataReceived):
#                length = struct.unpack("!H", bytes(event.data[:2]))[0]
#                answer = dns.message.from_wire(event.data[2 : 2 + length], ignore_trailing=True)
#
#                waiter = self._ack_waiter
#                self._ack_waiter = None
#                waiter.set_result(answer)
#            if isinstance(event, StreamReset):
#                waiter = self._ack_waiter
#                self._ack_waiter = None
#                waiter.set_result(event)
#
#class BogusDnsClientProtocol(DnsClientProtocol):
#    def pack(self, data):
#        # serialize query
#        data = bytes(data)
#        data = struct.pack("!H", len(data) * 2) + data
#        return data
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
            + [(k.encode(), v.encode()) for (k, v) in request.headers.items()],
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
    data: Optional[str],
    include: bool,
    output_dir: Optional[str],
) -> None:
    # perform request
    start = time.time()
    if data is not None:
        data_bytes = data.encode()
        http_events = await client.post(
            url,
            data=data_bytes,
            headers={
                "content-length": str(len(data_bytes)),
                "content-type": "application/x-www-form-urlencoded",
            },
        )
        method = "POST"
    else:
        http_events = await client.get(url)
        method = "GET"
    elapsed = time.time() - start

    result = bytes()
    for http_event in http_events:
        if isinstance(http_event, DataReceived):
            result += http_event.data
        if isinstance(http_event, StreamReset):
            result = http_event
    return result


async def async_h3_query(
    configuration: QuicConfiguration,
    baseurl: str,
    port: int,
    query: dns.message,
    timeout: float,
    create_protocol=HttpClient
) -> None:

    url = "{}?dns={}".format(baseurl, base64.urlsafe_b64encode(query.to_wire()).decode('UTF8').rstrip('='))
    async with connect(
        "127.0.0.1",
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
                    data=None,
                    include=False,
                    output_dir=None,
                )

                return answer
        except asyncio.TimeoutError as e:
            return e

def doh3_query(query, baseurl, timeout=2, port=853, verify=None, server_hostname=None):
    configuration = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=True)
    if verify:
        configuration.load_verify_locations(verify)
    result = asyncio.run(
        async_h3_query(
            configuration=configuration,
            baseurl=baseurl,
            port=port,
            query=query,
            timeout=timeout,
            create_protocol=HttpClient
        )
    )

    if (isinstance(result, StreamReset)):
        raise StreamResetError(result.error_code)
    if (isinstance(result, asyncio.TimeoutError)):
        raise TimeoutError()
    return dns.message.from_wire(result)
