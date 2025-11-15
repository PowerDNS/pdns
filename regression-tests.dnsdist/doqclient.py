import asyncio
import struct
from typing import Any, cast
import dns
import dns.message
import async_timeout

from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, StreamReset

class DnsClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ack_waiter: Any = None

    def pack(self, data):
        # serialize query
        data = bytes(data)
        data = struct.pack("!H", len(data)) + data
        return data

    async def query(self, query: dns.message) -> None:
        data = self.pack(query.to_wire())
        # send query and wait for answer
        stream_id = self._quic.get_next_available_stream_id()
        self._quic.send_stream_data(stream_id, data, end_stream=True)
        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._ack_waiter is not None:
            if isinstance(event, StreamDataReceived):
                length = struct.unpack("!H", bytes(event.data[:2]))[0]
                answer = dns.message.from_wire(event.data[2 : 2 + length], ignore_trailing=True)

                waiter = self._ack_waiter
                self._ack_waiter = None
                waiter.set_result(answer)
            if isinstance(event, StreamReset):
                waiter = self._ack_waiter
                self._ack_waiter = None
                waiter.set_result(event)

class BogusDnsClientProtocol(DnsClientProtocol):
    def pack(self, data):
        # serialize query
        data = bytes(data)
        data = struct.pack("!H", len(data) * 2) + data
        return data


async def async_quic_query(
    configuration: QuicConfiguration,
    host: str,
    port: int,
    query: dns.message,
    timeout: float,
    create_protocol=DnsClientProtocol
) -> None:
    print("Connecting to {}:{}".format(host, port))
    async with connect(
        host,
        port,
        configuration=configuration,
        create_protocol=create_protocol,
    ) as client:
        client = cast(DnsClientProtocol, client)
        print("Sending DNS query")
        try:
            async with async_timeout.timeout(timeout):
                answer = await client.query(query)
                return (answer, client._quic.tls._peer_certificate.serial_number)
        except asyncio.TimeoutError as e:
            return (e, None)

class StreamResetError(Exception):
    def __init__(self, error, message="Stream reset by peer"):
        self.error = error
        super().__init__(message)

def quic_query(query, host='127.0.0.1', timeout=2, port=853, verify=None, server_hostname=None):
    configuration = QuicConfiguration(alpn_protocols=["doq"], is_client=True, server_name=server_hostname)
    if verify:
        configuration.load_verify_locations(verify)
    (result, serial) = asyncio.run(
        async_quic_query(
            configuration=configuration,
            host=host,
            port=port,
            query=query,
            timeout=timeout,
            create_protocol=DnsClientProtocol
        )
    )
    if (isinstance(result, StreamReset)):
        raise StreamResetError(result.error_code)
    if (isinstance(result, asyncio.TimeoutError)):
        raise TimeoutError()
    return (result, serial)

def quic_bogus_query(query, host='127.0.0.1', timeout=2, port=853, verify=None, server_hostname=None):
    configuration = QuicConfiguration(alpn_protocols=["doq"], is_client=True, server_name=server_hostname)
    if verify:
        configuration.load_verify_locations(verify)
    (result, _) = asyncio.run(
        async_quic_query(
            configuration=configuration,
            host=host,
            port=port,
            query=query,
            timeout=timeout,
            create_protocol=BogusDnsClientProtocol
        )
    )
    if (isinstance(result, StreamReset)):
        raise StreamResetError(result.error_code)
    if (isinstance(result, asyncio.TimeoutError)):
        raise TimeoutError()
    return result
