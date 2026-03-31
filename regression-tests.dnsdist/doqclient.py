import asyncio
import pickle
import ssl
import struct
from typing import Any, Optional, cast
import dns
import dns.message
import async_timeout

from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, StreamReset
from aioquic.quic.logger import QuicFileLogger

class DnsClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ack_waiter: Any = None

    @staticmethod
    def pack(data):
        # serialize query
        data = bytes(data)
        data = struct.pack("!H", len(data)) + data
        return data

    async def query(self, data) -> None:
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
    @staticmethod
    def pack(data):
        # serialize query
        data = bytes(data)
        data = struct.pack("!H", len(data) * 2) + data
        return data


async def async_quic_query(
    configuration: QuicConfiguration,
    host: str,
    port: int,
    data: bytes,
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
                answer = await client.query(data)
                return (answer, client._quic.tls._peer_certificate.serial_number)
        except asyncio.TimeoutError as e:
            return (e, None)

class StreamResetError(Exception):
    def __init__(self, error, message="Stream reset by peer"):
        self.error = error
        super().__init__(message)

def quic_query(query, host='127.0.0.1', timeout=2, port=853, verify=None, server_hostname=None, rawQuery=False):
    configuration = QuicConfiguration(alpn_protocols=["doq"], is_client=True, server_name=server_hostname)
    if verify:
        configuration.load_verify_locations(verify)
    data = DnsClientProtocol.pack(query.to_wire()) if not rawQuery else query
    (result, serial) = asyncio.run(
        async_quic_query(
            configuration=configuration,
            host=host,
            port=port,
            data=data,
            timeout=timeout,
            create_protocol=DnsClientProtocol
        )
    )
    if (isinstance(result, StreamReset)):
        raise StreamResetError(result.error_code)
    if (isinstance(result, asyncio.TimeoutError)):
        raise TimeoutError()
    return (result, serial)

def quic_bogus_query(query, host='127.0.0.1', timeout=2, port=853, verify=None, server_hostname=None, rawQuery=False):
    configuration = QuicConfiguration(alpn_protocols=["doq"], is_client=True, server_name=server_hostname)
    if verify:
        configuration.load_verify_locations(verify)
    data = BogusDnsClientProtocol.pack(query.to_wire()) if not rawQuery else query
    (result, _) = asyncio.run(
        async_quic_query(
            configuration=configuration,
            host=host,
            port=port,
            data=data,
            timeout=timeout,
            create_protocol=BogusDnsClientProtocol
        )
    )
    if (isinstance(result, StreamReset)):
        raise StreamResetError(result.error_code)
    if (isinstance(result, asyncio.TimeoutError)):
        raise TimeoutError()
    return result
