#!/usr/bin/env python3

# run protoc -I ~/opentelemetry-proto ~/opentelemetry-proto/opentelemetry/proto/trace/v1/trace.proto --python_out=.
# run protoc -I ~/opentelemetry-proto ~/opentelemetry-proto/opentelemetry/proto/common/v1/common.proto --python_out=.
# run protoc -I ~/opentelemetry-proto ~/opentelemetry-proto/opentelemetry/proto/resource/v1/resource.proto --python_out=.
# to generate opentelemetry directory

import sys

import google.protobuf.message
import google.protobuf.json_format

import opentelemetry.proto.trace.v1.trace_pb2

json = sys.stdin.buffer.read()

msg = opentelemetry.proto.trace.v1.trace_pb2.TracesData()
google.protobuf.json_format.Parse(json, msg);

sys.stdout.buffer.write(msg.SerializeToString())
