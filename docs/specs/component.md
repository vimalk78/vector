# Component Specification

This document specifies Vector Component behavior (source, transforms, and
sinks) for the development of Vector.

The key words “MUST”, “MUST NOT”, “REQUIRED”, “SHALL”, “SHALL NOT”, “SHOULD”,
“SHOULD NOT”, “RECOMMENDED”, “MAY”, and “OPTIONAL” in this document are to be
interpreted as described in [RFC 2119].

<!-- MarkdownTOC autolink="true" style="ordered" indent="   " -->

1. [Introduction](#introduction)
1. [Scope](#scope)
1. [How to read this document](#how-to-read-this-document)
1. [Configuration](#configuration)
   1. [Options](#options)
      1. [`address`](#address)
      1. [`endpoint(s)`](#endpoints)
1. [Instrumentation](#instrumentation)
   1. [Batching](#batching)
   1. [Events](#events)
      1. [BytesReceived](#bytesreceived)
      1. [EventsRecevied](#eventsrecevied)
      1. [EventsSent](#eventssent)
      1. [BytesSent](#bytessent)
      1. [Error](#error)

<!-- /MarkdownTOC -->

## Introduction

Vector is a highly flexible observability data pipeline due to its directed
acyclic graph processing model. Each node in the graph is a Vector Component,
and in order to meet our [high user experience expectations] each Component must
adhere to a common set of behaviorial rules. This document aims to clearly
outline these rules to guide new component development and ongoing maintenance.

## Scope

This specification addresses _direct_ component development and does not cover
aspects that components inherit "for free". For example, this specification does
not cover gloal context, such as `component_id`, that all components receive in
their telemetry by nature of being a Vector compoent.

## How to read this document

This document is written from the broad perspective of a Vector component.
Unless otherwise stated, a section applies to all component types (sources,
transforms, and sinks).

## Configuration

### Options

#### `endpoint(s)`

When a component makes a connection to a downstream target, it MUST
expose either an `endpoint` option that takes a `string` representing a
single endpoint, or an `endpoints` option that takes an array of strings
representing multiple endpoints.

## Instrumentation

Vector components MUST be instrumented for optimal observability and monitoring.
This is required to drive various interfaces that Vector users depend on to
manage Vector installations in mission critical production environments.

### Batching

For performance reasons, components SHOULD instrument batches of Vector events
as opposed to individual Vector events. [Pull request #8383] demonstrated
meaningful performance improvements as a result of this strategy.

### Events

Vector implements an event driven pattern ([RFC 2064]) for internal
instrumentation. This section lists all required and optional events that a
component must emit. It is expected that components will emit custom events
beyond those listed here that reflect component specific behavior.

There is leeway in the implementation of these events:

* Events MAY be augmented with additional component-specific context. For
  example, the `socket` source adds a `mode` attribute as additional context.
* The naming of the events MAY deviate to satisfy implementation. For example,
  the `socket` source may rename the `EventRecevied` event to
  `SocketEventReceived` to add additional socket specific context.
* Components MAY emit events for batches of Vector events for performance
  reasons, but the resulting telemetry state MUST be equivalent to emitting
  individual events. For example, emitting the `EventsReceived` event for 10
  events MUST increment the `received_events_total` counter by 10.

#### BytesReceived

*Sources* MUST emit a `BytesReceived` event immediately after receiving bytes
from the upstream source and before the creation of a Vector event.

* Properties
  * `byte_size`
    * For UDP, TCP, and Unix protocols, the total number of bytes received from
      the socket excluding the delimiter.
    * For HTTP-based protocols, the total number of bytes in the HTTP body, as
      represented by the `Content-Length` header.
    * For files, the total number of bytes read from the file excluding the
      delimiter.
  * `protocol` - The protocol used to send the bytes (i.e., `tcp`, `udp`,
    `unix`, `http`, `https`, `file`, etc.)
  * `http_path` - If relevant, the HTTP path, excluding query strings.
  * `socket` - If relevant, the socket number that bytes were received from.
* Metrics
  * MUST increment the `received_bytes_total` counter by the defined value with
    the defined properties as metric tags.
* Logs
  * MUST log a `Bytes received.` message at the `trace` level with the
    defined properties as key-value pairs. It MUST NOT be rate limited.

#### EventsRecevied

*All components* MUST emit an `EventsReceived` event immediately after creating
or receiving one or more Vector events.

* Properties
  * `count` - The count of Vector events.
  * `byte_size` - The cumulative in-memory byte size of all events received.
* Metrics
  * MUST increment the `received_events_total` counter by the defined `quantity`
    property with the other properties as metric tags.
  * MUST increment the `received_event_bytes_total` counter by the defined
    `byte_size` property with the other properties as metric tags.
* Logs
  * MUST log a `Events received.` message at the `trace` level with the
    defined properties as key-value pairs. It MUST NOT be rate limited.

#### EventsSent

*All components* MUST emit an `EventsSent` event immediately before sending the
event down stream. This should happen before any transmission preparation, such
as encoding.

* Properties
  * `count` - The count of Vector events.
  * `byte_size` - The cumulative in-memory byte size of all events sent.
* Metrics
  * MUST increment the `sent_events_total` counter by the defined value with the
    defined properties as metric tags.
  * MUST increment the `sent_event_bytes_total` counter by the event's byte size
    in JSON representation.
* Logs
  * MUST log a `Events sent.` message at the `trace` level with the
    defined properties as key-value pairs. It MUST NOT be rate limited.

#### BytesSent

*Sinks* MUST emit a `BytesSent` event immediately after sending bytes to the
downstream target regardless if the transmission was successful or not.

* Properties
  * `byte_size`
    * For UDP, TCP, and Unix protocols, the total number of bytes placed on the
      socket excluding the delimiter.
    * For HTTP-based protocols, the total number of bytes in the HTTP body, as
      represented by the `Content-Length` header.
    * For files, the total number of bytes written to the file excluding the
      delimiter.
  * `protocol` - The protocol used to send the bytes (i.e., `tcp`, `udp`,
    `unix`, `http`, `http`, `file`, etc.)
  * `endpoint` - If relevant, the endpoint that the bytes were sent to. For
    HTTP, this MUST be the host and path only, excluding the query string.
  * `file` - If relevant, the absolute path of the file.
* Metrics
  * MUST increment the `sent_bytes_total` counter by the defined value with the
    defined properties as metric tags.
* Logs
  * MUST log a `Bytes received.` message at the `trace` level with the
    defined properties as key-value pairs. It MUST NOT be rate limited.

#### Error

*All components* MUST emit error events when an error occurs, and errors MUST be
named with an `Error` suffix. For example, the `socket` source emits a
`SocketReceiveError` representing any error that occurs while receiving data off
of the socket.

This specification does not list a standard set of errors that components must
implement since errors are specific to the component.

* Properties
  * `error` - The specifics of the error condition, such as system error code, etc.
  * `stage` - The stage at which the error occurred. MUST be one of
    `receiving`, `processing`, or `sending`. This MAY be omitted from
    being represented explicitly in the event data when the error may
    only happen at one stage, but MUST be included in the emitted logs
    and metrics as if it were present.
* Metrics
  * MUST increment the `errors_total` counter by 1 with the defined properties
    as metric tags.
  * MUST increment the `discarded_events_total` counter by the number of Vector
    events discarded if the error resulted in discarding (dropping) events.
* Logs
  * MUST log a message at the `error` level with the defined properties
    as key-value pairs. It SHOULD be rate limited to 10 seconds.

[high user experience expectations]: https://github.com/timberio/vector/blob/master/docs/USER_EXPERIENCE_DESIGN.md
[Pull request #8383]: https://github.com/timberio/vector/pull/8383/
[RFC 2064]: https://github.com/timberio/vector/blob/master/rfcs/2020-03-17-2064-event-driven-observability.md
[RFC 2119]: https://datatracker.ietf.org/doc/html/rfc2119
