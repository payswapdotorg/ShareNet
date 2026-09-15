package org.sharenet.transport.contract

/**
 * Typed transport errors. NO platform (GMS/Android) types leak here —
 * adapters classify their native errors into these at their boundary.
 */
sealed class TransportError(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {

    /** The app has not granted the platform permissions the transport needs. */
    class PermissionsDenied(
        message: String = "required platform permissions were denied or not granted",
    ) : TransportError(message)

    /** Google Play services is missing/disabled/out-of-date on this device. */
    class PlayServicesUnavailable(
        val detail: String,
    ) : TransportError("play services unavailable: $detail")

    /** The operation is not legal in the current transport state. */
    class IllegalState(
        message: String,
    ) : TransportError(message)

    /** The remote endpoint refused the connection. */
    class ConnectionRejected(
        val endpointId: EndpointId,
        message: String = "connection rejected by endpoint ${endpointId.value}",
    ) : TransportError(message)

    /** An I/O failure inside the transport (transfer failure, stream error, ...). */
    class IoFailure(
        cause: Throwable,
        message: String = "transport i/o failure",
    ) : TransportError(message, cause)
}
