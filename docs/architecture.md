# Architecture and protocol

The program uses a small length-prefixed JSON header followed by an optional byte payload. All integer lengths in the frame prefix use network byte order (big-endian).

## Message flow

1. The sender connects to the receiver's TCP port.
2. The sender sends a JSON frame identifying the message type and payload size.
3. For a text message, the sender sends the small UTF-8 payload; the receiver displays it in the terminal as JSON-escaped text, does not put the payload in application logs, and returns a framed JSON acknowledgement.
4. For a file, the header includes the basename, byte size, and SHA-256 digest.
5. The receiver validates the metadata and configured maximum file size, checks available storage, creates a unique temporary file, and probes hard-link support in the destination directory. Only then does it send a `ready` acknowledgement before the sender begins streaming the body.
6. The receiver writes chunks to disk while calculating SHA-256. If the connection breaks or the digest differs, the temporary file is removed and an error acknowledgement is attempted.
7. On success, the receiver publishes the verified file using an atomic no-overwrite hard link, removes the temporary file, and returns the destination name, size, and digest. The destination filesystem must support hard links; otherwise publication fails safely and the incomplete/temp file is cleaned up by the caller.

## Limits and failure handling

- JSON frames are limited to 16 KiB; message bodies are limited to 1 MiB.
- The default maximum file size is 8192 MiB (8 GiB) and is configurable independently on the sender and receiver. A file must fit both limits.
- The default socket inactivity timeout is 300 seconds and is configurable. Slow progress is allowed as long as each socket operation continues to make progress inside the timeout.
- A SHA-256 mismatch, size rejection, invalid header, or truncated stream prevents partial content from being published as a complete destination file.

## Security

There is no TLS, shared secret, client authentication, or access-control list. Use only on a network where peers are trusted, and protect the port with OS firewall rules. For production use, add authenticated TLS and authorization before accepting untrusted traffic.
