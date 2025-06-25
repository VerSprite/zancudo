# MQTT-Proxy

MQTT interception proxy made in Go. It can handle TLS and password authentication, can autodetect the encoding of message payloads, and can be configured to automatically modify certain payloads.

## Building from Source

To build the proxy and associated tools, you'll need Go installed on your system. Run `make` to build binaries for all supported platforms (Windows, macOS, Linux).

```bash
make all
```

This will create binaries in the `bin/` directory, organized by platform (e.g., `bin/windows_amd64/`, `bin/darwin_amd64/`).

The following examples assume you are running the binaries from the root of the repository. Remember to replace `<your-platform>` with the directory corresponding to your system (e.g. `linux_amd64`). On Windows, you should also use backslashes (`\`) for paths and add the `.exe` extension to the binary names.

## MQTT Interception Proxy (`mqtt_mitm_proxy`)

### Usage

The proxy supports the following command-line flags:

-   `--listen`: Address and port for the proxy to listen on. Default: `:8883`.
-   `--broker`: Address and port of the remote MQTT broker. Default: `test.mosquitto.org:8883`.
-   `--proxy-cert`: Path to the proxy's server public certificate file. If empty, the proxy listens for plaintext connections.
-   `--proxyKey`: Path to the proxy's server private key file. If empty, the proxy listens for plaintext connections.
-   `--client-cert`: Path to the client's public certificate file. If empty, the proxy connects to the broker via plaintext.
-   `--client-key`: Path to the client's private key file. If empty, the proxy connects to the broker via plaintext.
-   `--user`: Username for broker authentication. If provided, it overwrites the username sent by the client.
-   `--pass`: Password for broker authentication. If provided, it overwrites the password sent by the client.
-   `--verbose`: Enable verbose logging for detailed packet analysis.
-   `--no-color`: Disable colored output, which is useful for piping output to files.

### Example

```bash
./mqtt_mitm_proxy --listen 127.0.0.1:8888 --broker internal.broker.local:8883 --proxy-cert proxy.crt --proxy-key proxy.key --verbose
```

### Payload Analysis

The proxy automatically analyzes and decodes PUBLISH message payloads to provide human-readable output. It supports a variety of data formats:

*   **Text-based Formats**:
    *   JSON (with auto-correction for single quotes)
    *   XML
    *   YAML
    *   JWT (JSON Web Token) - includes signature verification if a key is provided via `--jwt-key`.
*   **Binary Formats**:
    *   BSON
    *   MessagePack
    *   UBJSON
    *   CBOR
    *   Smile
    *   Ion (binary and text)
    *   Protobuf (requires `.proto` schema files to be provided via the `--proto` flag)
*   **Encoded Strings**:
    *   Base64
    *   Hex
*   **Fallback**:
    *   Plaintext (if the payload is mostly printable text)
    *   Binary (displayed as a hex dump if no other format is detected)

## Certificate Generation (`gen_certs`)

This proxy requires server certificates to intercept TLS traffic. The `gen_certs` tool helps you generate the necessary `proxy.crt` and `proxy.key` files.

### Usage

The tool has two main subcommands: `fetch` and `clone`.

#### Fetching from a Remote Server

This is the recommended method. It connects to the real MQTT broker, fetches its public certificate, and generates a new, similar certificate for the proxy to use.

```bash
./gen_certs fetch test.mosquitto.org:8883
# Example:
./gen_certs fetch test.mosquitto.org:8883
```

This will create `proxy.crt` and `proxy.key` in the current directory.

#### Cloning a Local Certificate File

If you have a server certificate file locally, you can use it as a template.

```bash
./gen_certs clone <path_to_cert.pem>
# Example:
./gen_certs clone /path/to/server.crt
```

### Advanced Options

Both subcommands support the following flags:

-   `--proxy-hostname <host>`: Issue the new certificate for a specific hostname or IP address, instead of the one from the template certificate.
-   `--out-cert <path>`: Specify the output path for the new proxy certificate (default: `proxy.crt`).
-   `--out-key <path>`: Specify the output path for the new proxy private key (default: `proxy.key`).

### CA Signing Options

By default, generated certificates are self-signed. For clients that require a trusted CA, you can use the following options:

1.  **Generate a new Root CA**: This is useful for creating a new chain of trust for your proxy. The tool will generate `ca.crt` and `ca.key` and use them to sign the new proxy certificate.
    -   When using `fetch`, the new CA will mimic the *issuer* of the remote server's certificate.
    -   When using `clone`, the new CA will mimic the *issuer* of the local certificate file.

    ```bash
    ./gen_certs fetch --gen-ca test.mosquitto.org:8883
    ```

2.  **Use an Existing CA**: If you already have a CA, you can use it to sign the proxy certificate.

    ```bash
    ./gen_certs fetch --ca-cert /path/to/ca.crt --ca-key /path/to/ca.key test.mosquitto.org:8883
    ```

3.  **Use a CA Certificate as a Template**: If you only have the CA's public certificate (`.crt`) but not its private key, the tool can generate a new, mimicked CA based on it.

    ```bash
    ./gen_certs fetch --ca-cert /path/to/ca.crt test.mosquitto.org:8883
    ```
This will generate `ca.crt` and `ca.key` based on the provided template, then use them for signing.

## Scripting with JavaScript

The proxy can be extended with custom logic using JavaScript. You can intercept, modify, drop packets, and add custom payload decoders.

To load a script, use the `--script` command-line flag:

```sh
./mqtt_mitm_proxy --script ./example.js --listen :1883 --broker test.mosquitto.org:1883
```

The script is a standard JavaScript file that can export two special functions: `handlePacket` and `analyzePayload`. You don't need to export both; the proxy will only call the ones it finds.

```javascript
// example.js

// This function is called for every MQTT packet.
// It can inspect, modify, or drop packets.
function handlePacket(packet) {
  // ...
}

// This function is called for every PUBLISH payload.
// It can decode and format payloads for logging.
function analyzePayload(payload) {
  // ...
}

module.exports = {
  handlePacket,
  analyzePayload,
};
```

### `handlePacket(packet)`

This function is called for every packet flowing through the proxy. It receives a `packet` object as an argument.

The primary use cases are:
1.  **Inspecting traffic**: You can log details of any packet.
2.  **Dropping packets**: If `handlePacket` returns `null`, the packet will be dropped and not forwarded.
3.  **Modifying packets**: For certain packet types, the `packet` object contains mutable fields. Changing them will alter the packet that gets forwarded.

The `packet` object has the following common properties:

*   `direction` (string): The direction of the packet. Either `"C->S"` (Client to Server) or `"S->C"` (Server to Client). Read-only.
*   `type` (string): The MQTT packet type, e.g., `"PUBLISH"`, `"CONNECT"`. Read-only.
*   `raw` (Uint8Array): The raw bytes of the packet. If you modify this directly, your changes will be sent, but this is for advanced use. It's easier to modify the parsed fields.
*   `modifiable` (boolean): `true` if the packet has parsed, mutable fields.

**Modifiable PUBLISH Packets**

If `packet.type` is `"PUBLISH"`, `modifiable` will be `true` and the following fields are available and can be changed:

*   `topic` (string): The topic of the message.
*   `payload` (Uint8Array): The payload of the message. You can replace this with a new `Uint8Array`.
*   `qos` (integer): The Quality of Service level (0, 1, or 2).
*   `retain` (boolean): The retain flag.

**Example: Modifying and Dropping Packets**

```javascript
function handlePacket(packet) {
  // Log every packet
  console.log(`[JS] Intercepted ${packet.direction} ${packet.type}`);

  // Check if it's a PUBLISH packet we can modify
  if (packet.modifiable && packet.type === "PUBLISH") {

    // Drop all messages going to 'private/topic'
    if (packet.topic === 'private/topic') {
      console.log(`[JS] Dropping packet to ${packet.topic}`);
      return null; // Drop the packet
    }

    // Modify payload for topic 'test/hello'
    if (packet.topic === 'test/hello') {
      console.log(`[JS] Modifying payload for ${packet.topic}`);
      const newPayloadStr = "Hello from JavaScript! The original message was: " + new TextDecoder().decode(packet.payload);
      packet.payload = new TextEncoder().encode(newPayloadStr);
    }
  }

  // Return the packet object to forward it.
  // Note: you don't need to return packet.raw, returning the object is enough.
  return packet;
}
```

### `analyzePayload(payload)`

This function is called by the proxy's analysis engine when it receives a `PUBLISH` packet. It allows you to add custom logic to decode and pretty-print payloads.

*   `payload` (Uint8Array): The raw payload from a `PUBLISH` packet.

The function should return:
*   A `string` containing the formatted analysis of the payload. This string will be printed to the console, and the built-in analyzers (JSON, Protobuf, etc.) will be skipped.
*   `null` or `undefined` if your analyzer cannot handle this payload. The proxy will then proceed with its own analyzers.

**Example: Custom Payload Analyzer**

```javascript
function analyzePayload(payload) {
  // A custom format: "MyFormat:<some_text>"
  const text = new TextDecoder().decode(payload);
  if (text.startsWith("MyFormat:")) {
    const content = text.substring("MyFormat:".length);
    // Return a formatted string for the log
    return `[JS] Detected My Custom Format\n      Content: ${content}`;
  }

  // If it's not our format, return null to let the proxy handle it.
  return null;
}
```

### Available Helpers

The JavaScript environment provides several built-in helper functions and a crypto module to facilitate packet analysis and manipulation.

#### Global Functions

*   `console.log(...args)`: Prints arguments to the proxy's main console. Useful for debugging scripts.
*   `require(path)`: Loads a JavaScript file from the given path and executes it. This is a simple file loader, not a full Node.js-style module resolver. It's useful for splitting your code into multiple files.
*   `btoa(string)`: Performs Base64 encoding.
*   `atob(string)`: Performs Base64 decoding.
*   `TextEncoder` and `TextDecoder`: Standard browser APIs for converting between strings and `Uint8Array`s (assuming UTF-8 encoding).

#### Crypto Module

A global `crypto` object is available with a suite of cryptographic functions. For all functions, data can be passed as a `string`, `ArrayBuffer`, or `Uint8Array`. Keys should be in PEM format where applicable.

*   `crypto.hash(algorithm, data, [encoding])`: Computes a hash.
    *   `algorithm`: `'md5'`, `'sha1'`, `'sha256'`, `'sha512'`.
    *   `encoding` (optional): `'hex'` or `'base64'`. Returns an `ArrayBuffer` if omitted.

*   `crypto.hmac(algorithm, key, data, [encoding])`: Computes a Hash-based Message Authentication Code (HMAC).
    *   `algorithm`: `'sha1'`, `'sha256'`, `'sha512'`.
    *   `encoding` (optional): `'hex'` or `'base64'`. Returns an `ArrayBuffer` if omitted.

*   `crypto.encrypt(algorithm, key, iv, plaintext)`: Encrypts data.
    *   `algorithm`: `'aes-128-gcm'`, `'aes-256-gcm'`.
    *   Returns an object `{ ciphertext, authTag }` as `ArrayBuffer`s.

*   `crypto.decrypt(algorithm, key, iv, authTag, ciphertext)`: Decrypts data.
    *   `algorithm`: `'aes-128-gcm'`, `'aes-256-gcm'`.
    *   Returns the plaintext as an `ArrayBuffer`.

*   `crypto.rsaEncrypt(publicKey, hash, plaintext)`: Encrypts data using an RSA public key (OAEP padding).
    *   `hash`: The hash algorithm to use for OAEP (`'sha1'`, `'sha256'`, etc.).

*   `crypto.rsaDecrypt(privateKey, hash, ciphertext)`: Decrypts data using an RSA private key.

*   `crypto.rsaSign(privateKey, hash, data)`: Creates an RSA-PSS signature.

*   `crypto.rsaVerify(publicKey, hash, data, signature)`: Verifies an RSA-PSS signature. Returns `true` or `false`.

*   `crypto.ecdsaSign(privateKey, hash, data)`: Creates an ECDSA signature.

*   `crypto.ecdsaVerify(publicKey, hash, data, signature)`: Verifies an ECDSA signature. Returns `true` or `false`.

*   `crypto.ecdh(privateKey, publicKey)`: Performs an Elliptic-Curve Diffie-Hellman key exchange.
    *   Keys must be on the same curve (`P-256`, `P-384`, or `P-521`).
    *   Returns the shared secret as an `ArrayBuffer`.
