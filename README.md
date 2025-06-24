# MQTT-Proxy

MQTT interception proxy made in Go. It can handle TLS and password authentication, can autodetect the encoding of message payloads, and can be configured to automatically modify certain payloads.

## MQTT Interception Proxy (`mqtt_mitm_proxy.go`)

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
go run mqtt_mitm_proxy.go --listen 127.0.0.1:8888 --broker internal.broker.local:8883 --proxy-cert proxy.crt --proxy-key proxy.key --verbose
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

## Certificate Generation (`gen_certs.go`)

This proxy requires server certificates to intercept TLS traffic. The `gen_certs.go` tool helps you generate the necessary `proxy.crt` and `proxy.key` files.

### Usage

The tool has two main subcommands: `fetch` and `clone`.

#### Fetching from a Remote Server

This is the recommended method. It connects to the real MQTT broker, fetches its public certificate, and generates a new, similar certificate for the proxy to use.

```bash
go run gen_certs.go fetch <hostname:port>
# Example:
go run gen_certs.go fetch test.mosquitto.org:8883
```

This will create `proxy.crt` and `proxy.key` in the current directory.

#### Cloning a Local Certificate File

If you have a server certificate file locally, you can use it as a template.

```bash
go run gen_certs.go clone <path_to_cert.pem>
# Example:
go run gen_certs.go clone /path/to/server.crt
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
    go run gen_certs.go fetch --gen-ca test.mosquitto.org:8883
    ```

2.  **Use an Existing CA**: If you already have a CA, you can use it to sign the proxy certificate.

    ```bash
    go run gen_certs.go fetch --ca-cert /path/to/ca.crt --ca-key /path/to/ca.key test.mosquitto.org:8883
    ```

3.  **Use a CA Certificate as a Template**: If you only have the CA's public certificate (`.crt`) but not its private key, the tool can generate a new, mimicked CA based on it.

    ```bash
    go run gen_certs.go fetch --ca-cert /path/to/ca.crt test.mosquitto.org:8883
    ```
This will generate `ca.crt` and `ca.key` based on the provided template, then use them for signing.