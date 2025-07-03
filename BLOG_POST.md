<p align="center">
  <img src="ZANCUDO.png" alt="ZANCUDO LOGO" width="250"/>
<p align="center">

### **Introducing ZANCUDO: The Pentester's Burp Suite for MQTT**

In the world of web application security, we'd be lost without tools like Burp Suite. The ability to intercept, analyze, and manipulate HTTP traffic is fundamental to our work. But when we step into the rapidly expanding universe of IoT and embedded devices, the landscape changes. Here, MQTT is often the protocol of choice, and the tooling for security testing hasn't quite kept pace.

Pentesters often face a frustrating reality: a patchwork of scripts, limited-feature tools, and a lot of manual effort to achieve the kind of visibility and control we take for granted with HTTP. We've been there. In fact, that's why we built **ZANCUDO**.

Today, we're excited to announce that we are open-sourcing it for the security community.

ZANCUDO is a Go-based interception proxy designed by pentesters, for pentesters. It provides a powerful, scriptable, and user-friendly way to get in the middle of MQTT traffic, making it an essential addition to any IoT pentester's arsenal.

### The Spark: A Tale from the Trenches

The story of ZANCUDO begins, as many security tools do, during a client engagement. We were tasked with assessing an embedded device that communicated with its backend via MQTT. The setup was robust: the connection was secured with TLS, the device authenticated itself with a client certificate, and a custom Certificate Authority (CA) was used to ensure the device only trusted the authentic broker.

This presented a classic pentesting challenge: how do you perform a Man-in-the-Middle (MITM) attack when there's a custom chain of trust? Furthermore, the message payloads themselves were encrypted with a proprietary scheme.

Our initial solution was a collection of ad-hoc scripts that got the job done. But it left us thinking: there has to be a better way. We needed a tool that was as flexible and powerful as the challenges we face. That's why we went back to the drawing board and created ZANCUDO, a complete rewrite of our initial tool, built for flexibility and ease of use.

### A Pentester's Best Friend: Cloning Certificates for MITM

One of the biggest hurdles in IoT pentesting is defeating certificate-based security. ZANCUDO comes with a nifty sidekick utility, `gen_certs`, that makes this process remarkably simple.

Instead of wrestling with OpenSSL commands, you can point `gen_certs` at the real MQTT broker, and it will automatically fetch the server's public certificate and generate a new, perfectly mimicked certificate for your proxy to use.

For our engagement, the device trusted a specific custom CA. No problem. `gen_certs` can also generate a new CA that mimics the issuer of the server certificate, which you can then install on the target device.

Here's how easy it is to clone a certificate from a live server and simultaneously generate a mimicked CA to sign it:

```bash
# This fetches the cert from the real broker and creates a new CA
# (ca.crt, ca.key) and a new proxy cert (proxy.crt, proxy.key)
# signed by your new CA.
./gen_certs fetch --gen-ca test.mosquitto.org:8883
```

With these generated files, the hard part of preparing for the MITM is already done. In our case, after gaining root access to the device, we simply replaced its trusted CA with our newly generated one, pointed DNS to our proxy, and the device connected to us without a fuss.

### From Hex Dumps to Actionable Intel

Once you're in the middle, visibility is key. ZANCUDO shines here. It automatically decodes message payloads from a wide variety of common formats, turning opaque byte streams into human-readable text.

Supported formats include:
*   **Text**: JSON, XML, YAML, JWT
*   **Binary**: Protobuf, BSON, MessagePack, CBOR, and more.

Running the proxy is simple. You tell it where to listen and where the real broker is. For a TLS-enabled broker, you provide the certificates you just generated.

```bash
./zancudo \
    --listen 127.0.0.1:8883 \
    --broker real.broker.com:8883 \
    --proxy-cert proxy.crt \
    --proxy-key proxy.key \
    --verbose
```

The output is clear and color-coded, immediately showing you the content of conversations.

### The Ultimate Power-Up: Scripting with JavaScript

This is where ZANCUDO transforms from a useful tool into a game-changer. Like Burp's extensions or mitmproxy's scripts, you can load a custom JavaScript file to implement any logic you need. This is how we tackled the custom payload encryption in our engagement.

Your script can export two key functions: `handlePacket` and `analyzePayload`.

#### `analyzePayload`: Decrypting Custom Formats

The `analyzePayload` function lets you teach the proxy how to understand proprietary or encrypted data. It receives the raw payload, and if you can decode it, you return a string for the proxy to log.

While we can't share the client's actual crypto, here's what a skeleton for a custom decoder looks like. You would drop your decryption logic in here.

```javascript
// script.js

// This function is called for PUBLISH payloads.
function analyzePayload(payload) {
  // A hypothetical custom format: an XOR-encrypted message
  // In a real scenario, this could be AES, etc.
  try {
    const key = 0xAB;
    let decrypted = '';
    for (let i = 0; i < payload.length; i++) {
      decrypted += String.fromCharCode(payload[i] ^ key);
    }
    return `[JS] Custom XOR-Encrypted Payload:\n      Content: ${decrypted}`;
  } catch (e) {
    // If it's not our format, return null to let the proxy's built-in
    // analyzers take a crack at it.
    return null;
  }
}

module.exports = { analyzePayload };
```

You load it with the `--script` flag, and suddenly the proxy speaks your target's language.

While the example above uses a simple XOR cipher, real-world scenarios often involve more complex, standard cryptographic algorithms like AES or DES. To make tackling these even easier, ZANCUDO's scripting engine comes with a suite of built-in cryptographic helpers. You can perform encryption, decryption, and hashing directly from your scripts without needing to implement the algorithms from scratch. This makes reversing and re-implementing proprietary encryption schemes significantly faster.

#### `handlePacket`: Manipulating Traffic on the Fly

The real power of pentesting comes from manipulation, not just observation. The `handlePacket` function is your gateway to modifying, dropping, or injecting MQTT packets.

Want to test for authorization flaws? Change the topic of a message to see if you can publish to a restricted area. Fuzzing an endpoint? Systematically alter the payload.

Here's an example script that modifies a command sent to a smart light bulb:

```javascript
// script.js

function handlePacket(packet) {
  // We only care about modifiable PUBLISH packets from client to server
  if (packet.modifiable && packet.type === "PUBLISH" && packet.direction === "C->S") {

    // Target a specific topic for a smart device
    if (packet.topic === 'device/123/set_config') {
      console.log(`[JS] Intercepted config packet for ${packet.topic}`);

      // Let's say the payload is JSON: {"color": "blue"}
      // We'll change it to red.
      const newPayloadStr = `{"color": "red"}`;
      packet.payload = new TextEncoder().encode(newPayloadStr);
      console.log(`[JS] Modified payload to: ${newPayloadStr}`);
    }
  }

  // Return the (potentially modified) packet to forward it.
  // Returning null would drop it entirely.
  return packet;
}

module.exports = { handlePacket };
```

### Get It Now

We believe ZANCUDO fills a critical gap in the security tester's toolkit. It was born from real-world necessity and refined into a flexible, powerful platform for IoT and MQTT security analysis.

We're excited to share it with the community and can't wait to see what you do with it.

You can find the project, along with full documentation and examples, on our GitHub:
**[Link to your GitHub repository here]**

Give it a try on your next IoT engagement. We welcome your feedback, feature requests, and contributions!