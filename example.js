/*
 * MQTT-Proxy Example JavaScript Extension
 *
 * This script demonstrates how to use the scripting features of the MQTT-Proxy.
 *
 * To use it, run the proxy with the --script flag:
 * zancudo --script example.js
 */

/**
 * handlePacket is called for every MQTT packet that passes through the proxy.
 *
 * @param {object} packet - The packet object.
 * @property {string} packet.direction - "C->S" or "S->C".
 * @property {string} packet.type - e.g., "CONNECT", "PUBLISH".
 * @property {boolean} packet.modifiable - True if the packet's fields can be changed.
 * @property {string} [packet.topic] - The topic for PUBLISH packets.
 * @property {Uint8Array} [packet.payload] - The payload for PUBLISH packets.
 * @property {number} [packet.qos] - The QoS for PUBLISH packets.
 * @property {boolean} [packet.retain] - The retain flag for PUBLISH packets.
 *
 * @returns {object|null} - Return the modified packet object to forward it, or null to drop it.
 */
function handlePacket(packet) {
  // A simple logger to show all intercepted packets.
  console.log(`[JS Script] Intercepted packet: ${packet.direction} ${packet.type}`);

  // Check if it's a PUBLISH packet that we can modify.
  if (packet.modifiable && packet.type === 'PUBLISH') {
    // Example 1: Drop packets sent to a specific topic.
    if (packet.topic === 'sensordata/drop') {
      console.log(`[JS Script] Dropping packet to topic: ${packet.topic}`);
      return null; // Returning null drops the packet.
    }

    // Example 2: Modify the payload of packets sent to another topic.
    if (packet.topic === 'control/light') {
      const originalPayload = new TextDecoder().decode(packet.payload);
      console.log(`[JS Script] Modifying packet to topic '${packet.topic}'. Original payload: ${originalPayload}`);

      const newPayload = `MODIFIED BY JS: ${originalPayload}`;
      packet.payload = new TextEncoder().encode(newPayload);

      console.log(`[JS Script] New payload: ${newPayload}`);
    }
  }

  // Return the packet to allow it to be forwarded.
  // For modified packets, the proxy will re-assemble them from the modified fields.
  return packet;
}

/**
 * analyzePayload is called to analyze the payload of a PUBLISH packet.
 * It allows for custom payload decoders.
 *
 * @param {Uint8Array} payload - The raw payload of a PUBLISH packet.
 * @returns {string|null} - A formatted string if the payload is recognized, or null otherwise.
 *                          If a string is returned, the proxy's built-in analyzers are skipped.
 */
function analyzePayload(payload) {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(payload);

    // Example: A custom payload format "Key:Value"
    if (text.includes(':')) {
      const parts = text.split(':', 2);
      if (parts.length == 2) {
        // It matches our custom format. Return a pretty-printed version.
        return `[JS Custom Decoder] Detected Key-Value pair:\n      Key: ${parts[0]}\n      Value: ${parts[1]}`;
      }
    }
  } catch (e) {
    // Not valid UTF-8, so it's not our format.
  }

  // If we can't handle this payload, return null.
  // The proxy will then try its own decoders (JSON, Protobuf, etc.).
  return null;
}

// Export the functions that the proxy will call.
// You can export one or both.
module.exports = {
  handlePacket,
  analyzePayload,
};