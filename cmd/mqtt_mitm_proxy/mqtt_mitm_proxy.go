/*
 * MQTT Interception Proxy
 * Authors: Jorge Alvarez (poro@versprite.com) and Mario Vilas (marito@versprite.com)
 * Released under BSD 3-clause license
*/

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/rsa"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v4"
	"github.com/vmihailenco/msgpack/v5"
	"gopkg.in/yaml.v3"
)

// MQTT packet types
const (
	CONNECT     = 1
	CONNACK     = 2
	PUBLISH     = 3
	PUBACK      = 4
	PUBREC      = 5
	PUBREL      = 6
	PUBCOMP     = 7
	SUBSCRIBE   = 8
	SUBACK      = 9
	UNSUBSCRIBE = 10
	UNSUBACK    = 11
	PINGREQ     = 12
	PINGRESP    = 13
	DISCONNECT  = 14
)

// ANSI color codes
var (
	colorReset         = "\033[0m"
	colorRed           = "\033[31m"
	colorGreen         = "\033[32m"
	colorYellow        = "\033[33m"
	colorBlue          = "\033[34m"
	colorPurple        = "\033[35m"
	colorCyan          = "\033[36m"
	colorWhite         = "\033[37m"
	colorBold          = "\033[1m"
	colorBrightMagenta = "\033[95m"
	colorBrightWhite   = "\x1b[97m"
)

// Direction colors
var (
	clientToServerColor = colorCyan
	serverToClientColor = colorYellow
	packetTypeColor     = colorGreen
	topicColor          = colorBrightMagenta
	payloadColor        = colorBrightWhite
	noColor             bool
)

// Command line options
var (
	proxyListenAddr string
	brokerAddr      string

	proxyCertFile string
	proxyKeyFile  string

	clientCertFile string
	clientKeyFile  string

	username string
	password string

	verbose       bool
	jwtVerifyKeys multiStringFlag
	loadedJWTKeys []interface{}
)

// Custom type to allow a flag to be specified multiple times
type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return fmt.Sprintf("%v", *m)
}

func (m *multiStringFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// MQTT packet buffer for handling fragmented packets
type MQTTBuffer struct {
	buffer []byte
}

func (mb *MQTTBuffer) addData(data []byte) {
	mb.buffer = append(mb.buffer, data...)
}

func (mb *MQTTBuffer) extractCompletePackets() [][]byte {
	var packets [][]byte
	offset := 0

	for offset < len(mb.buffer) {
		if offset >= len(mb.buffer) {
			break
		}

		// Need at least 2 bytes to read the length
		if offset+1 >= len(mb.buffer) {
			break
		}

		// Decode the remaining length
		remainingLength, endPos := decodeLength(mb.buffer, offset+1)
		lengthBytes := endPos - (offset + 1)

		// Total packet size is: fixed header (1 byte) + length bytes + remaining length
		totalPacketSize := 1 + lengthBytes + remainingLength

		// Check if we have the complete packet
		if offset+totalPacketSize > len(mb.buffer) {
			// Incomplete packet, wait for more data
			break
		}

		// Extract complete packet
		packet := make([]byte, totalPacketSize)
		copy(packet, mb.buffer[offset:offset+totalPacketSize])
		packets = append(packets, packet)

		offset += totalPacketSize
	}

	// Remove processed data from buffer
	if offset > 0 {
		mb.buffer = mb.buffer[offset:]
	}

	return packets
}

func getPacketTypeName(packetType byte) string {
	switch packetType {
	case CONNECT:
		return "CONNECT"
	case CONNACK:
		return "CONNACK"
	case PUBLISH:
		return "PUBLISH"
	case PUBACK:
		return "PUBACK"
	case PUBREC:
		return "PUBREC"
	case PUBREL:
		return "PUBREL"
	case PUBCOMP:
		return "PUBCOMP"
	case SUBSCRIBE:
		return "SUBSCRIBE"
	case SUBACK:
		return "SUBACK"
	case UNSUBSCRIBE:
		return "UNSUBSCRIBE"
	case UNSUBACK:
		return "UNSUBACK"
	case PINGREQ:
		return "PINGREQ"
	case PINGRESP:
		return "PINGRESP"
	case DISCONNECT:
		return "DISCONNECT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", packetType)	// should not happen
	}
}

func decodeLength(data []byte, offset int) (int, int) {
	length := 0
	multiplier := 1
	pos := offset

	for {
		if pos >= len(data) {
			return 0, pos
		}

		digit := data[pos]
		length += int(digit&0x7F) * multiplier
		pos++

		if (digit & 0x80) == 0 {
			break
		}

		multiplier *= 128
		if multiplier > 128*128*128 {
			return 0, pos
		}
	}

	return length, pos
}

func encodeLength(length int) []byte {
	if length == 0 {
		return []byte{0}
	}

	result := make([]byte, 0, 4)
	for length > 0 {
		digit := byte(length % 128)
		length /= 128
		if length > 0 {
			digit |= 0x80
		}
		result = append(result, digit)
	}
	return result
}

func decodeString(data []byte, offset int) (string, int) {
	if offset+2 > len(data) {
		return "", offset
	}

	length := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	if offset+length > len(data) {
		return "", offset
	}

	str := string(data[offset : offset+length])
	return str, offset + length
}

func encodeString(s string) []byte {
	if len(s) > 65535 {
		s = s[:65535] // MQTT strings are limited by uint16
	}
	encoded := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(encoded, uint16(len(s)))
	copy(encoded[2:], s)
	return encoded
}

func prettyPrintJSON(jsonStr string) string {
	var obj interface{}
	if err := json.Unmarshal([]byte(jsonStr), &obj); err != nil {
		return jsonStr
	}

	pretty, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return jsonStr
	}

	return string(pretty)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func hexToASCII(hexData []byte) string {
	result := ""
	for _, b := range hexData {
		if b >= 32 && b <= 126 {
			result += string(b)
		} else {
			result += fmt.Sprintf("\\x%02x", b)
		}
	}
	return result
}

func processMQTTPackets(direction string, packets [][]byte) [][]byte {
	for _, packet := range packets {
		analyzeMQTTPacket(direction, packet)
	}
	return packets
}

func analyzeMQTTPacket(direction string, data []byte) {
	if len(data) == 0 {
		return
	}

	firstByte := data[0]
	packetType := (firstByte >> 4) & 0x0F

	// Skip logging ping packets if not in verbose mode
	if !verbose && (packetType == PINGREQ || packetType == PINGRESP) {
		return
	}

	flags := firstByte & 0x0F
	remainingLength, headerEnd := decodeLength(data, 1)
	if headerEnd > len(data) && !verbose {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	directionText := ""
	directionColor := ""
	if direction == "C→S" {
		directionText = "CLIENT → SERVER"
		directionColor = clientToServerColor
	} else {
		directionText = "SERVER → CLIENT"
		directionColor = serverToClientColor
	}

	log.Printf("\n=== %s%s%s %s MQTT Packet ===", directionColor, directionText, colorReset, timestamp)

	log.Printf("Packet Type: %s%s%s (0x%02X)", packetTypeColor, getPacketTypeName(packetType), colorReset, packetType)
	log.Printf("Flags: 0x%01X", flags)

	if verbose {
		log.Printf("Remaining Length: %d bytes", remainingLength)
	}
	if headerEnd > len(data) {
		log.Printf("=== Incomplete Packet ===\n")
		return
	}

	payload := data[headerEnd:]

	switch packetType {
	case PUBLISH:
		analyzePUBLISH(payload, flags, direction)
	case CONNECT:
		analyzeCONNECT(payload)
	case CONNACK:
		analyzeCONNACK(payload)
	case SUBSCRIBE:
		analyzeSUBSCRIBE(payload, flags)
	case SUBACK:
		analyzeSUBACK(payload)
	case UNSUBSCRIBE:
		analyzeUNSUBSCRIBE(payload, flags)
	case PUBACK:
		analyzeSimpleAck("PUBACK", payload)
	case UNSUBACK:
		analyzeSimpleAck("UNSUBACK", payload)
	case PINGREQ, PINGRESP:
		log.Printf("Ping packet (no payload)")
	case DISCONNECT:
		log.Printf("Disconnect packet")
	default:
		if len(payload) > 0 {
			log.Printf("Payload (%d bytes): %s", len(payload), hex.EncodeToString(payload))
			asciiPayload := hexToASCII(payload)
			if isMostlyPrintable([]byte(asciiPayload)) {
				log.Printf("Payload (ASCII): %s%s%s", payloadColor, asciiPayload, colorReset)
			} else {
				log.Printf("Payload (Hex): %s", hex.EncodeToString(payload))
			}
		}
	}

	log.Printf("=== End Packet ===\n")
}

func analyzeCONNACK(payload []byte) {
	if len(payload) < 2 {
		log.Printf("    [Broken CONNACK packet: expected 2 bytes, got %d]", len(payload))
		return
	}

	sessionPresent := (payload[0] & 0x01) != 0
	returnCode := payload[1]

	log.Printf("    Session Present: %t", sessionPresent)

	var returnCodeStr string
	switch returnCode {
	case 0:
		returnCodeStr = "Connection Accepted"
	case 1:
		returnCodeStr = "[!] Connection Refused: unacceptable protocol version"
	case 2:
		returnCodeStr = "[!] Connection Refused: identifier rejected"
	case 3:
		returnCodeStr = "[!] Connection Refused: server unavailable"
	case 4:
		returnCodeStr = "[!] Connection Refused: bad user name or password"
	case 5:
		returnCodeStr = "[!] Connection Refused: not authorized"
	default:
		returnCodeStr = fmt.Sprintf("[!] Connection Refused: unknown reason (%d)", returnCode)
	}
	log.Printf("    Return Code: %s", returnCodeStr)
}

func analyzeCONNECT(payload []byte) {
	offset := 0

	// Protocol Name
	protoName, newOffset := decodeString(payload, offset)
	log.Printf("    Protocol Name: %s", protoName)
	offset = newOffset

	if offset >= len(payload) {
		log.Printf("    [Broken CONNECT packet: missing protocol level]")
		return
	}
	protoLevel := payload[offset]
	log.Printf("    Protocol Level: %d", protoLevel)
	offset++

	if offset >= len(payload) {
		log.Printf("    [Broken CONNECT packet: missing connect flags]")
		return
	}
	flags := payload[offset]
	log.Printf("    Connect Flags: 0x%02X", flags)
	cleanSession := (flags&0x02) != 0
	willFlag := (flags & 0x04) != 0
	willQoS := (flags >> 3) & 0x03
	willRetain := (flags & 0x20) != 0
	userFlag := (flags & 0x80) != 0
	passFlag := (flags & 0x40) != 0

	log.Printf("        Clean Session: %t", cleanSession)
	log.Printf("        Will Flag: %t", willFlag)
	if willFlag {
		log.Printf("        Will QoS: %d", willQoS)
		log.Printf("        Will Retain: %t", willRetain)
	}
	log.Printf("        User Name Flag: %t", userFlag)
	log.Printf("        Password Flag: %t", passFlag)
	offset++

	if offset+1 >= len(payload) {
		log.Printf("    [Broken CONNECT packet: missing keep-alive]")
		return
	}
	keepAlive := int(payload[offset])<<8 | int(payload[offset+1])
	log.Printf("    Keep Alive: %d seconds", keepAlive)
	offset += 2

	// Client ID
	clientID, newOffset := decodeString(payload, offset)
	if newOffset == offset {
		log.Printf("    [Broken CONNECT packet: could not decode Client ID]")
		return
	}
	log.Printf("    Client ID: %s", clientID)
	offset = newOffset

	// Will Topic & Message
	if willFlag {
		willTopic, newOffset := decodeString(payload, offset)
		if newOffset == offset && len(willTopic) == 0 {
			log.Printf("    [Broken CONNECT packet: could not decode Will Topic]")
			return
		}
		log.Printf("    Will Topic: %s", willTopic)
		offset = newOffset

		// Decode Will Message (binary payload)
		if offset+2 > len(payload) {
			log.Printf("    [Broken CONNECT packet: missing Will Message length]")
			return
		}
		msgLen := int(payload[offset])<<8 | int(payload[offset+1])
		offset += 2
		if offset+msgLen > len(payload) {
			log.Printf("    [Broken CONNECT packet: missing Will Message body]")
			return
		}
		willMessage := payload[offset : offset+msgLen]
		log.Printf("    Will Message: %s (%s)", hexToASCII(willMessage), hex.EncodeToString(willMessage))
		offset += msgLen
	}

	// User Name
	if userFlag {
		userName, newOffset := decodeString(payload, offset)
		if newOffset == offset {
			log.Printf("    [Broken CONNECT packet: could not decode User Name]")
			return
		}
		log.Printf("    User Name: %s", userName)
		offset = newOffset
	}

	// Password
	if passFlag {
		// Decode Password (binary payload)
		if offset+2 > len(payload) {
			log.Printf("    [Broken CONNECT packet: missing Password length]")
			return
		}
		msgLen := int(payload[offset])<<8 | int(payload[offset+1])
		offset += 2
		if offset+msgLen > len(payload) {
			log.Printf("    [Broken CONNECT packet: missing Password body]")
			return
		}
		password := payload[offset : offset+msgLen]
		log.Printf("    Password: %s", hex.EncodeToString(password))
		offset += msgLen
	}
}

func analyzePUBLISH(payload []byte, flags byte, direction string) {
	topic, offset := decodeString(payload, 0)
	fmt.Printf("  Topic: %s%s%s\n", topicColor, topic, colorReset)

	// Packet identifier is only present for QoS > 0
	if (flags>>1)&0x03 > 0 {
		if len(payload) >= offset+2 {
			packetID := binary.BigEndian.Uint16(payload[offset:])
			fmt.Printf("  Packet ID: %d\n", packetID)
			offset += 2
		}
	}

	publishPayload := payload[offset:]
	if verbose {
		fmt.Printf("  %sOriginal Payload (%d bytes):%s\n%s\n", payloadColor, len(publishPayload), colorReset, hex.Dump(publishPayload))
	}

	fmt.Printf("  %sPayload:%s\n", payloadColor, colorReset)
	processPayload(publishPayload)
}

func analyzeSUBSCRIBE(payload []byte, flags byte) {
	if len(payload) < 2 {
		log.Printf("    [Broken SUBSCRIBE packet: missing packet identifier]")
		return
	}
	packetID := int(payload[0])<<8 | int(payload[1])
	log.Printf("    Packet ID: %d", packetID)
	offset := 2

	if flags&0x0F != 2 {
		log.Printf("    [Broken SUBSCRIBE packet: fixed header flags must be 0x02, but were 0x%01X]", flags&0x0F)
	}

	for offset < len(payload) {
		topic, newOffset := decodeString(payload, offset)
		if newOffset == offset {
			log.Printf("    [Broken SUBSCRIBE packet: could not decode topic filter]")
			break
		}
		offset = newOffset

		if offset >= len(payload) {
			log.Printf("    [Broken SUBSCRIBE packet: missing QoS for topic '%s']", topic)
			break
		}
		qos := payload[offset]
		log.Printf("    Topic Filter: %s%s%s, Requested QoS: %d", topicColor, topic, colorReset, qos)
		offset++
	}
}

func analyzeSUBACK(payload []byte) {
	if len(payload) < 2 {
		log.Printf("    [Broken SUBACK packet: missing packet identifier]")
		return
	}
	packetID := int(payload[0])<<8 | int(payload[1])
	log.Printf("    Packet ID: %d", packetID)
	offset := 2

	log.Printf("    Granted QoS Levels:")
	i := 0
	for offset < len(payload) {
		returnCode := payload[offset]
		var result string
		switch returnCode {
		case 0x00:
			result = "Success (Max QoS 0)"
		case 0x01:
			result = "Success (Max QoS 1)"
		case 0x02:
			result = "Success (Max QoS 2)"
		case 0x80:
			result = "[!] Failure"
		default:
			result = fmt.Sprintf("Unknown (0x%02X)", returnCode)
		}
		log.Printf("        Topic %d: %s", i, result)
		offset++
		i++
	}
}

func analyzeUNSUBSCRIBE(payload []byte, flags byte) {
	if len(payload) < 2 {
		log.Printf("    [Broken UNSUBSCRIBE packet: missing packet identifier]")
		return
	}
	packetID := int(payload[0])<<8 | int(payload[1])
	log.Printf("    Packet ID: %d", packetID)
	offset := 2

	if flags&0x0F != 2 {
		log.Printf("    [Broken UNSUBSCRIBE packet: fixed header flags must be 0x02, but were 0x%01X]", flags&0x0F)
	}

	log.Printf("    Topics to Unsubscribe:")
	for offset < len(payload) {
		topic, newOffset := decodeString(payload, offset)
		if newOffset == offset {
			log.Printf("    [Broken UNSUBSCRIBE packet: could not decode topic filter]")
			break
		}
		log.Printf("        - %s%s%s", topicColor, topic, colorReset)
		offset = newOffset
	}
}

func analyzeSimpleAck(name string, payload []byte) {
	if len(payload) < 2 {
		log.Printf("    [Broken %s packet: missing packet identifier]", name)
		return
	}
	packetID := int(payload[0])<<8 | int(payload[1])
	log.Printf("    %s for Packet ID: %d", name, packetID)
}

func handleConnection(clientConn net.Conn, username, password string) {
	defer clientConn.Close()
	log.Printf("Accepted connection from %s", clientConn.RemoteAddr())

	// 1. Setup Client -> Proxy connection (clientSideConn)
	var clientSideConn io.ReadWriteCloser = clientConn
	if proxyCertFile != "" && proxyKeyFile != "" {
		log.Printf("Proxy certificates provided, attempting TLS handshake with client.")
		cert, err := tls.LoadX509KeyPair(proxyCertFile, proxyKeyFile)
		if err != nil {
			log.Printf("[!] Failed to load proxy certs: %v. Closing connection.", err)
			return
		}
		tlsClient := tls.Server(clientConn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tlsClient.Handshake(); err != nil {
			log.Printf("[!] TLS handshake with client failed: %v", err)
			return
		}
		clientSideConn = tlsClient
		log.Printf("TLS handshake with client successful.")
	} else {
		log.Printf("Proxy certificates not provided. Using plaintext for client connection.")
	}

	// 2. Setup Proxy -> Broker connection (serverSideConn)
	var serverSideConn io.ReadWriteCloser
	if clientCertFile != "" && clientKeyFile != "" {
		log.Printf("Client certificates provided, attempting TLS connection to broker.")
		clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			log.Printf("[!] Failed to load client certs: %v. Will not connect to broker.", err)
			return // Cannot proceed
		}
		tlsServer, err := tls.Dial("tcp", brokerAddr, &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{clientCert},
		})
		if err != nil {
			log.Printf("[!] Failed to connect to real broker with TLS: %v", err)
			return
		}
		serverSideConn = tlsServer
		log.Printf("Connected to real broker at %s using TLS with client certificate.", brokerAddr)
	} else {
		log.Printf("Client certificates not provided. Connecting to broker with plaintext.")
		tcpConn, err := net.Dial("tcp", brokerAddr)
		if err != nil {
			log.Printf("[!] Failed to connect to real broker with plaintext: %v", err)
			return
		}
		serverSideConn = tcpConn
		log.Printf("Connected to real broker at %s using plaintext TCP.", brokerAddr)
	}
	defer serverSideConn.Close()

	// Create buffers for handling fragmented MQTT packets
	clientToServerBuffer := &MQTTBuffer{}
	serverToClientBuffer := &MQTTBuffer{}

	connectPacketModified := false

	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := clientSideConn.Read(buf)
			if err != nil {
				log.Printf("Client %s disconnected (error: %v). Closing connection to broker.", clientConn.RemoteAddr(), err)
				serverSideConn.Close()
				return
			}

			// Add data to buffer
			clientToServerBuffer.addData(buf[:n])

			// Extract complete packets
			packets := clientToServerBuffer.extractCompletePackets()

			// Modify CONNECT packet if needed
			packetsToSend := packets
			if !connectPacketModified && (username != "" || password != "") {
				var modified bool
				packetsToSend, modified, err = modifyFirstConnectPacket(packets, username, password)
				if err != nil {
					log.Printf("[!] Error modifying CONNECT packet: %v", err)
					serverSideConn.Close()
					return
				}
				if modified {
					connectPacketModified = true
					log.Printf("Injected/replaced username and password in CONNECT packet.")
				}
			}

			// Process packets for analysis
			processMQTTPackets("C→S", packetsToSend)

			// Send all original packets
			for _, packet := range packetsToSend {
				_, err = serverSideConn.Write(packet)
				if err != nil {
					log.Printf("[!] [C→S] write error: %v", err)
					return
				}
			}
		}
	}()

	buf := make([]byte, 65536)
	for {
		n, err := serverSideConn.Read(buf)
		if err != nil {
			log.Printf("Remote broker %s disconnected (error: %v). Closing connection to client.", brokerAddr, err)
			clientSideConn.Close()
			return
		}

		// Add data to buffer
		serverToClientBuffer.addData(buf[:n])

		// Extract complete packets
		packets := serverToClientBuffer.extractCompletePackets()

		// Process packets for analysis
		processMQTTPackets("S→C", packets)

		// Send all original packets
		for _, packet := range packets {
			_, err = clientSideConn.Write(packet)
			if err != nil {
				log.Printf("[!] [S→C] write error: %v", err)
				return
			}
		}
	}
}

// modifyFirstConnectPacket finds the first CONNECT packet in a batch, and if found,
// rebuilds it to include the provided username and password.
func modifyFirstConnectPacket(packets [][]byte, username, password string) (newPackets [][]byte, modified bool, err error) {
	for i, packet := range packets {
		if len(packet) > 0 && (packet[0]>>4) == CONNECT {
			newPacket, err := rebuildConnectPacket(packet, username, password)
			if err != nil {
				return nil, false, fmt.Errorf("could not rebuild CONNECT packet: %w", err)
			}
			// Replace original packet with the modified one
			modifiedPackets := make([][]byte, len(packets))
			copy(modifiedPackets, packets)
			modifiedPackets[i] = newPacket
			return modifiedPackets, true, nil
		}
	}
	return packets, false, nil // No CONNECT packet found, no modification
}

// rebuildConnectPacket parses an existing CONNECT packet and creates a new one with new credentials.
func rebuildConnectPacket(originalPacket []byte, newUsername, newPassword string) ([]byte, error) {
	// --- Begin Parsing ---
	_, headerEnd := decodeLength(originalPacket, 1)
	payload := originalPacket[headerEnd:]
	offset := 0

	// Protocol Name and Level
	_, newOffset := decodeString(payload, offset)
	if newOffset == offset {
		return nil, fmt.Errorf("could not decode protocol name")
	}
	variableHeaderPrefix := payload[offset:newOffset]
	offset = newOffset

	if offset >= len(payload) {
		return nil, fmt.Errorf("missing protocol level")
	}
	variableHeaderPrefix = append(variableHeaderPrefix, payload[offset])
	offset++

	// Connect Flags (original)
	if offset >= len(payload) {
		return nil, fmt.Errorf("missing connect flags")
	}
	originalFlags := payload[offset]
	offset++

	// Keep Alive
	if offset+1 >= len(payload) {
		return nil, fmt.Errorf("missing keep-alive")
	}
	variableHeaderPrefix = append(variableHeaderPrefix, payload[offset:offset+2]...)
	offset += 2

	// --- New Payload Construction ---
	var newPayload bytes.Buffer

	// Client ID (must be present)
	clientID, newOffset := decodeString(payload, offset)
	if newOffset == offset {
		return nil, fmt.Errorf("could not decode client ID")
	}
	newPayload.Write(encodeString(clientID))
	offset = newOffset

	// Will Properties (if present)
	willFlag := (originalFlags & 0x04) != 0
	if willFlag {
		// Will Topic
		willTopic, newOffset := decodeString(payload, offset)
		if newOffset == offset {
			return nil, fmt.Errorf("could not decode will topic")
		}
		newPayload.Write(encodeString(willTopic))
		offset = newOffset

		// Will Message
		if offset+2 > len(payload) {
			return nil, fmt.Errorf("missing will message length")
		}
		msgLen := int(payload[offset])<<8 | int(payload[offset+1])
		offset += 2
		if offset+msgLen > len(payload) {
			return nil, fmt.Errorf("missing will message body")
		}
		willMessage := payload[offset : offset+msgLen]
		newPayload.Write(encodeString(string(willMessage))) // Will Message is a binary payload, encodeString handles length
		offset += msgLen
	}

	// --- New Credentials ---
	newFlags := originalFlags
	// Unset original user/pass flags
	newFlags &^= 0xC0 // 1100 0000

	if newUsername != "" {
		newFlags |= 0x80 // Set User Name Flag
		newPayload.Write(encodeString(newUsername))
	}
	if newPassword != "" {
		newFlags |= 0x40 // Set Password Flag
		newPayload.Write(encodeString(newPassword))
	}

	// --- Reassembly ---
	var finalPacket bytes.Buffer
	finalPacket.WriteByte(0x10) // Packet Type CONNECT

	variableHeader := append(variableHeaderPrefix, newFlags)
	remainingLength := len(variableHeader) + newPayload.Len()
	finalPacket.Write(encodeLength(remainingLength))
	finalPacket.Write(variableHeader)
	finalPacket.Write(newPayload.Bytes())

	return finalPacket.Bytes(), nil
}

// Helper to check if a string is mostly printable ASCII
func isMostlyPrintable(data []byte) bool {
	s := string(data)
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func printProxyUsage() {
	fmt.Println("MQTT Interception Proxy")
	fmt.Println("Authors: Jorge Alvarez (poro@versprite.com) and Mario Vilas (marito@versprite.com)\n")
	fmt.Println("Usage: mqtt_mitm_proxy [flags]")
	fmt.Println("\nFlags:")
	fmt.Println("  --listen <addr:port>      Address and port for the proxy to listen on (default: :8883)")
	fmt.Println("  --broker <addr:port>      Address and port of the remote MQTT broker (default: test.mosquitto.org:8883)")
	fmt.Println("  --proxy-cert <path>       Path to the proxy's server public certificate file. If empty, listens for plaintext.")
	fmt.Println("  --proxy-key <path>        Path to the proxy's server private key file. If empty, listens for plaintext.")
	fmt.Println("  --client-cert <path>      Path to the client's public certificate file. If empty, connects via plaintext.")
	fmt.Println("  --client-key <path>       Path to the client's private key file for authenticating with the broker")
	fmt.Println("  --user <username>         Username for MQTT authentication (replaces client's username if any)")
	fmt.Println("  --pass <password>         Password for MQTT authentication (replaces client's password if any)")
	fmt.Println("  --verbose                 Enable verbose logging for detailed analysis.")
	fmt.Println("  --no-color                Disable colored output (useful for piping to files).")
	fmt.Fprintf(os.Stderr, "  --key <file>:        Path to a private key file (PEM format) for verifying JWT signatures. Can be specified multiple times.\n")
	fmt.Fprintf(os.Stderr, "\n")
}

func main() {
	log.SetFlags(0)

	flag.Usage = printProxyUsage
	flag.StringVar(&proxyListenAddr, "listen", ":8883", "Address and port for the proxy to listen on (e.g., '127.0.0.1:8883')")
	flag.StringVar(&brokerAddr, "broker", "test.mosquitto.org:8883", "Address and port of the remote MQTT broker. Use an IP address to avoid DNS loops.")
	flag.StringVar(&proxyCertFile, "proxy-cert", "", "Path to the proxy's server public certificate file. If empty, listens for plaintext.")
	flag.StringVar(&proxyKeyFile, "proxy-key", "", "Path to the proxy's server private key file. If empty, listens for plaintext.")
	flag.StringVar(&clientCertFile, "client-cert", "", "Path to the client's public certificate file. If empty, connects via plaintext.")
	flag.StringVar(&clientKeyFile, "client-key", "", "Path to the client's private key file for authenticating with the broker")
	flag.StringVar(&username, "user", "", "Username for MQTT authentication (replaces client's username if any)")
	flag.StringVar(&password, "pass", "", "Password for MQTT authentication (replaces client's password if any)")
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging for detailed analysis.")
	flag.BoolVar(&noColor, "no-color", false, "Disable colorized output")
	flag.Var(&jwtVerifyKeys, "key", "Path to a private key file (PEM format) for verifying JWT signatures. Can be specified multiple times.")

	flag.Parse()

	if noColor {
		clientToServerColor = ""
		serverToClientColor = ""
		packetTypeColor     = ""
		topicColor          = ""
		payloadColor        = ""
		// Also reset color values to avoid stray resets or manually added colors
		colorReset         = ""
		colorReset         = ""
		colorRed           = ""
		colorGreen         = ""
		colorYellow        = ""
		colorBlue          = ""
		colorPurple        = ""
		colorCyan          = ""
		colorWhite         = ""
		colorBold          = ""
		colorBrightMagenta = ""
		colorBrightWhite   = ""
	}

	// Load JWT verification keys
	if len(jwtVerifyKeys) > 0 {
		log.Println("Loading JWT verification keys...")
		for _, keyPath := range jwtVerifyKeys {
			pem, err := os.ReadFile(keyPath)
			if err != nil {
				log.Printf("  [!] Failed to read key file %s: %v", keyPath, err)
				continue
			}

			key, err := jwt.ParseRSAPrivateKeyFromPEM(pem)
			if err == nil {
				loadedJWTKeys = append(loadedJWTKeys, key)
				log.Printf("  [+] Loaded RSA key from %s", keyPath)
				continue
			}

			key2, err := jwt.ParseECPrivateKeyFromPEM(pem)
			if err == nil {
				loadedJWTKeys = append(loadedJWTKeys, key2)
				log.Printf("  [+] Loaded ECDSA key from %s", keyPath)
				continue
			}
			log.Printf("  [!] Failed to parse key from %s (supports RSA/ECDSA PEM)", keyPath)
		}
	}

	log.Printf("MQTT MITM proxy listening on %s%s%s", payloadColor, proxyListenAddr, colorReset)
	log.Printf("Targeting broker: %s%s%s", payloadColor, brokerAddr, colorReset)

	ln, err := net.Listen("tcp", proxyListenAddr)
	if err != nil {
		log.Fatalf("[!] Failed to listen: %v", err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[!] Accept error: %v", err)
			continue
		}
		go handleConnection(conn, username, password)
	}
}

// --- Payload Processing ---

func processPayload(data []byte) {
	// Trim whitespace as some formats are sensitive to it
	trimmedData := bytes.TrimSpace(data)
	if len(trimmedData) == 0 {
		fmt.Println("    (empty payload)")
		return
	}

	if tryJWT(trimmedData) {
		return
	}
	if tryPrettifyJSON(trimmedData) {
		return
	}
	if tryPrettifyXML(trimmedData) {
		return
	}
	if tryMessagePack(trimmedData) {
		return
	}
	if tryPrettifyYAML(trimmedData) {
		return
	}
	if tryBase64(trimmedData) {
		return
	}

	handlePlaintextOrHex(data) // Use original data for final fallback
}

func tryJWT(data []byte) bool {
	tokenString := string(data)
	if !strings.Contains(tokenString, ".") {
		return false
	}

	// Basic parse to decode header and claims without verification first
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return false // Not a JWT
	}

	fmt.Printf("    %sDetected Format: JWT%s\n", packetTypeColor, colorReset)

	// Pretty print header
	headerJSON, _ := json.MarshalIndent(token.Header, "    ", "  ")
	fmt.Printf("    %sHeader:%s\n%s\n", topicColor, colorReset, string(headerJSON))

	// Pretty print claims
	claimsJSON, _ := json.MarshalIndent(token.Claims, "    ", "  ")
	fmt.Printf("    %sClaims:%s\n%s\n", topicColor, colorReset, string(claimsJSON))

	// If keys are provided, verify signature
	if len(loadedJWTKeys) > 0 {
		fmt.Printf("    %sSignature Verification:%s\n", topicColor, colorReset)
		verified := false
		for i, key := range loadedJWTKeys {

			// Re-parse the token, this time with the key for verification
			_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				// The key is the private key, but for verification we need the public key.
				switch k := key.(type) {
				case *rsa.PrivateKey:
					return &k.PublicKey, nil
				case *ecdsa.PrivateKey:
					return &k.PublicKey, nil
				default:
					return nil, fmt.Errorf("unsupported key type: %T", k)
				}
			})

			keyIdentifier := fmt.Sprintf("key #%d", i+1)
			if i < len(jwtVerifyKeys) {
				keyIdentifier = jwtVerifyKeys[i]
			}

			if err == nil {
				fmt.Printf("      %s[%s] SUCCESS%s\n", colorGreen, keyIdentifier, colorReset)
				verified = true
				break // Stop on first success
			} else {
				fmt.Printf("      %s[%s] FAILED: %v%s\n", colorRed, keyIdentifier, err, colorReset)
			}
		}
		if !verified {
			fmt.Printf("      %sSignature not valid with any of the provided keys.%s\n", colorRed, colorReset)
		}
	} else if len(jwtVerifyKeys) > 0 {
		fmt.Printf("    %sSignature: %s(not verified, no valid keys were loaded)%s\n", topicColor, colorReset, colorReset)
	} else {
		fmt.Printf("    %sSignature: %s(not verified, no key provided)%s\n", topicColor, colorReset, colorReset)
	}

	return true
}

func tryPrettifyJSON(data []byte) bool {
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return false
	}

	// Avoid flagging simple strings, numbers, or booleans as a JSON object
	switch obj.(type) {
	case string, float64, bool:
		return false
	}

	fmt.Printf("    %sDetected Format: JSON%s\n", packetTypeColor, colorReset)
	pretty, err := json.MarshalIndent(obj, "    ", "  ")
	if err != nil {
		// This is unlikely to happen if unmarshaling succeeded
		fmt.Printf("      Could not re-marshal JSON: %v\n", err)
		return true // It was valid JSON, so we return true
	}

	fmt.Println(string(pretty))
	return true
}

func tryMessagePack(data []byte) bool {
	var v interface{}
	if err := msgpack.Unmarshal(data, &v); err != nil {
		return false
	}
	fmt.Printf("    %sDetected Format: MessagePack%s (decoded and shown as JSON)\n", packetTypeColor, colorReset)
	pretty, err := json.MarshalIndent(v, "    ", "  ")
	if err != nil {
		// This should not happen if unmarshal to interface worked
		fmt.Printf("      Could not convert to JSON: %v\n", err)
		return true
	}
	fmt.Println(string(pretty))
	return true
}

func tryBase64(data []byte) bool {
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		// Try URL encoding as a fallback
		decoded, err = base64.URLEncoding.DecodeString(string(data))
		if err != nil {
			return false
		}
	}

	// It's base64, but only process it if the decoded content is not the same as the original
	// or if it's not printable (to avoid decoding simple printable strings that happen to be valid base64)
	if !isMostlyPrintable(data) || !bytes.Equal(data, decoded) {
		fmt.Printf("    %sDetected Format: Base64%s\n", packetTypeColor, colorReset)
		fmt.Printf("    %s--- Begin Decoded Base64 ---%s\n", topicColor, colorReset)
		processPayload(decoded) // Recursive call
		fmt.Printf("    %s--- End Decoded Base64 ---%s\n", topicColor, colorReset)
		return true
	}

	return false
}

func tryPrettifyXML(data []byte) bool {
	if !bytes.HasPrefix(data, []byte("<")) {
		return false
	}
	var out bytes.Buffer
	decoder := xml.NewDecoder(bytes.NewReader(data))
	encoder := xml.NewEncoder(&out)
	encoder.Indent("    ", "  ")
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false // Not valid XML
		}
		if err := encoder.EncodeToken(tok); err != nil {
			return false // Should not happen
		}
	}
	if err := encoder.Flush(); err != nil {
		return false
	}

	fmt.Printf("    %sDetected Format: XML%s\n", packetTypeColor, colorReset)
	fmt.Println(out.String())
	return true
}

func tryPrettifyYAML(data []byte) bool {
	var v interface{}
	if err := yaml.Unmarshal(data, &v); err != nil {
		return false
	}

	// Check for simple strings that can be parsed as YAML but are not maps or slices
	if _, ok := v.(string); ok && !strings.Contains(string(data), "\n") {
		return false
	}

	fmt.Printf("    %sDetected Format: YAML%s\n", packetTypeColor, colorReset)
	out, err := yaml.Marshal(v) // yaml.Marshal provides good enough formatting
	if err != nil {
		return false
	}
	// Indent for display
	indented := "    " + strings.ReplaceAll(string(out), "\n", "\n    ")
	fmt.Println(strings.TrimRight(indented, " "))
	return true
}

func handlePlaintextOrHex(data []byte) {
	if isMostlyPrintable(data) {
		fmt.Printf("    %sDetected Format: Plaintext%s\n", packetTypeColor, colorReset)
		// Indent the text for display
		indented := "    " + strings.ReplaceAll(string(data), "\n", "\n    ")
		fmt.Println(indented)
	} else {
		fmt.Printf("    %sDetected Format: Binary Data%s\n", packetTypeColor, colorReset)
		fmt.Print(hex.Dump(data))
	}
}
