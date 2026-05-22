/*
 * MQTT Interception Proxy
 * Authors: Jorge Alvarez (poro@versprite.com) and Mario Vilas (marito@versprite.com)
 * Released under BSD 3-clause license
 */

package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // G501: intentionally exposed to JS crypto.hash for legacy/interop.
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // G505: intentionally exposed to JS crypto.hash / HMAC.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jhump/protoreflect/desc"            //nolint:staticcheck // SA1019: v1 protobuf API pending migration to google.golang.org/protobuf.
	"github.com/jhump/protoreflect/desc/protoparse" //nolint:staticcheck // SA1019: protoparse wrapper; migration to protocompile is non-trivial.
	"github.com/jhump/protoreflect/dynamic"         //nolint:staticcheck // SA1019: dynamic messages for v1 descriptors.
	"github.com/vmihailenco/msgpack/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
	"gopkg.in/yaml.v3"

	"github.com/amazon-ion/ion-go/ion"
	"github.com/brightcove/playback_go-smile/smile"
	"github.com/dop251/goja"
	"github.com/jmank88/ubjson"
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

var propertyNames = map[int]string{
	0x01: "Payload Format Indicator",
	0x02: "Message Expiry Interval",
	0x03: "Content Type",
	0x08: "Response Topic",
	0x09: "Correlation Data",
	0x0B: "Subscription Identifier",
	0x11: "Session Expiry Interval",
	0x12: "Assigned Client Identifier",
	0x13: "Server Keep Alive",
	0x15: "Authentication Method",
	0x16: "Authentication Data",
	0x17: "Request Problem Information",
	0x18: "Will Delay Interval",
	0x19: "Request Response Information",
	0x1A: "Response Information",
	0x1C: "Server Reference",
	0x1F: "Reason String",
	0x21: "Receive Maximum",
	0x22: "Topic Alias Maximum",
	0x23: "Topic Alias",
	0x24: "Maximum QoS",
	0x25: "Retain Available",
	0x26: "User Property",
	0x27: "Maximum Packet Size",
	0x28: "Wildcard Subscription Available",
	0x29: "Subscription Identifier Available",
	0x2A: "Shared Subscription Available",
}

// ANSI color codes
var (
	colorReset         = "\033[0m"
	colorRed           = "\033[31m"
	colorGreen         = "\033[32m"
	colorYellow        = "\033[33m"
	colorBlue          = "\033[34m" //nolint:unused // reserved for future CLI styling
	colorPurple        = "\033[35m" //nolint:unused // reserved for future CLI styling
	colorCyan          = "\033[36m"
	colorWhite         = "\033[37m" //nolint:unused // reserved for future CLI styling
	colorBold          = "\033[1m"  //nolint:unused // reserved for future CLI styling
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

// Set at link time via: -ldflags "-X main.version=..." (see Makefile). Default for plain go build.
var version = "dev"

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

	verbose     bool
	vShorthand  bool // for -v alias
	showVersion bool

	jwtVerifyKeys      multiStringFlag
	loadedJWTKeys      []interface{}
	protoPaths         multiStringFlag
	messageDescriptors []*desc.MessageDescriptor
)

// Scripting engine
var (
	scriptPath string
	jsEngine   *ScriptEngine
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

// --- Scripting Engine ---

type ScriptEngine struct {
	vm             *goja.Runtime
	handlePacket   goja.Callable
	analyzePayload goja.Callable
}

func mustRuntimeSet(vm *goja.Runtime, name string, val interface{}) {
	if err := vm.Set(name, val); err != nil {
		panic(fmt.Errorf("goja runtime set %q: %w", name, err))
	}
}

func mustObjectSet(obj *goja.Object, name string, val interface{}) {
	if err := obj.Set(name, val); err != nil {
		panic(fmt.Errorf("goja object set %q: %w", name, err))
	}
}

func newScriptEngine(scriptPath string) (*ScriptEngine, error) {
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("could not read script file: %w", err)
	}

	vm := goja.New()

	// Expose console.log to the script
	mustRuntimeSet(vm, "console", map[string]interface{}{
		"log": func(args ...interface{}) {
			var parts []string
			for _, arg := range args {
				parts = append(parts, fmt.Sprintf("%v", arg))
			}
			log.Println(strings.Join(parts, " "))
		},
	})

	// Simplistic implementation of "require" to provide a more CommonJS-like environment
	mustRuntimeSet(vm, "require", func(call goja.FunctionCall) goja.Value {
		filename := call.Argument(0).String()
		content, err := os.ReadFile(filename)
		if err != nil {
			panic(err)
		}
		value, err := vm.RunString(string(content))
		if err != nil {
			panic(err)
		}
		return value
	})

	// Polyfill TextDecoder and TextEncoder to provide a more browser-like environment
	mustRuntimeSet(vm, "TextDecoder", func(call goja.ConstructorCall) *goja.Object {
		// We'll ignore the encoding argument and assume UTF-8, which is the default.
		mustObjectSet(call.This, "decode", func(v goja.Value) (string, error) {
			var buffer []byte
			if ab, ok := v.Export().(goja.ArrayBuffer); ok {
				buffer = ab.Bytes()
			} else {
				// It could be a TypedArray view like Uint8Array
				if tobj, ok := v.(*goja.Object); ok {
					if bufVal := tobj.Get("buffer"); bufVal != nil {
						if ab, ok := bufVal.Export().(goja.ArrayBuffer); ok {
							byteOffset := tobj.Get("byteOffset").ToInteger()
							byteLength := tobj.Get("byteLength").ToInteger()
							srcBuffer := ab.Bytes()
							if byteOffset > int64(len(srcBuffer)) {
								// As per spec, throw RangeError
								panic(vm.NewGoError(fmt.Errorf("byteOffset is out of range")))
							}
							end := byteOffset + byteLength
							if end > int64(len(srcBuffer)) {
								panic(vm.NewGoError(fmt.Errorf("byteLength is out of range")))
							}
							buffer = srcBuffer[byteOffset:end]
						}
					}
				}
			}

			if buffer == nil {
				return "", fmt.Errorf("TextDecoder.decode: argument must be an ArrayBuffer or a TypedArray view")
			}
			return string(buffer), nil
		})
		return nil
	})

	mustRuntimeSet(vm, "TextEncoder", func(call goja.ConstructorCall) *goja.Object {
		mustObjectSet(call.This, "encode", func(s string) goja.Value {
			return vm.ToValue(vm.NewArrayBuffer([]byte(s)))
		})
		return nil
	})

	// Polyfill btoa and atob for Base64 encoding/decoding
	mustRuntimeSet(vm, "btoa", func(s string) (string, error) {
		for _, r := range s {
			if r > 0xff {
				return "", fmt.Errorf("InvalidCharacterError: String contains characters outside of the Latin1 range")
			}
		}
		return base64.StdEncoding.EncodeToString([]byte(s)), nil
	})

	mustRuntimeSet(vm, "atob", func(s string) (string, error) {
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return "", fmt.Errorf("InvalidCharacterError: The string to be decoded is not correctly encoded")
		}
		return string(decoded), nil
	})

	// --- Crypto Module ---
	cryptoObj := vm.NewObject()

	// Helper to extract bytes from a JS value (string, ArrayBuffer, or TypedArray)
	getBytesFromValue := func(vm *goja.Runtime, v goja.Value) ([]byte, error) {
		if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
			return nil, fmt.Errorf("value is null or undefined")
		}
		if str, ok := v.(goja.String); ok {
			return []byte(str.String()), nil
		}
		if obj, ok := v.(*goja.Object); ok {
			if ab, ok := obj.Export().(goja.ArrayBuffer); ok {
				return ab.Bytes(), nil
			}
			if bufVal := obj.Get("buffer"); bufVal != nil {
				if ab, ok := bufVal.Export().(goja.ArrayBuffer); ok {
					byteOffset := obj.Get("byteOffset").ToInteger()
					byteLength := obj.Get("byteLength").ToInteger()
					srcBuffer := ab.Bytes()
					if byteOffset < 0 || byteOffset > int64(len(srcBuffer)) {
						return nil, fmt.Errorf("byteOffset is out of range")
					}
					end := byteOffset + byteLength
					if end > int64(len(srcBuffer)) {
						return nil, fmt.Errorf("byteLength is out of range")
					}
					return srcBuffer[byteOffset:end], nil
				}
			}
		}
		return nil, fmt.Errorf("value must be a string, ArrayBuffer, or a TypedArray view")
	}

	// Helper for getting a hash implementation from a string name.
	getHasher := func(name string) (func() hash.Hash, crypto.Hash, error) {
		switch strings.ToLower(name) {
		case "md5":
			return md5.New, crypto.MD5, nil //#nosec G401 - factory for JS crypto bridge.
		case "sha1":
			return sha1.New, crypto.SHA1, nil //#nosec G401 - factory for JS crypto bridge.
		case "sha256":
			return sha256.New, crypto.SHA256, nil
		case "sha512":
			return sha512.New, crypto.SHA512, nil
		default:
			return nil, 0, fmt.Errorf("unsupported hash algorithm: %s", name)
		}
	}

	// Helper to parse RSA and ECDSA keys from PEM format.
	parseRsaPrivateKeyFromPEM := func(pemBytes []byte) (*rsa.PrivateKey, error) {
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if rsaKey, ok := key.(*rsa.PrivateKey); ok {
				return rsaKey, nil
			}
			return nil, fmt.Errorf("key is not an RSA private key")
		}
		return nil, fmt.Errorf("failed to parse RSA private key")
	}
	parseRsaPublicKeyFromPEM := func(pemBytes []byte) (*rsa.PublicKey, error) {
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		if rsaKey, ok := pub.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("key is not an RSA public key")
	}
	parseEcdsaPrivateKeyFromPEM := func(pemBytes []byte) (*ecdsa.PrivateKey, error) {
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
				return ecdsaKey, nil
			}
			return nil, fmt.Errorf("key is not an ECDSA private key")
		}
		return nil, fmt.Errorf("failed to parse ECDSA private key")
	}
	parseEcdsaPublicKeyFromPEM := func(pemBytes []byte) (*ecdsa.PublicKey, error) {
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		if ecdsaKey, ok := pub.(*ecdsa.PublicKey); ok {
			return ecdsaKey, nil
		}
		return nil, fmt.Errorf("key is not an ECDSA public key")
	}

	// crypto.hash(algorithm, data, [encoding])
	mustObjectSet(cryptoObj, "hash", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			panic(vm.NewGoError(fmt.Errorf("hash requires at least 2 arguments: algorithm and data")))
		}
		algorithm := strings.ToLower(call.Argument(0).String())
		data, err := getBytesFromValue(vm, call.Argument(1))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("hash data: %w", err)))
		}

		var h hash.Hash
		switch algorithm {
		case "md5":
			h = md5.New() //#nosec G401 - exposed to JS crypto.hash for legacy algorithms.
		case "sha1":
			h = sha1.New() //#nosec G401 - exposed to JS crypto.hash for legacy algorithms.
		case "sha256":
			h = sha256.New()
		case "sha512":
			h = sha512.New()
		default:
			panic(vm.NewGoError(fmt.Errorf("unsupported hash algorithm: %s", algorithm)))
		}
		h.Write(data)
		digest := h.Sum(nil)

		if len(call.Arguments) > 2 {
			enc := strings.ToLower(call.Argument(2).String())
			switch enc {
			case "hex":
				return vm.ToValue(hex.EncodeToString(digest))
			case "base64":
				return vm.ToValue(base64.StdEncoding.EncodeToString(digest))
			default:
				panic(vm.NewGoError(fmt.Errorf("unsupported encoding: %s", enc)))
			}
		}
		return vm.ToValue(vm.NewArrayBuffer(digest))
	})

	// crypto.hmac(algorithm, key, data, [encoding])
	mustObjectSet(cryptoObj, "hmac", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 3 {
			panic(vm.NewGoError(fmt.Errorf("hmac requires at least 3 arguments: algorithm, key, and data")))
		}
		algorithm := strings.ToLower(call.Argument(0).String())
		key, err := getBytesFromValue(vm, call.Argument(1))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("hmac key: %w", err)))
		}
		data, err := getBytesFromValue(vm, call.Argument(2))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("hmac data: %w", err)))
		}

		var h func() hash.Hash
		switch algorithm {
		case "sha1":
			h = sha1.New //#nosec G401 - exposed to JS crypto.hmac.
		case "sha256":
			h = sha256.New
		case "sha512":
			h = sha512.New
		default:
			panic(vm.NewGoError(fmt.Errorf("unsupported hmac algorithm: %s", algorithm)))
		}

		mac := hmac.New(h, key)
		mac.Write(data)
		sig := mac.Sum(nil)

		if len(call.Arguments) > 3 {
			enc := strings.ToLower(call.Argument(3).String())
			switch enc {
			case "hex":
				return vm.ToValue(hex.EncodeToString(sig))
			case "base64":
				return vm.ToValue(base64.StdEncoding.EncodeToString(sig))
			default:
				panic(vm.NewGoError(fmt.Errorf("unsupported encoding: %s", enc)))
			}
		}
		return vm.ToValue(vm.NewArrayBuffer(sig))
	})

	// crypto.encrypt(algorithm, key, iv, plaintext)
	mustObjectSet(cryptoObj, "encrypt", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 4 {
			panic(vm.NewGoError(fmt.Errorf("encrypt requires 4 arguments: algorithm, key, iv, and plaintext")))
		}
		algorithm := strings.ToLower(call.Argument(0).String())
		key, _ := getBytesFromValue(vm, call.Argument(1))
		iv, _ := getBytesFromValue(vm, call.Argument(2))
		plaintext, _ := getBytesFromValue(vm, call.Argument(3))

		block, err := aes.NewCipher(key)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("failed to create cipher: %w", err)))
		}

		var aead cipher.AEAD
		switch algorithm {
		case "aes-128-gcm", "aes-256-gcm":
			aead, err = cipher.NewGCM(block)
			if err != nil {
				panic(vm.NewGoError(fmt.Errorf("failed to create GCM: %w", err)))
			}
		default:
			panic(vm.NewGoError(fmt.Errorf("unsupported encryption algorithm: %s. Try 'aes-128-gcm' or 'aes-256-gcm'", algorithm)))
		}

		if len(iv) != aead.NonceSize() {
			panic(vm.NewGoError(fmt.Errorf("incorrect nonce/iv length: got %d, want %d", len(iv), aead.NonceSize())))
		}

		sealed := aead.Seal(nil, iv, plaintext, nil)
		ciphertext := sealed[:len(sealed)-aead.Overhead()]
		authTag := sealed[len(sealed)-aead.Overhead():]

		result := vm.NewObject()
		mustObjectSet(result, "ciphertext", vm.NewArrayBuffer(ciphertext))
		mustObjectSet(result, "authTag", vm.NewArrayBuffer(authTag))
		return result
	})

	// crypto.decrypt(algorithm, key, iv, authTag, ciphertext)
	mustObjectSet(cryptoObj, "decrypt", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 5 {
			panic(vm.NewGoError(fmt.Errorf("decrypt requires 5 arguments: algorithm, key, iv, authTag, and ciphertext")))
		}
		algorithm := strings.ToLower(call.Argument(0).String())
		key, _ := getBytesFromValue(vm, call.Argument(1))
		iv, _ := getBytesFromValue(vm, call.Argument(2))
		authTag, _ := getBytesFromValue(vm, call.Argument(3))
		ciphertext, _ := getBytesFromValue(vm, call.Argument(4))

		block, err := aes.NewCipher(key)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("failed to create cipher: %w", err)))
		}

		var aead cipher.AEAD
		switch algorithm {
		case "aes-128-gcm", "aes-256-gcm":
			aead, err = cipher.NewGCM(block)
			if err != nil {
				panic(vm.NewGoError(fmt.Errorf("failed to create GCM: %w", err)))
			}
		default:
			panic(vm.NewGoError(fmt.Errorf("unsupported encryption algorithm: %s", algorithm)))
		}

		if len(iv) != aead.NonceSize() {
			panic(vm.NewGoError(fmt.Errorf("incorrect nonce/iv length: got %d, want %d", len(iv), aead.NonceSize())))
		}

		payload := append(ciphertext, authTag...)
		plaintext, err := aead.Open(nil, iv, payload, nil)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("decryption failed (authentication error): %w", err)))
		}
		return vm.ToValue(vm.NewArrayBuffer(plaintext))
	})

	// --- Public Key Crypto ---

	// crypto.rsaEncrypt(publicKey, hash, plaintext)
	mustObjectSet(cryptoObj, "rsaEncrypt", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 3 {
			panic(vm.NewGoError(fmt.Errorf("rsaEncrypt requires 3 arguments: publicKey, hash, and plaintext")))
		}
		pubKeyPEM, err := getBytesFromValue(vm, call.Argument(0))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("rsaEncrypt publicKey: %w", err)))
		}
		hashName := call.Argument(1).String()
		plaintext, err := getBytesFromValue(vm, call.Argument(2))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("rsaEncrypt plaintext: %w", err)))
		}

		pubKey, err := parseRsaPublicKeyFromPEM(pubKeyPEM)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("invalid public key: %w", err)))
		}

		hashFn, _, err := getHasher(hashName)
		if err != nil {
			panic(vm.NewGoError(err))
		}

		ciphertext, err := rsa.EncryptOAEP(hashFn(), rand.Reader, pubKey, plaintext, nil)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("RSA encryption failed: %w", err)))
		}
		return vm.ToValue(vm.NewArrayBuffer(ciphertext))
	})

	// crypto.rsaDecrypt(privateKey, hash, ciphertext)
	mustObjectSet(cryptoObj, "rsaDecrypt", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 3 {
			panic(vm.NewGoError(fmt.Errorf("rsaDecrypt requires 3 arguments: privateKey, hash, and ciphertext")))
		}
		privKeyPEM, err := getBytesFromValue(vm, call.Argument(0))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("rsaDecrypt privateKey: %w", err)))
		}
		hashName := call.Argument(1).String()
		ciphertext, err := getBytesFromValue(vm, call.Argument(2))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("rsaDecrypt ciphertext: %w", err)))
		}

		privKey, err := parseRsaPrivateKeyFromPEM(privKeyPEM)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("invalid private key: %w", err)))
		}

		hashFn, _, err := getHasher(hashName)
		if err != nil {
			panic(vm.NewGoError(err))
		}

		plaintext, err := rsa.DecryptOAEP(hashFn(), rand.Reader, privKey, ciphertext, nil)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("RSA decryption failed: %w", err)))
		}
		return vm.ToValue(vm.NewArrayBuffer(plaintext))
	})

	// crypto.rsaSign(privateKey, hash, data)
	mustObjectSet(cryptoObj, "rsaSign", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 3 {
			panic(vm.NewGoError(fmt.Errorf("rsaSign requires 3 arguments: privateKey, hash, and data")))
		}
		privKeyPEM, err := getBytesFromValue(vm, call.Argument(0))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("rsaSign privateKey: %w", err)))
		}
		hashName := call.Argument(1).String()
		data, err := getBytesFromValue(vm, call.Argument(2))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("rsaSign data: %w", err)))
		}

		privKey, err := parseRsaPrivateKeyFromPEM(privKeyPEM)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("invalid private key: %w", err)))
		}

		hashFn, cryptoHash, err := getHasher(hashName)
		if err != nil {
			panic(vm.NewGoError(err))
		}

		h := hashFn()
		h.Write(data)
		hashed := h.Sum(nil)

		sig, err := rsa.SignPSS(rand.Reader, privKey, cryptoHash, hashed, nil)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("RSA PSS signing failed: %w", err)))
		}
		return vm.ToValue(vm.NewArrayBuffer(sig))
	})

	// crypto.rsaVerify(publicKey, hash, data, signature)
	mustObjectSet(cryptoObj, "rsaVerify", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 4 {
			panic(vm.NewGoError(fmt.Errorf("rsaVerify requires 4 arguments: publicKey, hash, data, and signature")))
		}
		pubKeyPEM, err := getBytesFromValue(vm, call.Argument(0))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("rsaVerify publicKey: %w", err)))
		}
		hashName := call.Argument(1).String()
		data, err := getBytesFromValue(vm, call.Argument(2))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("rsaVerify data: %w", err)))
		}
		signature, err := getBytesFromValue(vm, call.Argument(3))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("rsaVerify signature: %w", err)))
		}

		pubKey, err := parseRsaPublicKeyFromPEM(pubKeyPEM)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("invalid public key: %w", err)))
		}

		hashFn, cryptoHash, err := getHasher(hashName)
		if err != nil {
			panic(vm.NewGoError(err))
		}

		h := hashFn()
		h.Write(data)
		hashed := h.Sum(nil)

		err = rsa.VerifyPSS(pubKey, cryptoHash, hashed, signature, nil)
		return vm.ToValue(err == nil)
	})

	// crypto.ecdsaSign(privateKey, hash, data)
	mustObjectSet(cryptoObj, "ecdsaSign", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 3 {
			panic(vm.NewGoError(fmt.Errorf("ecdsaSign requires 3 arguments: privateKey, hash, and data")))
		}
		privKeyPEM, err := getBytesFromValue(vm, call.Argument(0))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("ecdsaSign privateKey: %w", err)))
		}
		hashName := call.Argument(1).String()
		data, err := getBytesFromValue(vm, call.Argument(2))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("ecdsaSign data: %w", err)))
		}

		privKey, err := parseEcdsaPrivateKeyFromPEM(privKeyPEM)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("invalid private key: %w", err)))
		}

		hashFn, _, err := getHasher(hashName)
		if err != nil {
			panic(vm.NewGoError(err))
		}

		h := hashFn()
		h.Write(data)
		hashed := h.Sum(nil)

		sig, err := ecdsa.SignASN1(rand.Reader, privKey, hashed)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("ECDSA signing failed: %w", err)))
		}
		return vm.ToValue(vm.NewArrayBuffer(sig))
	})

	// crypto.ecdsaVerify(publicKey, hash, data, signature)
	mustObjectSet(cryptoObj, "ecdsaVerify", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 4 {
			panic(vm.NewGoError(fmt.Errorf("ecdsaVerify requires 4 arguments: publicKey, hash, data, and signature")))
		}
		pubKeyPEM, err := getBytesFromValue(vm, call.Argument(0))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("ecdsaVerify publicKey: %w", err)))
		}
		hashName := call.Argument(1).String()
		data, err := getBytesFromValue(vm, call.Argument(2))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("ecdsaVerify data: %w", err)))
		}
		signature, err := getBytesFromValue(vm, call.Argument(3))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("ecdsaVerify signature: %w", err)))
		}

		pubKey, err := parseEcdsaPublicKeyFromPEM(pubKeyPEM)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("invalid public key: %w", err)))
		}

		hashFn, _, err := getHasher(hashName)
		if err != nil {
			panic(vm.NewGoError(err))
		}

		h := hashFn()
		h.Write(data)
		hashed := h.Sum(nil)

		return vm.ToValue(ecdsa.VerifyASN1(pubKey, hashed, signature))
	})

	// crypto.ecdh(privateKey, publicKey)
	mustObjectSet(cryptoObj, "ecdh", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			panic(vm.NewGoError(fmt.Errorf("ecdh requires 2 arguments: privateKey and publicKey")))
		}
		privKeyPEM, err := getBytesFromValue(vm, call.Argument(0))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("ecdh privateKey: %w", err)))
		}
		pubKeyPEM, err := getBytesFromValue(vm, call.Argument(1))
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("ecdh publicKey: %w", err)))
		}

		privKey, err := parseEcdsaPrivateKeyFromPEM(privKeyPEM)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("invalid private key: %w", err)))
		}

		pubKey, err := parseEcdsaPublicKeyFromPEM(pubKeyPEM)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("invalid public key: %w", err)))
		}

		if privKey.Curve != pubKey.Curve {
			panic(vm.NewGoError(fmt.Errorf("keys are not on the same curve")))
		}

		var c ecdh.Curve
		switch privKey.Curve {
		case elliptic.P256():
			c = ecdh.P256()
		case elliptic.P384():
			c = ecdh.P384()
		case elliptic.P521():
			c = ecdh.P521()
		default:
			panic(vm.NewGoError(fmt.Errorf("unsupported elliptic curve")))
		}

		ecdhPrivKey, err := c.NewPrivateKey(privKey.D.Bytes()) //nolint:staticcheck // SA1019: bridge ecdsa.PrivateKey to ecdh for shared secret.
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("failed to create ECDH private key: %w", err)))
		}

		pubBytes := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y) //nolint:staticcheck // SA1019: wire format for ecdh.NewPublicKey on same curve.
		ecdhPubKey, err := c.NewPublicKey(pubBytes)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("failed to create ECDH public key from bytes: %w", err)))
		}

		shared, err := ecdhPrivKey.ECDH(ecdhPubKey)
		if err != nil {
			panic(vm.NewGoError(fmt.Errorf("ECDH key exchange failed: %w", err)))
		}

		return vm.ToValue(vm.NewArrayBuffer(shared))
	})

	mustRuntimeSet(vm, "crypto", cryptoObj)

	// Set up a CommonJS-like environment by creating `module` and `exports`
	exports := vm.NewObject()
	module := vm.NewObject()
	mustObjectSet(module, "exports", exports)
	mustRuntimeSet(vm, "module", module)
	mustRuntimeSet(vm, "exports", exports) // Allow using 'exports.handlePacket = ...' directly

	// Execute the script
	_, err = vm.RunScript(filepath.Base(scriptPath), string(scriptBytes))
	if err != nil {
		return nil, fmt.Errorf("error executing script: %w", err)
	}

	engine := &ScriptEngine{vm: vm}

	// Get exported functions from module.exports
	var exportsObj *goja.Object
	if moduleVal := vm.Get("module"); moduleVal != nil {
		if obj, ok := moduleVal.ToObject(vm).Get("exports").(*goja.Object); ok {
			exportsObj = obj
		}
	}

	// Fallback for scripts that don't use module.exports
	if exportsObj == nil {
		exportsObj = vm.GlobalObject()
	}

	// Get a reference to the handlePacket function
	if handlePacket := exportsObj.Get("handlePacket"); handlePacket != nil && !goja.IsUndefined(handlePacket) && !goja.IsNull(handlePacket) {
		if fn, ok := goja.AssertFunction(handlePacket); ok {
			engine.handlePacket = fn
		}
	}

	// Get a reference to the analyzePayload function
	if analyzePayload := exportsObj.Get("analyzePayload"); analyzePayload != nil && !goja.IsUndefined(analyzePayload) && !goja.IsNull(analyzePayload) {
		if fn, ok := goja.AssertFunction(analyzePayload); ok {
			engine.analyzePayload = fn
		}
	}

	if engine.handlePacket == nil && engine.analyzePayload == nil {
		return nil, fmt.Errorf("script must export at least one of 'handlePacket' or 'analyzePayload'")
	}

	return engine, nil
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
		remainingLength, endPos := decodeVarByteInt(mb.buffer[offset+1:])
		lengthBytes := endPos

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
		return fmt.Sprintf("UNKNOWN(%d)", packetType) // should not happen
	}
}

func decodeVarByteInt(data []byte) (int, int) {
	multiplier := 1
	value := 0
	bytesRead := 0
	for {
		if bytesRead >= len(data) {
			return 0, 0 // Error: not enough data
		}
		encodedByte := data[bytesRead]
		bytesRead++
		value += int(encodedByte&0x7F) * multiplier
		if (encodedByte & 0x80) == 0 {
			break
		}
		if bytesRead >= 4 {
			return 0, 0 // Error: malformed integer, more than 4 bytes
		}
		multiplier *= 128
	}
	return value, bytesRead
}

func decodeLength(data []byte) (int, int) {
	return decodeVarByteInt(data)
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
	binary.BigEndian.PutUint16(encoded, uint16(len(s))) //#nosec G115 - len(s) capped to 65535 above.
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
	remainingLength, headerEnd := decodeLength(data[1:])
	if headerEnd == 0 && remainingLength > 0 { // Should not happen with valid packets
		log.Printf("=== Malformed Packet (bad remaining length) ===")
		return
	}
	headerEnd++ // Account for the first byte

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
	cleanSession := (flags & 0x02) != 0
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

	if protoLevel >= 5 {
		offset = analyzeProperties(payload, offset, "Connect")
	}

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
		if protoLevel >= 5 {
			// Will Properties
			offset = analyzeProperties(payload, offset, "Will")
		}

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
		offset += msgLen //nolint:ineffassign // advance offset for clarity if CONNECT layout gains trailing fields
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
			InsecureSkipVerify: true, //#nosec G402 - MITM proxy terminates TLS to broker; verification is optional for lab use.
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

			// Process packets with script
			finalPackets := make([][]byte, 0, len(packetsToSend))
			for _, packet := range packetsToSend {
				processedPacket, err := applyScriptToPacket(packet, "C→S")
				if err != nil {
					log.Printf("[!] Error applying script to C→S packet: %v", err)
					continue
				}
				if processedPacket != nil {
					finalPackets = append(finalPackets, processedPacket)
				}
			}
			packetsToSend = finalPackets

			// Process packets for analysis
			processMQTTPackets("C→S", packetsToSend)

			// Send all packets
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

		// Process packets with script
		finalPackets := make([][]byte, 0, len(packets))
		for _, packet := range packets {
			processedPacket, err := applyScriptToPacket(packet, "S→C")
			if err != nil {
				log.Printf("[!] Error applying script to S→C packet: %v", err)
				continue
			}
			if processedPacket != nil {
				finalPackets = append(finalPackets, processedPacket)
			}
		}
		packets = finalPackets

		// Process packets for analysis
		processMQTTPackets("S→C", packets)

		// Send all packets
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

// analyzeProperties parses and logs MQTT v5 properties.
// It returns the new offset after parsing all properties.
func analyzeProperties(payload []byte, offset int, context string) int {
	propLen, propLenBytes := decodeVarByteInt(payload[offset:])
	if propLenBytes == 0 && propLen > 0 {
		log.Printf("    [Broken %s Properties: could not read properties length]", context)
		return offset
	}
	propStart := offset + propLenBytes
	propEnd := propStart + propLen

	if propEnd > len(payload) {
		log.Printf("    [Broken %s Properties: length (%d) exceeds packet bounds]", context, propLen)
		return propStart // Return offset after the length, to avoid parsing garbage but still advance
	}

	if propLen > 0 {
		log.Printf("    %s Properties (len %d):", context, propLen)
	}

	currentOffset := propStart
	for currentOffset < propEnd {
		propID, idBytes := decodeVarByteInt(payload[currentOffset:])
		if idBytes == 0 {
			log.Printf("        [Broken Properties: could not read property ID at offset %d]", currentOffset)
			break
		}
		currentOffset += idBytes

		propName, ok := propertyNames[propID]
		if !ok {
			propName = fmt.Sprintf("Unknown Property (0x%X)", propID)
		}

		var valStr string
		var valBytes int
		switch propID {
		case 0x01, 0x17, 0x19, 0x24, 0x25, 0x28, 0x29, 0x2A: // Byte
			if currentOffset+1 > propEnd {
				break
			}
			valStr = fmt.Sprintf("%d", payload[currentOffset])
			valBytes = 1
		case 0x13, 0x21, 0x22, 0x23: // Two-Byte Integer
			if currentOffset+2 > propEnd {
				break
			}
			valStr = fmt.Sprintf("%d", binary.BigEndian.Uint16(payload[currentOffset:]))
			valBytes = 2
		case 0x02, 0x11, 0x18, 0x27: // Four-Byte Integer
			if currentOffset+4 > propEnd {
				break
			}
			valStr = fmt.Sprintf("%d", binary.BigEndian.Uint32(payload[currentOffset:]))
			valBytes = 4
		case 0x0B: // Variable Byte Integer
			val, n := decodeVarByteInt(payload[currentOffset:])
			valStr = fmt.Sprintf("%d", val)
			valBytes = n
		case 0x03, 0x08, 0x12, 0x1A, 0x1C, 0x1F, 0x15: // UTF-8 Encoded String
			val, newOffset := decodeString(payload, currentOffset)
			valStr = fmt.Sprintf("\"%s\"", val)
			valBytes = newOffset - currentOffset
		case 0x09, 0x16: // Binary Data
			// Binary data is encoded like a string (length prefixed)
			val, newOffset := decodeString(payload, currentOffset)
			valStr = fmt.Sprintf("bytes(%d) %s", len(val), hex.EncodeToString([]byte(val)))
			valBytes = newOffset - currentOffset
		case 0x26: // UTF-8 String Pair
			key, n1 := decodeString(payload, currentOffset)
			val, n2 := decodeString(payload, n1)
			valStr = fmt.Sprintf("\"%s\" -> \"%s\"", key, val)
			valBytes = n2 - currentOffset
		default:
			log.Printf("        - %s: [Cannot parse unknown property, skipping remaining properties]", propName)
			currentOffset = propEnd // Bail out
			continue
		}

		if valBytes == 0 || currentOffset+valBytes > propEnd {
			log.Printf("        [Broken Property %s: value overflows properties section]", propName)
			break
		}
		log.Printf("        - %s: %s", propName, valStr)
		currentOffset += valBytes
	}

	return propEnd
}

// rebuildConnectPacket parses an existing CONNECT packet and creates a new one with new credentials.
func rebuildConnectPacket(originalPacket []byte, newUsername, newPassword string) ([]byte, error) {
	// --- Begin Parsing ---
	_, lenBytes := decodeLength(originalPacket[1:])
	headerEnd := 1 + lenBytes
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
		offset += msgLen                                    //nolint:ineffassign // advance offset for clarity if CONNECT payload layout changes
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
	fmt.Println("MQTT Interception Proxy for Zancudo")
	fmt.Println("Authors: Jorge Alvarez (poro@versprite.com) and Mario Vilas (marito@versprite.com)")
	fmt.Println()
	fmt.Println("Usage: zancudo [flags]")
	fmt.Println("\nFlags:")
	fmt.Println("  --listen <addr:port>      Address and port for the proxy to listen on (default: :8883)")
	fmt.Println("  --broker <addr:port>      Address and port of the remote MQTT broker (default: test.mosquitto.org:8883)")
	fmt.Println("  --proxy-cert <path>       Path to the proxy's server public certificate file. If empty, listens for plaintext.")
	fmt.Println("  --proxy-key <path>        Path to the proxy's server private key file. If empty, listens for plaintext.")
	fmt.Println("  --client-cert <path>      Path to the client's public certificate file. If empty, connects via plaintext.")
	fmt.Println("  --client-key <path>       Path to the client's private key file for authenticating with the broker")
	fmt.Println("  --jwt-key <file>          Path to a private key file (PEM format) for verifying JWT signatures. Can be specified multiple times.")
	fmt.Println("  --proto <path>            Path to a .proto file or a directory of .proto files for payload decoding. Can be repeated.")
	fmt.Println("  --user <username>         Username for MQTT authentication (replaces client's username if any)")
	fmt.Println("  --pass <password>         Password for MQTT authentication (replaces client's password if any)")
	fmt.Println("  --verbose, -v             Enable verbose output")
	fmt.Println("  --no-color                Disable colored output (useful for piping to files).")
	fmt.Println("  --script <path>           Path to a JavaScript file for extending the proxy.")
	fmt.Println("  --version                 Print version and exit.")
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
	flag.Var(&jwtVerifyKeys, "jwt-key", "Path to a private key file (PEM format) for verifying JWT signatures. Can be specified multiple times.")
	flag.Var(&protoPaths, "proto", "Path to a .proto file or a directory of .proto files for payload decoding. Can be repeated.")
	flag.StringVar(&username, "user", "", "Username for MQTT authentication (replaces client's username if any)")
	flag.StringVar(&password, "pass", "", "Password for MQTT authentication (replaces client's password if any)")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&vShorthand, "v", false, "Enable verbose output (shorthand)")
	flag.BoolVar(&noColor, "no-color", false, "Disable colorized output")
	flag.StringVar(&scriptPath, "script", "", "Path to a JavaScript file for extending the proxy.")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit.")

	flag.Parse()

	if showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	verbose = verbose || vShorthand

	if noColor {
		colorReset = ""
		clientToServerColor = ""
		serverToClientColor = ""
		packetTypeColor = ""
		topicColor = ""
		payloadColor = ""
		// Also reset color values to avoid stray resets or manually added colors
		colorReset = ""
		colorReset = ""
		colorRed = ""
		colorGreen = ""
		colorYellow = ""
		colorBlue = ""
		colorPurple = ""
		colorCyan = ""
		colorWhite = ""
		colorBold = ""
		colorBrightMagenta = ""
		colorBrightWhite = ""
	}

	if scriptPath != "" {
		var err error
		jsEngine, err = newScriptEngine(scriptPath)
		if err != nil {
			log.Fatalf("[!] Failed to load script: %v", err)
		}
		log.Printf("JavaScript extension loaded from %s", scriptPath)
	}

	if len(protoPaths) > 0 {
		loadProtobufSchemas(protoPaths)
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

func loadProtobufSchemas(paths []string) {
	log.Println("Loading protobuf schemas...")
	protoFileToPath := make(map[string]string)
	var importPaths []string

	for _, p := range paths {
		stat, err := os.Stat(p)
		if err != nil {
			log.Printf("  [!] cannot access proto path %s: %v", p, err)
			continue
		}
		if stat.IsDir() {
			importPaths = append(importPaths, p)
			if err := filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() && strings.HasSuffix(info.Name(), ".proto") {
					rel, err := filepath.Rel(p, path)
					if err != nil {
						return err
					}
					protoFileToPath[rel] = p
				}
				return nil
			}); err != nil {
				log.Printf("  [!] cannot access proto path %s: %v", p, err)
			}
		} else {
			if strings.HasSuffix(p, ".proto") {
				dir := filepath.Dir(p)
				file := filepath.Base(p)
				protoFileToPath[file] = dir
				importPaths = append(importPaths, dir)
			}
		}
	}

	protoFiles := make([]string, 0, len(protoFileToPath))
	for k := range protoFileToPath {
		protoFiles = append(protoFiles, k)
	}

	parser := protoparse.Parser{
		ImportPaths: importPaths,
	}

	fds, err := parser.ParseFiles(protoFiles...)
	if err != nil {
		log.Printf("  [!] Failed to parse .proto files: %v", err)
		return
	}

	for _, fd := range fds {
		for _, md := range fd.GetMessageTypes() {
			messageDescriptors = append(messageDescriptors, md)
			log.Printf("  [+] Loaded message type: %s", md.GetFullyQualifiedName())
		}
	}
	log.Printf("Loaded %d message types from .proto files.", len(messageDescriptors))
}

// --- Payload Processing ---

func processPayload(data []byte) {
	// Handle empty payload first.
	if len(data) == 0 {
		fmt.Println("    (empty payload)")
		return
	}

	// Try scripting engine first
	if jsEngine != nil && jsEngine.analyzePayload != nil {
		jsResult, err := jsEngine.analyzePayload(goja.Undefined(), jsEngine.vm.ToValue(jsEngine.vm.NewArrayBuffer(data)))
		if err != nil {
			log.Printf("[!] Scripted payload analysis failed: %v", err)
		} else if !goja.IsUndefined(jsResult) && !goja.IsNull(jsResult) {
			fmt.Printf("    %s\n", jsResult.String())
			return
		}
	}

	// For text-based formats, trim whitespace.
	trimmedData := bytes.TrimSpace(data)

	// We must check for JSON *before* Ion, because JSON is a subset of the Ion
	// text format. A JSON payload will be successfully parsed by an Ion parser.
	if len(trimmedData) > 0 {
		if tryPrettifyJSON(trimmedData) {
			return
		}
	}

	// Try binary formats that are whitespace-sensitive with the original data.
	if trySmile(data) {
		return
	}
	if tryIon(data) {
		return
	}
	if tryMessagePack(data) {
		return
	}
	if tryCBOR(data) {
		return
	}
	if tryBSON(data) {
		return
	}
	if tryUBJSON(data) {
		return
	}
	if tryProtobuf(data) {
		return
	}

	// If after trimming, the payload is not empty, check other text formats.
	if len(trimmedData) > 0 {
		if tryJWT(trimmedData) {
			return
		}
		if tryPrettifyXML(trimmedData) {
			return
		}
		if tryPrettifyYAML(trimmedData) {
			return
		}
		if tryBase64(trimmedData) {
			return
		}
		if tryHex(trimmedData) {
			return
		}
	}

	// Use original data for final fallback (plaintext, hex, or all-whitespace).
	handlePlaintextOrHex(data)
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
	headerJSON, _ := json.MarshalIndent(token.Header, "", "  ")
	fmt.Printf("    %sHeader:%s\n", topicColor, colorReset)
	indentedHeader := "    " + strings.ReplaceAll(string(headerJSON), "\n", "\n    ")
	fmt.Println(strings.TrimRight(indentedHeader, " "))

	// Pretty print claims
	claimsJSON, _ := json.MarshalIndent(token.Claims, "", "  ")
	fmt.Printf("    %sClaims:%s\n", topicColor, colorReset)
	indentedClaims := "    " + strings.ReplaceAll(string(claimsJSON), "\n", "\n    ")
	fmt.Println(strings.TrimRight(indentedClaims, " "))

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
	err := json.Unmarshal(data, &obj)
	corrected := false

	// If initial parsing fails, try to fix common issues like single quotes.
	if err != nil {
		trimmedStr := string(bytes.TrimSpace(data))
		if strings.Contains(trimmedStr, "'") &&
			((strings.HasPrefix(trimmedStr, "{") && strings.HasSuffix(trimmedStr, "}")) ||
				(strings.HasPrefix(trimmedStr, "[") && strings.HasSuffix(trimmedStr, "]"))) {

			correctedData := []byte(strings.ReplaceAll(trimmedStr, "'", "\""))
			if json.Unmarshal(correctedData, &obj) == nil {
				err = nil
				corrected = true
			}
		}
	}

	// If we still have an error, it's not JSON we can handle.
	if err != nil {
		return false
	}

	// Avoid flagging simple primitives that aren't complex objects
	switch obj.(type) {
	case string, float64, bool, nil:
		return false
	}

	if corrected {
		fmt.Printf("    %sDetected Format: JSON%s (single quotes auto-corrected)\n", packetTypeColor, colorReset)
	} else {
		fmt.Printf("    %sDetected Format: JSON%s\n", packetTypeColor, colorReset)
	}

	pretty, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		// This is unlikely to happen if unmarshaling succeeded
		fmt.Printf("      Could not re-marshal JSON: %v\n", err)
		return true // It was valid JSON, so we return true
	}

	indented := "    " + strings.ReplaceAll(string(pretty), "\n", "\n    ")
	fmt.Println(strings.TrimRight(indented, " "))
	return true
}

func tryMessagePack(data []byte) bool {
	r := bytes.NewReader(data)
	dec := msgpack.NewDecoder(r)

	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return false
	}

	// If there is any data left in the reader, it's not a clean MessagePack object.
	if r.Len() > 0 {
		return false
	}

	// Heuristic: If the decoded value is not a map or a slice,
	// it's probably not the intended format.
	switch v.(type) {
	case map[string]interface{}, []interface{}, map[interface{}]interface{}:
		// This looks like a complex object, proceed.
	default:
		// It's a simple primitive (string, int, bool, etc.).
		// While technically valid MessagePack, it's likely a false positive for our use case.
		return false
	}

	fmt.Printf("    %sDetected Format: MessagePack%s (decoded and shown as JSON)\n", packetTypeColor, colorReset)
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		// This should not happen if unmarshal to interface worked
		fmt.Printf("      Could not convert to JSON: %v\n", err)
		return true
	}
	indented := "    " + strings.ReplaceAll(string(pretty), "\n", "\n    ")
	fmt.Println(strings.TrimRight(indented, " "))
	return true
}

// convertMapKeysToStrings recursively converts map keys from interface{} to string
// to allow marshaling to JSON. CBOR maps can have any key type, but JSON requires strings.
func convertMapKeysToStrings(i interface{}) interface{} {
	switch v := i.(type) {
	case map[interface{}]interface{}:
		m := make(map[string]interface{})
		for k, val := range v {
			m[fmt.Sprintf("%v", k)] = convertMapKeysToStrings(val)
		}
		return m
	case []interface{}:
		for i, val := range v {
			v[i] = convertMapKeysToStrings(val)
		}
		return v
	case map[string]interface{}:
		for k, val := range v {
			v[k] = convertMapKeysToStrings(val)
		}
		return v
	default:
		return i
	}
}

func tryCBOR(data []byte) bool {
	var v interface{}
	if err := cbor.Unmarshal(data, &v); err != nil {
		return false
	}

	// Heuristic: If the decoded value is not a map or a slice,
	// it's probably not the intended format.
	switch v.(type) {
	case map[string]interface{}, []interface{}, map[interface{}]interface{}:
		// This looks like a complex object, proceed.
	default:
		// It's a simple primitive (string, int, bool, etc.).
		// While technically valid CBOR, it's likely a false positive for our use case.
		return false
	}

	// Convert map keys for JSON compatibility
	v = convertMapKeysToStrings(v)

	fmt.Printf("    %sDetected Format: CBOR%s (decoded and shown as JSON)\n", packetTypeColor, colorReset)
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		// This should not happen if unmarshal to interface worked
		fmt.Printf("      Could not convert to JSON: %v\n", err)
		return true
	}
	indented := "    " + strings.ReplaceAll(string(pretty), "\n", "\n    ")
	fmt.Println(strings.TrimRight(indented, " "))
	return true
}

func tryBSON(data []byte) bool {
	var v interface{}
	if err := bson.Unmarshal(data, &v); err != nil {
		return false
	}

	// Heuristic: If the decoded value is not a map or a slice (document/array),
	// it's probably not the intended format.
	switch v.(type) {
	case bson.D, bson.M, bson.A, []interface{}:
		// This looks like a complex object, proceed.
	default:
		// It's a simple primitive (string, int, bool, etc.).
		// While technically valid BSON, it's likely a false positive for our use case.
		return false
	}

	fmt.Printf("    %sDetected Format: BSON%s (decoded and shown as JSON)\n", packetTypeColor, colorReset)

	// Use extended JSON for a more readable representation of BSON types.
	extJSON, err := bson.MarshalExtJSON(v, false, false)
	if err != nil {
		fmt.Printf("      Could not convert BSON to extended JSON: %v\n", err)
		return true // It was valid BSON, so we return true.
	}

	// Pretty print the resulting JSON
	prettyJSON := prettyPrintJSON(string(extJSON))
	indented := "    " + strings.ReplaceAll(prettyJSON, "\n", "\n    ")
	fmt.Println(strings.TrimRight(indented, " "))
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

func tryHex(data []byte) bool {
	// Heuristic: require more than 4 chars and all must be hex to avoid false positives on short strings.
	if len(data) <= 4 || len(data)%2 != 0 {
		return false
	}
	for _, b := range data {
		isHex := (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
		if !isHex {
			return false
		}
	}

	decoded, err := hex.DecodeString(string(data))
	if err != nil {
		return false // Should not happen given the check above, but for safety.
	}

	// It's hex, but only process it if the decoded content is not the same as the original.
	if !bytes.Equal(data, decoded) {
		fmt.Printf("    %sDetected Format: Hex%s\n", packetTypeColor, colorReset)
		fmt.Printf("    %s--- Begin Decoded Hex ---%s\n", topicColor, colorReset)
		processPayload(decoded) // Recursive call
		fmt.Printf("    %s--- End Decoded Hex ---%s\n", topicColor, colorReset)
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
	encoder.Indent("", "  ")
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
	indented := "    " + strings.ReplaceAll(out.String(), "\n", "\n    ")
	fmt.Println(strings.TrimRight(indented, " "))
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

func tryProtobuf(data []byte) bool {
	// If schemas are loaded, try to unmarshal against known types
	if len(messageDescriptors) > 0 {
		for _, md := range messageDescriptors {
			msg := dynamic.NewMessage(md)
			if err := msg.Unmarshal(data); err == nil {
				// Success, now pretty print
				fmt.Printf("    %sDetected Format: Protobuf (%s)%s\n", packetTypeColor, md.GetFullyQualifiedName(), colorReset)
				json, err := msg.MarshalJSON()
				if err != nil {
					fmt.Printf("      Could not convert protobuf to JSON: %v\n", err)
					return true
				}

				prettyJSON := prettyPrintJSON(string(json))
				indented := "    " + strings.ReplaceAll(prettyJSON, "\n", "\n    ")
				fmt.Println(strings.TrimRight(indented, " "))
				return true
			}
		}
		// If schemas were provided but none matched, do not fall back to guesswork.
		return false
	}

	// Basic protobuf check: does it look like key-value pairs?
	// This is a weak check and might have false positives.
	if len(data) == 0 || (data[0]&0x07) > 5 {
		return false
	}

	// Attempt a generic parse if no schemas match or are loaded
	var out strings.Builder
	p := data
	valid := false
	for len(p) > 0 {
		field, n := binary.Uvarint(p)
		if n <= 0 {
			break
		}
		p = p[n:]
		fieldNum := field >> 3
		wireType := field & 0x07

		var valStr string
		switch wireType {
		case 0: // Varint
			val, n := binary.Uvarint(p)
			if n <= 0 {
				break
			}
			p = p[n:]
			valStr = fmt.Sprintf("%d", val)
		case 1: // 64-bit
			if len(p) < 8 {
				p = nil
				break
			}
			valStr = fmt.Sprintf("0x%x", p[:8])
			p = p[8:]
		case 2: // Length-delimited
			l, n := binary.Uvarint(p)
			if n <= 0 {
				p = nil
				break
			}
			if n > len(p) || uint64(len(p)-n) < l { //#nosec G115 - RHS only runs when n <= len(p); len(p)-n is non-negative.
				p = nil
				break
			}
			ln := int(l) //#nosec G115 - l bounded by len(p)-n above (slice length fits int on supported platforms).
			p = p[n:]
			payload := p[:ln]
			if isMostlyPrintable(payload) {
				valStr = fmt.Sprintf("\"%s\"", string(payload))
			} else {
				valStr = fmt.Sprintf("bytes(%d)", ln)
			}
			p = p[ln:]
		case 5: // 32-bit
			if len(p) < 4 {
				p = nil
				break
			}
			valStr = fmt.Sprintf("0x%x", p[:4])
			p = p[4:]
		default: // 3 (group start) and 4 (group end) are deprecated
			return false // Invalid wire type
		}
		if len(p) == 0 {
			valid = true // reached end of buffer cleanly
		}
		fmt.Fprintf(&out, "    Field %d (type %d): %s\n", fieldNum, wireType, valStr)
	}

	if valid {
		fmt.Printf("    %sDetected Format: Protobuf%s (generic decode, no schema)\n", packetTypeColor, colorReset)
		fmt.Print(out.String())
		return true
	}

	return false
}

func tryIon(data []byte) bool {
	// Heuristic to avoid false positives on simple strings/numbers that are valid Ion text.
	isBinaryIon := bytes.HasPrefix(data, []byte{0xE0, 0x01, 0x00, 0xEA})

	var values []interface{}
	dec := ion.NewDecoder(ion.NewReader(bytes.NewReader(data)))

	for {
		val, err := dec.Decode()
		if err == io.EOF || err == ion.ErrNoInput {
			break
		}
		if err != nil {
			// If we fail at any point, it's not valid Ion we can parse.
			return false
		}
		values = append(values, val)
	}

	if len(values) == 0 {
		return false
	}

	// Heuristic to avoid flagging plaintext as Ion.
	// If it's not binary Ion, we expect to see at least one complex type (struct/list)
	// to consider it Ion. A simple string or a sequence of symbols is likely a false positive.
	if !isBinaryIon {
		isComplexFound := false
		for _, v := range values {
			switch v.(type) {
			case map[string]interface{}, []interface{}:
				isComplexFound = true
			}
			if isComplexFound {
				break
			}
		}
		if !isComplexFound {
			return false
		}
	}

	fmt.Printf("    %sDetected Format: Ion%s (decoded and shown as JSON)\n", packetTypeColor, colorReset)

	for _, v := range values {
		// Marshal each top-level value to JSON for pretty printing.
		pretty, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			// This might happen if the Ion value can't be represented as JSON,
			// in which case we just print a placeholder.
			fmt.Printf("      <could not convert Ion value to JSON: %v>\n", err)
			continue
		}
		indented := "    " + strings.ReplaceAll(string(pretty), "\n", "\n    ")
		fmt.Println(strings.TrimRight(indented, " "))
	}

	return true
}

func tryUBJSON(data []byte) bool {
	var v interface{}
	if err := ubjson.Unmarshal(data, &v); err != nil {
		return false
	}

	// Heuristic: If the decoded value is not a map or a slice,
	// it's probably not the intended format.
	switch v.(type) {
	case map[string]interface{}, []interface{}:
		// This looks like a complex object, proceed.
	default:
		// It's a simple primitive (string, int, bool, etc.).
		// While technically valid UBJSON, it's likely a false positive for our use case.
		return false
	}

	fmt.Printf("    %sDetected Format: UBJSON%s (decoded and shown as JSON)\n", packetTypeColor, colorReset)
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		// This should not happen if unmarshal to interface worked
		fmt.Printf("      Could not convert to JSON: %v\n", err)
		return true
	}
	indented := "    " + strings.ReplaceAll(string(pretty), "\n", "\n    ")
	fmt.Println(strings.TrimRight(indented, " "))
	return true
}

func trySmile(data []byte) bool {
	// Smile header is :)
	if len(data) < 3 || data[0] != 0x3A || data[1] != 0x29 || data[2] != 0x0A {
		return false
	}

	var v interface{}
	v, err := smile.DecodeToObject(data)
	if err != nil {
		return false
	}

	// Heuristic: If the decoded value is not a map or a slice,
	// it's probably not the intended format.
	switch v.(type) {
	case map[string]interface{}, []interface{}:
		// This looks like a complex object, proceed.
	default:
		// It's a simple primitive (string, int, bool, etc.).
		// While technically valid Smile, it's likely a false positive for our use case.
		return false
	}

	fmt.Printf("    %sDetected Format: Smile%s (decoded and shown as JSON)\n", packetTypeColor, colorReset)
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		// This should not happen if unmarshal to interface worked
		fmt.Printf("      Could not convert to JSON: %v\n", err)
		return true
	}
	indented := "    " + strings.ReplaceAll(string(pretty), "\n", "\n    ")
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

func rebuildPublishPacket(topic string, payload []byte, flags byte, packetID []byte) []byte {
	var packet bytes.Buffer
	packet.WriteByte(PUBLISH<<4 | flags)

	var variableHeaderAndPayload bytes.Buffer
	variableHeaderAndPayload.Write(encodeString(topic))
	if (flags>>1)&0x03 > 0 {
		variableHeaderAndPayload.Write(packetID)
	}
	variableHeaderAndPayload.Write(payload)

	packet.Write(encodeLength(variableHeaderAndPayload.Len()))
	packet.Write(variableHeaderAndPayload.Bytes())

	return packet.Bytes()
}

func applyScriptToPacket(packet []byte, direction string) ([]byte, error) {
	if jsEngine == nil || jsEngine.handlePacket == nil {
		return packet, nil
	}

	// 1. Parse the packet to create the JS object
	packetType := (packet[0] >> 4) & 0x0F
	flags := packet[0] & 0x0F
	_, lenBytes := decodeLength(packet[1:])
	headerEnd := 1 + lenBytes
	payload := packet[headerEnd:]

	jsPacket := make(map[string]interface{})
	jsPacket["direction"] = direction
	jsPacket["type"] = getPacketTypeName(packetType)
	jsPacket["raw"] = jsEngine.vm.NewArrayBuffer(packet)
	jsPacket["modifiable"] = false

	var originalPacketID []byte

	if packetType == PUBLISH {
		jsPacket["modifiable"] = true
		topic, offset := decodeString(payload, 0)
		jsPacket["topic"] = topic
		jsPacket["qos"] = (flags >> 1) & 0x03
		jsPacket["retain"] = (flags & 0x01) != 0

		if jsPacket["qos"].(byte) > 0 {
			if len(payload) >= offset+2 {
				originalPacketID = payload[offset : offset+2]
				offset += 2
			}
		}
		jsPacket["payload"] = jsEngine.vm.NewArrayBuffer(payload[offset:])
	}

	// 2. Call the script function
	result, err := jsEngine.handlePacket(goja.Undefined(), jsEngine.vm.ToValue(jsPacket))
	if err != nil {
		return nil, fmt.Errorf("script execution failed: %w", err)
	}

	// 3. Process the result
	if result.Export() == nil { // Dropped
		return nil, nil
	}

	// 4. Rebuild if modified
	if jsPacket["modifiable"].(bool) {
		modifiedPacket, ok := result.Export().(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("script must return an object or null")
		}

		newTopic := modifiedPacket["topic"].(string)
		newPayloadValue, ok := modifiedPacket["payload"].(goja.ArrayBuffer)
		if !ok {
			return nil, fmt.Errorf("modified payload must be a Uint8Array (or ArrayBuffer in Go)")
		}
		newPayload := newPayloadValue.Bytes()
		newFlags := flags // TODO: Allow modifying QoS/Retain

		return rebuildPublishPacket(newTopic, newPayload, newFlags, originalPacketID), nil
	}

	return packet, nil
}
