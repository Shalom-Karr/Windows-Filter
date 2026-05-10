// pack-crx — produce a signed Chrome CRX3 + update.xml from an unpacked extension dir.
//
// Usage:
//
//	go run ./tools/pack-crx -key=key.pem -src=./extension -out=./web \
//	    -url=https://skfilter.pages.dev/skfilter.crx
//
// Inputs:
//   -key   PEM-encoded RSA-2048 private key (PKCS#1 "RSA PRIVATE KEY" or PKCS#8 "PRIVATE KEY")
//   -src   path to unpacked extension dir (must contain manifest.json)
//   -out   output directory; writes skfilter.crx and update.xml
//   -url   public HTTPS URL of the .crx (goes into update.xml codebase=)
//   -id    optional: print the deterministic extension ID and exit
//
// CRX3 wire format reference: chromium /components/crx_file/crx3.proto
//
//	[ "Cr24" magic (4 bytes) ]
//	[ version = 3   uint32 LE ]
//	[ header_len    uint32 LE ]
//	[ CrxFileHeader protobuf bytes (header_len) ]
//	[ zip data of extension ]
//
// CrxFileHeader protobuf (field numbers from crx3.proto):
//
//	message AsymmetricKeyProof {
//	  optional bytes public_key = 1;
//	  optional bytes signature  = 2;
//	}
//	message CrxFileHeader {
//	  repeated AsymmetricKeyProof sha256_with_rsa = 2;
//	  repeated AsymmetricKeyProof sha256_with_ecdsa = 3;
//	  optional bytes signed_header_data = 10000;
//	}
//	message SignedData {
//	  optional bytes crx_id = 1;  // first 16 bytes of SHA-256(SubjectPublicKeyInfo)
//	}
//
// Signature input:
//
//	"CRX3 SignedData\x00" || uint32_le(len(signed_header_data)) || signed_header_data || zip_data
package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	keyPath := flag.String("key", "", "path to PEM-encoded RSA private key")
	srcDir := flag.String("src", "./extension", "source extension dir")
	outDir := flag.String("out", "./web", "output dir (writes skfilter.crx + update.xml)")
	crxURL := flag.String("url", "https://skfilter.pages.dev/skfilter.crx", "public CRX URL")
	idOnly := flag.Bool("id", false, "just print the extension ID for the given key and exit")
	flag.Parse()

	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -key is required")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Generate a key locally with:")
		fmt.Fprintln(os.Stderr, "    openssl genrsa -out skfilter-extension.pem 2048")
		fmt.Fprintln(os.Stderr, "Then either pass -key=skfilter-extension.pem, or set the EXTENSION_SIGNING_KEY")
		fmt.Fprintln(os.Stderr, "GitHub secret (see tools/pack-crx/README.md).")
		os.Exit(2)
	}

	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		die("loading key: %v", err)
	}

	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		die("marshaling pubkey: %v", err)
	}
	idDigest := sha256.Sum256(spki)
	crxID := idDigest[:16]
	extID := crxIDToExtensionID(crxID)
	pubKeyB64 := base64Encode(spki)

	if *idOnly {
		fmt.Println(extID)
		return
	}

	// Read version from manifest.json
	manifestPath := filepath.Join(*srcDir, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		die("reading manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		die("parsing manifest: %v", err)
	}
	version, _ := manifest["version"].(string)
	if version == "" {
		die("manifest.json missing version field")
	}

	// Zip the extension dir.
	zipBytes, err := zipDir(*srcDir)
	if err != nil {
		die("zipping extension: %v", err)
	}

	// Build signed_header_data = SignedData{ crx_id = first16 }.
	signedHeader := protoBytes(1, crxID) // SignedData.crx_id = field 1, bytes

	// Build signature input: "CRX3 SignedData\x00" || uint32_le(len) || signed_header_data || zip
	var toSign bytes.Buffer
	toSign.WriteString("CRX3 SignedData\x00")
	_ = binary.Write(&toSign, binary.LittleEndian, uint32(len(signedHeader)))
	toSign.Write(signedHeader)
	toSign.Write(zipBytes)

	hashed := sha256.Sum256(toSign.Bytes())
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		die("signing: %v", err)
	}

	// Build AsymmetricKeyProof { public_key=1: spki, signature=2: sig }
	proof := protoConcat(
		protoBytes(1, spki),
		protoBytes(2, sig),
	)

	// Build CrxFileHeader { sha256_with_rsa=2: proof, signed_header_data=10000: signedHeader }
	header := protoConcat(
		protoBytes(2, proof),
		protoBytes(10000, signedHeader),
	)

	// Assemble the .crx
	var crx bytes.Buffer
	crx.WriteString("Cr24")
	_ = binary.Write(&crx, binary.LittleEndian, uint32(3))
	_ = binary.Write(&crx, binary.LittleEndian, uint32(len(header)))
	crx.Write(header)
	crx.Write(zipBytes)

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		die("mkdir out: %v", err)
	}
	crxPath := filepath.Join(*outDir, "skfilter.crx")
	if err := writeIfChanged(crxPath, crx.Bytes()); err != nil {
		die("writing crx: %v", err)
	}

	// Build update.xml
	xmlBody := fmt.Sprintf(
		`<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='%s'>
    <updatecheck codebase='%s' version='%s' />
  </app>
</gupdate>
`, extID, *crxURL, version)
	xmlPath := filepath.Join(*outDir, "update.xml")
	if err := writeIfChanged(xmlPath, []byte(xmlBody)); err != nil {
		die("writing update.xml: %v", err)
	}

	fmt.Printf("packed extension %s v%s\n", extID, version)
	fmt.Printf("  pubkey (manifest \"key\" field): %s\n", pubKeyB64)
	fmt.Printf("  crx:        %s (%d bytes)\n", crxPath, crx.Len())
	fmt.Printf("  update.xml: %s\n", xmlPath)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pack-crx: "+format+"\n", args...)
	os.Exit(1)
}

// loadPrivateKey reads a PEM file and parses an RSA private key (PKCS#1 or PKCS#8).
func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not RSA")
		}
		return rk, nil
	}
	return nil, fmt.Errorf("could not parse %s as PKCS#1 or PKCS#8 RSA private key", path)
}

// zipDir produces a deterministic-ish zip of an extension dir.
// Walk order is filepath.Walk (lexicographic), which gives stable archives.
func zipDir(dir string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		// Skip the committed extension-id.txt — it's not part of the published extension.
		if rel == "extension-id.txt" {
			return nil
		}
		fh, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		fh.Name = rel
		fh.Method = zip.Deflate
		w, err := zw.CreateHeader(fh)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(w, f)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeIfChanged only rewrites the file if its bytes differ from what's on disk.
// Keeps git commits quiet on no-op rebuilds.
func writeIfChanged(path string, data []byte) error {
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
		return nil
	}
	return os.WriteFile(path, data, 0o644)
}

// protoBytes encodes a length-delimited (wire type 2) protobuf field: tag, varint(len), bytes.
func protoBytes(fieldNum int, value []byte) []byte {
	var buf bytes.Buffer
	tag := uint64(fieldNum)<<3 | 2
	writeVarint(&buf, tag)
	writeVarint(&buf, uint64(len(value)))
	buf.Write(value)
	return buf.Bytes()
}

func protoConcat(parts ...[]byte) []byte {
	var buf bytes.Buffer
	for _, p := range parts {
		buf.Write(p)
	}
	return buf.Bytes()
}

func writeVarint(buf *bytes.Buffer, v uint64) {
	for v >= 0x80 {
		buf.WriteByte(byte(v) | 0x80)
		v >>= 7
	}
	buf.WriteByte(byte(v))
}

// crxIDToExtensionID converts the 16-byte crx_id to Chrome's 32-char a-p extension ID.
// Each byte 0..15 maps to two letters in 'a'..'p' (byte >> 4 and byte & 0xf, plus 'a').
func crxIDToExtensionID(id []byte) string {
	var sb strings.Builder
	sb.Grow(32)
	for _, b := range id {
		sb.WriteByte('a' + (b >> 4))
		sb.WriteByte('a' + (b & 0x0f))
	}
	return sb.String()
}

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
