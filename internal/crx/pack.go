// Package crx packs an unpacked Chrome extension directory into a signed
// CRX3 file and computes the deterministic extension ID. Pure Go, no
// dependencies outside the standard library. The CRX3 wire format is
// documented at chromium/components/crx_file/crx3.proto.
package crx

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Result captures everything the caller might want from one pack: the bytes
// of the resulting .crx, the deterministic extension ID, the public-key
// SubjectPublicKeyInfo bytes (suitable for the `key` field in manifest.json),
// and the extension version (read from the unpacked manifest.json).
type Result struct {
	CRX         []byte
	ExtensionID string
	PublicKey   []byte
	Version     string
}

// Pack zips srcDir, signs it with key, and returns a CRX3 file in memory.
func Pack(srcDir string, key *rsa.PrivateKey) (*Result, error) {
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("crx: marshal pubkey: %w", err)
	}
	idDigest := sha256.Sum256(spki)
	crxID := idDigest[:16]
	extID := crxIDToExtensionID(crxID)

	manifestBytes, err := os.ReadFile(filepath.Join(srcDir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("crx: read manifest: %w", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("crx: parse manifest: %w", err)
	}
	version, _ := manifest["version"].(string)
	if version == "" {
		return nil, fmt.Errorf("crx: manifest.json missing version field")
	}

	zipBytes, err := zipDir(srcDir)
	if err != nil {
		return nil, fmt.Errorf("crx: zip dir: %w", err)
	}

	signedHeader := protoBytes(1, crxID) // SignedData.crx_id

	var toSign bytes.Buffer
	toSign.WriteString("CRX3 SignedData\x00")
	_ = binary.Write(&toSign, binary.LittleEndian, uint32(len(signedHeader)))
	toSign.Write(signedHeader)
	toSign.Write(zipBytes)

	hashed := sha256.Sum256(toSign.Bytes())
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("crx: sign: %w", err)
	}

	proof := protoConcat(protoBytes(1, spki), protoBytes(2, sig))
	header := protoConcat(protoBytes(2, proof), protoBytes(10000, signedHeader))

	var crx bytes.Buffer
	crx.WriteString("Cr24")
	_ = binary.Write(&crx, binary.LittleEndian, uint32(3))
	_ = binary.Write(&crx, binary.LittleEndian, uint32(len(header)))
	crx.Write(header)
	crx.Write(zipBytes)

	return &Result{
		CRX:         crx.Bytes(),
		ExtensionID: extID,
		PublicKey:   spki,
		Version:     version,
	}, nil
}

// LoadOrGenerateKey reads an RSA private key from path (PKCS#1 or PKCS#8 PEM).
// If the file doesn't exist, generates a fresh RSA-2048 key, writes it
// PKCS#1-encoded to path with 0600 perms, and returns it. Generated == true
// when a new key was created.
func LoadOrGenerateKey(path string) (key *rsa.PrivateKey, generated bool, err error) {
	if data, e := os.ReadFile(path); e == nil {
		key, err := parseKey(data)
		if err != nil {
			return nil, false, fmt.Errorf("crx: parse %s: %w", path, err)
		}
		return key, false, nil
	}
	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, false, fmt.Errorf("crx: generate key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, false, fmt.Errorf("crx: mkdir for key: %w", err)
	}
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		return nil, false, fmt.Errorf("crx: write key: %w", err)
	}
	return key, true, nil
}

func parseKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
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
	return nil, fmt.Errorf("not a PKCS#1 or PKCS#8 RSA private key")
}

// zipDir produces a deterministic zip of srcDir. Lexicographic walk order.
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
		// Skip extension-id.txt — it's not part of the shipped extension.
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

// crxIDToExtensionID converts the 16-byte crx_id to Chrome's 32-char a-p ID.
func crxIDToExtensionID(id []byte) string {
	var sb strings.Builder
	sb.Grow(32)
	for _, b := range id {
		sb.WriteByte('a' + (b >> 4))
		sb.WriteByte('a' + (b & 0x0f))
	}
	return sb.String()
}
