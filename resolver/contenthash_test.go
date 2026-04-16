package resolver

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestMulticodecADNLValue(t *testing.T) {
	if MulticodecADNL != 0xb69910 {
		t.Fatalf("MulticodecADNL = %#x, want %#x", MulticodecADNL, 0xb69910)
	}
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, MulticodecADNL)
	got := buf[:n]
	want := []byte{0x90, 0xb2, 0xda, 0x05}
	if !bytes.Equal(got, want) {
		t.Fatalf("uvarint encoding = % x, want % x", got, want)
	}
}

func TestEncodeDecodeRoundtrip(t *testing.T) {
	payload := make([]byte, ADNLAddressSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	encoded := EncodeContenthash(MulticodecADNL, payload)
	codec, decoded, err := DecodeContenthash(encoded)
	if err != nil {
		t.Fatalf("DecodeContenthash: %v", err)
	}
	if codec != MulticodecADNL {
		t.Fatalf("codec = %#x, want %#x", codec, MulticodecADNL)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("payload mismatch: got % x, want % x", decoded, payload)
	}
}

func TestExtractADNLFromContenthash_Valid(t *testing.T) {
	payload := make([]byte, ADNLAddressSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	ch := append([]byte{0x90, 0xb2, 0xda, 0x05}, payload...)

	got, ok, err := ExtractADNLFromContenthash(ch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	want := hex.EncodeToString(payload)
	if got != want {
		t.Fatalf("hex = %q, want %q", got, want)
	}
	if len(got) != ADNLAddressSize*2 {
		t.Fatalf("hex length = %d, want %d", len(got), ADNLAddressSize*2)
	}
}

func TestExtractADNLFromContenthash_UnknownCodec(t *testing.T) {
	// sha256 codec (0x12) + 32 bytes of hash
	payload := make([]byte, 32)
	ch := append([]byte{0x12, 0x20}, payload...) // 0x12 codec, 0x20 len prefix (still just bytes)
	// Actually we just need ANY codec != MulticodecADNL; use 0x12 directly.
	ch = append([]byte{0x12}, payload...)

	hexAdnl, ok, err := ExtractADNLFromContenthash(ch)
	if err != nil {
		t.Fatalf("unexpected error for unknown codec: %v", err)
	}
	if ok {
		t.Fatalf("ok = true, want false for unknown codec")
	}
	if hexAdnl != "" {
		t.Fatalf("hex = %q, want empty", hexAdnl)
	}
}

func TestExtractADNLFromContenthash_WrongPayloadLength(t *testing.T) {
	payload := make([]byte, 16)
	ch := append([]byte{0x90, 0xb2, 0xda, 0x05}, payload...)

	_, ok, err := ExtractADNLFromContenthash(ch)
	if err == nil {
		t.Fatalf("expected error for 16-byte payload, got nil")
	}
	if ok {
		t.Fatalf("ok = true, want false on error")
	}
}

func TestExtractADNLFromContenthash_Empty(t *testing.T) {
	_, ok, err := ExtractADNLFromContenthash([]byte{})
	if err == nil {
		t.Fatalf("expected error for empty contenthash, got nil")
	}
	if ok {
		t.Fatalf("ok = true, want false on error")
	}
}

func TestDecodeContenthash_InvalidUvarint(t *testing.T) {
	// 10 bytes of 0xff is an overflow uvarint (Uvarint returns n<=0)
	broken := bytes.Repeat([]byte{0xff}, 10)
	_, _, err := DecodeContenthash(broken)
	if err == nil {
		t.Fatalf("expected error for broken uvarint, got nil")
	}
}
