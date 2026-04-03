package resolver

import (
	"testing"
)

// buildV2Data constructs a raw account data buffer for a SNS v2 record.
//   - 96 bytes zeros (name registry header)
//   - 2 bytes stalenessType (LE)
//   - 2 bytes roaType (LE)
//   - 4 bytes contentLen (LE)
//   - stalenessData (variable)
//   - roaData (variable)
//   - content
func buildV2Data(stalenessType, roaType uint16, contentLen uint32, stalenessData, roaData, content []byte) []byte {
	buf := make([]byte, 96+8)
	// header: 96 zeros (already zero)
	buf[96] = byte(stalenessType)
	buf[97] = byte(stalenessType >> 8)
	buf[98] = byte(roaType)
	buf[99] = byte(roaType >> 8)
	buf[100] = byte(contentLen)
	buf[101] = byte(contentLen >> 8)
	buf[102] = byte(contentLen >> 16)
	buf[103] = byte(contentLen >> 24)
	buf = append(buf, stalenessData...)
	buf = append(buf, roaData...)
	buf = append(buf, content...)
	return buf
}

func TestExtractADNLFromV2Record_MinimalHeader(t *testing.T) {
	content := []byte(testADNLHex)
	data := buildV2Data(0, 0, uint32(len(content)), nil, nil, content)

	got, err := extractADNLFromV2Record(data, "test.sol")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testADNLHex {
		t.Errorf("expected %q, got %q", testADNLHex, got)
	}
}

func TestExtractADNLFromV2Record_WithStaleness(t *testing.T) {
	content := []byte(testADNLHex)
	stalenessData := make([]byte, 32)
	data := buildV2Data(1, 0, uint32(len(content)), stalenessData, nil, content)

	got, err := extractADNLFromV2Record(data, "test.sol")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testADNLHex {
		t.Errorf("expected %q, got %q", testADNLHex, got)
	}
}

func TestExtractADNLFromV2Record_BothValidation(t *testing.T) {
	content := []byte(testADNLHex)
	stalenessData := make([]byte, 32)
	roaData := make([]byte, 32)
	data := buildV2Data(1, 1, uint32(len(content)), stalenessData, roaData, content)

	got, err := extractADNLFromV2Record(data, "test.sol")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testADNLHex {
		t.Errorf("expected %q, got %q", testADNLHex, got)
	}
}

func TestExtractADNLFromV2Record_Truncated(t *testing.T) {
	// 96 header + 8 metadata + 1 byte content → passes first length check,
	// but contentLen=64 exceeds available bytes → truncated error.
	data := buildV2Data(0, 0, 64, nil, nil, []byte{0x01}) // only 1 byte content

	_, err := extractADNLFromV2Record(data, "test.sol")
	if err == nil {
		t.Error("expected error for truncated record")
	}
}

func TestExtractADNLFromV2Record_ContentLenTooLarge(t *testing.T) {
	data := buildV2Data(0, 0, 1000, nil, nil, nil)
	// pad to pass the first length check
	data = append(data, make([]byte, 10)...)

	_, err := extractADNLFromV2Record(data, "test.sol")
	if err == nil {
		t.Error("expected error for contentLen=1000 (> 256)")
	}
}

func TestExtractADNLFromV2Record_UnknownStalenessType(t *testing.T) {
	data := buildV2Data(2, 0, 0, nil, nil, nil)
	// pad to pass first length check
	data = append(data, 0x00)

	_, err := extractADNLFromV2Record(data, "test.sol")
	if err == nil {
		t.Error("expected error for unknown stalenessType=2")
	}
}

func TestExtractADNLFromV2Record_UnknownRoaType(t *testing.T) {
	data := buildV2Data(0, 5, 0, nil, nil, nil)
	// pad to pass first length check
	data = append(data, 0x00)

	_, err := extractADNLFromV2Record(data, "test.sol")
	if err == nil {
		t.Error("expected error for unknown roaType=5")
	}
}

func TestExtractADNLFromV2Record_Overflow(t *testing.T) {
	// contentLen near uint32 max — must be rejected by the >256 guard.
	data := buildV2Data(0, 0, 0xFFFFFFFF, nil, nil, nil)
	data = append(data, 0x00)

	_, err := extractADNLFromV2Record(data, "test.sol")
	if err == nil {
		t.Error("expected error for contentLen=0xFFFFFFFF")
	}
}

func TestExtractADNLFromV1Record_Valid(t *testing.T) {
	data := make([]byte, 96)
	data = append(data, []byte(testADNLHex)...)

	got, err := extractADNLFromV1Record(data, "test.sol")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testADNLHex {
		t.Errorf("expected %q, got %q", testADNLHex, got)
	}
}

func TestExtractADNLFromV1Record_Empty(t *testing.T) {
	data := make([]byte, 96)

	_, err := extractADNLFromV1Record(data, "test.sol")
	if err == nil {
		t.Error("expected error for exactly 96 bytes (no payload)")
	}
}

func TestExtractADNLFromV1Record_TooShort(t *testing.T) {
	data := make([]byte, 50)

	_, err := extractADNLFromV1Record(data, "test.sol")
	if err == nil {
		t.Error("expected error for 50 bytes (< 96 header)")
	}
}

func TestDeriveDomainKey(t *testing.T) {
	key, err := deriveDomainKey("tonnet")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var zero [32]byte
	if [32]byte(key) == zero {
		t.Error("expected non-zero PublicKey for 'tonnet'")
	}

	// Verify determinism: second call must return same key.
	key2, err := deriveDomainKey("tonnet")
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if key != key2 {
		t.Error("deriveDomainKey is not deterministic")
	}
}

func TestDeriveRecordV1VsV2(t *testing.T) {
	domainKey, err := deriveDomainKey("tonnet")
	if err != nil {
		t.Fatalf("deriveDomainKey: %v", err)
	}

	v1, err := deriveRecordV1Key(snsTXTRecord, domainKey)
	if err != nil {
		t.Fatalf("deriveRecordV1Key: %v", err)
	}

	v2, err := deriveRecordV2Key(snsTXTRecord, domainKey)
	if err != nil {
		t.Fatalf("deriveRecordV2Key: %v", err)
	}

	if v1 == v2 {
		t.Error("V1 and V2 PDAs must be different for the same domain+record")
	}
}
