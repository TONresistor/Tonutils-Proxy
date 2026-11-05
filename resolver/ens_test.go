package resolver

import (
	"errors"
	"testing"
)

type mockENSRecords struct {
	raw       []byte
	readErr   error
	text      string
	textCalls int
}

func (r *mockENSRecords) Contenthash() ([]byte, error) { return r.raw, r.readErr }

func (r *mockENSRecords) Text(key string) (string, error) {
	if key != ADNLRecordKey {
		return "", errors.New("unexpected text record")
	}
	r.textCalls++
	return r.text, nil
}

func TestResolveENSRecords(t *testing.T) {
	id, err := ParseADNLAddress(testADNLHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		records   mockENSRecords
		want      SiteTarget
		wantText  int
		wantError bool
	}{
		{
			name:    "ADNL contenthash takes priority",
			records: mockENSRecords{raw: EncodeContenthash(MulticodecADNL, id[:]), text: testADNLHex},
			want:    SiteTarget{Codec: MulticodecADNL, ID: id},
		},
		{
			name:    "storage contenthash takes priority over legacy ADNL",
			records: mockENSRecords{raw: EncodeContenthash(MulticodecTONStorage, id[:]), text: testADNLHex},
			want:    SiteTarget{Codec: MulticodecTONStorage, ID: id},
		},
		{
			name:     "missing contenthash falls back to legacy ADNL",
			records:  mockENSRecords{text: "0x" + testADNLHex},
			want:     SiteTarget{Codec: MulticodecADNL, ID: id},
			wantText: 1,
		},
		{
			name:     "contenthash RPC error preserves legacy fallback",
			records:  mockENSRecords{readErr: errors.New("no contenthash support"), text: testADNLHex},
			want:     SiteTarget{Codec: MulticodecADNL, ID: id},
			wantText: 1,
		},
		{
			name:     "unrelated contenthash preserves legacy fallback",
			records:  mockENSRecords{raw: EncodeContenthash(0xe3, id[:]), text: testADNLHex},
			want:     SiteTarget{Codec: MulticodecADNL, ID: id},
			wantText: 1,
		},
		{
			name:      "malformed bag ID is not resolved",
			records:   mockENSRecords{raw: EncodeContenthash(MulticodecTONStorage, id[:31])},
			wantText:  1,
			wantError: true,
		},
		{
			name:      "invalid legacy ADNL is not resolved",
			records:   mockENSRecords{text: "not-an-address"},
			wantText:  1,
			wantError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveENSRecords(&tc.records, "site.eth")
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, want error = %v", err, tc.wantError)
			}
			if got != tc.want {
				t.Errorf("target = %+v, want %+v", got, tc.want)
			}
			if tc.records.textCalls != tc.wantText {
				t.Errorf("text reads = %d, want %d", tc.records.textCalls, tc.wantText)
			}
		})
	}
}
