package resolver

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// MulticodecADNL est le code multicodec réservé pour une adresse ADNL
// (32-byte Ed25519-derived endpoint identifier du réseau TON).
// Format contenthash ENSIP-7 : <MulticodecADNL uvarint><32 bytes ADNL>.
const MulticodecADNL uint64 = 0xb69910

const MulticodecTONStorage uint64 = 0xb79910

// DecodeContenthash parses an ENSIP-7 contenthash into its multicodec and payload.
func DecodeContenthash(ch []byte) (codec uint64, payload []byte, err error) {
	if len(ch) == 0 {
		return 0, nil, errors.New("empty contenthash")
	}
	codec, n := binary.Uvarint(ch)
	if n <= 0 {
		return 0, nil, errors.New("invalid contenthash uvarint")
	}
	return codec, ch[n:], nil
}

// EncodeContenthash builds an ENSIP-7 contenthash from a multicodec and payload.
func EncodeContenthash(codec uint64, payload []byte) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, codec)
	out := make([]byte, 0, n+len(payload))
	out = append(out, buf[:n]...)
	out = append(out, payload...)
	return out
}

// ExtractADNLFromContenthash returns the lowercase hex of the 32-byte ADNL address
// when the contenthash uses the ADNL multicodec. Returns ok=false without error
// when the codec is recognized-but-not-ours, so callers can fall back silently.
func ExtractADNLFromContenthash(ch []byte) (hexAdnl string, ok bool, err error) {
	codec, payload, err := DecodeContenthash(ch)
	if err != nil {
		return "", false, err
	}
	if codec != MulticodecADNL {
		return "", false, nil
	}
	if len(payload) != ADNLAddressSize {
		return "", false, fmt.Errorf("invalid ADNL payload length: expected %d, got %d", ADNLAddressSize, len(payload))
	}
	return hex.EncodeToString(payload), true, nil
}

func ExtractSiteFromContenthash(ch []byte) (target SiteTarget, ok bool, err error) {
	codec, payload, err := DecodeContenthash(ch)
	if err != nil {
		return SiteTarget{}, false, err
	}
	if codec != MulticodecADNL && codec != MulticodecTONStorage {
		return SiteTarget{}, false, nil
	}
	if len(payload) != len(target.ID) {
		return SiteTarget{}, false, fmt.Errorf("invalid site payload length: expected %d, got %d", len(target.ID), len(payload))
	}
	target.Codec = codec
	copy(target.ID[:], payload)
	return target, true, nil
}
