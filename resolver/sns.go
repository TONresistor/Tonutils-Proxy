package resolver

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

const (
	snsNameProgramID       = "namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX"
	snsRecordsProgramID    = "HP3D4D1ZCmohQGFVms2SS4LCANgJyksBf5s1F77FuFjZ"
	solTLDAuthority        = "58PwtjSDuFHuUkYjH9BYnnQKHfwo9reZhC2zMJv9JPkx"
	snsHashPrefix          = "SPL Name Service"
	nameRegistryHeaderSize = 96

	snsTXTRecord    = "TXT"
	snsV1Prefix     = "\x01"
	snsV2Prefix     = "\x02"

	snsV2HeaderSize = 8 // stalenessType(2) + roaType(2) + contentLen(4)
)

func init() {
	RegisterChain(ChainConfig{
		TLD:       ".sol",
		Name:      "Solana SNS",
		RecordKey: "TXT",
		DefaultRPCs: []string{
			"https://api.mainnet-beta.solana.com",
			"https://solana-rpc.publicnode.com",
		},
		NewResolver: func(rpcURL string) (Resolver, error) {
			return newSNSResolver(rpcURL)
		},
	})
}

type SNSResolver struct {
	client *rpc.Client
}

func newSNSResolver(rpcURL string) (*SNSResolver, error) {
	if rpcURL != "" {
		client, err := dialAndVerifySolana(rpcURL)
		if err != nil {
			return nil, err
		}
		return &SNSResolver{client: client}, nil
	}

	cfg := findChainConfig(".sol")
	var lastErr error
	for _, url := range cfg.DefaultRPCs {
		client, err := dialAndVerifySolana(url)
		if err == nil {
			return &SNSResolver{client: client}, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("no working Solana RPC found: %w", lastErr)
}

func (r *SNSResolver) Resolve(domain string) (string, error) {
	name := strings.TrimSuffix(domain, ".sol")
	if name == "" {
		return "", fmt.Errorf("empty domain name")
	}

	domainKey, err := deriveDomainKey(name)
	if err != nil {
		return "", fmt.Errorf("derive domain key for %q: %w", domain, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try V2 record first (used by sns.id), then fall back to V1
	adnl, err := r.resolveRecordV2(ctx, domain, domainKey)
	if err == nil {
		return adnl, nil
	}

	adnl, err2 := r.resolveRecordV1(ctx, domain, domainKey)
	if err2 == nil {
		return adnl, nil
	}

	return "", fmt.Errorf("no ADNL TXT record for %q (v2: %v, v1: %v)", domain, err, err2)
}

func (r *SNSResolver) resolveRecordV2(ctx context.Context, domain string, domainKey solana.PublicKey) (string, error) {
	recordKey, err := deriveRecordV2Key(snsTXTRecord, domainKey)
	if err != nil {
		return "", err
	}

	info, err := r.client.GetAccountInfo(ctx, recordKey)
	if err != nil {
		return "", fmt.Errorf("fetch: %w", err)
	}
	if info == nil || info.Value == nil {
		return "", fmt.Errorf("not found")
	}

	data := info.Value.Data.GetBinary()
	return extractADNLFromV2Record(data, domain)
}

func (r *SNSResolver) resolveRecordV1(ctx context.Context, domain string, domainKey solana.PublicKey) (string, error) {
	recordKey, err := deriveRecordV1Key(snsTXTRecord, domainKey)
	if err != nil {
		return "", err
	}

	info, err := r.client.GetAccountInfo(ctx, recordKey)
	if err != nil {
		return "", fmt.Errorf("fetch: %w", err)
	}
	if info == nil || info.Value == nil {
		return "", fmt.Errorf("not found")
	}

	data := info.Value.Data.GetBinary()
	return extractADNLFromV1Record(data, domain)
}

// extractADNLFromV1Record extracts ADNL from a V1 record (raw data after 96-byte header).
func extractADNLFromV1Record(data []byte, domain string) (string, error) {
	if len(data) <= nameRegistryHeaderSize {
		return "", fmt.Errorf("empty record for %q", domain)
	}

	payload := data[nameRegistryHeaderSize:]
	if len(payload) > 256 {
		payload = payload[:256]
	}
	return parseADNLFromPayload(payload, domain)
}

// extractADNLFromV2Record extracts ADNL from a V2 record.
// V2 layout after the 96-byte name registry header:
//   - Staleness Validation Type: u16 LE
//   - RoA Validation Type:       u16 LE
//   - Content-Length:             u32 LE
//   - Staleness ID:              variable (32 bytes when type=1 Solana, 0 when type=0)
//   - RoA ID:                    variable (32 bytes when type > 0, 0 when type=0)
//   - Content:                   Content-Length bytes
func extractADNLFromV2Record(data []byte, domain string) (string, error) {
	if len(data) <= nameRegistryHeaderSize+snsV2HeaderSize {
		return "", fmt.Errorf("empty V2 record for %q", domain)
	}

	payload := data[nameRegistryHeaderSize:]

	stalenessType := uint16(payload[0]) | uint16(payload[1])<<8
	roaType := uint16(payload[2]) | uint16(payload[3])<<8
	contentLen := uint32(payload[4]) | uint32(payload[5])<<8 | uint32(payload[6])<<16 | uint32(payload[7])<<24

	if contentLen > 256 {
		return "", fmt.Errorf("V2 contentLen too large for %q: %d", domain, contentLen)
	}

	offset := uint32(snsV2HeaderSize)

	// Skip staleness validation data
	switch stalenessType {
	case 0: // no validation data
	case 1:
		offset += 32 // Solana signature
	default:
		return "", fmt.Errorf("unknown V2 staleness type %d for %q", stalenessType, domain)
	}
	// Skip RoA validation data
	switch roaType {
	case 0: // no validation data
	case 1:
		offset += 32
	default:
		return "", fmt.Errorf("unknown V2 roaType %d for %q", roaType, domain)
	}

	if uint64(len(payload)) < uint64(offset)+uint64(contentLen) {
		return "", fmt.Errorf("truncated V2 record for %q", domain)
	}

	content := payload[offset : offset+contentLen]
	return parseADNLFromPayload(content, domain)
}

func parseADNLFromPayload(payload []byte, domain string) (string, error) {
	adnlHex := strings.TrimSpace(string(payload))
	adnlHex = strings.TrimRight(adnlHex, "\x00")
	// Trim trailing dashes observed in some SNS V2 TXT records (encoding artifact)
	adnlHex = strings.Trim(adnlHex, "-")
	adnlHex = strings.TrimPrefix(adnlHex, "0x")
	adnlHex = strings.TrimPrefix(adnlHex, "0X")

	if _, err := ParseADNLAddress(adnlHex); err != nil {
		return "", fmt.Errorf("invalid ADNL in TXT record for %q: %w", domain, err)
	}

	return adnlHex, nil
}

func (r *SNSResolver) Close() {}

// deriveDomainKey derives the PDA for a .sol domain name.
func deriveDomainKey(name string) (solana.PublicKey, error) {
	h := sha256.Sum256([]byte(snsHashPrefix + name))

	programID := solana.MustPublicKeyFromBase58(snsNameProgramID)
	tldAuthority := solana.MustPublicKeyFromBase58(solTLDAuthority)

	classKey := make([]byte, 32)

	pda, _, err := solana.FindProgramAddress(
		[][]byte{
			h[:],
			classKey,
			tldAuthority.Bytes(),
		},
		programID,
	)
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("find program address: %w", err)
	}

	return pda, nil
}

// deriveRecordV1Key derives the PDA for a SNS v1 record.
// Seeds: [SHA256("SPL Name Service" + "\x01" + record), zeros32, domainKey]
func deriveRecordV1Key(recordName string, domainKey solana.PublicKey) (solana.PublicKey, error) {
	h := sha256.Sum256([]byte(snsHashPrefix + snsV1Prefix + recordName))
	programID := solana.MustPublicKeyFromBase58(snsNameProgramID)
	classKey := make([]byte, 32)

	pda, _, err := solana.FindProgramAddress(
		[][]byte{h[:], classKey, domainKey.Bytes()},
		programID,
	)
	if err != nil {
		return solana.PublicKey{}, err
	}
	return pda, nil
}

// deriveRecordV2Key derives the PDA for a SNS v2 record.
// Seeds: [SHA256("SPL Name Service" + "\x02" + record), centralState, domainKey]
// centralState = FindProgramAddress([snsRecordsProgramID], snsRecordsProgramID)
func deriveRecordV2Key(recordName string, domainKey solana.PublicKey) (solana.PublicKey, error) {
	h := sha256.Sum256([]byte(snsHashPrefix + snsV2Prefix + recordName))
	programID := solana.MustPublicKeyFromBase58(snsNameProgramID)
	recordsProgramID := solana.MustPublicKeyFromBase58(snsRecordsProgramID)

	// Central state is a PDA of the sns-records program itself
	centralState, _, err := solana.FindProgramAddress(
		[][]byte{recordsProgramID.Bytes()},
		recordsProgramID,
	)
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("derive central state: %w", err)
	}

	pda, _, err := solana.FindProgramAddress(
		[][]byte{h[:], centralState.Bytes(), domainKey.Bytes()},
		programID,
	)
	if err != nil {
		return solana.PublicKey{}, err
	}
	return pda, nil
}

func dialAndVerifySolana(rpcURL string) (*rpc.Client, error) {
	client := rpc.New(rpcURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.GetSlot(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("solana RPC check failed for %s: %w", rpcURL, err)
	}

	return client, nil
}
