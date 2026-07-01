package proxy

import (
	"strings"
	"testing"
)

var fwdSuffixes = []string{".adnl", ".ton", ".eth", ".sol"}

func TestValidateForwardsBareADNLGetsSuffix(t *testing.T) {
	valid, warns := validateForwards([]Forward{
		{Listen: "127.0.0.1:18090", Target: "vtgc7w35xotihnhmjdhvq5bmzkthoxyfwm32wf5xl5kp4xib2kfm7hv"},
	}, fwdSuffixes)
	if len(valid) != 1 {
		t.Fatalf("valid = %d, want 1", len(valid))
	}
	if got, want := valid[0].Target, "vtgc7w35xotihnhmjdhvq5bmzkthoxyfwm32wf5xl5kp4xib2kfm7hv.adnl"; got != want {
		t.Fatalf("target = %q, want %q", got, want)
	}
	if len(warns) != 0 {
		t.Fatalf("warns = %v, want none", warns)
	}
}

func TestValidateForwardsKeepsRoutableSuffixes(t *testing.T) {
	for _, tgt := range []string{"node.ton", "abc.adnl", "tonnet.eth", "name.sol"} {
		valid, warns := validateForwards([]Forward{{Listen: "127.0.0.1:1", Target: tgt}}, fwdSuffixes)
		if len(valid) != 1 || valid[0].Target != tgt {
			t.Fatalf("target %q not kept as-is: %+v", tgt, valid)
		}
		if len(warns) != 0 {
			t.Fatalf("target %q produced warnings: %v", tgt, warns)
		}
	}
}

func TestValidateForwardsTrimsListenAndTarget(t *testing.T) {
	valid, warns := validateForwards([]Forward{
		{Listen: " 127.0.0.1:1 ", Target: " node.ton/ "},
	}, fwdSuffixes)
	if len(valid) != 1 {
		t.Fatalf("valid = %+v, want 1", valid)
	}
	if valid[0].Listen != "127.0.0.1:1" {
		t.Fatalf("listen = %q, want trimmed 127.0.0.1:1", valid[0].Listen)
	}
	if valid[0].Target != "node.ton" {
		t.Fatalf("target = %q, want node.ton", valid[0].Target)
	}
	if len(warns) != 0 {
		t.Fatalf("warns = %v, want none", warns)
	}
}

func TestValidateForwardsInvalidListen(t *testing.T) {
	valid, warns := validateForwards([]Forward{
		{Listen: "not-an-addr", Target: "x.adnl"},
		{Listen: "127.0.0.1:", Target: "x.adnl"},
	}, fwdSuffixes)
	if len(valid) != 0 {
		t.Fatalf("valid = %+v, want none", valid)
	}
	if len(warns) != 2 {
		t.Fatalf("warns = %d, want 2", len(warns))
	}
}

func TestValidateForwardsEmptyTarget(t *testing.T) {
	valid, warns := validateForwards([]Forward{
		{Listen: "127.0.0.1:1", Target: "  "},
		{Listen: "127.0.0.1:2", Target: "/"},
	}, fwdSuffixes)
	if len(valid) != 0 {
		t.Fatalf("valid = %+v, want none", valid)
	}
	if len(warns) != 2 {
		t.Fatalf("warns = %d, want 2", len(warns))
	}
}

func TestValidateForwardsClearnetTargetWarns(t *testing.T) {
	valid, warns := validateForwards([]Forward{
		{Listen: "127.0.0.1:1", Target: "example.com"},
	}, fwdSuffixes)
	if len(valid) != 1 {
		t.Fatalf("valid = %d, want 1 (kept)", len(valid))
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "clearnet") {
		t.Fatalf("warns = %v, want one clearnet warning", warns)
	}
}

func TestValidateForwardsDuplicateListenKeepsLast(t *testing.T) {
	valid, warns := validateForwards([]Forward{
		{Listen: "127.0.0.1:18090", Target: "first.ton"},
		{Listen: "127.0.0.1:18090", Target: "second.ton"},
	}, fwdSuffixes)
	if len(valid) != 1 {
		t.Fatalf("valid = %d, want 1", len(valid))
	}
	if valid[0].Target != "second.ton" {
		t.Fatalf("target = %q, want second.ton (last wins)", valid[0].Target)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "duplicate") {
		t.Fatalf("warns = %v, want one duplicate warning", warns)
	}
}

func TestValidateForwardsNonLoopbackWarns(t *testing.T) {
	valid, warns := validateForwards([]Forward{
		{Listen: "0.0.0.0:18090", Target: "x.adnl"},
	}, fwdSuffixes)
	if len(valid) != 1 {
		t.Fatalf("valid = %d, want 1 (kept)", len(valid))
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "non-loopback") {
		t.Fatalf("warns = %v, want one non-loopback warning", warns)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "::1", "localhost"} {
		if !isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"0.0.0.0", "192.168.1.10", "example.com"} {
		if isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = true, want false", h)
		}
	}
}
