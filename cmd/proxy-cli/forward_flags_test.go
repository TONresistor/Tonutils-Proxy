package main

import "testing"

func TestForwardFlagsSet(t *testing.T) {
	var f forwardFlags
	if err := f.Set("127.0.0.1:18090=node.ton"); err != nil {
		t.Fatalf("Set valid: %v", err)
	}
	if len(f) != 1 || f[0].Listen != "127.0.0.1:18090" || f[0].Target != "node.ton" {
		t.Fatalf("parsed = %+v", f)
	}
	if err := f.Set("127.0.0.1:1=a=b"); err != nil {
		t.Fatalf("Set with '=' in target: %v", err)
	}
	if f[1].Target != "a=b" {
		t.Fatalf("target = %q, want a=b", f[1].Target)
	}
}

func TestForwardFlagsSetInvalid(t *testing.T) {
	for _, in := range []string{"noequals", "=missingleft", "missingright="} {
		var f forwardFlags
		if err := f.Set(in); err == nil {
			t.Errorf("Set(%q) = nil err, want error", in)
		}
	}
}

func TestForwardFlagsString(t *testing.T) {
	f := forwardFlags{
		{Listen: "127.0.0.1:1", Target: "a.ton"},
		{Listen: "127.0.0.1:2", Target: "b.adnl"},
	}
	if got, want := f.String(), "127.0.0.1:1=a.ton,127.0.0.1:2=b.adnl"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
