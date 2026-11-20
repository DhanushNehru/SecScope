package main

import "testing"

func TestChoose(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
		want string
	}{
		{"single core", Spec{CPUs: 1, TotalMemMB: 8192}, "low"},
		{"two cores", Spec{CPUs: 2, TotalMemMB: 16384}, "low"},
		{"little memory", Spec{CPUs: 8, TotalMemMB: 1024}, "low"},
		{"mid range", Spec{CPUs: 4, TotalMemMB: 8192}, "balanced"},
		{"big cpu small ram", Spec{CPUs: 16, TotalMemMB: 8192}, "balanced"},
		{"large", Spec{CPUs: 16, TotalMemMB: 32768}, "high"},
		{"edge high", Spec{CPUs: 8, TotalMemMB: 16384}, "high"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, why := Choose(c.spec)
			if m.Name != c.want {
				t.Fatalf("Choose(%+v) = %s, want %s (%s)", c.spec, m.Name, c.want, why)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	if _, _, err := Resolve("nonsense", Spec{}); err == nil {
		t.Fatal("expected error for unknown mode")
	}
	m, _, err := Resolve("low", Spec{CPUs: 64, TotalMemMB: 1 << 20})
	if err != nil || m.Name != "low" {
		t.Fatalf("forced low got %v %v", m, err)
	}
	if _, _, err := Resolve("", Spec{CPUs: 1, TotalMemMB: 512}); err != nil {
		t.Fatal(err)
	}
}
