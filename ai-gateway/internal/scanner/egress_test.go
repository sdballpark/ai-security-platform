package scanner

import (
	"context"
	"strings"
	"testing"
)

func TestEgressDetectsSecretsAndRedacts(t *testing.T) {
	e := NewEgressScanner()
	leak := "Sure! The API key is sk-ABCDEFGHIJKLMNOPQRSTUVWX and the root key is AKIAIOSFODNN7EXAMPLE."
	ds, err := e.Scan(context.Background(), leak)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) < 2 {
		t.Fatalf("expected >=2 detections, got %d", len(ds))
	}
	for _, d := range ds {
		// The redacted excerpt must not contain the raw secret value.
		if strings.Contains(d.Excerpt, "ABCDEFGHIJKLMNOPQRSTUVWX") ||
			strings.Contains(d.Excerpt, "IOSFODNN7EXAMPLE") {
			t.Fatalf("excerpt leaked the secret: %q", d.Excerpt)
		}
	}
}

func TestEgressLuhnFiltersInvalidCards(t *testing.T) {
	e := NewEgressScanner()
	// Valid Visa test number passes Luhn; the second 16-digit run does not.
	valid := "card on file: 4111 1111 1111 1111"
	invalid := "order number: 4111 1111 1111 1112"

	dv, _ := e.Scan(context.Background(), valid)
	if !hasDetector(dv, "credit_card") {
		t.Fatal("valid Luhn card should be detected")
	}
	di, _ := e.Scan(context.Background(), invalid)
	if hasDetector(di, "credit_card") {
		t.Fatal("invalid Luhn run should be filtered out")
	}
}

func TestEgressCleanOutputIsClean(t *testing.T) {
	e := NewEgressScanner()
	ds, _ := e.Scan(context.Background(), "Your quarterly revenue grew 12% over the prior period.")
	if len(ds) != 0 {
		t.Fatalf("benign output should not flag, got %v", ds)
	}
}

func hasDetector(ds []Detection, name string) bool {
	for _, d := range ds {
		if d.Detector == name {
			return true
		}
	}
	return false
}
