package account

import "testing"

func TestParse(t *testing.T) {
	a, err := Parse("BCA", "123 456 7890")
	if err != nil || a.Canonical != "bank:bca:1234567890" || a.Masked != "BCA ******7890" {
		t.Fatalf("%+v %v", a, err)
	}
	a, err = Parse("dana", "0812-3456-7890")
	if err != nil || a.Canonical != "ewallet:dana:+6281234567890" || a.Masked != "DANA 0812*****890" {
		t.Fatalf("%+v %v", a, err)
	}
	if _, err := Parse("bankxyz", "123456"); err != ErrProvider {
		t.Fatal(err)
	}
	for _, bad := range []string{"123", "12345a", "123456789012345678901"} {
		if _, err := Parse("bri", bad); err != ErrNumber {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := Parse("ovo", "021555123"); err != ErrNumber {
		t.Fatal("e-wallet must be a mobile number")
	}
}
