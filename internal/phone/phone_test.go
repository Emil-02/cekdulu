package phone

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in, e164, masked, op, typ string
	}{
		{"0812-3456-7890", "+6281234567890", "0812*****890", "Telkomsel", "seluler"},
		{"+62 857 1234 5678", "+6285712345678", "0857*****678", "Indosat Ooredoo", "seluler"},
		{"6287812345678", "+6287812345678", "0878*****678", "XL Axiata", "seluler"},
		{"(021) 5551234", "+62215551234", "0215***234", "", "telepon rumah/kantor"},
		{"81234567890", "+6281234567890", "0812*****890", "Telkomsel", "seluler"},
	}
	for _, c := range cases {
		n, err := Parse(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if n.E164 != c.e164 || n.Masked != c.masked || n.Operator != c.op || n.Type != c.typ {
			t.Errorf("%s: got %+v", c.in, n)
		}
	}
	n, err := Parse("+1 415 555 0100")
	if err != nil || n.Country == "ID" {
		t.Fatalf("foreign: %+v %v", n, err)
	}
	if sigs := Signals(n, nil); len(sigs) != 1 || sigs[0].ID != "phone.foreign" {
		t.Fatalf("foreign signal: %v", sigs)
	}
	for _, bad := range []string{"", "abc", "0812", "08123456789012345", "+12"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}
