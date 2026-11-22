package punycode

import "testing"

// Expected values were produced by Python's built in "punycode" codec, an
// independent implementation of the same RFC.
func TestEncode(t *testing.T) {
	cases := map[string]string{
		"bücher":   "bcher-kva",
		"公司":       "55qx5d",
		"網絡":       "od0alg",
		"aéroport": "aroport-bya",
		"münchen":  "mnchen-3ya",
		"ελληνικά": "hxargifdar",
		"россия":   "h1alffa9f",
		"日本語":      "wgv71a119e",
		"ü":        "tda",
		"a-ü-b":    "a--b-1ra",
		"例え":       "r8jz45g",
		"嘿嘿嘿嘿嘿":    "g6raaaa",
	}
	for in, want := range cases {
		got, err := Encode(in)
		if err != nil || got != want {
			t.Errorf("Encode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestToASCII(t *testing.T) {
	cases := map[string]string{
		"example": "example",
		"EXAMPLE": "example",
		"bücher":  "xn--bcher-kva",
		"BÜCHER":  "xn--bcher-kva",
		"公司":      "xn--55qx5d",
	}
	for in, want := range cases {
		if got, err := ToASCII(in); err != nil || got != want {
			t.Errorf("ToASCII(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
