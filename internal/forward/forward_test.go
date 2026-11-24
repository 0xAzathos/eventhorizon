package forward

import "testing"

func TestLookup(t *testing.T) {
	table, err := Parse("lan=192.168.1.1, iot.lan=192.168.1.2:5353, home.arpa=[fd00::1]:53")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"lan":               "192.168.1.1:53",
		"nas.lan":           "192.168.1.1:53",
		"NAS.LAN.":          "192.168.1.1:53",
		"bulb.iot.lan":      "192.168.1.2:5353", // the longer zone wins
		"printer.home.arpa": "[fd00::1]:53",
		"plan":              "", // a suffix of letters is not a parent zone
		"example.com":       "",
		"":                  "",
	} {
		got, ok := table.Lookup(name)
		if want == "" {
			if ok {
				t.Errorf("Lookup(%q) = %v, want no match", name, got)
			}
			continue
		}
		if !ok || got.String() != want {
			t.Errorf("Lookup(%q) = %v %v, want %s", name, got, ok, want)
		}
	}
}

func TestParseError(t *testing.T) {
	for _, spec := range []string{
		"lan",              // no server
		"=192.168.1.1",     // no zone
		"lan=router.local", // a name, not an IP
		"lan=192.168.1.1:99999",
		"*.lan=192.168.1.1",
		"lan=192.168.1.1,LAN.=192.168.1.2", // the same zone twice
	} {
		if _, err := Parse(spec); err == nil {
			t.Errorf("Parse(%q) accepted a bad rule", spec)
		}
	}
}

func TestEmpty(t *testing.T) {
	table, err := Parse("")
	if err != nil || table.Len() != 0 {
		t.Fatalf("Parse(\"\") = %v, %v", table, err)
	}
	var none *Table
	if _, ok := none.Lookup("nas.lan"); ok {
		t.Fatal("a nil table matched")
	}
}
