package main

import (
	"fmt"
	"net"
)

// hint is one line of advice shown after startup: what to do, and how.
type hint struct {
	what, how string
}

// startupHints tells a new user what to do next: add a blocklist if
// there is none, test the server, point this machine at it, and open telescope.
// The advice depends on the OS, because Windows can only use DNS servers on port 53 and has no dig.
func startupHints(goos, listen string, blocked int, apiAddr string) []hint {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1" // listening everywhere: test through loopback
	}

	var out []hint
	if blocked == 0 {
		out = append(out, hint{"nothing is blocked yet, add a list",
			"-blocklist https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"})
	}

	switch goos {
	case "windows":
		out = append(out, hint{"test it", fmt.Sprintf("nslookup -port=%s doubleclick.net %s", port, host)})
		if port != "53" {
			out = append(out, hint{"Windows only uses DNS servers on port 53",
				"to use it for this machine, start with -listen 127.0.0.1:53"})
		} else {
			out = append(out, hint{"use it for this machine", "set your network adapter's DNS server to " + host})
		}
	default:
		test := fmt.Sprintf("dig @%s -p %s doubleclick.net", host, port)
		if port == "53" {
			test = fmt.Sprintf("dig @%s doubleclick.net", host)
		}
		out = append(out, hint{"test it", test})
		if goos == "linux" {
			out = append(out, hint{"use it for this machine",
				"https://github.com/0xAzathos/eventhorizon#use-it-for-your-whole-machine-linux-with-systemd"})
		}
	}

	switch apiAddr {
	case "":
	case "127.0.0.1:5380":
		out = append(out, hint{"watch it live", "telescope"})
	default:
		out = append(out, hint{"watch it live", "telescope -addr " + apiAddr})
	}
	return out
}
