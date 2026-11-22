// Package punycode converts Unicode domain labels to the ASCII form used on
// the wire, e.g. "bücher" becomes "xn--bcher-kva". Only encoding is needed:
// we turn Unicode rules from the Public Suffix List into what DNS queries
// actually contain.
//
// The algorithm is RFC 3492 ("Bootstring" with the punycode parameters).
// The idea: copy the ASCII characters as they are, then describe where each
// non ASCII character goes as a series of numbers, written in a compact
// variable length base 36 code.
package punycode

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// RFC 3492 section 5: parameter values for punycode.
const (
	base        = 36
	tmin        = 1
	tmax        = 26
	skew        = 38
	damp        = 700
	initialBias = 72
	initialN    = 128
)

var errOverflow = errors.New("punycode: overflow")

// ToASCII returns the wire form of one label: unchanged (lowercased) if it
// is already ASCII, otherwise "xn--" plus the punycode encoding.
func ToASCII(label string) (string, error) {
	label = strings.ToLower(label)
	if isASCII(label) {
		return label, nil
	}
	enc, err := Encode(label)
	if err != nil {
		return "", err
	}
	return "xn--" + enc, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// Encode implements RFC 3492 section 6.3.
func Encode(s string) (string, error) {
	input := []rune(s)
	var out strings.Builder

	// Basic (ASCII) code points are copied first, in order.
	for _, r := range input {
		if r < 0x80 {
			out.WriteRune(r)
		}
	}
	basic := out.Len()
	handled := basic
	if basic > 0 {
		out.WriteByte('-') // separates the basic part from the encoded part
	}

	n, delta, bias := rune(initialN), 0, initialBias

	for handled < len(input) {
		// The next code point to insert: the smallest one not yet handled.
		m := rune(utf8.MaxRune + 1)
		for _, r := range input {
			if r >= n && r < m {
				m = r
			}
		}

		// Skip ahead: every step past a code point costs (handled+1).
		step := int(m-n) * (handled + 1)
		if step/(handled+1) != int(m-n) || delta+step < delta {
			return "", errOverflow
		}
		delta += step
		n = m

		for _, r := range input {
			if r < n {
				delta++
			}
			if r == n {
				// Write delta as a generalized variable length integer.
				q := delta
				for k := base; ; k += base {
					t := threshold(k, bias)
					if q < t {
						break
					}
					out.WriteByte(digit(t + (q-t)%(base-t)))
					q = (q - t) / (base - t)
				}
				out.WriteByte(digit(q))
				bias = adapt(delta, handled+1, handled == basic)
				delta = 0
				handled++
			}
		}
		delta++
		n++
	}
	return out.String(), nil
}

// threshold is the "t" of RFC 3492 section 6.3, clamped to [tmin, tmax].
func threshold(k, bias int) int {
	switch {
	case k <= bias:
		return tmin
	case k >= bias+tmax:
		return tmax
	default:
		return k - bias
	}
}

// adapt is RFC 3492 section 6.1: tune the bias after each code point so
// typical deltas need few digits.
func adapt(delta, numPoints int, first bool) int {
	if first {
		delta /= damp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((base-tmin)*tmax)/2 {
		delta /= base - tmin
		k += base
	}
	return k + (base-tmin+1)*delta/(delta+skew)
}

// digit maps 0..25 to 'a'..'z' and 26..35 to '0'..'9'.
func digit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}
