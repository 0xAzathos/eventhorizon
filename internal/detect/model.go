package detect

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"strings"
)

// The model is a character trigram model: for every pair of characters it
// knows how likely each next character is in real domain names. A name made
// of combinations real names rarely use gets a low score.
//
// Alphabet: index 0 marks the start and end of a label, then a..z, 0..9
// and '-'. Labels with any other character are not scored.
const alphabet = 38

func symbol(c byte) (int, bool) {
	switch {
	case c >= 'a' && c <= 'z':
		return 1 + int(c-'a'), true
	case c >= '0' && c <= '9':
		return 27 + int(c-'0'), true
	case c == '-':
		return 37, true
	}
	return 0, false
}

// Counts holds how often each trigram was seen during training, indexed
// as (first*alphabet + second)*alphabet + third.
type Counts [alphabet * alphabet * alphabet]uint32

// Add counts every trigram of one label, padded as "^^label$".
func (c *Counts) Add(label string) bool {
	syms, ok := symbols(label)
	if !ok {
		return false
	}
	for i := 0; i+2 < len(syms); i++ {
		c[(syms[i]*alphabet+syms[i+1])*alphabet+syms[i+2]]++
	}
	return true
}

func symbols(label string) ([]int, bool) {
	if label == "" {
		return nil, false
	}
	syms := make([]int, 0, len(label)+3)
	syms = append(syms, 0, 0)
	for i := 0; i < len(label); i++ {
		s, ok := symbol(label[i])
		if !ok {
			return nil, false
		}
		syms = append(syms, s)
	}
	return append(syms, 0), true
}

const magic = "EHT1"

// WriteTo stores the counts gzip compressed: magic, then little endian
// uint32 values.
func (c *Counts) WriteTo(w io.Writer) (int64, error) {
	zw, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return 0, err
	}
	if _, err := zw.Write([]byte(magic)); err != nil {
		return 0, err
	}
	if err := binary.Write(zw, binary.LittleEndian, c[:]); err != nil {
		return 0, err
	}
	return 0, zw.Close()
}

func ReadCounts(r io.Reader) (*Counts, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	head := make([]byte, len(magic))
	if _, err := io.ReadFull(zr, head); err != nil {
		return nil, err
	}
	if string(head) != magic {
		return nil, errors.New("detect: not a trigram model file")
	}
	c := new(Counts)
	if err := binary.Read(zr, binary.LittleEndian, c[:]); err != nil {
		return nil, err
	}
	return c, nil
}

// smoothing is added to every count so unseen trigrams are unlikely
// rather than impossible (additive smoothing).
const smoothing = 0.1

// Model turns counts into log probabilities once, so scoring is a few
// table lookups per character.
type Model struct {
	logp [alphabet * alphabet * alphabet]float32
}

func NewModel(c *Counts) *Model {
	m := new(Model)
	for ctx := 0; ctx < alphabet*alphabet; ctx++ {
		row := c[ctx*alphabet : (ctx+1)*alphabet]
		var total float64
		for _, v := range row {
			total += float64(v)
		}
		for next, v := range row {
			p := (float64(v) + smoothing) / (total + smoothing*alphabet)
			m.logp[ctx*alphabet+next] = float32(math.Log(p))
		}
	}
	return m
}

// Score is the average log probability per character transition. Real
// words land around -2.8; random strings around -3.9. ok is false for
// labels the model cannot score.
func (m *Model) Score(label string) (score float64, ok bool) {
	syms, ok := symbols(label)
	if !ok {
		return 0, false
	}
	var sum float64
	n := 0
	for i := 0; i+2 < len(syms); i++ {
		sum += float64(m.logp[(syms[i]*alphabet+syms[i+1])*alphabet+syms[i+2]])
		n++
	}
	return sum / float64(n), true
}

//go:embed data/trigram.bin.gz
var trigramData []byte

//go:embed data/popular.txt.gz
var popularData []byte

// DefaultModel is trained on Chrome UX Report top sites (see cmd/train).
func DefaultModel() (*Model, error) {
	c, err := ReadCounts(bytes.NewReader(trigramData))
	if err != nil {
		return nil, err
	}
	return NewModel(c), nil
}

// DefaultPopular returns the registrable domains of the most visited
// sites. Detection skips them: they are not malware infrastructure, and
// big platforms produce exactly the odd looking names that cause false
// alarms.
func DefaultPopular() (map[string]bool, error) {
	zr, err := gzip.NewReader(bytes.NewReader(popularData))
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool)
	for _, d := range strings.Fields(string(data)) {
		set[d] = true
	}
	return set, nil
}
