// Command train builds the detection data embedded in eventhorizon and
// measures how well it works.
//
//	curl -LO https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz
//	go run ./cmd/train -crux current.csv.gz -dga internal/detect/testdata/dga_examples.tsv
//
// It writes internal/detect/data/trigram.bin.gz and popular.txt.gz.
package main

import (
	"bufio"
	"compress/gzip"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/0xAzathos/eventhorizon/internal/detect"
	"github.com/0xAzathos/eventhorizon/internal/psl"
)

func main() {
	cruxPath := flag.String("crux", "", "Chrome UX Report top list (.csv.gz with origin,rank)")
	dgaPath := flag.String("dga", "", "optional family<TAB>domain file to measure detection")
	outDir := flag.String("out", "internal/detect/data", "output directory")
	popularRank := flag.Int("popular-rank", 100000, "sites up to this rank go in the popular list")
	flag.Parse()
	if *cruxPath == "" {
		log.Fatal("-crux is required")
	}

	labels, popular, err := readCrUX(*cruxPath, *popularRank)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%d unique labels, %d popular registrable domains", len(labels), len(popular))

	if *dgaPath != "" {
		if err := evaluate(labels, *dgaPath); err != nil {
			log.Fatal(err)
		}
	}

	// The shipped model learns from every label; the holdout split above
	// exists only to measure it honestly.
	var counts detect.Counts
	for l := range labels {
		counts.Add(l)
	}
	if err := writeModel(*outDir+"/trigram.bin.gz", &counts); err != nil {
		log.Fatal(err)
	}
	if err := writePopular(*outDir+"/popular.txt.gz", popular); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s", *outDir)
}

// readCrUX returns each usable registered label with its best rank, and
// the registrable domains of sites ranked at or above popularRank.
func readCrUX(path string, popularRank int) (map[string]int, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, err
	}

	labels := make(map[string]int)
	popSet := make(map[string]bool)
	sc := bufio.NewScanner(zr)
	sc.Scan() // header: origin,rank
	for sc.Scan() {
		origin, rankStr, ok := strings.Cut(sc.Text(), ",")
		if !ok {
			continue
		}
		rank, err := strconv.Atoi(rankStr)
		if err != nil {
			continue
		}
		host := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
		if i := strings.LastIndexByte(host, ':'); i >= 0 {
			host = host[:i] // drop a port
		}
		p := psl.Default.Split(strings.ToLower(host))
		if p.Registrable == "" {
			continue
		}
		if rank <= popularRank {
			popSet[p.Registrable] = true
		}
		// IDN labels look random by nature; they would teach the model noise.
		if strings.HasPrefix(p.Label, "xn--") {
			continue
		}
		if best, seen := labels[p.Label]; !seen || rank < best {
			labels[p.Label] = rank
		}
	}
	popular := make([]string, 0, len(popSet))
	for d := range popSet {
		popular = append(popular, d)
	}
	slices.Sort(popular)
	return labels, popular, sc.Err()
}

// evaluate trains on 90% of labels and scores the other 10% (false
// positives, split by popularity) and the DGA samples (detection).
func evaluate(labels map[string]int, dgaPath string) error {
	all := make([]string, 0, len(labels))
	for l := range labels {
		all = append(all, l)
	}
	slices.Sort(all) // map order is random; sort so the shuffle is repeatable
	rng := rand.New(rand.NewPCG(7, 7))
	rng.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
	cut := len(all) * 9 / 10

	var counts detect.Counts
	for _, l := range all[:cut] {
		counts.Add(l)
	}
	m := detect.NewModel(&counts)

	type sample struct{ family, label string }
	var dga []sample
	f, err := os.Open(dgaPath)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fam, domain, ok := strings.Cut(line, "\t")
		if ok {
			dga = append(dga, sample{fam, psl.Default.Split(domain).Label})
		}
	}

	const minLen = 8
	thresholds := []float64{-3.2, -3.4, -3.6, -3.8}
	fmt.Printf("\nthreshold | FP popular (top 100k) | FP long tail | DGA detected\n")
	for _, thr := range thresholds {
		var popN, popFP, tailN, tailFP, dgaN, dgaHit int
		for _, l := range all[cut:] {
			s, ok := m.Score(l)
			if !ok || len(l) < minLen {
				continue
			}
			if labels[l] <= 100000 {
				popN++
				if s < thr {
					popFP++
				}
			} else {
				tailN++
				if s < thr {
					tailFP++
				}
			}
		}
		for _, d := range dga {
			if s, ok := m.Score(d.label); ok && len(d.label) >= minLen {
				dgaN++
				if s < thr {
					dgaHit++
				}
			}
		}
		fmt.Printf("%9.1f | %20.2f%% | %11.2f%% | %10.1f%% of %d\n",
			thr, pct(popFP, popN), pct(tailFP, tailN), pct(dgaHit, dgaN), dgaN)
	}

	// Per family at the default threshold: which kinds slip through.
	def := detect.DefaultConfig().DGAThreshold
	fmt.Printf("\nper family at %.1f:\n", def)
	hit, tot := map[string]int{}, map[string]int{}
	var fams []string
	for _, d := range dga {
		s, ok := m.Score(d.label)
		if !ok || len(d.label) < minLen {
			continue
		}
		if tot[d.family] == 0 {
			fams = append(fams, d.family)
		}
		tot[d.family]++
		if s < def {
			hit[d.family]++
		}
	}
	slices.SortFunc(fams, func(a, b string) int { return hit[a]*tot[b] - hit[b]*tot[a] })
	for _, f := range fams {
		fmt.Printf("  %-24s %2d/%-2d\n", f, hit[f], tot[f])
	}
	return nil
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

func writeModel(path string, c *detect.Counts) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := c.WriteTo(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func writePopular(path string, domains []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	zw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		f.Close()
		return err
	}
	w := bufio.NewWriter(zw)
	for _, d := range domains {
		w.WriteString(d)
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
