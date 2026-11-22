// telescope is a live terminal dashboard for eventhorizon: what you see
// when you look at the event horizon.
//
//	go run . -addr 127.0.0.1:5380
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/0xAzathos/eventhorizon/internal/api"
	"github.com/0xAzathos/eventhorizon/internal/apiclient"
	"github.com/0xAzathos/eventhorizon/internal/events"
	"github.com/0xAzathos/eventhorizon/internal/version"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:5380", "eventhorizon API address")
	tokenFile := flag.String("token-file", "", "API token file, when eventhorizon runs with -api-token-file (or set EVENTHORIZON_API_TOKEN)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("telescope", version.String())
		return
	}

	client := apiclient.New(*addr)
	if token := os.Getenv("EVENTHORIZON_API_TOKEN"); token != "" {
		client.SetToken(token)
	}
	if *tokenFile != "" {
		token, err := api.ReadToken(*tokenFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "telescope:", err)
			os.Exit(1)
		}
		client.SetToken(token)
	}
	p := tea.NewProgram(newModel(client, *addr))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go stream(ctx, client, p)

	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "telescope:", err)
		os.Exit(1)
	}
}

// stream keeps the live event feed connected, reconnecting with backoff
// when eventhorizon restarts. Events go into the program with p.Send,
// which is safe to call from other goroutines.
func stream(ctx context.Context, client *apiclient.Client, p *tea.Program) {
	for attempt := 0; ctx.Err() == nil; attempt++ {
		// A new connection replays the recent backlog, so start clean
		// instead of showing those events twice.
		p.Send(streamRestartMsg{})

		received := false
		client.Stream(ctx, func(e events.Event) {
			received = true
			p.Send(eventMsg(e))
		})
		if received {
			attempt = 0 // it worked for a while; retry quickly
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(apiclient.Backoff(attempt)):
		}
	}
}
