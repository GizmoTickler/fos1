// threatintel-controller is the entry point for the Sprint-30 Ticket-44 v0
// ThreatFeed reconciler. It watches ThreatFeed CRs, polls each feed on its
// RefreshInterval, and translates indicators into Cilium deny policies via
// the pkg/security/threatintel package.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	"github.com/GizmoTickler/fos1/pkg/security/threatintel"
)

func main() {
	ciliumAPI := flag.String("cilium-api", "", "Cilium API endpoint (empty uses kubectl)")
	tick := flag.Duration("tick-interval", 15*time.Second, "Reconcile loop tick interval")
	httpTimeout := flag.Duration("http-timeout", 30*time.Second, "HTTP timeout for feed fetches")
	flag.Parse()

	ciliumClient := cilium.NewDefaultCiliumClient(*ciliumAPI, "")

	store, err := threatintel.NewKubectlFeedStore()
	if err != nil {
		log.Fatalf("threatintel-controller: build feed store: %v", err)
	}

	ctrl := threatintel.NewController(store, ciliumClient)
	ctrl.TickInterval = *tick
	ctrl.HTTPClient = &http.Client{Timeout: *httpTimeout}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		fmt.Printf("threatintel-controller: received %v, shutting down\n", sig)
		cancel()
	}()

	log.Println("threatintel-controller: starting reconcile loop")
	if err := ctrl.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("threatintel-controller: run: %v", err)
	}
	log.Println("threatintel-controller: stopped")
}
