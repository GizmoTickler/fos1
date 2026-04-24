// threatintel-controller is the entry point for the ThreatFeed reconciler.
// It watches ThreatFeed CRs, polls each feed on its RefreshInterval, and
// translates indicators into Cilium deny policies via the
// pkg/security/threatintel package.
//
// Supports URLhaus CSV (Sprint 30 Ticket 44) and MISP JSON (Sprint 31
// Ticket 53) feed formats. For MISP feeds the controller loads API keys
// from Kubernetes Secrets referenced by spec.authSecretRef via kubectl.
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
	defaultSecretNS := flag.String("default-secret-namespace", "security", "Namespace used to resolve authSecretRef when the ThreatFeed does not set one")
	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig (empty uses in-cluster or KUBECONFIG)")
	flag.Parse()

	ciliumClient := cilium.NewDefaultCiliumClient(*ciliumAPI, "")

	store, err := threatintel.NewKubectlFeedStore()
	if err != nil {
		log.Fatalf("threatintel-controller: build feed store: %v", err)
	}
	store.Kubeconfig = *kubeconfig

	ctrl := threatintel.NewController(store, ciliumClient)
	ctrl.TickInterval = *tick
	ctrl.HTTPClient = &http.Client{Timeout: *httpTimeout}
	ctrl.Secrets = &threatintel.KubectlSecretReader{Kubeconfig: *kubeconfig}
	ctrl.DefaultSecretNamespace = *defaultSecretNS

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
