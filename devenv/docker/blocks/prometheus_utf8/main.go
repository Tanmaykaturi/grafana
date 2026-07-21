package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	mathrand "math/rand/v2"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/model"
)

func randomValues(max int) func() (string, bool) {
	i := 0
	return func() (string, bool) {
		i++
		return strconv.Itoa(i), i < max+1
	}
}

func staticList(input []string) func() string {
	return func() string {
		i := mathrand.IntN(len(input))

		return input[i]
	}
}

// generateSelfSignedCert creates a temporary self-signed TLS certificate and
// key, writes them to certFile/keyFile on disk, and returns any error.
func generateSelfSignedCert(certFile, keyFile string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

type dimension struct {
	label        string
	getNextValue func() string
}

func init() {
	// This can be removed when the default validation scheme in common is updated.
	model.NameValidationScheme = model.UTF8Validation
	model.NameEscapingScheme = model.ValueEncodingEscaping
}

func main() {

	fakeUtf8Metrics := []dimension{
		{
			label:        "a_legacy_label",
			getNextValue: staticList([]string{"legacy"}),
		},
		{
			label:        "label with space",
			getNextValue: staticList([]string{"space"}),
		},
		{
			label:        "label with 📈",
			getNextValue: staticList([]string{"metrics"}),
		},
		{
			label:        "label.with.spaß",
			getNextValue: staticList([]string{"this_is_fun"}),
		},
		{
			label:        "instance",
			getNextValue: staticList([]string{"instance"}),
		},
		{
			label:        "job",
			getNextValue: staticList([]string{"job"}),
		},
		{
			label:        "site",
			getNextValue: staticList([]string{"LA-EPI"}),
		},
		{
			label:        "room",
			getNextValue: staticList([]string{`"Friends Don't Lie"`}),
		},
	}

	dimensions := []string{}
	for _, dim := range fakeUtf8Metrics {
		dimensions = append(dimensions, dim.label)
	}

	utf8Metric := promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "a.utf8.metric 🤘",
		Help: "a utf8 metric with utf8 labels",
	}, dimensions)

	opsProcessed := promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "a_utf8_http_requests_total",
		Help: "a metric with utf8 labels",
	}, dimensions)

	target_info := promauto.NewGauge(prometheus.GaugeOpts{
		Name:        "target_info",
		Help:        "an info metric model for otel",
		ConstLabels: map[string]string{"job": "job", "instance": "instance", "resource 1": "1", "resource 2": "2", "resource ę": "e", "deployment_environment": "prod"},
	})

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, is it me you're looking for?"))
	})

	go func() {
		for {
			labels := []string{}
			for _, dim := range fakeUtf8Metrics {
				value := dim.getNextValue()
				labels = append(labels, value)
			}

			utf8Metric.WithLabelValues(labels...).Inc()
			opsProcessed.WithLabelValues(labels...).Inc()
			target_info.Set(1)

			time.Sleep(time.Second * 5)
		}
	}()

	const certFile = "cert.pem"
	const keyFile = "key.pem"
	if err := generateSelfSignedCert(certFile, keyFile); err != nil {
		log.Fatalf("Failed to generate TLS certificate: %v", err)
	}

	fmt.Printf("Server started at :9112 (TLS)\n")

	log.Fatal(http.ListenAndServeTLS(":9112", certFile, keyFile, nil))
}
