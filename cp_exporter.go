package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type CertInfo struct {
	IssuerINN      string
	User           string
	Serial         string
	NotBefore      string
	NotAfter       string
	Thumbprint     string
	SignatureAlgo  string
	PrivateKeyLink string
	Container      string
	NotValidAfter  time.Time
}

var (
	certExpiration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cert_expiration_seconds",
			Help: "Seconds until certificate expiration for individual certs",
		},
		[]string{"issuer_inn", "user", "serial", "not_before", "not_after", "thumbprint", "signature_algo", "private_key", "container"},
	)
)

func init() {
	prometheus.MustRegister(certExpiration)
}

var (
	reSeparator = regexp.MustCompile(`^\d+-+$`)
	reIssuer    = regexp.MustCompile(`Issuer\s*:\s*(.+)`)
	reIssuerINN = regexp.MustCompile(`ИНН( ЮЛ)?=([0-9]+)`)

	reUser         = regexp.MustCompile(`^User\s*:\s*(.+)$`)
	reSerial       = regexp.MustCompile(`^Serial\s*:\s*(.+)$`)
	reThumbprint   = regexp.MustCompile(`^SHA1 Thumbprint\s*:\s*(.+)$`)
	reSigAlgo      = regexp.MustCompile(`^Signature Algorithm\s*:\s*(.+)$`)
	rePrivateKey   = regexp.MustCompile(`^PrivateKey Link\s*:\s*(.+)$`)
	reContainer    = regexp.MustCompile(`^Container\s*:\s*(.+)$`)
	reNotBefore    = regexp.MustCompile(`^Not valid before\s*:\s*(.+)$`)
	reNotAfter     = regexp.MustCompile(`^Not valid after\s*:\s*(.+)$`)
)

func parseCertOutput(output string) []CertInfo {
	var certs []CertInfo
	var current CertInfo
	lines := strings.Split(output, "\n")

	dateLayout := "02/01/2006 15:04:05 MST"

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if reSeparator.MatchString(line) {
			if current.Thumbprint != "" {
				certs = append(certs, current)
				current = CertInfo{}
			}
			continue
		}

		if m := reIssuer.FindStringSubmatch(line); len(m) == 2 {
			if inn := reIssuerINN.FindStringSubmatch(m[1]); len(inn) > 2 {
				current.IssuerINN = inn[2]
			}
		} else if m := reUser.FindStringSubmatch(line); len(m) == 2 {
			current.User = m[1]
		} else if m := reSerial.FindStringSubmatch(line); len(m) == 2 {
			current.Serial = m[1]
		} else if m := reThumbprint.FindStringSubmatch(line); len(m) == 2 {
			current.Thumbprint = m[1]
		} else if m := reSigAlgo.FindStringSubmatch(line); len(m) == 2 {
			current.SignatureAlgo = m[1]
		} else if m := rePrivateKey.FindStringSubmatch(line); len(m) == 2 {
			current.PrivateKeyLink = m[1]
		} else if m := reContainer.FindStringSubmatch(line); len(m) == 2 {
			current.Container = m[1]
		} else if m := reNotBefore.FindStringSubmatch(line); len(m) == 2 {
			current.NotBefore = m[1]
		} else if m := reNotAfter.FindStringSubmatch(line); len(m) == 2 {
			current.NotAfter = m[1]
			t, err := time.Parse(dateLayout, strings.TrimSpace(m[1]))
			if err == nil {
				current.NotValidAfter = t
			}
		}
	}
	if current.Thumbprint != "" {
		certs = append(certs, current)
	}

	return certs
}

func runCertmgr(user, certmgrPath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "-u", user, certmgrPath, "-list")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%w; output: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func updateMetrics(certs []CertInfo) {
	certExpiration.Reset()
	for _, cert := range certs {
		secondsLeft := time.Until(cert.NotValidAfter).Seconds()

		certExpiration.WithLabelValues(
			cert.IssuerINN,
			cert.User,
			cert.Serial,
			cert.NotBefore,
			cert.NotAfter,
			cert.Thumbprint,
			cert.SignatureAlgo,
			cert.PrivateKeyLink,
			cert.Container,
		).Set(secondsLeft)
	}
}

func updateAllMetrics(users []string, certmgrPath string) {
	var outputs string

	for _, user := range users {
		output, err := runCertmgr(user, certmgrPath)
		if err != nil {
			log.Printf("Error running certmgr for user %s: %v", user, err)
			if output == "" {
				continue
			}
		}

		lines := strings.Split(output, "\n")
		var result []string

		for _, line := range lines {
			result = append(result, line)
			if strings.HasPrefix(line, "Issuer              :") {
				result = append(result, "User              : "+user)
			}
		}
		output = strings.Join(result, "\n")

		outputs += output + "\n"
	}

	certs := parseCertOutput(outputs)
	updateMetrics(certs)
}

func main() {
	users := flag.String("users", "nginx", "Comma-separated list of users")
	port := flag.Int("port", 9105, "TCP port")
	interval := flag.Int("interval", 60, "Update interval in seconds")
	certmgrPath := flag.String("certmgr", "/opt/cprocsp/bin/amd64/certmgr", "Path to certmgr binary")
	flag.Parse()

	if *port < 1 || *port > 65535 {
		log.Fatalf("Invalid port: %d", *port)
	}

	usersSlice := strings.Split(*users, ",")

	updateAllMetrics(usersSlice, *certmgrPath)

	go func() {
		ticker := time.NewTicker(time.Duration(*interval) * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			updateAllMetrics(usersSlice, *certmgrPath)
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:    ":" + strconv.Itoa(*port),
		Handler: mux,
	}

	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Println("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
	}()

	log.Printf("Exporter listening on :%d/metrics, users: %s", *port, *users)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %v", err)
	}
}
