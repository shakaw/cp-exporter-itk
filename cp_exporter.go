package main

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"strconv"
	"time"
	"net/http"
	"flag"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type CertInfo struct {
	IssuerINN         string
	User              string
	Serial            string
	NotBefore         string
	NotAfter          string
	Thumbprint        string
	SignatureAlgo     string
	PrivateKeyLink    string
	Container         string
	NotValidAfter     time.Time
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

func parseCertOutput(output string) []CertInfo {
	var certs []CertInfo
	var current CertInfo
	lines := strings.Split(output, "\n")

	dateLayout := "02/01/2006 15:04:05 MST"
	reIssuer := regexp.MustCompile(`Issuer\s*:\s*(.+)`)
	reIssuerINN := regexp.MustCompile(`ИНН( ЮЛ)?=([0-9]+)`)
	reField := func(name string) *regexp.Regexp {
		return regexp.MustCompile(fmt.Sprintf(`^%s\s*:\s*(.+)$`, regexp.QuoteMeta(name)))
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if matched, _ := regexp.MatchString(`^\d+-+$`, line); matched {
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
		} else if m := reField("User").FindStringSubmatch(line); len(m) == 2 {
			current.User = m[1]
		} else if m := reField("Serial").FindStringSubmatch(line); len(m) == 2 {
			current.Serial = m[1]
		} else if m := reField("SHA1 Thumbprint").FindStringSubmatch(line); len(m) == 2 {
			current.Thumbprint = m[1]
		} else if m := reField("Signature Algorithm").FindStringSubmatch(line); len(m) == 2 {
			current.SignatureAlgo = m[1]
		} else if m := reField("PrivateKey Link").FindStringSubmatch(line); len(m) == 2 {
			current.PrivateKeyLink = m[1]
		} else if m := reField("Container").FindStringSubmatch(line); len(m) == 2 {
			current.Container = m[1]
		} else if m := reField("Not valid before").FindStringSubmatch(line); len(m) == 2 {
			current.NotBefore = m[1]
		} else if m := reField("Not valid after").FindStringSubmatch(line); len(m) == 2 {
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

func runCertmgr(user string) (string, error) {
	cmd := exec.Command("sudo", "-u", user, "/opt/cprocsp/bin/amd64/certmgr", "-list")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func subTimeAbs(later, earlier time.Time) time.Duration {
    diff := later.Sub(earlier)
    return diff
}

func updateMetrics(certs []CertInfo) {
	now := time.Now()
	for _, cert := range certs {
		secondsLeft := subTimeAbs(cert.NotValidAfter, now).Seconds()

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

func updateAllMetrics(users []string) {
	var outputs string

	for _, user := range users {
		output, err := runCertmgr(user)
		if err != nil {
			log.Printf("Error running certmgr for user %s: %v", user, err)
			continue
		}

		lines := strings.Split(output, "\n")
		var result []string

		for _, line := range lines {
			result = append(result, line)
			if strings.HasPrefix(line, "Issuer              :") {
				result = append(result, "User              : " + user)
			}
		}
		output = strings.Join(result, "\n")

		outputs += output + "\n"
	}

	certs := parseCertOutput(outputs)
	updateMetrics(certs)
}

func main() {
	users := flag.String("users", "nginx", "User")
	port := flag.Int("port", 9105, "TCP port")
	interval := flag.Int("interval", 60, "Update interval in seconds")
	flag.Parse()

	usersSlice := strings.Split(*users, ",")

	go func() {
		ticker := time.NewTicker(time.Duration(*interval) * time.Second)
		defer ticker.Stop()

		for {
			updateAllMetrics(usersSlice)
			<-ticker.C
		}
	}()

	updateAllMetrics(usersSlice)

	http.Handle("/metrics", promhttp.Handler())
	log.Println("Exporter listening on :" + strconv.Itoa(*port) + "/metrics\nUsers : " + *users)
	log.Fatal(http.ListenAndServe(":" + strconv.Itoa(*port), nil))

}

