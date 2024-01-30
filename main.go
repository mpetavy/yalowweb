package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/mpetavy/common"
	"html/template"
	"net/http"
	"os"
	"time"
)

type PatientDetails struct {
	ID        string
	LastName  string
	FirstName string
	BirthDate string
	Sex       string
	Worklist  string
}

type OrderDetails struct {
	ID              string
	AccessionNumber string
	StartDate       string
	EndDate         string
	Status          string
}

var (
	dir          = flag.String("d", "", "directory to serve")
	port         = flag.Int("port", 8443, "port to serve the directory")
	username     = flag.String("username", "", "username")
	password     = flag.String("password", "", "password")
	useTls       = flag.Bool("tls", false, "use TLS")
	certFilename = flag.String("certfile", "", "x509 cert filename")
	keyFilename  = flag.String("keyfile", "", "x509 private key filename")
	certFile     *os.File
	keyFile      *os.File
)

//go:embed go.mod
var resources embed.FS

func init() {
	common.Init("", "", "", "", "", "", "", "", &resources, start, nil, nil, 0)
}

func start() error {
	if *useTls && *certFilename == "" {
		tlsConfig, err := common.NewTlsConfigFromFlags()
		if common.Error(err) {
			return err
		}

		certPEM := common.CertificateAsPEM(&tlsConfig.Certificates[0])
		certBytes, _ := pem.Decode(certPEM)
		if certBytes == nil {
			return fmt.Errorf("cannot find PEM block with certificate")
		}

		certFile, err = common.CreateTempFile()
		if common.Error(err) {
			return err
		}
		*certFilename = certFile.Name()

		err = os.WriteFile(certFile.Name(), certPEM, common.DefaultFileMode)
		if common.Error(err) {
			return err
		}

		keyPEM, err := common.PrivateKeyAsPEM(tlsConfig.Certificates[0].PrivateKey.(*ecdsa.PrivateKey))
		if common.Error(err) {
			return err
		}
		keyBytes, _ := pem.Decode(keyPEM)
		if keyBytes == nil {
			return fmt.Errorf("cannot find PEM block with key")
		}

		keyFile, err = common.CreateTempFile()
		if common.Error(err) {
			return err
		}
		*keyFilename = keyFile.Name()

		err = os.WriteFile(keyFile.Name(), keyPEM, common.DefaultFileMode)
		if common.Error(err) {
			return err
		}
	}

	tmpl, err := template.ParseFiles("index.html")
	if common.Error(err) {
		return err
	}

	indexFunc := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			tmpl.Execute(w, nil)
			return
		}

		patientDetails := PatientDetails{
			ID:        r.FormValue("ID"),
			LastName:  r.FormValue("LastName"),
			FirstName: r.FormValue("FirstName"),
			BirthDate: r.FormValue("BirthDate"),
			Sex:       r.FormValue("Sex"),
			Worklist:  r.FormValue("Worklist"),
		}

		// do something with details
		_ = patientDetails

		tmpl.Execute(w, struct{ Success bool }{true})
	}

	mux := http.NewServeMux()

	if *username != "" {
		mux.HandleFunc("/", basicAuth(indexFunc))
	} else {
		mux.HandleFunc("/", indexFunc)
	}

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      mux,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	common.Info("starting server on %s", srv.Addr)

	if *useTls {
		err := srv.ListenAndServeTLS(*certFilename, *keyFilename)
		if common.Error(err) {
			return err
		}
	} else {
		err := srv.ListenAndServe()
		if common.Error(err) {
			return err
		}
	}

	return nil
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(u))
			passwordHash := sha256.Sum256([]byte(p))
			expectedUsernameHash := sha256.Sum256([]byte(*username))
			expectedPasswordHash := sha256.Sum256([]byte(*password))

			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			if usernameMatch && passwordMatch {
				common.Info("Successful login: %s %s", r.RemoteAddr, u)

				next.ServeHTTP(w, r)
				return
			} else {
				common.Warn("Unsuccessful login: %s %s", r.RemoteAddr, p)
			}
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

func main() {
	common.Run(nil)
}
