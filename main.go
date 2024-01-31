package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"flag"
	"fmt"
	"github.com/mpetavy/common"
	"html/template"
	"net/http"
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

type PatientPayload struct {
	Patient struct {
		Id          string `json:"id"`
		Mrn         string `json:"mrn"`
		MrnAssigner string `json:"mrnAssigner"`
		Identifier  []struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"identifier"`
		HealthInsurance struct {
			Type         string `json:"type"`
			SubscriberId string `json:"subscriberId"`
		} `json:"healthInsurance"`
		LastName                 string `json:"lastName"`
		FirstName                string `json:"firstName"`
		DateOfBirth              string `json:"dateOfBirth"`
		Gender                   string `json:"gender"`
		Ethnicity                string `json:"ethnicity"`
		AddressLine1             string `json:"addressLine1"`
		AddressLine2             string `json:"addressLine2"`
		City                     string `json:"city"`
		EmailAddress             string `json:"emailAddress"`
		PhoneHome                string `json:"phoneHome"`
		PhoneMobile              string `json:"phoneMobile"`
		PhoneWork                string `json:"phoneWork"`
		PreferredMethodOfContact string `json:"preferredMethodOfContact"`
		Race                     string `json:"race"`
		State                    string `json:"state"`
		Country                  string `json:"country"`
		Zip                      string `json:"zip"`
	} `json:"patient"`
}

type OrderPayload struct {
	PatientId    string `json:"patientId"`
	Appointments []struct {
		EmrId      string    `json:"emrId"`
		Date       time.Time `json:"date"`
		EndDate    time.Time `json:"endDate"`
		FacilityId string    `json:"facilityId"`
		ProviderId string    `json:"providerId"`
		Status     string    `json:"status"`
		Type       string    `json:"type"`
	} `json:"appointments"`
}

var (
	port     = flag.Int("port", 8443, "port to serve the directory")
	username = flag.String("username", "", "username")
	password = flag.String("password", "", "password")
	useTls   = flag.Bool("tls", false, "use TLS")

	srv     *http.Server
	srvDone chan struct{}
)

//go:embed go.mod
var resources embed.FS

func init() {
	common.Init("", "", "", "", "", "", "", "", &resources, start, stop, nil, 0)
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	action := func() error {
		tmpl, err := template.ParseFiles("index.html")
		if common.Error(err) {
			return err
		}

		err = tmpl.Execute(w, nil)
		if common.Error(err) {
			return err
		}

		return nil
	}

	err := action()
	if common.Error(err) {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func notify(w http.ResponseWriter, msg string, statuscode int) {
	content := `
<html>
    <head>
        <meta http-equiv="refresh" content="2;url=/" />
    </head>
    <body>
		<h1 style="text-align: center;">Error: %s</h1>
    </body>
</html>`

	w.WriteHeader(statuscode)
	w.Write([]byte(fmt.Sprintf(content, msg)))
}

func postPatient(w http.ResponseWriter, r *http.Request) {
	action := func() error {
		patientDetails := PatientDetails{
			ID:        r.FormValue("ID"),
			LastName:  r.FormValue("LastName"),
			FirstName: r.FormValue("FirstName"),
			BirthDate: r.FormValue("BirthDate"),
			Sex:       r.FormValue("Sex"),
			Worklist:  r.FormValue("Worklist"),
		}

		fmt.Printf("%+v\n", patientDetails)

		return nil
	}

	err := action()
	if common.Error(err) {
		notify(w, err.Error(), http.StatusBadRequest)
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func postOrder(w http.ResponseWriter, r *http.Request) {
	action := func() error {
		orderDetails := OrderDetails{
			ID:              r.FormValue("ID"),
			AccessionNumber: r.FormValue("AccessionNumber"),
			StartDate:       r.FormValue("StartDate"),
			EndDate:         r.FormValue("EndDate"),
			Status:          r.FormValue("Status"),
		}

		fmt.Printf("%+v\n", orderDetails)

		return nil
	}

	err := action()
	if common.Error(err) {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *username == "" {
			next.ServeHTTP(w, r)

			return
		}

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

func start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", basicAuth(getIndex))
	mux.HandleFunc("/patient", basicAuth(postPatient))
	mux.HandleFunc("/order", basicAuth(postOrder))

	var tlsConfig *tls.Config
	var err error

	if *useTls {
		tlsConfig, err = common.NewTlsConfigFromFlags()
		if common.Error(err) {
			return err
		}
	}

	go func() {
		common.Info("Starting server on %d", *port)

		srv = &http.Server{
			Addr:         fmt.Sprintf(":%d", *port),
			Handler:      mux,
			IdleTimeout:  time.Minute,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 30 * time.Second,
			TLSConfig:    tlsConfig,
		}

		srvDone = make(chan struct{})

		if *useTls {
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}

		<-srvDone

		if err == http.ErrServerClosed {
			return
		} else {
			common.Error(err)
		}
	}()

	time.Sleep(time.Second)

	if common.Error(err) {
		return err
	}

	return nil
}

func stop() error {
	if srv == nil {
		return nil
	}

	common.Info("Stoping server on %d", *port)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
	defer func() {
		cancel()
	}()

	err := srv.Shutdown(ctx)
	if common.Error(err) {
		return err
	}

	close(srvDone)

	return nil
}

func main() {
	common.Run(nil)
}
