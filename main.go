package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"flag"
	"fmt"
	"github.com/mpetavy/common"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"
)

type Identifier struct {
	Value string `json:"value,omitempty"`
	Type  string `json:"type,omitempty"`
}

type HealthInsurance struct {
	Type         string `json:"type,omitempty"`
	SubscriberId string `json:"subscriberId,omitempty"`
}

type PatientPayload struct {
	Id                       string          `json:"id,omitempty"`
	Mrn                      string          `json:"mrn,omitempty"`
	MrnAssigner              string          `json:"mrnAssigner,omitempty"`
	Identifier               []Identifier    `json:"identifier,omitempty"`
	HealthInsurance          HealthInsurance `json:"healthInsurance,omitempty"`
	LastName                 string          `json:"lastName,omitempty"`
	FirstName                string          `json:"firstName,omitempty"`
	DateOfBirth              string          `json:"dateOfBirth,omitempty"`
	Gender                   string          `json:"gender,omitempty"`
	Ethnicity                string          `json:"ethnicity,omitempty"`
	AddressLine1             string          `json:"addressLine1,omitempty"`
	AddressLine2             string          `json:"addressLine2,omitempty"`
	City                     string          `json:"city,omitempty"`
	EmailAddress             string          `json:"emailAddress,omitempty"`
	PhoneHome                string          `json:"phoneHome,omitempty"`
	PhoneMobile              string          `json:"phoneMobile,omitempty"`
	PhoneWork                string          `json:"phoneWork,omitempty"`
	PreferredMethodOfContact string          `json:"preferredMethodOfContact,omitempty"`
	Race                     string          `json:"race,omitempty"`
	State                    string          `json:"state,omitempty"`
	Country                  string          `json:"country,omitempty"`
	Zip                      string          `json:"zip,omitempty"`
}

type Appointment struct {
	EmrId           string `json:"emrId,omitempty"`
	Date            string `json:"date,omitempty"`
	EndDate         string `json:"endDate,omitempty"`
	FacilityId      string `json:"facilityId,omitempty"`
	ProviderId      string `json:"providerId,omitempty"`
	Status          string `json:"status,omitempty"`
	Type            string `json:"type,omitempty"`
	DeviceGroupId   string `json:"deviceGroupId,omitempty"`
	AccessionNumber string `json:"accessionNumber,omitempty"`
	OrderNumber     string `json:"orderNumber,omitempty"`
}

type OrderPayload struct {
	PatientId    string        `json:"patientId,omitempty"`
	Appointments []Appointment `json:"appointments,omitempty"`
}

var (
	port        = flag.Int("port", 8443, "port to serve the directory")
	username    = flag.String("username", "", "username")
	password    = flag.String("password", "", "password")
	httpTimeout = flag.Int("httpTimeout", 10000, "http request timeout")
	useTls      = flag.Bool("tls", false, "use TLS")
	baseUrl     = flag.String("baseUrl", "", "baseUrl")     // https://ew1.veracitydoc.com/api/emr-integration/api-docs
	kid         = flag.String("kid", "", "kid")             // postman:dev:a
	tenant      = flag.String("tenant", "", "tenant")       // emr-yala
	sub         = flag.String("sub", "", "sub")             // EMR Web Simulator
	cLocation   = flag.String("cLocation", "", "cLocation") // location1
	provider    = flag.String("provider", "", "provider")   // provider1
	secret      = flag.String("secret", "", "secret")       // postman-dev-a.private.pem (in diesem Beispiel der Name der Datei)

	srv     *http.Server
	srvDone chan struct{}
)

//go:embed go.mod
var resources embed.FS

func init() {
	common.Init("", "", "", "", "", "", "", "", &resources, start, stop, nil, 0)
}

func executeHttpRequest(method string, headers map[string]string, username string, password string, address string, body io.Reader, expectedCode int) (*http.Response, []byte, error) {
	common.DebugFunc("Method: %s URL: %s Username: %s Password: %s", method, address, username, strings.Repeat("X", len(password)))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), common.MillisecondToDuration(*httpTimeout))
	defer cancel()

	req, err := http.NewRequest(method, address, body)
	if common.Error(err) {
		return nil, nil, err
	}

	if username != "" || password != "" {
		if username == "" {
			username = "dummy"
		}

		req.SetBasicAuth(username, password)
	}

	if headers != nil {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}

	resp, err := client.Do(req.WithContext(ctx))
	if common.Error(err) {
		return nil, nil, err
	}

	if expectedCode > 0 && resp.StatusCode != expectedCode {
		return nil, nil, fmt.Errorf("unexpected HTTP staus code, expected %d got %d", expectedCode, resp.StatusCode)
	}

	buf := bytes.Buffer{}

	if err == nil {
		defer func() {
			common.DebugError(resp.Body.Close())
		}()

		_, err = io.Copy(&buf, resp.Body)
	}

	return resp, buf.Bytes(), err
}

func getHome(w http.ResponseWriter, r *http.Request) {
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
		//patientDetails := PatientDetails{
		//	ID:        r.FormValue("ID"),
		//	LastName:  r.FormValue("LastName"),
		//	FirstName: r.FormValue("FirstName"),
		//	BirthDate: r.FormValue("BirthDate"),
		//	Sex:       r.FormValue("Sex"),
		//	Worklist:  r.FormValue("Worklist"),
		//}

		birthdate, err := time.Parse(time.DateOnly, r.FormValue("BirthDate"))
		if common.Error(err) {
			return err
		}

		patientPayload := PatientPayload{
			Id:                       r.FormValue("ID"),
			Mrn:                      "",
			MrnAssigner:              "",
			Identifier:               nil,
			HealthInsurance:          HealthInsurance{},
			LastName:                 r.FormValue("LastName"),
			FirstName:                r.FormValue("FirstName"),
			DateOfBirth:              birthdate.Format(time.RFC3339),
			Gender:                   r.FormValue("Sex"),
			Ethnicity:                "",
			AddressLine1:             "",
			AddressLine2:             "",
			City:                     "",
			EmailAddress:             "",
			PhoneHome:                "",
			PhoneMobile:              "",
			PhoneWork:                "",
			PreferredMethodOfContact: "",
			Race:                     "",
			State:                    "",
			Country:                  "",
			Zip:                      "",
		}

		fmt.Printf("%+v\n", patientPayload)

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
		//orderDetails := OrderDetails{
		//	ID:              r.FormValue("ID"),
		//	AccessionNumber: r.FormValue("AccessionNumber"),
		//	StartDate:       r.FormValue("StartDate"),
		//	EndDate:         r.FormValue("EndDate"),
		//	Status:          r.FormValue("Status"),
		//}

		startDate, err := time.Parse(time.DateOnly, r.FormValue("StartDate"))
		if common.Error(err) {
			return err
		}

		endDate, err := time.Parse(time.DateOnly, r.FormValue("EndDate"))
		if common.Error(err) {
			return err
		}

		orderPayload := OrderPayload{
			PatientId: "",
			Appointments: []Appointment{Appointment{
				EmrId:           "",
				Date:            startDate.Format(time.RFC3339),
				EndDate:         endDate.Format(time.RFC3339),
				FacilityId:      "",
				ProviderId:      "",
				Status:          r.FormValue("Status"),
				Type:            "",
				DeviceGroupId:   "",
				AccessionNumber: "",
				OrderNumber:     "",
			}},
		}

		fmt.Printf("%+v\n", orderPayload)

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

	mux.HandleFunc("/", basicAuth(getHome))
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
			IdleTimeout:  common.MillisecondToDuration(*httpTimeout),
			ReadTimeout:  common.MillisecondToDuration(*httpTimeout),
			WriteTimeout: common.MillisecondToDuration(*httpTimeout),
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

	common.Info("Stopping server on %d", *port)

	ctx, cancel := context.WithTimeout(context.Background(), common.MillisecondToDuration(*common.FlagServiceTimeout))
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
