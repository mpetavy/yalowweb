package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mpetavy/common"
	"html/template"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	YALOWWEB_INI = "yalowweb.ini"
	INDEX_GOHTML = "index.gohtml"
)

type PatientForm struct {
	ID        string
	LastName  string
	FirstName string
	BirthDate string
	Sex       string
	Worklist  string
}

type OrderForm struct {
	Kind            string
	ID              string
	AccessionNumber string
	StartDate       string
	EndDate         string
	Status          string
}

type Data struct {
	Name    string
	Content string
}

type Form struct {
	Logo        string
	Title       string
	Kid         string
	Sub         string
	Tenant      string
	GIT         string
	CurrentDate string
	Patient     PatientForm
	Order       OrderForm
	Success     bool
	Failure     bool
	Msg         string
	Statuscode  string
	Datas       []Data
}

type Identifier struct {
	Value string `json:"value,omitempty"`
	Type  string `json:"type,omitempty"`
}

type HealthInsurance struct {
	Type         string `json:"type,omitempty"`
	SubscriberId string `json:"subscriberId,omitempty"`
}

type Patient struct {
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

type PatientPayload struct {
	DryRun             bool    `json:"dryRun"`
	CreateWorklistItem bool    `json:"createWorklistItem"`
	Patient            Patient `json:"patient"`
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
	port      = flag.Int("port", 8443, "port to serve the directory")
	username  = flag.String("username", "", "username")
	password  = flag.String("password", "", "password")
	timeout   = flag.Int("timeout", 10000, "http request timeout")
	useTls    = flag.Bool("tls", false, "use TLS")
	baseUrl   = flag.String("baseUrl", "", "baseUrl")                // https://ew1.veracitydoc.com/api/emr-integration/api-docs
	kid       = flag.String("kid", "", "kid")                        // postman:dev:a
	tenant    = flag.String("tenant", "", "tenant")                  // emr-yala
	sub       = flag.String("sub", "", "sub")                        // EMR Web Simulator
	cLocation = flag.String("cLocation", "", "cLocation")            // location1
	provider  = flag.String("provider", "", "provider")              // provider1
	secret    = flag.String("secret", "", "secret")                  // postman-dev-a.private.pem (in diesem Beispiel der Name der Datei)
	datapath  = flag.String("datapath", "", "path to message files") // postman-dev-a.private.pem (in diesem Beispiel der Name der Datei)

	indexTmpl []byte
	srv       *http.Server
	srvDone   chan struct{}
	form      *Form
)

//go:embed go.mod
//go:embed index.gohtml
//go:embed yalowweb.ini
//go:embed logo.png
//go:embed script.js
//go:embed favicon.ico
var resources embed.FS

func init() {
	common.Init("", "1.2.0", "", "", "", "", "", "", &resources, start, stop, nil, 0)
}

func createJWT(content interface{}) (string, error) {
	common.DebugFunc()

	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(*secret))
	if common.Error(err) {
		return "", err
	}

	now := time.Now().UTC()

	claims := make(jwt.MapClaims)
	if content != nil {
		claims["dat"] = content
	}
	claims["sub"] = *sub
	claims["tenant"] = *tenant
	claims["exp"] = now.Add(time.Hour * 24).Unix() // The expiration time after which the token must be disregarded.

	j := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	j.Header["kid"] = *kid

	token, err := j.SignedString(key)
	if common.Error(err) {
		return "", err
	}

	common.DebugFunc(token)

	return token, nil
}

func executeHttpRequest(method string, headers http.Header, username string, password string, address string, body *bytes.Buffer, expectedCode int) (*http.Response, []byte, error) {
	common.DebugFunc("Method: %s URL: %s Username: %s Password: %s", method, address, username, strings.Repeat("X", len(password)))

	if headers == nil {
		headers = make(http.Header)
	}

	if body != nil {
		headers.Set("Content-Length", strconv.Itoa(body.Len()))
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: common.MillisecondToDuration(*timeout),
	}

	ctx, cancel := context.WithTimeout(context.Background(), common.MillisecondToDuration(*timeout))
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
		req.Header = headers
	}

	ba, err := httputil.DumpRequest(req, true)
	if common.Error(err) {
		return nil, nil, err
	}

	common.DebugFunc("Dump request: %s", string(ba))

	resp, err := client.Do(req.WithContext(ctx))
	if common.Error(err) {
		return nil, nil, err
	}

	buf := bytes.Buffer{}

	defer func() {
		common.DebugError(resp.Body.Close())
	}()

	_, err = io.Copy(&buf, resp.Body)

	common.DebugFunc("Response statuscode: %d", resp.StatusCode)
	common.DebugFunc("Response body: %s", string(buf.Bytes()))

	if expectedCode > 0 && resp.StatusCode != expectedCode {
		return resp, buf.Bytes(), fmt.Errorf("unexpected HTTP staus code, expected %d got %d", expectedCode, resp.StatusCode)
	}

	return resp, buf.Bytes(), nil
}

func getHome(w http.ResponseWriter, r *http.Request) {
	common.DebugFunc()

	action := func() error {
		defer func() {
			form.Success = false
			form.Failure = false
			form.Msg = ""
		}()

		var err error
		var tmpl *template.Template

		if common.IsRunningAsExecutable() {
			tmpl = template.New(INDEX_GOHTML)
			tmpl, err = tmpl.Parse(string(indexTmpl))
			if common.Error(err) {
				return err
			}
		} else {
			tmpl, err = template.ParseFiles(INDEX_GOHTML)
			if common.Error(err) {
				return err
			}
		}

		today := time.Now().Format(time.RFC3339)
		today = today[:strings.Index(today, "T")]

		form.CurrentDate = today
		form.Patient = PatientForm{}
		form.Order = OrderForm{}
		form.Datas = nil

		if *datapath != "" {
			err := common.WalkFiles(*datapath, false, false, func(path string, fi os.FileInfo) error {
				if fi.IsDir() {
					return nil
				}

				ba, err := os.ReadFile(path)
				if common.Error(err) {
					return err
				}

				form.Datas = append(form.Datas, Data{
					Name:    filepath.Base(path),
					Content: string(ba),
				})

				sort.Slice(form.Datas, func(i, j int) bool {
					return cmp.Compare(form.Datas[i].Name, form.Datas[j].Name) < 0
				})

				return nil
			})
			if common.Error(err) {
				return err
			}
		}

		err = tmpl.Execute(w, form)
		if common.Error(err) {
			return err
		}

		return nil
	}

	err := action()
	if common.Error(err) {
		notify(w, r, err.Error(), http.StatusBadRequest)
	}
}

func notify(w http.ResponseWriter, r *http.Request, msg string, statuscode int) {
	common.DebugFunc()

	form.Msg = msg
	form.Statuscode = strconv.Itoa(statuscode)
	if statuscode == http.StatusOK {
		form.Success = true
	} else {
		form.Failure = true
	}

	r.Method = http.MethodGet

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func postPatient(w http.ResponseWriter, r *http.Request) {
	common.DebugFunc()

	action := func() (*http.Response, error) {
		form.Patient = PatientForm{
			ID:        r.FormValue("ID"),
			LastName:  r.FormValue("LastName"),
			FirstName: r.FormValue("FirstName"),
			BirthDate: r.FormValue("BirthDate"),
			Sex:       r.FormValue("Sex"),
			Worklist:  r.FormValue("Worklist"),
		}

		common.Debug("patientForm: %+v\n", form.Patient)

		birthdate, err := time.Parse(time.DateOnly, r.FormValue("BirthDate"))
		if common.Error(err) {
			return nil, err
		}

		patientPayload := PatientPayload{
			DryRun:             false,
			CreateWorklistItem: common.ToBool(r.FormValue("Worklist")),
			Patient: Patient{
				Id:          form.Patient.ID,
				Mrn:         form.Patient.ID,
				MrnAssigner: "MED",
				Identifier: []Identifier{Identifier{
					Value: form.Patient.ID,
					Type:  "EMR",
				}},
				HealthInsurance: HealthInsurance{
					Type:         "MED",
					SubscriberId: "M-" + form.Patient.ID,
				},
				LastName:                 form.Patient.LastName,
				FirstName:                form.Patient.FirstName,
				DateOfBirth:              birthdate.Format(time.RFC3339),
				Gender:                   form.Patient.Sex,
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
			},
		}

		payload, err := json.MarshalIndent(&patientPayload, "", "    ")
		if common.Error(err) {
			return nil, err
		}

		common.Debug("patientPayload: %+v\n", string(payload))

		token, err := createJWT(nil)
		if common.Error(err) {
			return nil, err
		}

		headers := make(http.Header)
		headers.Set("x-veracity-token", token)
		headers.Set("Content-Type", common.MimetypeApplicationJson.MimeType)

		resp, _, err := executeHttpRequest(http.MethodPost, headers, "", "", *baseUrl+"/v1/sendPatient", bytes.NewBuffer(payload), http.StatusOK)

		return resp, err
	}

	resp, err := action()
	if common.Error(err) {
		statuscode := http.StatusBadRequest
		if resp != nil {
			statuscode = resp.StatusCode
		}

		notify(w, r, err.Error(), statuscode)
	} else {
		notify(w, r, "Success!", http.StatusOK)
	}
}

func postOrder(w http.ResponseWriter, r *http.Request) {
	common.DebugFunc()

	action := func() (*http.Response, error) {
		form.Order = OrderForm{
			Kind:            r.FormValue("Kind"),
			ID:              r.FormValue("ID"),
			AccessionNumber: r.FormValue("AccessionNumber"),
			StartDate:       r.FormValue("StartDate"),
			EndDate:         r.FormValue("EndDate"),
			Status:          r.FormValue("Status"),
		}

		common.Debug("form.Order: %+v\n", form.Order)

		startDate, err := time.Parse(time.DateOnly, form.Order.StartDate)
		if common.Error(err) {
			return nil, err
		}

		endDate, err := time.Parse(time.DateOnly, form.Order.EndDate)
		if common.Error(err) {
			return nil, err
		}

		deviceGroupId := ""
		if form.Order.Kind == "ORDER" {
			deviceGroupId = "ALL"
		}

		orderPayload := OrderPayload{
			PatientId: form.Order.ID,
			Appointments: []Appointment{Appointment{
				EmrId:           form.Order.AccessionNumber,
				Date:            startDate.Format(time.RFC3339Nano),
				EndDate:         endDate.Format(time.RFC3339Nano),
				FacilityId:      "",
				ProviderId:      "",
				Status:          form.Order.Status,
				Type:            "Established",
				DeviceGroupId:   deviceGroupId,
				AccessionNumber: form.Order.AccessionNumber,
				OrderNumber:     form.Order.AccessionNumber,
			}},
		}

		payload, err := json.MarshalIndent(&orderPayload, "", "    ")
		if common.Error(err) {
			return nil, err
		}

		common.Debug("orderPayload: %+v\n", string(payload))

		token, err := createJWT(nil)
		if common.Error(err) {
			return nil, err
		}

		headers := make(http.Header)
		headers.Set("x-veracity-token", token)
		headers.Set("Content-Type", common.MimetypeApplicationJson.MimeType)

		resp, _, err := executeHttpRequest(http.MethodPost, headers, "", "", *baseUrl+"/v1/sendAppointments", bytes.NewBuffer(payload), http.StatusOK)

		return resp, err
	}

	resp, err := action()
	if common.Error(err) {
		statuscode := http.StatusBadRequest
		if resp != nil {
			statuscode = resp.StatusCode
		}

		notify(w, r, err.Error(), statuscode)
	} else {
		notify(w, r, "Success!", http.StatusOK)
	}
}

func sendMedicalData(w http.ResponseWriter, r *http.Request) {
	common.DebugFunc()

	action := func() (*http.Response, error) {
		payload := r.FormValue("content")

		common.Debug("payload: %+v\n", payload)

		token, err := createJWT(nil)
		if common.Error(err) {
			return nil, err
		}

		headers := make(http.Header)
		headers.Set("x-veracity-token", token)
		headers.Set("Content-Type", common.MimetypeApplicationJson.MimeType)

		resp, _, err := executeHttpRequest(http.MethodPost, headers, "", "", *baseUrl+"/v1/sendMedicalData", bytes.NewBuffer([]byte(payload)), http.StatusOK)

		return resp, err
	}

	resp, err := action()
	if common.Error(err) {
		statuscode := http.StatusBadRequest
		if resp != nil {
			statuscode = resp.StatusCode
		}

		notify(w, r, err.Error(), statuscode)
	} else {
		notify(w, r, "Success!", http.StatusOK)
	}
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	common.DebugFunc()

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

func resource(next http.HandlerFunc) http.HandlerFunc {
	common.DebugFunc()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := func() error {
			if r.URL.Path != "/" {
				resourceName := r.URL.Path[1:]

				res, mimeType, err := common.ReadResource(resourceName)
				if err == nil {
					w.Header().Add("Content-Type", mimeType)
					w.WriteHeader(http.StatusOK)
					_, err := w.Write(res)
					if common.Error(err) {
						return err
					}

					common.Debug("request resource: %s", resourceName)

					return nil
				}
			}

			return fmt.Errorf("unknown resource: %s", r.URL.Path)
		}

		err := action()
		if err != nil {
			next.ServeHTTP(w, r)
		}
	})
}

func start() error {
	common.DebugFunc()

	files := []string{YALOWWEB_INI}
	for _, file := range files {
		if !common.FileExists(file) {
			ba, _, err := common.ReadResource(file)
			if common.Error(err) {
				return err
			}

			common.WarnError(os.WriteFile(file, ba, os.ModePerm))
		}
	}

	var err error

	indexTmpl, _, err = common.ReadResource(INDEX_GOHTML)
	if common.Error(err) {
		return err
	}

	logo, err := resources.ReadFile("logo.png")
	if common.Error(err) {
		return err
	}

	form = &Form{
		Logo:   base64.StdEncoding.EncodeToString(logo),
		Title:  fmt.Sprintf("EMR Simulator %s", common.Version(true, true, true)),
		Tenant: *tenant,
		Kid:    *kid,
		Sub:    *sub,
		GIT:    common.App().Git,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", resource(basicAuth(getHome)))
	mux.HandleFunc("/patient", basicAuth(postPatient))
	mux.HandleFunc("/order", basicAuth(postOrder))
	mux.HandleFunc("/sendMedicalData", basicAuth(sendMedicalData))

	var tlsConfig *tls.Config

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
			IdleTimeout:  common.MillisecondToDuration(*timeout),
			ReadTimeout:  common.MillisecondToDuration(*timeout),
			WriteTimeout: common.MillisecondToDuration(*timeout),
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
	common.DebugFunc()

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
