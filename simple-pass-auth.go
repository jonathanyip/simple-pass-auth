package main

import (
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	toml "github.com/pelletier/go-toml"

	"html/template"

	mux "github.com/gorilla/mux"
)

const authPage = "auth.html"
const passwordFieldName = "password"
const redirectUrlParam = "redirect"

type ContextualHandler struct {
	Config *Config
}

type Config struct {
	Server struct {
		Host           string `toml:"host"`
		Port           int    `toml:"port"`
		RequestTimeout int    `toml:"request_timeout"`
	}
	Authentication struct {
		SecretKey      string `toml:"secret_key"`
		ExpiryTime     int    `toml:"expiry_time"`
		HashedPassword string `toml:"hashed_password"`
	}
	Custom struct {
		PageTitle             string `toml:"page_title"`
		InvalidPasswordString string `toml:"invalid_password_string"`
	}
}

type AuthPageContext struct {
	PageTitle    string
	ErrorMessage string
}

// Parses the config TOML into the struct
func parseConfig(configPath string) (*Config, error) {
	file, err := os.Open(configPath)

	if err != nil {
		return nil, fmt.Errorf("error opening config file: %e", err)
	}
	defer file.Close()

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %e", err)
	}

	var config Config
	err = toml.Unmarshal(fileBytes, &config)

	if err != nil {
		return nil, fmt.Errorf("error parsing config file: %e", err)
	}

	return &config, nil
}

// Confirm the password matches the sha1 hashed password in the config
func confirmPassword(config *Config, providedPassword string) bool {
	h := sha1.New()
	h.Write([]byte(providedPassword))
	sha1Hash := hex.EncodeToString(h.Sum(nil))
	return sha1Hash == config.Authentication.HashedPassword
}

func setCookie(config *Config) error {
	return nil
}

func (ctx ContextualHandler) AuthPageHandler(w http.ResponseWriter, req *http.Request) {
	t, err := template.ParseFiles(authPage)

	if err != nil {
		log.Fatal(fmt.Errorf("error parsing template file: %e", err))
		fmt.Fprintf(w, "Error parsing template file. Please contact the administrator.")
		return
	}

	// Fetch redirect URL from query params or the base path if not provided
	redirectTo := req.URL.Query().Get(redirectUrlParam)
	if redirectTo == "" {
		redirectTo = "/"
	}

	// Parse password if they submitted the form
	req.ParseForm()
	hasPassword := req.PostForm.Has(passwordFieldName)

	errorMessage := ""
	if hasPassword {
		providedPassword := req.PostForm.Get(passwordFieldName)
		if !confirmPassword(ctx.Config, providedPassword) {
			// With an invalid password, we want to show the error message
			errorMessage = ctx.Config.Custom.InvalidPasswordString
		} else {
			// If correct password, set the cookie and redirect them to where they were going
			setCookie(ctx.Config)
			http.Redirect(w, req, redirectTo, http.StatusFound)
			return
		}
	}

	pageContext := AuthPageContext{
		PageTitle:    ctx.Config.Custom.PageTitle,
		ErrorMessage: errorMessage,
	}
	t.Execute(w, pageContext)
}

func (ctx ContextualHandler) VerifyHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "Verify!")
}

func main() {
	configPath := flag.String("config-path", "", "Path to the configuration file")
	flag.Parse()

	if *configPath == "" {
		log.Fatal("You must provide the location of the config with the -config-path flag")
	}

	config, err := parseConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	contextualHandler := ContextualHandler{
		Config: config,
	}

	router := mux.NewRouter()
	router.HandleFunc("/auth", contextualHandler.AuthPageHandler)
	router.HandleFunc("/verify", contextualHandler.VerifyHandler)

	srv := &http.Server{
		Handler:      router,
		Addr:         fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port),
		WriteTimeout: time.Duration(config.Server.RequestTimeout) * time.Second,
		ReadTimeout:  time.Duration(config.Server.RequestTimeout) * time.Second,
	}

	log.Printf("Starting server on %s:%d\n", config.Server.Host, config.Server.Port)
	log.Fatal(srv.ListenAndServe())
}
