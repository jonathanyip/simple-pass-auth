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

	"errors"
	"html/template"

	"github.com/golang-jwt/jwt/v5"
	toml "github.com/pelletier/go-toml"
)

const authPage = "auth.html"
const passwordFieldName = "password"
const redirectUrlParam = "redirect"
const cookieName = "simplePassAuthToken"

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
		PageTitle               string `toml:"page_title"`
		HeaderText              string `toml:"header_text"`
		PromptText              string `toml:"prompt_text"`
		SubmitButtonText        string `toml:"submit_button_text"`
		InvalidPasswordString   string `toml:"invalid_password_string"`
		DefaultRedirectLocation string `toml:"default_redirect_location"`
	}
}

type AuthPageContext struct {
	PageTitle        string
	HeaderText       string
	PromptText       string
	SubmitButtonText string
	ErrorMessage     string
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

// Generates a JWT auth token with expiry time specified in the config
func generateAuthJWTToken(config *Config) (string, error) {
	var jwtSecretKey = []byte(config.Authentication.SecretKey)
	claims := jwt.MapClaims{
		"exp": time.Now().Add(time.Duration(config.Authentication.ExpiryTime) * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)

	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// Validates that the JWT token is valid and not expired
func validateAuthJWTToken(config *Config, tokenString string) (bool, error) {
	var jwtSecretKey = []byte(config.Authentication.SecretKey)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecretKey, nil
	})

	if err != nil {
		return false, err
	}

	if !token.Valid {
		return false, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, fmt.Errorf("error parsing claims")
	}

	expiryTime := claims["exp"].(float64)
	if time.Now().Unix() > int64(expiryTime) {
		return false, nil
	}

	return true, nil
}

// Sets the authentication cookie with the JWT token and expiry time specified in the config
func setAuthCookie(config *Config, w http.ResponseWriter) error {
	token, err := generateAuthJWTToken(config)
	if err != nil {
		return err
	}

	cookie := http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   config.Authentication.ExpiryTime * 60,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)
	return nil
}

func (ctx ContextualHandler) AuthPageHandler(w http.ResponseWriter, req *http.Request) {
	t, err := template.ParseFiles(authPage)

	if err != nil {
		log.Println(fmt.Errorf("error parsing template file: %e", err))
		http.Error(w, "Internal Server Error. Please contact the administrator.", http.StatusInternalServerError)
		return
	}

	// Fetch redirect URL from query params or the base path if not provided
	redirectTo := req.URL.Query().Get(redirectUrlParam)
	if redirectTo == "" {
		redirectTo = ctx.Config.Custom.DefaultRedirectLocation
	}

	// Perform password validation if they submitted the form
	errorMessage := ""
	if req.Method == http.MethodPost {
		req.ParseForm()
		hasPassword := req.PostForm.Has(passwordFieldName)

		if hasPassword {
			providedPassword := req.PostForm.Get(passwordFieldName)
			if !confirmPassword(ctx.Config, providedPassword) {
				// With an invalid password, we want to show the error message
				errorMessage = ctx.Config.Custom.InvalidPasswordString
			} else {
				// If correct password, set the cookie and redirect them to where they were going
				err := setAuthCookie(ctx.Config, w)
				if err != nil {
					log.Println(fmt.Errorf("error setting auth cookie: %e", err))
					http.Error(w, "Internal Server Error. Please go back and try again", http.StatusInternalServerError)
					return
				}

				http.Redirect(w, req, redirectTo, http.StatusFound)
				return
			}
		}
	}

	pageContext := AuthPageContext{
		PageTitle:        ctx.Config.Custom.PageTitle,
		HeaderText:       ctx.Config.Custom.HeaderText,
		PromptText:       ctx.Config.Custom.PromptText,
		SubmitButtonText: ctx.Config.Custom.SubmitButtonText,
		ErrorMessage:     errorMessage,
	}
	t.Execute(w, pageContext)
}

func (ctx ContextualHandler) VerifyHandler(w http.ResponseWriter, req *http.Request) {
	// If they have the cookie, redirect them to where they were going
	cookie, err := req.Cookie(cookieName)
	if err != nil {
		if !errors.Is(err, http.ErrNoCookie) {
			log.Println(fmt.Errorf("error getting cookie: %e", err))
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	valid, err := validateAuthJWTToken(ctx.Config, cookie.Value)
	if err != nil {
		log.Println(fmt.Errorf("error validating cookie: %e", err))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
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

	router := http.NewServeMux()
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
