package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	jwtmiddleware "github.com/adigunhammedolalekan/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const jwtSecret = "JWT$ecret"
func main() {
	store, err := jwtmiddleware.NewBadgerDBStore("tmp.auths")
	if err != nil {
		log.Fatal(err)
	}

	mw := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		},
		SigningMethod: jwt.SigningMethodHS256,
		PassThrough: []string{"/account/new",},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err string) {
			http.Error(w, err, http.StatusUnauthorized)
		},
		Store: store,
	})

	app := NewApp(store)
	router := mux.NewRouter()
	router.Use(mw.Handler)
	router.HandleFunc("/secure", app.secureHandler).Methods("GET")
	router.HandleFunc("/account/new", app.createAccount).Methods("GET")
	router.HandleFunc("/logout", app.logoutHandler).Methods("GET")

	log.Println("serving on :9000")
	if err := http.ListenAndServe(":9000", router); err != nil {
		log.Fatal(err)
	}
}

type Account struct {
	Id string
	Name string
	jwt.StandardClaims
}

type App struct {
	store jwtmiddleware.JwtStorer
	mtx sync.Mutex
	db map[string]Account
}

func NewApp(store jwtmiddleware.JwtStorer) *App {
	return &App{
		store: store,
		db:    make(map[string]Account),
	}
}

func (a *App) createAccount(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name is empty", http.StatusBadRequest)
		return
	}
	id := a.nextId()
	account := Account{Name: name, Id: id}
	token, err := a.generateToken(account)
	if err != nil {
		http.Error(w, "server error " + err.Error(), http.StatusInternalServerError)
		return
	}
	a.mtx.Lock()
	a.db[id] = account
	a.mtx.Unlock()

	type response struct {
		Token string `json:"token"`
		Account Account `json:"account"`
	}
	a.ok(w, response{Token: token, Account: account})
}

func (a *App) ok(w http.ResponseWriter, resp interface{}) {
	data, _ := json.Marshal(resp)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (a *App) generateToken(account Account) (string, error) {
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), account)
	rawToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}
	if err := a.store.Put(rawToken); err != nil {
		return "", err
	}
	return rawToken, nil
}

func (a *App) nextId() string {
	x := md5.New()
	x.Write([]byte(time.Now().String()))
	return fmt.Sprintf("%x", x.Sum(nil))
}

func (a *App) secureHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user")
	claim := user.(*jwt.Token).Claims
	account, ok := claim.(jwt.MapClaims)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	type response struct {
		Message string `json:"message"`
	}
	a.ok(w, response{Message: fmt.Sprintf("Hello, %s", account["Name"])})
}

func (a *App) logoutHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "token header is missing", http.StatusBadRequest)
		return
	}
	s := strings.Split(authHeader, " ")
	if len(s) != 2 {
		http.Error(w, "auth header is malformed. expected Authorization: Bearer {token}", http.StatusForbidden)
		return
	}
	key := s[1]
	if err := a.store.Revoke(key); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	a.ok(w, map[string]string{"status": "ok"})
}
