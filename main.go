package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Credentials struct {
	Username string
	Password string
}

var userss = make(map[string]string)

func init() {
	// Считывание логинов и паролей из файла
	file, err := os.Open("data.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 2 {
			userss[parts[0]] = parts[1]
		}
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}
}

// this map stores the users sessions. For larger scale applications, you can use a database or cache for this purpose
var sessions = map[string]session{}

// each session contains the username of the user and the time at which it expires
type session struct {
	username string
	expiry   time.Time
}

// we'll use this method later to determine if the session has expired
func (s session) isExpired() bool {
	return s.expiry.Before(time.Now())
}

func readCredentialsFromFile(filepath string) ([]Credentials, error) {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var userCredentials []Credentials

	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			cred := Credentials{
				Username: parts[0],
				Password: parts[1],
			}
			userCredentials = append(userCredentials, cred)
		}
	}

	return userCredentials, nil
}

func isAuthorized(username, password string, credentials []Credentials) bool {
	for _, cred := range credentials {
		if cred.Username == username && cred.Password == password {
			return true
		}
	}
	return false
}

func basedAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html")

	userCredentials, err := readCredentialsFromFile("data.txt")
	if err != nil {
		http.Error(w, "Unable to read file", http.StatusInternalServerError)
		return
	}

	username, password, ok := r.BasicAuth()

	if !ok {
		w.Header().Add("WWW-Authenticate", `Basic realm="Give username and password"`)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "No basic auth present"}`))
		return
	}

	if !isAuthorized(string(username), string(password), userCredentials) {
		w.Header().Add("WWW-Authenticate", `Basic realm="Give username and password"`)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "Invalid username or password"}`))
		return
	}

	w.WriteHeader(http.StatusOK)
	//w.Write([]byte(`{"message": "welcome to basic world!"}`))
	w.Write([]byte(fmt.Sprintf(`
		Welcome, %s!
		<form action="/logout">
			<input type="submit" value="Logout">
		</form>
	`, username)))
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	// Очищаем заголовок Authorization, чтобы выйти из аккаунта
	w.Header().Add("WWW-Authenticate", `Basic realm="Give username and password"`)
	w.WriteHeader(http.StatusUnauthorized)

	fmt.Fprint(w, "Logged out. ")
	w.Write([]byte(`
		Back to Main Page?
		<form action="/">
			<input type="submit" value="Back">
		</form>
	`))
}

func home(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join("index.html")
	//создаем html-шаблон
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	//выводим шаблон клиенту в браузер
	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
}
func yandexAuth(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join("yandexAuth.html")
	//создаем html-шаблон
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	//выводим шаблон клиенту в браузер
	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
}

type users struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

func Signin(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	html := `
		<!DOCTYPE html>
		<html>
		<head>
			<title>Main Page</title>
		</head>
		<body>
			<form method="POST" action="/welcome">
        		<label>Login</label><input name="login" type="text" value="">
        		<br>
        		<label>Password</label><input name="password" type="password" value="">
        		<br>
        		<input type="submit" value="submit">
    		</form>
		</body>
		</html>
	`
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	var creds users
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get the expected password from our in memory map
	expectedPassword, ok := userss[creds.Username]

	// If a password exists for the given user
	// AND, if it is the same as the password we received, the we can move ahead
	// if NOT, then we return an "Unauthorized" status
	if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Create a new random session token
	// we use the "github.com/google/uuid" library to generate UUIDs
	sessionToken := uuid.NewString()
	expiresAt := time.Now().Add(120 * time.Second)

	// Set the token in the session map, along with the session information
	sessions[sessionToken] = session{
		username: creds.Username,
		expiry:   expiresAt,
	}

	// Finally, we set the client cookie for "session_token" as the session token we just generated
	// we also set an expiry time of 120 seconds
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: expiresAt,
	})

}

func main() {
	http.HandleFunc("/", home)
	http.HandleFunc("/based", basedAuth)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/yandexAuth", yandexAuth)
	/*http.HandleFunc("/cookie", cookie)
	http.HandleFunc("/token", basedAuth)*/

	fmt.Println("Starting Server at port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
