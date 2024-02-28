package main

import (
	"bufio"

	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
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
	w.Header().Add("Content-Type", "text/html")

	html := `
		<!DOCTYPE html>
		<html>
		<head>
			<title>Main Page</title>
		</head>
		<body>
			<h1>Welcome to Main Page!</h1>
			<p>Choose a page:</p>
			<ul>
				<li><a href="/based">Based Authorization</a></li>
				<li><a href="/signin">Second Page</a></li>
				<li><a href="/token">Third Page</a></li>
			</ul>
		</body>
		</html>
	`
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

type users struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

func signinHome(w http.ResponseWriter, r *http.Request) {
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
}

func main() {
	http.HandleFunc("/", home)
	http.HandleFunc("/based", basedAuth)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/sign", signinHome)
	//http.HandleFunc("/welcome", Welcome)
	//http.HandleFunc("/logoutcookie", Logout)
	/*http.HandleFunc("/cookie", cookie)
	http.HandleFunc("/token", basedAuth)*/

	fmt.Println("Starting Server at port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
