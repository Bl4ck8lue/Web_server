package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

type Credentials struct {
	Username string
	Password string
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
		<form action="/logout" method="POST">
			<input type="submit" value="Logout">
		</form>
	`, username)))
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	// Очищаем заголовок Authorization, чтобы выйти из аккаунта
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
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
				<li><a href="/cookie">Second Page</a></li>
				<li><a href="/token">Third Page</a></li>
			</ul>
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
	/*http.HandleFunc("/cookie", cookie)
	http.HandleFunc("/token", basedAuth)*/

	fmt.Println("Starting Server at port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
