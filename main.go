package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
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

func setCookieHandler(w http.ResponseWriter, r *http.Request) {

	c, err := r.Cookie("username")
	if err != nil || c.MaxAge == -1 {
		// Использование параметра
		path := filepath.Join("cookie.html")
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
	} else {
		http.Redirect(w, r, "/welcomeCookie", http.StatusSeeOther)
	}

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

func redirOnWelcomeCookie(w http.ResponseWriter, r *http.Request) {

	userCredentials, err := readCredentialsFromFile("data.txt")
	if err != nil {
		http.Error(w, "Unable to read file", http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if !isAuthorized(string(username), string(password), userCredentials) {
		// w.WriteHeader(http.StatusUnauthorized)
		path := filepath.Join("qwe.html")
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
	} else {
		cookie := http.Cookie{
			Name:     "username",
			Value:    username,
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}

		// Use the http.SetCookie() function to send the cookie to the client.
		// Behind the scenes this adds a `Set-Cookie` header to the response
		// containing the necessary cookie data.
		http.SetCookie(w, &cookie)
		http.Redirect(w, r, "/welcomeCookie", http.StatusSeeOther)
	}
}

func welcomeCookie(w http.ResponseWriter, r *http.Request) {

	path := filepath.Join("welcome.html")
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

	c, err := r.Cookie("username")
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Write([]byte(fmt.Sprintf(`
		Welcome, %s!
		<form action="/logoutCookie">
			<input type="submit" value="Logout">
		</form>
	`, c.Value)))

	w.Write([]byte(fmt.Sprintf(`
		<form action="/">
			<input type="submit" value="Back to main page">
		</form>
	`)))
}

func logoutCookie(w http.ResponseWriter, r *http.Request) {

	cookie := http.Cookie{
		Name:     "username",
		Value:    " ",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	// Use the http.SetCookie() function to send the cookie to the client.
	// Behind the scenes this adds a `Set-Cookie` header to the response
	// containing the necessary cookie data.
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	http.HandleFunc("/", home)
	/*http.HandleFunc("/based", basedAuth)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/welcomeYa", welcomeYa)*/
	//http.HandleFunc("/logoutYa", logoutYa)
	http.HandleFunc("/redirOnWelcomeCookie", redirOnWelcomeCookie)
	http.HandleFunc("/welcomeCookie", welcomeCookie)
	http.HandleFunc("/logoutCookie", logoutCookie)
	http.HandleFunc("/cookie", setCookieHandler)

	fmt.Println("Starting Server at port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
