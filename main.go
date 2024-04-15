package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Credentials struct {
	Username string
	Password string
}

var str_Token string = ""
var str_Name string = ""

var userss = make(map[string]string)

// BASED authentication AND READING DATA FROM FILE ----------------------------------------------------------

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

// COOKIE AUTHORIZATION --------------------------------------------------------

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

// YANDEX authentication ------------------------------------------------------

func welcomeYa(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.URL.Query().Get("code"))
	if err != nil || id < 1 {
		http.NotFound(w, r)
		return
	}

	data := []byte(("grant_type=authorization_code&code=" + fmt.Sprint(id) + "&client_id=476e1aa7abaa4dddba753090db19ce0a&client_secret=685c2349141b4e7f9f9e727c2fbe8452"))
	re := bytes.NewReader(data)
	resp, err := http.Post("https://oauth.yandex.ru/token", "application/x-www-form-urlencoded", re)

	if err != nil {
		fmt.Println("Ошибка при выполнении запроса:", err)
		return
	}
	defer resp.Body.Close()

	// Чтение и декодирование JSON-ответа
	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		fmt.Println("Ошибка при декодировании JSON:", err)
		return
	}

	// Извлечение access_token
	accessToken, ok := response["access_token"].(string)
	if !ok {
		fmt.Println("Не удалось извлечь access_token из ответа")
		return
	}

	// Использование параметра
	fmt.Println("Access Token:", accessToken)

	datax := []byte(("oauth_token=" + accessToken + "&format=json"))
	rex := bytes.NewReader(datax)
	x, err := http.Post("https://login.yandex.ru/info?", "application/x-www-form-urlencoded", rex)
	if err != nil {
		fmt.Println("Ошибка при выполнении запроса:", err)
		return
	}
	defer x.Body.Close()

	// Чтение и декодирование JSON-ответа
	var responsex map[string]interface{}
	err = json.NewDecoder(x.Body).Decode(&responsex)
	if err != nil {
		fmt.Println("Ошибка при декодировании JSON:", err)
		return
	}

	// Извлечение access_token
	login, ok := responsex["login"].(string)
	if !ok {
		fmt.Println("Не удалось извлечь access_token из ответа")
		return
	}

	str_Token = accessToken
	str_Name = login

	http.Redirect(w, r, "/buffForYa", http.StatusSeeOther)
}

func logoutYa(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:     str_Name,
		Value:    " ",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func buffForYa(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	cookie := http.Cookie{
		Name:     str_Name,
		Value:    str_Token,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)

	// Использование параметра
	fmt.Println("Welcome: ", str_Name)

	w.Write([]byte(fmt.Sprintf(`
		Welcome, %s!
		<form action="/logoutYa">
			<input type="submit" value="Logout">
		</form>
	`, str_Name)))
}

func main() {
	http.HandleFunc("/", home)
	http.HandleFunc("/based", basedAuth)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/welcomeYa", welcomeYa)
	http.HandleFunc("/buffForYa", buffForYa)
	http.HandleFunc("/logoutYa", logoutYa)
	http.HandleFunc("/redirOnWelcomeCookie", redirOnWelcomeCookie)
	http.HandleFunc("/welcomeCookie", welcomeCookie)
	http.HandleFunc("/logoutCookie", logoutCookie)
	http.HandleFunc("/cookie", setCookieHandler)

	fmt.Println("Starting Server at port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
