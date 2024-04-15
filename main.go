package main

import (
	"bufio"
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
	"time"
)

type Credentials struct {
	Username string
	Password string
}

var userss = make(map[string]string)

// this map stores the users sessions. For larger scale applications, you can use a database or cache for this purpose
var sessions = map[string]session{}

// each session contains the username of the user and the time at which it expires
type session struct {
	username string
	expiry   time.Time
}

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

// YANDEX authentication ------------------------------------------------------

func welcomeYa(w http.ResponseWriter, r *http.Request) {
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

	id, err := strconv.Atoi(r.URL.Query().Get("code"))
	if err != nil || id < 1 {
		http.NotFound(w, r)
		return
	}

	// Используем функцию fmt.Fprintf() для вставки значения из id в строку ответа
	// и записываем его в http.ResponseWriter.
	//fmt.Fprintf(w, "Отображение выбранной заметки с ID %d...", id)

	data := []byte(("grant_type=authorization_code&code=" + fmt.Sprint(id) + "&client_id=476e1aa7abaa4dddba753090db19ce0a&client_secret=685c2349141b4e7f9f9e727c2fbe8452"))
	re := bytes.NewReader(data)
	resp, err := http.Post("https://oauth.yandex.ru/token", "application/x-www-form-urlencoded", re)

	// https://oauth.yandex.ru/authorize?response_type=code&client_id=476e1aa7abaa4dddba753090db19ce0a

	/* data := []byte(("&access_token=" + fmt.Sprint(accessToken) + "&client_id=476e1aa7abaa4dddba753090db19ce0a&client_secret=685c2349141b4e7f9f9e727c2fbe8452"))
	re := bytes.NewReader(data)
	resp, err := http.Post("https://oauth.yandex.ru/token", "application/x-www-form-urlencoded", re) */

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

	// Использование параметра
	fmt.Println("Welcome: ", login)
	w.Write([]byte(fmt.Sprintf(`Welcome, %s!`, login)))

	cookie := http.Cookie{
		Name:     "exampleCookie",
		Value:    "Hello world!",
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)

	w.Write([]byte("cookie set!"))

	w.Write([]byte(fmt.Sprintf(`
		<form action="/logoutYa">
			<input type="submit" value="Logout">
		</form>`)))

	/*data1 := []byte(("&access_token=y0_AgAAAAAVmfTTAAtlSgAAAAD9HcRVAACTUVgOZ8BH87a81rm3ge6Si-pG6w&client_id=476e1aa7abaa4dddba753090db19ce0a&client_secret=685c2349141b4e7f9f9e727c2fbe8452"))
	re1 := bytes.NewReader(data1)
	resp1, err := http.Post("https://oauth.yandex.ru/token", "application/x-www-form-urlencoded", re1)
	if err != nil {
		fmt.Println("Ошибка при выполнении запроса:", err)
		return
	}
	defer resp1.Body.Close()
	http.Redirect(w, r, "/", http.StatusSeeOther)*/
}

func logoutYa(w http.ResponseWriter, r *http.Request) {

	// Delete the older session token
	delete(sessions, "0")

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// MAIN PAGE AND HandleFuncs ----------------------------------------------------------

func home(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{Name: "", Value: ""}
	http.SetCookie(w, &cookie)
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

func main() {
	http.HandleFunc("/", home)
	http.HandleFunc("/based", basedAuth)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/welcomeYa", welcomeYa)
	http.HandleFunc("/logoutYa", logoutYa)
	/*http.HandleFunc("/cookie", cookie)
	http.HandleFunc("/token", basedAuth)*/

	fmt.Println("Starting Server at port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
