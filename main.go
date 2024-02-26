package main

import (
	"fmt"
	"log"
	"net/http"
)

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
	/*http.HandleFunc("/based", basedAuth)
	http.HandleFunc("/cookie", cookie)
	http.HandleFunc("/token", basedAuth)*/

	fmt.Println("Starting Server at port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
