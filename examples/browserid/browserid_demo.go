package main

import (
	"fmt"
	"github.com/bradrydzewski/go.auth"
	"net/http"
)

var homepage = `
<html>
<head>
<script src="https://browserid.org/include.js" type="text/javascript"></script>
<script>
var login = function(){
	navigator.id.getVerifiedEmail(function(assertion) {
		if (assertion) {
			xmlHttp = new XMLHttpRequest(); 
			xmlHttp.open("POST", "/auth/login?assertion="+assertion, false );
			xmlHttp.onreadystatechange = function() {
				if(xmlHttp.readyState == 4 && xmlHttp.status == 200) {
					window.setTimeout('window.location = "/auth/login"',500);
				}
			}
			xmlHttp.send({"assertion":assertion});	
		} else {
			alert("something wrong");
		}
	});
}
</script>
</head>

<body>
<a href="#" onClick='login();'>
login</a>
	</body>
</html>
`

var privatepage = `
<html>
	<head>
		<title>Login</title>
	</head>
	<body>
		<div>BrowserId Email: <a href="%s" target="_blank">%s</a></div>
		<div><a href="/auth/logout">Logout</a><div>
	</body>
</html>
`

// private webpage, authentication required
func Private(w http.ResponseWriter, r *http.Request) {
	user := r.URL.User.Username()
	fmt.Fprintf(w, fmt.Sprintf(privatepage, user, user))
}

// public webpage, no authentication required
func Public(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, homepage)
}

// logout handler
func Logout(w http.ResponseWriter, r *http.Request) {
	auth.DeleteUserCookie(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {

	// set the auth parameters
	auth.Config.CookieSecret = []byte("7H9xiimk2QdTdYI7rDddfJeV")
	auth.Config.LoginSuccessRedirect = "/private"

	// login handler
	browserIdHandler := auth.BrowserId("localhost:8080")
	http.Handle("/auth/login", browserIdHandler)

	// logout handler
	http.HandleFunc("/auth/logout", Logout)

	// public urls
	http.HandleFunc("/", Public)

	// private, secured urls
	http.HandleFunc("/private", auth.SecureFunc(Private))

	println("browserId demo starting on port 8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
	}
}
