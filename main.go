package main

import (
	// "crypto/rand"
	"database/sql"
	"encoding/base64"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	// "github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	_ "github.com/mattn/go-sqlite3"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

/////////////////////////////////////////////////////////////////

type Page struct {
	Title string
	Body  []byte
}

var (
	tmplView   = template.Must(template.New("test").ParseFiles("base.html", "testPage.html", "indexPage.html"))
	tmplEdit   = template.Must(template.New("edit").ParseFiles("base.html", "editPage.html", "indexPage.html"))
	tmplUpload = template.Must(template.New("upload").ParseFiles("base.html", "uploadPage.html", "indexPage.html"))
	db, _      = sql.Open("sqlite3", "cache/web.db")
	createDB   = "create table if not exists pages (title text, body blob, timestamp text)"
)

func (p *Page) saveCache() error {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	f := "cache/" + p.Title + ".txt"
	db.Exec(createDB)
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("insert into pages (title, body, timestamp) values (?, ?, ?)")
	_, err := stmt.Exec(p.Title, p.Body, timestamp)
	tx.Commit()
	ioutil.WriteFile(f, p.Body, 0600)
	return err
}

func load(title string) (*Page, error) {
	f := "cache/" + title + ".txt"
	body, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return &Page{Title: title, Body: body}, nil
}

func loadSource(title string) (*Page, error) {
	var name string
	var body []byte
	q, err := db.Query("select title, body from pages where title = '" + title + "' order by timestamp Desc limit 1")
	if err != nil {
		return nil, err
	}
	for q.Next() {
		q.Scan(&name, &body)
	}
	return &Page{Title: name, Body: body}, nil
}

func view(w http.ResponseWriter, r *http.Request) {

	title := r.URL.Path[len("/test/"):]
	p, err := loadSource(title)
	if err != nil {
		p, _ = load(title)
	}
	if p.Title == "" {
		p, _ = load(title)
	}

	tmplView.ExecuteTemplate(w, "base", p)
	//t, _ := template.ParseFiles("test.html")
	//t.Execute(w, p)
}

func edit(w http.ResponseWriter, r *http.Request) {
	title := r.URL.Path[len("/edit/"):]
	p, err := loadSource(title)
	if err != nil {
		p, _ = load(title)
	}
	if p.Title == "" {
		p, _ = load(title)
	}
	tmplEdit.ExecuteTemplate(w, "base", p)
	//t, _ := template.ParseFiles("edit.html")
	//t.Execute(w, p)
}

func save(w http.ResponseWriter, r *http.Request) {
	title := r.URL.Path[len("/save/"):]

	body := r.FormValue("body")
	p := &Page{Title: title, Body: []byte(body)}
	p.saveCache()
	http.Redirect(w, r, "/test/"+title, http.StatusFound)
}

func upload(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		title := "Upload"
		p := &Page{Title: title}
		tmplUpload.ExecuteTemplate(w, "base", p)

	case "POST":
		err := r.ParseMultipartForm(100000)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		m := r.MultipartForm
		files := m.File["Myfiles"]
		for i := range files {
			file, err := files[i].Open()
			defer file.Close()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			f, err := os.Create(".files/" + files[i].Filename)
			defer f.Close()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if _, err := io.Copy(f, file); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "files/"+files[i].Filename, http.StatusFound)

		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

/////////////////////////////////////////////////////////////////

type User struct {
	Uuid     string            `valid:"required,uuidv4"`
	Username string            `valid:"required,alpha"`
	Password string            `valid:"required"`
	Fname    string            `valid:"required,alpha"`
	Lname    string            `valid:"required,alpha"`
	Email    string            `valid:"required,email"`
	Errors   map[string]string `valid:"-"`
}

var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

func enptps(password string) string {
	pass := []byte(password)
	hashpw, _ := bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)
	return string(hashpw)
}

//---UUID maker------///

// func Uuid() (id string) {
// 	b := make([]byte, 16)
// 	_, err := rand.Read(b)
// 	if err != nil {
// 		return
// 	}
// 	id = fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
// 	return
// }

func Uuid() string {
	id, _ := uuid.NewV4()
	return id.String()
}

var router = mux.NewRouter()

/////////////////////////////////////////////////////////////////////////////////////////
// flash massage

func encode(s []byte) string {
	return base64.URLEncoding.EncodeToString(s)
}

func decode(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}

func getMsg(w http.ResponseWriter, r *http.Request, name string) (msg string) {
	if cookie, err := r.Cookie(name); err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode(name, cookie.Value, &cookieValue); err == nil {
			msg = cookieValue[name]
			clearSession(w, name)
		}
	}

	return msg
}

func setMsg(w http.ResponseWriter, name string, msg string) {
	value := map[string]string{
		name: msg,
	}
	if encoded, err := cookieHandler.Encode(name, value); err == nil {
		cookie := &http.Cookie{
			Name:  name,
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(w, cookie)
	}
}

//////////////////////////////////////////////////////////////////////////////////

// session

func setSession(u *User, w http.ResponseWriter) {
	value := map[string]string{
		"uuid": u.Uuid,
	}
	if encoded, err := cookieHandler.Encode("session", value); err == nil {
		cookie := &http.Cookie{
			Name:  "session",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(w, cookie)
	}
}

func getUuid(r *http.Request) (uuid string) {
	if cookie, err := r.Cookie("session"); err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
			uuid = cookieValue["uuid"]
		}
	}
	return uuid
}

func clearSession(w http.ResponseWriter, name string) {
	cookie := &http.Cookie{
		Name:   name,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(w, cookie)
}

//////////////////////////////////////////////////////////////////////////////////

//-----------ROUTE HANDLERS---------------//

func indexPage(w http.ResponseWriter, r *http.Request) {
	msg := getMsg(w, r, "Message")
	var u = &User{}
	u.Errors = make(map[string]string)

	if msg != "" {
		u.Errors["Message"] = msg
		tmpl, _ := template.ParseFiles("login.html", "index.html")
		err := tmpl.ExecuteTemplate(w, "loginpage", u)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		// render(w, "loginpage", u)
	} else {

		u := &User{}
		tmpl, _ := template.ParseFiles("login.html", "index.html")
		err := tmpl.ExecuteTemplate(w, "loginpage", u)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		// render(w, "loginpage", u)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("uname")
	pass := r.FormValue("password")
	u := &User{Username: name, Password: pass}
	redirect := "/"
	if name != "" && pass != "" {
		if b, uuid := userExists(u); b == true {
			setSession(&User{Uuid: uuid}, w)
			redirect = "/example"
		} else {
			setMsg(w, "Message", "please sign up the vaild login username and password ")

		}

	} else {
		setMsg(w, "Message", "username or Password Fields are Empty")

	}
	http.Redirect(w, r, redirect, 302)
}

func logout(w http.ResponseWriter, r *http.Request) {
	clearSession(w, "session")
	http.Redirect(w, r, "/", 302)
}

func examplePage(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("mainpage.html", "index.html")
	uuid := getUuid(r)
	u := getUserFromUuid(uuid)
	if uuid != "" {
		err := tmpl.ExecuteTemplate(w, "mainpage", u)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		// render(w, "mainpage", &User{Username: username})
	} else {
		setMsg(w, "Message", "please login the page")
		http.Redirect(w, r, "/", 302)
	}
}

func signup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		u := &User{}
		u.Errors = make(map[string]string)
		u.Errors["lname"] = getMsg(w, r, "lname")
		u.Errors["fname"] = getMsg(w, r, "fname")
		u.Errors["email"] = getMsg(w, r, "email")
		u.Errors["username"] = getMsg(w, r, "username")
		u.Errors["password"] = getMsg(w, r, "password")
		tmpl, _ := template.ParseFiles("signup.html", "index.html")
		tmpl.ExecuteTemplate(w, "signuppage", u)
		// render(w, "signuppage", u)
	case "POST":
		if n := checkUser(r.FormValue("username")); n == true {
			setMsg(w, "username", "User already exists. Please enter a unique username!")
			http.Redirect(w, r, "/signup", 302)
			return
		}
		u := &User{
			Uuid:     Uuid(),
			Fname:    r.FormValue("fname"),
			Lname:    r.FormValue("lname"),
			Email:    r.FormValue("email"),
			Username: r.FormValue("username"),
			Password: r.FormValue("password"),
		}
		result, err := govalidator.ValidateStruct(u)
		if err != nil {
			e := err.Error()
			if re := strings.Contains(e, "Lname"); re == true {
				setMsg(w, "lname", "Please enter a valid Last Name")
			}
			if re := strings.Contains(e, "Email"); re == true {
				setMsg(w, "email", "Please enter a valid Email Address!")
			}
			if re := strings.Contains(e, "Fname"); re == true {
				setMsg(w, "fname", "Please enter a valid First Name")
			}
			if re := strings.Contains(e, "Username"); re == true {
				setMsg(w, "username", "Please enter a valid Username!")
			}
			if re := strings.Contains(e, "Password"); re == true {
				setMsg(w, "password", "Please enter a Password!")
			}

		}

		if r.FormValue("fname") == "" {
			setMsg(w, "fname", "Please enter a valid First Name")
		}
		if r.FormValue("lname") == "" {
			setMsg(w, "lname", "Please enter a valid last Name")

		}
		if r.FormValue("password") == "" {
			setMsg(w, "password", "Please enter a password ")

		}

		if r.FormValue("username") == "" {
			setMsg(w, "username", "Please enter a valid username Name")
		}

		if r.FormValue("password") != r.FormValue("cpassword") {
			setMsg(w, "password", "The passwords you entered do not Match!")
			http.Redirect(w, r, "/signup", 302)
			return
		}

		if result == true {
			u.Password = enptps(u.Password)
			saveData(u)
			http.Redirect(w, r, "/", 302)
			return
		}

		// saveData(u)
		// setSession(u, w)
		http.Redirect(w, r, "/example", 302)
	}
}

func saveData(u *User) error {
	var db, _ = sql.Open("sqlite3", "users.sqlite3")
	defer db.Close()
	db.Exec("create table if not exists users (uuid text not null unique, firstname text not null, lastname text not null, username text not null unique, email text not null, password text not null, primary key(uuid))")
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("insert into users (uuid, firstname, lastname, username, email, password) values (?, ?, ?, ?, ?, ?)")
	_, err := stmt.Exec(u.Uuid, u.Fname, u.Lname, u.Username, u.Email, u.Password)
	tx.Commit()
	return err
}

func userExists(u *User) (bool, string) {
	var db, _ = sql.Open("sqlite3", "users.sqlite3")
	defer db.Close()
	var ps, uu string
	q, err := db.Query("select uuid, password from users where username = '" + u.Username + "'")
	if err != nil {
		return false, ""
	}
	for q.Next() {
		q.Scan(&uu, &ps)
	}
	pw := bcrypt.CompareHashAndPassword([]byte(ps), []byte(u.Password))
	if uu != "" && pw == nil {
		return true, uu
	}
	return false, ""
}

func checkUser(user string) bool {
	var db, _ = sql.Open("sqlite3", "users.sqlite3")
	defer db.Close()
	var un string
	q, err := db.Query("select username from users where username = '" + user + "'")
	if err != nil {
		return false
	}
	for q.Next() {
		q.Scan(&un)
	}
	if un == user {
		return true
	}
	return false

}

func getUserFromUuid(uuid string) *User {
	var db, _ = sql.Open("sqlite3", "users.sqlite3")
	defer db.Close()
	var uu, fn, ln, un, em, pass string
	q, err := db.Query("select * from users where uuid = '" + uuid + "'")
	if err != nil {
		return &User{}
	}
	for q.Next() {
		q.Scan(&uu, &fn, &ln, &un, &em, &pass)
	}
	return &User{Username: un, Fname: fn, Lname: ln, Email: em, Password: pass}
}

// func render(w http.ResponseWriter, name string, data interface{}) {
// 	tmpl, err := template.ParseGlob("*.html")
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 	}
// 	tmpl.ExecuteTemplate(w, name, data)
// }

func main() {

	//routes
	govalidator.SetFieldsRequiredByDefault(true)
	http.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir("files"))))
	http.Handle("/cache/", http.StripPrefix("/cache/", http.FileServer(http.Dir("cache"))))
	http.HandleFunc("/", indexPage)
	http.HandleFunc("/test/", view)
	http.HandleFunc("/edit/", edit)
	http.HandleFunc("/save/", save)
	http.HandleFunc("/upload/", upload)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/example", examplePage)
	http.HandleFunc("/signup", signup)
	http.ListenAndServe(":8000", nil)
}
