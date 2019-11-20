package main

import (
	"os"
	"fmt"
	"log"
	"time"
	"net/http"
	"github.com/julienschmidt/httprouter"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"context"
	"encoding/json"
)

type user struct {
	UserName string	`json:"username" bson:"username"`
	Password []byte `json:"password" bson:"password"`
	First    string `json:"first" bson:"first"`
	Last     string `json:"last" bson:"last"`
}

type result struct {
	UserID	 primitive.ObjectID `bson:"_id,omitempty"`
	UserName string				`bson:"username"`
	Password []byte				`bson:"password"`
	First    string				`bson:"first"`
	Last     string				`bson:"last"`
}

type session struct {
	user    	 result
	LastActivity time.Time
}

var tpl *template.Template
var dbSessions = map[string]*session{} // session ID, session
const sessionLength int = 30
var col *mongo.Collection

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	go expireOldSessions()
}

func main() {
	connectToDatabase()
	router := httprouter.New()
	// APIs
	router.POST("/user", createUser)
	router.GET("/user/:id", getUser)
	router.POST("/login", loginUser)
	// Routes
	router.GET("/", index)
	router.GET("/signup", signup)
	router.GET("/bar", bar)
	router.GET("/login", login)
	router.GET("/logout", logout)
	router.GET("/json", js)

	http.Handle("/favicon.ico", http.NotFoundHandler())
	log.Fatal(http.ListenAndServe(":8080", router))
}

//////////////////// APIs

func createUser(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	// get form values
	un := req.FormValue("username")
	p := req.FormValue("password")
	f := req.FormValue("firstname")
	l := req.FormValue("lastname")

	// username taken?
	var u user
	filter := bson.D{primitive.E{Key: "username", Value: un}}
	ctx := context.Background()
	err := col.FindOne(ctx, filter).Decode(&u)
	if err == nil {
		http.Error(w, "Username already taken", http.StatusUnauthorized)
		return
	}

	// store user in dbUsers
	bs, _ := bcrypt.GenerateFromPassword([]byte(p), bcrypt.MinCost)
	u = user{un, bs, f, l}
	insertResult, err := col.InsertOne(ctx, u)
	if err != nil {
		http.Error(w, "Sorry something went wrong, try again later", http.StatusInternalServerError)
		return
	}
	uID, _ := insertResult.InsertedID.(primitive.ObjectID)
	r := result{uID, un, bs, f, l}
	fmt.Println("New user inserted in database: ", r)

	// create session
	sID := createCookie(w)
	createSession(sID, r)
	fmt.Println("New user session created:", sID, r)

	// redirect
	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func getUser(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {	
	u := getUserFromSession(req)

	fmt.Println(u.UserID.String())
	fmt.Println(u.UserID.Hex())

	// user id and params match?
	if u.UserID.String() != ps.ByName("id") {
		fmt.Println("User session does not match requst param:", u.UserID.String(), ps.ByName("id"))
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return	
	}

	// get user from database
	filter := bson.D{primitive.E{Key: "_id", Value: u.UserID}}
	ctx := context.Background()
	err := col.FindOne(ctx, filter).Decode(&u)
	if err != nil {
		fmt.Println("User not found in database:", u.UserID.Hex())
		http.Error(w, "User not found", http.StatusForbidden)
		return
	}

	err = tpl.ExecuteTemplate(w, "user.gohtml", u)
	if err != nil {
		fmt.Println("Error serving page:", err)
		http.Error(w, "Sorry something went wrong, try again later", http.StatusInternalServerError)
		return
	}
}

func loginUser(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	// get form values
	un := req.FormValue("username")
	p := req.FormValue("password")

	// username and password match?
	var r result
	filter := bson.D{primitive.E{Key: "username", Value: un}}
	ctx := context.Background()
	err := col.FindOne(ctx, filter).Decode(&r)
	if err != nil {
		fmt.Println("User not found in database:", un)
		http.Error(w, "Username and password incorrect", http.StatusUnauthorized)
		return
    }
	err = bcrypt.CompareHashAndPassword(r.Password, []byte(p))
	if err != nil {
		http.Error(w, "Username and password incorrect", http.StatusUnauthorized)
		return
	}

	// create session
	sID := createCookie(w)
	createSession(sID, r)
	fmt.Println("Existing user session created:", sID, r)

	// redirect
	http.Redirect(w, req, "/", http.StatusSeeOther)
}

//////////////////// Routes

func index(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	u := getUserFromSession(req)
	err := tpl.ExecuteTemplate(w, "index.gohtml", u)
	if err != nil {
		fmt.Println("Error serving page:", err)
		http.Error(w, "Sorry something went wrong, try again later", http.StatusInternalServerError)
		return
	}
}

func signup(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	u := getUserFromSession(req)
	if u.UserName != "" {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	err := tpl.ExecuteTemplate(w, "signup.gohtml", nil)
	if err != nil {
		fmt.Println("Error serving page:", err)
		http.Error(w, "Sorry something went wrong, try again later", http.StatusInternalServerError)
		return
	}
}

func bar(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	u := getUserFromSession(req)
	err := tpl.ExecuteTemplate(w, "bar.gohtml", u)
	if err != nil {
		fmt.Println("Error serving page:", err)
		http.Error(w, "Sorry something went wrong, try again later", http.StatusInternalServerError)
		return
	}
}

func login(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	u := getUserFromSession(req)
	if u.UserName != "" {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	err := tpl.ExecuteTemplate(w, "login.gohtml", nil)
	if err != nil {
		fmt.Println("Error serving page:", err)
		http.Error(w, "Sorry something went wrong, try again later", http.StatusInternalServerError)
		return
	}
}

func logout(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	u := getUserFromSession(req)
	if u.UserName == "" {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	// delete session
	c, _ := req.Cookie("session")
	delete(dbSessions, c.Value)
	fmt.Println("User session deleted:", c.Value, u.UserName)

	// remove cookie
	removeCookie(w)

	// redirect
	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func connectToDatabase() {
	ctx := context.Background()
    clientOptions := options.Client().ApplyURI("mongodb://admin:admin@cluster0-shard-00-00-a8tc8.mongodb.net:27017,cluster0-shard-00-01-a8tc8.mongodb.net:27017,cluster0-shard-00-02-a8tc8.mongodb.net:27017/test?ssl=true&replicaSet=Cluster0-shard-0&authSource=admin&retryWrites=true&w=majority")
    client, err := mongo.Connect(ctx, clientOptions)
    if err != nil {
        log.Fatal(err)
    }
    err = client.Ping(ctx, nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Connected to MongoDB!")
    db := client.Database("webserver")
    col = db.Collection("users")
}

func js(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	// this is a work in progressn
	// curl -H "Content-Type: application/json" -d '{"username":"abc@test.com","password":"cGFzc3dvcmQ=","first":"xyz","last":"xyz"}' -X POST http://localhost:8080/json
	// {abc@test.com [112 97 115 115 119 111 114 100] xyz xyz}
	decoder := json.NewDecoder(req.Body)
	var u user
	err := decoder.Decode(&u)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(u)
	s := `{"username":"abc@test.com","password":"[112 97 115 115 119 111 114 100]","first":"xyz","last":"xyz"}`
	encoder := json.NewEncoder(os.Stdout)
	err = encoder.Encode(s)
	if err != nil {
		log.Println(err)
		return
	}
}