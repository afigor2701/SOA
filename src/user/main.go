package main

import (
	"context"
	"crypto/md5"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
)

type LoginPasswordMail struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	Mail     string `json:"mail"`
}

type LoginPassword struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type AuthHandlers struct {
	jwtPrivate *rsa.PrivateKey
	jwtPublic  *rsa.PublicKey
	Conn       *pgx.Conn
	Ctx        context.Context
}

type User struct {
	Login            string    `json:"login"`
	Name             string    `json:"name,omitempty"`
	Surname          string    `json:"surname,omitempty"`
	DateOfBirth      string    `json:"date_of_birth,omitempty"`
	Mail             string    `json:"mail"`
	PhoneNumber      string    `json:"phone_number,omitempty"`
	DateOfCreation   time.Time `json:"date_of_creation"`
	DateOfLastChange time.Time `json:"date_of_last_change"`
}

func HashPassword(password string) string {
	// Create MD5 hash
	hash := md5.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

func createDatabase(ctx context.Context, conn *pgx.Conn, dbName string) error {
	checkQuery := `SELECT 1 FROM pg_database WHERE datname=$1;`
	var exists int
	err := conn.QueryRow(ctx, checkQuery, dbName).Scan(&exists)
	if err == nil { // Database exists
		fmt.Println("Database already exists:", dbName)
		return nil
	}

	// Create the database if it does not exist
	createDBQuery := fmt.Sprintf("CREATE DATABASE %s;", dbName)
	_, err = conn.Exec(ctx, createDBQuery)
	if err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}
	fmt.Println("Database created:", dbName)
	return nil
}

func NewAuthHandlers(jwtprivateFile string, jwtPublicFile string, adminConnStr string, connStr string, dbName string) *AuthHandlers {
	private, err := os.ReadFile(jwtprivateFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	public, err := os.ReadFile(jwtPublicFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	jwtPrivate, err := jwt.ParseRSAPrivateKeyFromPEM(private)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	jwtPublic, err := jwt.ParseRSAPublicKeyFromPEM(public)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx := context.Background()

	adminConn, err := pgx.Connect(ctx, adminConnStr)
	if err != nil {
		log.Fatal("Unable to connect to default database:", err)
	}
	defer adminConn.Close(ctx)

	// Step 2: Create the target database if it doesn't exist
	err = createDatabase(ctx, adminConn, dbName)
	if err != nil {
		log.Fatal("Error creating database:", err)
	}

	// Connect to the database
	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		fmt.Println("Can't connect to PostgreSQL")
		return nil
	}

	fmt.Println("Connected to PostgreSQL!")

	createTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
		login VARCHAR(100) PRIMARY KEY,
		name VARCHAR(100),
		surname VARCHAR(100),
		date_of_birth DATE,
		mail VARCHAR(255),
		phone_number VARCHAR(20),
		password VARCHAR(255),
		date_of_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		date_of_last_change TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err = conn.Exec(ctx, createTableQuery)
	if err != nil {
		fmt.Println("Can't execute create table query")
		return nil
	}

	return &AuthHandlers{
		jwtPrivate: jwtPrivate,
		jwtPublic:  jwtPublic,
		Conn:       conn,
		Ctx:        ctx,
	}
}

func (h *AuthHandlers) Close() {
	h.Conn.Close(h.Ctx)
	fmt.Println("Database connection closed!")
}

func UserExists(db *AuthHandlers, login string) (bool, error) {
	query := "SELECT COUNT(*) FROM users WHERE login = $1"

	var count int
	err := db.Conn.QueryRow(db.Ctx, query, login).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("error executing query: %w", err)
	}

	// If count is greater than 0, the user exists
	if count > 0 {
		return true, nil
	}

	return false, nil
}

func InsertUser(db *AuthHandlers, login, password, mail string) error {
	hashedPassword := HashPassword(password)

	query := `
		INSERT INTO users (login, password, mail, date_of_creation, date_of_last_change)
		VALUES ($1, $2, $3, $4, $4)
	`

	_, err := db.Conn.Exec(db.Ctx, query, login, hashedPassword, mail, time.Now())
	if err != nil {
		return fmt.Errorf("failed to insert user: %w", err)
	}

	return nil
}

func CheckPassword(db *AuthHandlers, login, password string) (bool, error) {
	query := "SELECT password FROM users WHERE login = $1"
	var storedHash string

	err := db.Conn.QueryRow(db.Ctx, query, login).Scan(&storedHash)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return false, fmt.Errorf("user with login %s does not exist", login)
		}
		return false, fmt.Errorf("failed to query password: %w", err)
	}

	// Hash the input password
	hashedInputPassword := HashPassword(password)

	// Compare the input password hash with the stored password hash
	if hashedInputPassword == storedHash {
		return true, nil // Password matches
	}

	return false, nil // Password does not match
}

func GetUser(db *AuthHandlers, login string) (User, error) {
	// SQL query to fetch user details excluding password
	query := `
		SELECT
			login,
			COALESCE(name, ''),
			COALESCE(surname, ''),
			COALESCE(date_of_birth::text, ''),
			mail,
			COALESCE(phone_number, ''),
			date_of_creation,
			date_of_last_change
		FROM users WHERE login = $1
	`

	var user User
	err := db.Conn.QueryRow(db.Ctx, query, login).Scan(
		&user.Login,
		&user.Name,
		&user.Surname,
		&user.DateOfBirth,
		&user.Mail,
		&user.PhoneNumber,
		&user.DateOfCreation,
		&user.DateOfLastChange,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return User{}, fmt.Errorf("user with login %s does not exist", login)
		}
		return User{}, fmt.Errorf("failed to retrieve user data: %w", err)
	}

	return user, nil
}

func UpdateUser(db *AuthHandlers, login string, user User) error {
	// SQL query to update user information
	query := `
		UPDATE users 
		SET 
			name = COALESCE($1, name),
			surname = COALESCE($2, surname),
			date_of_birth = COALESCE($3, date_of_birth),
			mail = COALESCE($4, mail),
			phone_number = COALESCE($5, phone_number),
			date_of_last_change = CURRENT_TIMESTAMP
		WHERE login = $6
	`

	var dateOfBirth interface{}
	if user.DateOfBirth == "" {
		dateOfBirth = nil
	} else {
		dateOfBirth = user.DateOfBirth
	}

	// Execute the query
	_, err := db.Conn.Exec(db.Ctx, query,
		user.Name,
		user.Surname,
		dateOfBirth,
		user.Mail,
		user.PhoneNumber,
		login,
	)
	return err
}

func (h *AuthHandlers) signup(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "signup can be done only with POST HTTP method")
		return
	}
	fmt.Println(req.ContentLength)

	body := make([]byte, req.ContentLength)
	read, err := req.Body.Read(body)
	defer req.Body.Close()
	if read != int(req.ContentLength) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err != io.EOF {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error reading body: %v", err)
		return
	}
	creds := LoginPasswordMail{}
	err = json.Unmarshal(body, &creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Error unmarshalling body: %v", err)
		return
	}

	// TODO: register user, check if exists, generate jwt token and cookie

	query := "SELECT COUNT(*) FROM users WHERE login = $1"
	var count int
	err = h.Conn.QueryRow(h.Ctx, query, creds.Login).Scan(&count)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error executing query: %v", err)
		return
	}

	exists, err := UserExists(h, creds.Login)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error executing query: %v", err)
		return
	}

	if !exists {
		// User does not exit
		err = InsertUser(h, creds.Login, creds.Password, creds.Mail)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Error executing query: %v", err)
			return
		}
	} else {
		// User does exit
		w.WriteHeader(http.StatusForbidden)
		return
	}

	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["Login"] = creds.Login

	tokenString, err := token.SignedString(h.jwtPrivate)

	http.SetCookie(w, &http.Cookie{
		Name:  "jwt",
		Value: tokenString, // jwt token string
	})
}

func (h *AuthHandlers) login(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "login can be done only with POST HTTP method")
		return
	}
	body := make([]byte, req.ContentLength)
	read, err := req.Body.Read(body)
	defer req.Body.Close()
	if read != int(req.ContentLength) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err != io.EOF {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error reading body: %v", err)
		return
	}
	creds := LoginPassword{}
	err = json.Unmarshal(body, &creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Error unmarshalling body: %v", err)
		return
	}

	exists, err := UserExists(h, creds.Login)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error executing query: %v", err)
		return
	}

	if exists {
		// Add the key-value pair if the key doesn't exist
		checked, err := CheckPassword(h, creds.Login, creds.Password)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Error executing query: %v", err)
			return
		}

		if !checked {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	} else {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["Login"] = creds.Login

	tokenString, err := token.SignedString(h.jwtPrivate)

	http.SetCookie(w, &http.Cookie{
		Name:  "jwt",
		Value: tokenString, // jwt token string
	})
}

func (h *AuthHandlers) update(w http.ResponseWriter, req *http.Request) {
	tokenCookie, err := req.Cookie("jwt")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tokenString := tokenCookie.Value

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return h.jwtPublic, nil
	})

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok || !token.Valid {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	login := claims["Login"].(string)

	var user User
	decoder := json.NewDecoder(req.Body)
	err = decoder.Decode(&user)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode JSON: %v", err), http.StatusBadRequest)
		return
	}

	err = UpdateUser(h, login, user)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to update user: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *AuthHandlers) get(w http.ResponseWriter, req *http.Request) {
	tokenCookie, err := req.Cookie("jwt")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tokenString := tokenCookie.Value

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return h.jwtPublic, nil
	})

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok || !token.Valid {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	login := claims["Login"].(string)

	user, err := GetUser(h, login)
	if err != nil {
		log.Fatalf("Error retrieving user: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(user)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to write JSON response: %v", err), http.StatusInternalServerError)
	}
}

func (h *AuthHandlers) healthCheckHandler(w http.ResponseWriter, req *http.Request) {
	// Check database connection
	err := h.Conn.Ping(h.Ctx)
	if err != nil {
		http.Error(w, "Database not reachable", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	privateFile := flag.String("private", "", "path to JWT private key `file`")
	publicFile := flag.String("public", "", "path to JWT public key `file`")
	port := flag.Int("port", 8091, "http server port")
	flag.Parse()

	if port == nil {
		fmt.Fprintln(os.Stderr, "Port is required")
		os.Exit(1)
	}

	if privateFile == nil || *privateFile == "" {
		fmt.Fprintln(os.Stderr, "Please provide a path to JWT private key file")
		os.Exit(1)
	}

	if publicFile == nil || *publicFile == "" {
		fmt.Fprintln(os.Stderr, "Please provide a path to JWT public key file")
		os.Exit(1)
	}

	absoluteprivateFile, err := filepath.Abs(*privateFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	absolutePublicFile, err := filepath.Abs(*publicFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	adminConnString := os.Getenv("ADMIN_CONNECTION")
	connString := os.Getenv("DATABASE_URL")
	dbName := os.Getenv("DATABASE_NAME")
	if adminConnString == "" || connString == "" || dbName == "" {
		fmt.Println("Some database url is not set")
		os.Exit(1)
	}
	authHandlers := NewAuthHandlers(absoluteprivateFile, absolutePublicFile, adminConnString, connString, dbName)
	defer authHandlers.Close()

	http.HandleFunc("/signup", authHandlers.signup)
	http.HandleFunc("/login", authHandlers.login)
	http.HandleFunc("/update", authHandlers.update)
	http.HandleFunc("/get", authHandlers.get)
	http.HandleFunc("/health", authHandlers.healthCheckHandler)

	fmt.Println("Starting server on port", *port, "with jwt private key file", absoluteprivateFile, "and jwt public key file", absolutePublicFile)

	if err = http.ListenAndServe(fmt.Sprintf(":%d", *port), nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
