package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq" // Import the pq driver
	"golang.org/x/crypto/bcrypt"
)

var (
	jwtSecret                                   = []byte("your-secret-key")
	connections map[int]map[int]*websocket.Conn = make(map[int]map[int]*websocket.Conn)
	mutex                                       = &sync.Mutex{}
)

var (
	DB_HOST     = os.Getenv("DB_HOST")
	DB_PORT     = os.Getenv("DB_PORT")
	DB_USER     = os.Getenv("DB_USER")
	DB_PASSWORD = os.Getenv("DB_PASSWORD")
	DB_NAME     = os.Getenv("DB_NAME")
	URL         = os.Getenv("URL")
)

type Session struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type Circle struct {
	ID       int       `json:"id"`
	Name     string    `json:"name"`
	Sessions []Session `json:"sessions"`
}

type FileMessage struct {
	Type     string `json:"type"`
	Data     string `json:"data"`
	Filename string `json:"filename"`
}

type SessionStatus struct {
	ID     int    `json:"id"`
	Status int    `json:"status"`
	Name   string `json:"name"`
}

func AddConnection(user_id int, circle_id int, conn *websocket.Conn) {
	mutex.Lock()
	if _, ok := connections[circle_id]; !ok {
		connections[circle_id] = make(map[int]*websocket.Conn)
	}
	connections[circle_id][user_id] = conn
	mutex.Unlock()
}

func RemoveConnection(user_id int, circle_id int) {
	mutex.Lock()
	delete(connections[circle_id], user_id)
	if len(connections[circle_id]) == 0 {
		delete(connections, circle_id)
	}
	mutex.Unlock()
}

// Database connection function
func dbConnection() (*sql.DB, error) {
	connStr := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable", DB_HOST, DB_PORT, DB_USER, DB_NAME, DB_PASSWORD)
	return sql.Open("postgres", connStr)
}

// HashPassword hashes the password with bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash compares plain password with hashed password
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateJWT(userID int) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = userID
	claims["exp"] = time.Now().Add(24 * time.Hour).Unix() // 24-hour expiration

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func SetSessionCookie(w http.ResponseWriter, sessionToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
	})
}

func GenerateGuestJWT(guestID int) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["guest_id"] = guestID
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func SetGuestSessionCookie(w http.ResponseWriter, sessionToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "guest_session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
	})
}

// AuthenticateUser checks the user's credentials
func AuthenticateUser(db *sql.DB, username, password string) (int, bool) {
	var userID int
	var passwordHash string

	// Query to fetch user data by username
	err := db.QueryRow("SELECT id, password FROM users WHERE name = $1", username).Scan(&userID, &passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, false // Username not found
		}
		log.Println("Database query error:", err)
		return 0, false
	}

	// Check if the password matches
	if CheckPasswordHash(password, passwordHash) {
		return userID, true
	}
	return 0, false
}

func InsertUser(db *sql.DB, username, hash, superkey string) (int, error) {
	insertQuery := `
		INSERT INTO Users (name, password)
		VALUES ($1, $2)
		RETURNING id;
	`

	var userID int
	err := db.QueryRow(insertQuery, username, hash).Scan(&userID)
	if err != nil {
		log.Println("Database query error:", err)
		return 0, err
	}

	updateQuery := "UPDATE SuperKeys SET id_user = $1 WHERE superkey = $2;"
	_, err = db.Exec(updateQuery, userID, superkey)

	if err != nil {
		log.Println("Database query error:", err)
		return 0, err
	}

	return userID, nil
}

func InsertCircle(db *sql.DB, user_id int, name string) error {
	_, err := db.Exec("INSERT INTO circles (id_user, name) VALUES ($1, $2)", user_id, name)
	return err
}

func DeleteCircle(db *sql.DB, user_id int, circle_id int) error {
	_, err := db.Exec("DELETE FROM circles WHERE id_user = $1 AND id = $2", user_id, circle_id)
	return err
}

func DeleteSessionDB(db *sql.DB, session_id int) error {
	_, err := db.Exec("DELETE FROM sessions WHERE id = $1", session_id)
	return err
}

func InsertSession(db *sql.DB, name string) (int, error) {
	var id int
	err := db.QueryRow("INSERT INTO sessions (name) VALUES ($1) RETURNING id", name).Scan(&id)
	return id, err
}

func InsertSessionCircle(db *sql.DB, session_id int, circle_id int) error {
	_, err := db.Exec("INSERT INTO SessionsCircles (id_session, id_circle) VALUES ($1, $2)", session_id, circle_id)
	return err
}

func VerifyUserCircle(db *sql.DB, user_id int, circle_id int) (bool, error) {
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT * FROM circles WHERE id_user = $1 AND id = $2)", user_id, circle_id).Scan(&exists)
	return exists, err
}

func VerifySessionEmpty(db *sql.DB, session_id int) (bool, error) {
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT * FROM SessionsCircles WHERE id_session = $1)", session_id).Scan(&exists)
	return exists, err
}

func GetSessionCircle(db *sql.DB, session_id int) (int, error) {
	var circle_id int
	err := db.QueryRow("SELECT id_circle FROM SessionsCircles WHERE id_session = $1", session_id).Scan(&circle_id)
	return circle_id, err
}

func GetSessionName(db *sql.DB, session_id int) (string, error) {
	var name string
	err := db.QueryRow("SELECT name FROM sessions WHERE id = $1", session_id).Scan(&name)
	return name, err
}

func GetCircleName(db *sql.DB, circle_id int) (string, error) {
	var name string
	err := db.QueryRow("SELECT name FROM circles WHERE id = $1", circle_id).Scan(&name)
	return name, err
}

func GetCricleUser(db *sql.DB, circle_id int) (int, string, error) {
	var name string
	var id int
	query := `
		SELECT Users.id, Users.name FROM Users
		INNER JOIN Circles on Circles.id_user = Users.id
		WHERE Circles.id = $1;
	`
	err := db.QueryRow(query, circle_id).Scan(&id, &name)
	return id, name, err
}

func GetUserName(db *sql.DB, userID int) (string, error) {
	var name string
	err := db.QueryRow("SELECT name FROM users WHERE id = $1", userID).Scan(&name)
	if err != nil {
		log.Println("Error fetching user name:", err)
		return "", err
	}
	return name, nil
}

func FetchSessions(db *sql.DB, circle_id int) ([]Session, error) {
	query := `
		SELECT s.id, s.name
		FROM Sessions s
		JOIN SessionsCircles sc ON s.id = sc.id_session
		WHERE sc.id_circle = $1;`

	rows, err := db.Query(query, circle_id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		sessions = append(sessions, Session{ID: id, Name: name})
	}
	return sessions, nil
}

func FetchCircles(db *sql.DB, user_id int) ([]Circle, error) {
	rows, err := db.Query("SELECT id, name FROM circles WHERE id_user = $1", user_id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var circles []Circle
	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		sessions, err := FetchSessions(db, id)
		if err != nil {
			return nil, err
		}

		circles = append(circles, Circle{ID: id, Name: name, Sessions: sessions})
	}

	return circles, nil
}

// VerifySessionCookie checks if the session cookie is valid and returns the user ID as an int if authenticated.
func VerifySessionCookie(r *http.Request) (int, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return 0, err
	}

	// Parse and validate the JWT
	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return 0, fmt.Errorf("invalid session")
	}

	// Extract the user ID from the token claims with flexible type checking
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		userID, exists := claims["user_id"]
		if !exists {
			return 0, fmt.Errorf("invalid session claims")
		}

		// Convert userID to an int if it’s a float64
		if v, ok := userID.(float64); ok {
			return int(v), nil // Convert float64 to int
		}

		return 0, fmt.Errorf("invalid session claims")
	}
	return 0, fmt.Errorf("invalid session claims")
}

func VerifyGuestSessionCookie(r *http.Request) (int, error) {
	cookie, err := r.Cookie("guest_session_token")
	if err != nil {
		return 0, err
	}

	// Parse and validate the JWT
	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return 0, fmt.Errorf("invalid session")
	}

	// Extract the user ID from the token claims with flexible type checking
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		userID, exists := claims["guest_id"]
		if !exists {
			return 0, fmt.Errorf("invalid session claims")
		}

		// Convert userID to an int if it’s a float64
		if v, ok := userID.(float64); ok {
			return int(v), nil // Convert float64 to int
		}

		return 0, fmt.Errorf("invalid session claims")
	}
	return 0, fmt.Errorf("invalid session claims")
}

func LoginPage(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	if userID, err := VerifySessionCookie(r); err == nil {
		name, err := GetUserName(db, userID)
		if err != nil {
			http.Error(w, "Error fetching user name", http.StatusInternalServerError)
			return
		}

		url := fmt.Sprintf("/circles?name=%s", name)
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	if _, err := VerifyGuestSessionCookie(r); err == nil {
		http.Redirect(w, r, "/pair-guest", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		userID, authenticated := AuthenticateUser(db, username, password)
		if authenticated {
			sessionToken, err := GenerateJWT(userID)
			if err != nil {
				http.Error(w, "Error generating session token", http.StatusInternalServerError)
				return
			}
			name, err := GetUserName(db, userID)
			if err != nil {
				http.Error(w, "Error fetching user name", http.StatusInternalServerError)
				return
			}
			SetSessionCookie(w, sessionToken)
			url := fmt.Sprintf("/circles?name=%s", name)
			http.Redirect(w, r, url, http.StatusSeeOther)
		} else {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		}
	} else {
		http.ServeFile(w, r, "public/index.html") // Show login form
	}
}

func CirclesPage(w http.ResponseWriter, r *http.Request) {
	_, err := VerifySessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	http.ServeFile(w, r, "public/circles.html")
}

func CreateCirclePage(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	userID, err := VerifySessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodPost {
		error := "Invalid request method"
		http.Error(w, error, http.StatusMethodNotAllowed)
	}

	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	// Insert the new record into the database
	if err := InsertCircle(db, userID, name); err != nil {
		http.Error(w, "Error creating circle", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Circle created",
	})
}

func FetchCirclesPage(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	userID, err := VerifySessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodGet {
		error := "Invalid request method"
		http.Error(w, error, http.StatusMethodNotAllowed)
		return
	}

	circles, err := FetchCircles(db, userID)
	if err != nil {
		http.Error(w, "Error fetching circles", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Encode the circle data into JSON and send it as the response
	if err := json.NewEncoder(w).Encode(circles); err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}
}

func ParseUrlPath(url string) (int, error) {
	urlParts := strings.Split(url, "/")
	if len(urlParts) != 3 {
		return 0, fmt.Errorf("invalid URL")
	}

	id, err := strconv.Atoi(urlParts[2])
	if err != nil {
		return 0, fmt.Errorf("invalid ID")
	}

	return id, nil
}

func ParseGuestCircle(url string) (int, int, error) {
	urlParts := strings.Split(url, "/")
	if len(urlParts) != 4 {
		return 0, 0, fmt.Errorf("invalid URL")
	}

	id, err := strconv.Atoi(urlParts[2])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid ID")
	}

	circleID, err := strconv.Atoi(urlParts[3])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid circle ID")
	}

	return id, circleID, nil
}

func DeleteCirclePage(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	userID, err := VerifySessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodDelete {
		error := "Invalid request method"
		http.Error(w, error, http.StatusMethodNotAllowed)
		return
	}

	circleID, err := ParseUrlPath(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := DeleteCircle(db, userID, circleID); err != nil {
		http.Error(w, "Error deleting circle", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// send success response
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Circle deleted",
	})
}

func FetchCircleMember(db *sql.DB, w http.ResponseWriter, r *http.Request) {

	userID, err := VerifySessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodGet {
		error := "Invalid request method"
		http.Error(w, error, http.StatusMethodNotAllowed)
		return
	}

	circleID, err := ParseUrlPath(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	exists, err := VerifyUserCircle(db, userID, circleID)
	if err != nil {
		http.Error(w, "Error verifying circle", http.StatusInternalServerError)
		return
	} else if !exists {
		http.Error(w, "Circle not found", http.StatusNotFound)
		return
	}

	sessions, err := FetchSessions(db, circleID)
	if err != nil {
		http.Error(w, "Error fetching circle members", http.StatusInternalServerError)
		return
	}

	sessionStatuses := make([]SessionStatus, len(sessions))
	for i, session := range sessions {
		var status = 1
		if _, ok := connections[circleID][-session.ID]; !ok {
			status = 0
		}
		sessionStatuses[i] = SessionStatus{ID: session.ID, Name: session.Name, Status: status}
		log.Println("Session status:", i, sessionStatuses[i])
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sessionStatuses); err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}
}

func FetchCircleMemberGuest(db *sql.DB, w http.ResponseWriter, r *http.Request) {

	guestID, err := VerifyGuestSessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodGet {
		error := "Invalid request method"
		http.Error(w, error, http.StatusMethodNotAllowed)
		return
	}

	circleID, err := ParseUrlPath(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	realCircleID, err := GetSessionCircle(db, guestID)
	if err != nil {
		http.Error(w, "Error verifying circle", http.StatusInternalServerError)
		return
	} else if realCircleID != circleID {
		http.Error(w, "Error wrong circle", http.StatusNotFound)
		return
	}

	userID, name, err := GetCricleUser(db, circleID)
	if err != nil {
		http.Error(w, "Error getting circle user", http.StatusInternalServerError)
		return
	}

	sessions, err := FetchSessions(db, circleID)
	if err != nil {
		http.Error(w, "Error fetching circle members", http.StatusInternalServerError)
		return
	}

	sessionStatuses := make([]SessionStatus, len(sessions))

	var userStatus = 1
	if _, ok := connections[circleID][userID]; !ok {
		userStatus = 0
	}
	sessionStatuses[0] = SessionStatus{ID: 0, Name: name, Status: userStatus}

	var i = 1
	for _, session := range sessions {
		if session.ID != guestID {
			var status = 1
			if _, ok := connections[circleID][-session.ID]; !ok {
				status = 0
			}
			sessionStatuses[i] = SessionStatus{ID: i, Name: session.Name, Status: status}
			i++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sessionStatuses); err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}
}

func ConnectUserRedirect(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	_, err := VerifySessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodGet {
		error := "Invalid request method"
		http.Error(w, error, http.StatusMethodNotAllowed)
		return
	}

	circleID, err := ParseUrlPath(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	circleName, err := GetCircleName(db, circleID)
	if err != nil {
		http.Error(w, "Error getting circle name", http.StatusInternalServerError)
		return
	}

	url := fmt.Sprintf("/circle?id=%d&name=%s&addr=%s", circleID, circleName, URL)
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func CirclePage(w http.ResponseWriter, r *http.Request) {
	_, err := VerifySessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	http.ServeFile(w, r, "public/circle.html")
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func receiveMessages(circleID int, conn *websocket.Conn) {
	for {
		var msg FileMessage
		// Read the incoming JSON message
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Println("Error reading message:", err)
			break
		}

		// Handle the message based on its type
		log.Println("Received message:", msg.Type)
		switch msg.Type {
		case "file":
			handleFileTransfer(circleID, conn, msg)

		default:
			log.Println("Unknown message type:", msg)
		}
	}
}

func handleFileTransfer(circleID int, conn *websocket.Conn, msg FileMessage) {
	// Send file to all connections in the circle except the sender
	for _, otherConn := range connections[circleID] {
		if otherConn == conn {
			continue
		}
		log.Println("Sending file to client")
		if err := sendFile(otherConn, msg); err != nil {
			log.Println("Error sending file to client:", err)
		}
	}
	log.Println("File transfer complete")
}

func sendFile(conn *websocket.Conn, msg FileMessage) error {
	return conn.WriteJSON(msg)
}

func Socket(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	user_id, err := VerifySessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	circle_id, err := ParseUrlPath(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	exists, err := VerifyUserCircle(db, user_id, circle_id)
	if err != nil {
		http.Error(w, "Error verifying circle", http.StatusInternalServerError)
		return
	} else if !exists {
		http.Error(w, "Circle not found", http.StatusNotFound)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer conn.Close()

	AddConnection(user_id, circle_id, conn)
	receiveMessages(circle_id, conn)
	RemoveConnection(user_id, circle_id)
}

func SocketGuest(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	guestID, err := VerifyGuestSessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	circleIDclient, err := ParseUrlPath(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	circleID, err := GetSessionCircle(db, guestID)
	if err != nil {
		http.Error(w, "Error getting circle", http.StatusInternalServerError)
		return
	}

	if circleID != circleIDclient {
		http.Error(w, "Invalid circle", http.StatusForbidden)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer conn.Close()

	guestID = -guestID
	AddConnection(guestID, circleID, conn)
	receiveMessages(circleID, conn)
	RemoveConnection(guestID, circleID)
}

func JoinGuestRedirect(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		error := "Invalid request method"
		http.Error(w, error, http.StatusMethodNotAllowed)
		return
	}

	name := r.FormValue("username")
	if name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	sessionID, err := InsertSession(db, name)
	if err != nil {
		http.Error(w, "Error creating session", http.StatusInternalServerError)
		return
	}

	sessionToken, err := GenerateGuestJWT(sessionID)
	if err != nil {
		http.Error(w, "Error generating session token", http.StatusInternalServerError)
		return
	}

	SetGuestSessionCookie(w, sessionToken)
	http.Redirect(w, r, "/pair-guest", http.StatusSeeOther)
}

func PairRedirect(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	guestID, err := VerifyGuestSessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	exists, err := VerifySessionEmpty(db, guestID)
	if err != nil {
		http.Error(w, "Error verifying session", http.StatusInternalServerError)
		return
	} else if exists {
		http.Redirect(w, r, "/connect-guest", http.StatusSeeOther)
		return
	}

	url := fmt.Sprintf("pair?id=%d&addr=%s", guestID, URL)
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func PairPage(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	guestID, err := VerifyGuestSessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	name, err := GetSessionName(db, guestID)
	if err != nil || name == "" {
		http.Redirect(w, r, "/delete-session-guest", http.StatusSeeOther)
		return
	}

	exists, err := VerifySessionEmpty(db, guestID)
	if err != nil {
		http.Error(w, "Error verifying session", http.StatusInternalServerError)
		return
	} else if exists {
		http.Redirect(w, r, "/connect-guest", http.StatusSeeOther)
		return
	}

	http.ServeFile(w, r, "public/pair.html")
}

func AddGuestRedirect(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	_, err := VerifySessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	guestID, err := ParseUrlPath(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	guestName, err := GetSessionName(db, guestID)
	if err != nil {
		http.Error(w, "Error getting session name", http.StatusInternalServerError)
		return
	}

	url := fmt.Sprintf("/add?id=%d&name=%s", guestID, guestName)
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func DeleteSession(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		error := "Invalid request method"
		http.Error(w, error, http.StatusMethodNotAllowed)
		return
	}

	userID, err := VerifySessionCookie(r)
	if err != nil {
		http.Error(w, "Error verifying session", http.StatusInternalServerError)
		return
	}

	circleID, sessionID, err := ParseGuestCircle(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	exists, err := VerifyUserCircle(db, userID, circleID)
	if err != nil {
		http.Error(w, "Error verifying circle", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "Circle not found", http.StatusNotFound)
		return
	}

	circleIDofSession, err := GetSessionCircle(db, sessionID)
	if err != nil {
		http.Error(w, "Error getting session circle", http.StatusInternalServerError)
		return
	}

	if circleID != circleIDofSession {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	err = DeleteSessionDB(db, sessionID)
	if err != nil {
		http.Error(w, "Error deleting session", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Session deleted",
	})
}

func AddGuestPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "public/add.html")
}

func AddToCircle(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	userID, err := VerifySessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodPost {
		error := "Invalid request method"
		http.Error(w, error, http.StatusMethodNotAllowed)
		return
	}

	guestID, circleID, err := ParseGuestCircle(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	exists, err := VerifyUserCircle(db, userID, circleID)
	if err != nil {
		http.Error(w, "Error verifying circle", http.StatusInternalServerError)
		return
	} else if !exists {
		http.Error(w, "Circle not found", http.StatusNotFound)
		return
	}

	exists, err = VerifySessionEmpty(db, guestID)
	if err != nil {
		http.Error(w, "Error verifying session", http.StatusInternalServerError)
		return
	} else if exists {
		http.Error(w, "Session already set", http.StatusNotFound)
		return
	}

	err = InsertSessionCircle(db, guestID, circleID)
	if err != nil {
		http.Error(w, "Error adding session to circle", http.StatusInternalServerError)
		return
	}

	// send success response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Session added to circle",
	})
}

func ConnectGuestRedirect(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	guestID, err := VerifyGuestSessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	circleID, err := GetSessionCircle(db, guestID)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	circleName, err := GetCircleName(db, circleID)
	if err != nil {
		http.Error(w, "Error getting circle name", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/circle-guest?id=%d&name=%s&addr=%s", circleID, circleName, URL), http.StatusSeeOther)

}

func CircleGuestPage(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	guestID, err := VerifyGuestSessionCookie(r)
	if err != nil {
		log.Println("Error verifying guest session")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	exists, err := VerifySessionEmpty(db, guestID)
	if err != nil {
		http.Error(w, "Error verifying session", http.StatusInternalServerError)
		return
	} else if !exists {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	http.ServeFile(w, r, "public/circle-guest.html")
}

func DeleteSessionGuest(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	guestID, err := VerifyGuestSessionCookie(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Delete the session cookies by setting them with a past expiration date
	http.SetCookie(w, &http.Cookie{
		Name:    "guest_session_token",
		Value:   "",
		Expires: time.Unix(0, 0), // Set expiration date to a past date
		Path:    "/",
	})

	err = DeleteSessionDB(db, guestID)
	if err != nil {
		http.Error(w, "Error deleting session", http.StatusInternalServerError)
		return
	}

	// Redirect to the homepage
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func GetSuperkey(db *sql.DB, superkey string) (bool, error) {
	query := `
		SELECT 
			EXISTS (
				SELECT 1
				FROM SuperKeys
				WHERE superkey = $1
				AND id_user IS NULL
			) AS result;	
	`

	var isEmpy bool
	err := db.QueryRow(query, superkey).Scan(&isEmpy)
	if err != nil {
		return false, err
	}
	return isEmpy, nil
}

func Register(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		error := "Invalid request method"
		http.Error(w, error, http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	superkey := r.FormValue("superkey")

	if username == "" || password == "" || superkey == "" {
		http.Error(w, "Username, password and superkey are required", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	isEmpy, err := GetSuperkey(db, superkey)
	if err != nil {
		http.Error(w, "Invalid superkey", http.StatusBadRequest)
		log.Println("Error getting superkey:", superkey, err)
		return
	} else if !isEmpy {
		http.Error(w, "Superkey not found or expired", http.StatusBadRequest)
		return
	}

	userID, err := InsertUser(db, username, string(hash), superkey)
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	sessionToken, err := GenerateJWT(userID)
	if err != nil {
		http.Error(w, "Error generating session token", http.StatusInternalServerError)
		return
	}
	SetSessionCookie(w, sessionToken)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func readSuperkeysFromFile(filename string) ([]string, error) {
	// Open the file for reading
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Read the superkeys from the file into a slice
	var superkeys []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text()) // Remove any extra whitespace
		if line != "" {
			superkeys = append(superkeys, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	return superkeys, nil
}

func insertSuperkeys(db *sql.DB, superkeys []string) error {
	query := `
		INSERT INTO SuperKeys (superkey) 
		VALUES ($1)
		ON CONFLICT (superkey) 
		DO NOTHING;
	`

	for _, superkey := range superkeys {
		_, err := db.Exec(query, superkey)
		if err != nil {
			return err
		}
	}
	return nil
}

func initDatabase(db *sql.DB) error {
	_, err := db.Exec(Query)
	return err
}

func main() {
	time.Sleep(5 * time.Second)
	db, err := dbConnection()
	if err != nil {
		log.Fatal("Database connection error:", err)
		return
	}
	defer db.Close()

	// Initialize the database schema
	if err := initDatabase(db); err != nil {
		log.Fatal("Error initializing database:", err)
		return
	}

	// Load the superkeys from the file
	superkeys, err := readSuperkeysFromFile("superkeys.txt")
	if err != nil {
		log.Fatal("Error reading superkeys:", err)
		return
	}

	// Insert the superkeys into the database
	if err := insertSuperkeys(db, superkeys); err != nil {
		log.Fatal("Error inserting superkeys:", err)
		return
	}

	// General route
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { LoginPage(db, w, r) })
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// Register
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) { Register(db, w, r) })

	// User routes
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) { LoginPage(db, w, r) })
	http.HandleFunc("/circles", CirclesPage)
	http.HandleFunc("/connect-user/", func(w http.ResponseWriter, r *http.Request) { ConnectUserRedirect(db, w, r) })
	http.HandleFunc("/delete-session/", func(w http.ResponseWriter, r *http.Request) { DeleteSession(db, w, r) })
	http.HandleFunc("/circle", CirclePage)

	// Websocket route
	http.HandleFunc("/socket/", func(w http.ResponseWriter, r *http.Request) { Socket(db, w, r) })
	http.HandleFunc("/socket-guest/", func(w http.ResponseWriter, r *http.Request) { SocketGuest(db, w, r) })

	// User routes for guest
	http.HandleFunc("/add-guest/", func(w http.ResponseWriter, r *http.Request) { AddGuestRedirect(db, w, r) })
	http.HandleFunc("/add", AddGuestPage)
	http.HandleFunc("/add-to-circle/", func(w http.ResponseWriter, r *http.Request) { AddToCircle(db, w, r) })

	// Circle routes
	http.HandleFunc("/create-circle", func(w http.ResponseWriter, r *http.Request) { CreateCirclePage(db, w, r) })
	http.HandleFunc("/fetch-circles", func(w http.ResponseWriter, r *http.Request) { FetchCirclesPage(db, w, r) })
	http.HandleFunc("/delete-circle/", func(w http.ResponseWriter, r *http.Request) { DeleteCirclePage(db, w, r) })
	http.HandleFunc("/circle-members/", func(w http.ResponseWriter, r *http.Request) { FetchCircleMember(db, w, r) })
	http.HandleFunc("/circle-members-guest/", func(w http.ResponseWriter, r *http.Request) { FetchCircleMemberGuest(db, w, r) })

	// Guest routes
	http.HandleFunc("/join-guest", func(w http.ResponseWriter, r *http.Request) { JoinGuestRedirect(db, w, r) })
	http.HandleFunc("/pair-guest", func(w http.ResponseWriter, r *http.Request) { PairRedirect(db, w, r) })
	http.HandleFunc("/pair", func(w http.ResponseWriter, r *http.Request) { PairPage(db, w, r) })
	http.HandleFunc("/connect-guest", func(w http.ResponseWriter, r *http.Request) { ConnectGuestRedirect(db, w, r) })
	http.HandleFunc("/circle-guest", func(w http.ResponseWriter, r *http.Request) { CircleGuestPage(db, w, r) })
	http.HandleFunc("/delete-session-guest/", func(w http.ResponseWriter, r *http.Request) { DeleteSessionGuest(db, w, r) })

	log.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
