package main

import (
    "fmt"
    "context"
    "html/template"
    "log"
    "net/http"
    "os"

    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
    "google.golang.org/api/calendar/v3"
    "google.golang.org/api/option"
    "google.golang.org/api/googleapi"
)

var (
    googleOauthConfig *oauth2.Config
    oauthStateString  = "random"
)

func init() {
    fmt.Println("initializing")
    googleOauthConfig = &oauth2.Config{
        RedirectURL:  "http://localhost:8080/callback",
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        Scopes:       []string{calendar.CalendarReadonlyScope},
        Endpoint:     google.Endpoint,
    }
}

func main() {
    http.HandleFunc("/", handleMain)
    http.HandleFunc("/login", handleGoogleLogin)
    http.HandleFunc("/callback", handleGoogleCallback)
    http.HandleFunc("/logout", handleLogout)
    http.HandleFunc("/select-calendar", handleSelectCalendar)
    http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

    log.Println("Started running on http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleMain(w http.ResponseWriter, r *http.Request) {
    // Check if the user is logged in by looking for the OAuth token cookie
    cookie, err := r.Cookie("oauth_token")
    if err != nil || cookie.Value == "" {
        // Not logged in, show login page
        fmt.Println("not logged in")
        t, _ := template.ParseFiles("templates/index.html")
        t.Execute(w, nil)
        return
    }

    // Decode the token to check its expiration time
    token := &oauth2.Token{AccessToken: cookie.Value}
    client := googleOauthConfig.Client(context.Background(), token)

    srv, err := calendar.NewService(context.Background(), option.WithHTTPClient(client))
    if err != nil {
        log.Fatalf("Unable to retrieve Calendar client: %v", err)
    }

    calendarList, err := srv.CalendarList.List().Do()
    if err != nil {
        // Check if the error is due to an invalid token
        if isAuthError(err) {
            // Token is invalid, redirect to login
            http.Redirect(w, r, "/login", http.StatusFound)
            return
        }
        log.Fatalf("Unable to retrieve calendar list: %v", err)
    }

    data := struct {
        Calendars []*calendar.CalendarListEntry
    }{
        Calendars: calendarList.Items,
    }

    t, _ := template.ParseFiles("templates/main.html")
    t.Execute(w, data)
}

func isAuthError(err error) bool {
    apiErr, ok := err.(*googleapi.Error)
    if !ok {
        return false
    }
    for _, e := range apiErr.Errors {
        if e.Reason == "authError" {
            return true
        }
    }
    return false
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
    url := googleOauthConfig.AuthCodeURL(oauthStateString)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
    if r.FormValue("state") != oauthStateString {
        log.Println("invalid oauth state")
        http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
        return
    }

    code := r.FormValue("code")
    token, err := googleOauthConfig.Exchange(context.Background(), code)
    if err != nil {
        log.Println("code exchange failed: ", err)
        http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
        return
    }

    // Store token in a secure cookie
    cookie := http.Cookie{
        Name:     "oauth_token",
        Value:    token.AccessToken,
        HttpOnly: true,
        Secure:   true, // Use 'true' in production with HTTPS
        Path:     "/",
    }
    http.SetCookie(w, &cookie)

    http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
    // Retrieve the token from the cookie
    cookie, err := r.Cookie("oauth_token")
    if err != nil {
        log.Println("No valid token found")
        http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
        return
    }

    token := &oauth2.Token{
        AccessToken: cookie.Value,
    }

    // Revoke the token
    revokeToken(token)

    // Clear the cookie
    clearCookie := http.Cookie{
        Name:     "oauth_token",
        Value:    "",
        HttpOnly: true,
        Secure:   true, // Use 'true' in production with HTTPS
        Path:     "/",
        MaxAge:   -1, // Expire the cookie immediately
    }
    http.SetCookie(w, &clearCookie)

    // Redirect to the home page
    http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func handleSelectCalendar(w http.ResponseWriter, r *http.Request) {
    // Retrieve the token from the cookie
    cookie, err := r.Cookie("oauth_token")
    if err != nil {
        log.Println("No valid token found")
        http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
        return
    }

    token := &oauth2.Token{AccessToken: cookie.Value}
    client := googleOauthConfig.Client(context.Background(), token)
    srv, err := calendar.NewService(context.Background(), option.WithHTTPClient(client))
    if err != nil {
        log.Fatalf("Unable to retrieve Calendar client: %v", err)
    }

    calendarId := r.FormValue("calendarId")
    events, err := srv.Events.List(calendarId).Do()
    if err != nil {
        log.Fatalf("Unable to retrieve calendar events: %v", err)
    }

    data := struct {
        EventCount int
    }{
        EventCount: len(events.Items),
    }

    t, _ := template.ParseFiles("templates/calendar.html")
    t.Execute(w, data)
}

func revokeToken(token *oauth2.Token) {
    url := "https://accounts.google.com/o/oauth2/revoke?token=" + token.AccessToken
    resp, err := http.Get(url)
    if err != nil {
        log.Printf("Failed to revoke token: %v", err)
    } else {
        defer resp.Body.Close()
        if resp.StatusCode == http.StatusOK {
            log.Println("Successfully revoked token")
        } else {
            log.Printf("Failed to revoke token, status code: %d", resp.StatusCode)
        }
    }
}
