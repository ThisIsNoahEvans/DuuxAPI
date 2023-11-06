package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"encoding/json"
)

func login() {
	fmt.Println("Logging in...")

	// ask for email
	fmt.Println("\nEnter your email: ")
	var email string
	fmt.Scanln(&email)

	url := "https://v4.api.cloudgarden.nl/tenants/44/auth/passwordlessLogin/code"
	method := "POST"

	// Parameters from the iOS app.
	// Effectively, we are emulating the iOS app here.
	payload := strings.NewReader(`{
    "email": "` + email + `",
    "client_id": "83f34a5fa5faca9023c78980a57a87b41f6972fc4ee45e9c",
    "redirect_uri": "https://duux-deeplink.vercel.app/login/verify",
    "code_challenge_method": "sha256",
    "code_challenge": "NzyryiS6cQ7w7ZjwXmFkM4a3ZU0wZ8tLKe1VfuRaYCY"
}`)

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Host", "v4.api.cloudgarden.nl")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("If-None-Match", "W/\"66-H6c9DH7yr0xVY8YpuhpYVXVKCCw\"")
	req.Header.Add("Accept", "*/*")
	req.Header.Add("Accept-Language", "en-GB,en;q=0.9")
	req.Header.Add("User-Agent", "Duux/154 CFNetwork/1335.0.3.4 Darwin/21.6.0")
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	
	loginCodeResponse := LoginCodeResponse{}
	json.Unmarshal(body, &loginCodeResponse)

	if loginCodeResponse.Success {
		fmt.Println("Successfully sent login code!\nPlease check your email.")
		// ask for login code
		fmt.Println("\nEnter your login code: ")
		var loginCode string
		fmt.Scanln(&loginCode)

		// pass login code to getAuthToken()
	} else {
		fmt.Println("Failed!")
		fmt.Println("Message: " + loginCodeResponse.Message)
	}
}

func main() {
	login()
}