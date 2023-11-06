package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var encodedKey = "gM4NSmqvYb5ajCxsDwWz5W/+b+RM1LXs11e0zw4gwVY="
var encryptionKey []byte

func init() {
	var err error
	encryptionKey, err = base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		panic(err)
	}
}

func saveAPIKey(apiKey string, name string) error {
	// Get the user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Specify the file path
	filePath := filepath.Join(homeDir, ".duux-"+name+".enc")

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return err
	}

	ciphertext := make([]byte, aes.BlockSize+len(apiKey))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(apiKey))

	encodedStr := base64.StdEncoding.EncodeToString(ciphertext)

	err = ioutil.WriteFile(filePath, []byte(encodedStr), 0644)
	if err != nil {
		return err
	}

	fmt.Println("API key saved")
	return nil
}

func getAPIKey(name string) (string, error) {
	// Get the user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	// Specify the file path
	filePath := filepath.Join(homeDir, ".duux-"+name+".enc")

	encodedStr, err := ioutil.ReadFile(filePath)
	if err != nil {
		// the file doesn't exist
		return "", errors.New("API key file not found")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(string(encodedStr))
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

func saveUserData(userData UserResponseSubset) error {
	// Get the user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Specify the file path
	filePath := filepath.Join(homeDir, ".duux-user.json")

	// Marshal the userData into JSON
	jsonData, err := json.MarshalIndent(userData, "", "  ")
	if err != nil {
		return err
	}

	// Write the JSON data to the file
	err = os.WriteFile(filePath, jsonData, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("User data saved to %s\n", filePath)
	return nil
}

func sendLoginCode() {
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
		getAuthToken(loginCode)
	} else {
		fmt.Println("Failed!")
		fmt.Println("Message: " + loginCodeResponse.Message)
	}
}

func getAuthToken(loginCode string) {
	fmt.Println("Getting auth token...")

	url := "https://v4.api.cloudgarden.nl/auth/oauth2/token"
	method := "POST"

	// Parameters from the iOS app.
	// Effectively, we are emulating the iOS app here.
	payload := strings.NewReader(`{
    "grant_type": "authorization_code",
    "code": "` + loginCode + `",
    "code_verifier": "j2yOyLB3KbdFE3ZjYtm6QGMDBL8-_5FWo0UMYkRVdljLYATNMFa4fJ86vwe3jsVHPsuZcZXGLkezJqHnvhLrRMJjymjDnw-LvCA8WVAFQZNWwFmiUULgNsldc29ZyI36",
    "client_id": "83f34a5fa5faca9023c78980a57a87b41f6972fc4ee45e9c",
    "redirect_uri": "https://duux-deeplink.vercel.app/login/verify",
    "makeAccessTokenLongLasting": true
}`)

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Host", "v4.api.cloudgarden.nl")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Accept", "*/*")
	req.Header.Add("User-Agent", "Duux/154 CFNetwork/1335.0.3.4 Darwin/21.6.0")
	req.Header.Add("Accept-Language", "en-GB,en;q=0.9")
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

	authTokenResponse := AuthTokenResponse{}
	json.Unmarshal(body, &authTokenResponse)

	if authTokenResponse.AccessToken != "" {
		fmt.Println("Successfully got auth token!")
		saveAPIKey(authTokenResponse.AccessToken, "access_token")
		saveAPIKey(authTokenResponse.RefreshToken, "refresh_token")
	} else {
		fmt.Println("Failed!")
		fmt.Println("Message: " + authTokenResponse.AccessToken)
	}
}

func getUser() {
	fmt.Println("Getting user...")

	url := "https://v4.api.cloudgarden.nl/users/current"
	method := "GET"

	// get the API key
	apiKey, err := getAPIKey("access_token")
	if err != nil {
		fmt.Println(err)
		return
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Authorization", "Bearer "+apiKey)

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
	// check if there is content in the body
	if len(body) == 0 {
		fmt.Println("Failed!")
		fmt.Println("Body: " + string(body))
		return
	}

	userResponse := UserResponseSubset{}
	json.Unmarshal(body, &userResponse)

	// save the user data to a file
	saveUserData(userResponse)

	fmt.Println("Successfully got user!")
}

// devices are called "sensors" in the API
func getSensors() []SensorResponse {
	url := "https://v4.api.cloudgarden.nl/tenants/31897/sensors"
	method := "GET"

	// get the API key
	apiKey, err := getAPIKey("access_token")
	if err != nil {
		fmt.Println(err)
		return nil
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return nil
	}
	req.Header.Add("Authorization", "Bearer "+apiKey)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	
	// check if there is content in the body
	if len(body) == 0 {
		fmt.Println("Failed!")
		fmt.Println("Body: " + string(body))
		return nil
	}

	sensorResponse := []SensorResponse{}
	json.Unmarshal(body, &sensorResponse)

	fmt.Println("Successfully got sensors!")
	
	return sensorResponse

}
func main() {

}
