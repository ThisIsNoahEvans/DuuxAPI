package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lnquy/cron"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
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

		// get the user data
		getUserData()
	} else {
		fmt.Println("Failed!")
		fmt.Println("Message: " + authTokenResponse.AccessToken)
	}
}

func getUserData() {
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

// get the user data from the file
func getUserDataFromFile() UserResponseSubset {
	// Get the user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println(err)
		return UserResponseSubset{}
	}

	// Specify the file path
	filePath := filepath.Join(homeDir, ".duux-user.json")

	// read the file
	jsonData, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println(err)
		return UserResponseSubset{}
	}

	userResponse := UserResponseSubset{}
	json.Unmarshal(jsonData, &userResponse)

	return userResponse
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

	// print the sensors with tabwriter
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.Debug)
	fmt.Fprintln(w, "\nID\tType\tDisplay Name")
	for _, sensor := range sensorResponse {
		fmt.Fprintf(w, "%d\t%s\t%s\n", sensor.ID, sensor.Type, sensor.DisplayName)
	}
	w.Flush()

	return sensorResponse
}

func logout() {
	fmt.Println("Logging out...")

	// delete the API key files
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println(err)
		return
	}

	// Access token
	filePath := filepath.Join(homeDir, ".duux-access_token.enc")
	err = os.Remove(filePath)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Refresh token
	filePath = filepath.Join(homeDir, ".duux-refresh_token.enc")
	err = os.Remove(filePath)
	if err != nil {
		fmt.Println(err)
		return
	}

	// User data
	filePath = filepath.Join(homeDir, ".duux-user.json")
	err = os.Remove(filePath)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Successfully logged out!")
}

func setPower(fanID string, power string) {
	fmt.Println("Setting power...")

	// get the tenant from the user data
	userData := getUserDataFromFile()
	// get the first tenant that isn't id '44' (this is duux default)
	var tenantID int
	for _, tenant := range userData.User.Tenants {
		if tenant.ID != 44 {
			tenantID = tenant.ID
			break
		}
	}

	// check if tenantID is still 0
	if tenantID == 0 {
		fmt.Println("Failed!")
		fmt.Println("Tenant ID is 0")
		return
	}

	url := "https://v4.api.cloudgarden.nl/tenants/" + fmt.Sprint(tenantID) + "/sensors/" + fanID + "/command"
	method := "POST"

	if power == "on" {
		power = "01"
	} else if power == "off" {
		power = "00"
	} else {
		fmt.Println("Invalid power state: " + power)
		return
	}

	formData := "command=tune+set+power+" + power

	// get the API key
	apiKey, err := getAPIKey("access_token")
	if err != nil {
		fmt.Println(err)
		return
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, strings.NewReader(formData))

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Authorization", "Bearer "+apiKey)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

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

	// if success = true
	successResponse := SuccessResponse{}
	json.Unmarshal(body, &successResponse)

	if successResponse.Response.Success {
		fmt.Println("Successfully set power!")
	} else {
		fmt.Println("Failed!")
		fmt.Println("Body: " + string(body))
	}
}

func setSpeed(fanID string, speed string) {
	fmt.Println("Setting speed...")

	// convert speed to int
	speedInt := 0
	fmt.Sscanf(speed, "%d", &speedInt)

	// check if speed is between 1 and 26
	if speedInt < 1 || speedInt > 26 {
		fmt.Println("Invalid speed: " + speed)
		return
	}

	// get the tenant from the user data
	userData := getUserDataFromFile()
	// get the first tenant that isn't id '44' (this is duux default)
	var tenantID int
	for _, tenant := range userData.User.Tenants {
		if tenant.ID != 44 {
			tenantID = tenant.ID
			break
		}
	}

	// check if tenantID is still 0
	if tenantID == 0 {
		fmt.Println("Failed!")
		fmt.Println("Tenant ID is 0")
		return
	}

	url := "https://v4.api.cloudgarden.nl/tenants/" + fmt.Sprint(tenantID) + "/sensors/" + fanID + "/command"
	method := "POST"

	formData := "command=tune+set+speed+" + speed

	// get the API key
	apiKey, err := getAPIKey("access_token")
	if err != nil {
		fmt.Println(err)
		return
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, strings.NewReader(formData))

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Authorization", "Bearer "+apiKey)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

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

	// if success = true
	successResponse := SuccessResponse{}
	json.Unmarshal(body, &successResponse)

	if successResponse.Response.Success {
		fmt.Println("Successfully set speed!")
	} else {
		fmt.Println("Failed!")
		fmt.Println("Body: " + string(body))
	}
}

func setMode(fanID string, mode string) {
	fmt.Println("Setting mode...")

	// get the tenant from the user data
	userData := getUserDataFromFile()
	// get the first tenant that isn't id '44' (this is duux default)
	var tenantID int
	for _, tenant := range userData.User.Tenants {
		if tenant.ID != 44 {
			tenantID = tenant.ID
			break
		}
	}

	// check if tenantID is still 0
	if tenantID == 0 {
		fmt.Println("Failed!")
		fmt.Println("Tenant ID is 0")
		return
	}

	url := "https://v4.api.cloudgarden.nl/tenants/" + fmt.Sprint(tenantID) + "/sensors/" + fanID + "/command"
	method := "POST"

	if mode == "normal" {
		mode = "0"
	} else if mode == "natural" {
		mode = "1"
	} else if mode == "night" {
		mode = "2"
	} else {
		fmt.Println("Invalid mode: " + mode)
		return
	}
	formData := "command=tune+set+mode+" + mode

	// get the API key
	apiKey, err := getAPIKey("access_token")
	if err != nil {
		fmt.Println(err)
		return
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, strings.NewReader(formData))

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Authorization", "Bearer "+apiKey)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

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

	// if success = true
	successResponse := SuccessResponse{}
	json.Unmarshal(body, &successResponse)

	if successResponse.Response.Success {
		fmt.Println("Successfully set mode!")
	} else {
		fmt.Println("Failed!")
		fmt.Println("Body: " + string(body))
	}
}

func setTimer(fanID string, hours string) {
	fmt.Println("Setting timer...")

	// get the tenant from the user data
	userData := getUserDataFromFile()
	// get the first tenant that isn't id '44' (this is duux default)
	var tenantID int
	for _, tenant := range userData.User.Tenants {
		if tenant.ID != 44 {
			tenantID = tenant.ID
			break
		}
	}

	// check if tenantID is still 0
	if tenantID == 0 {
		fmt.Println("Failed!")
		fmt.Println("Tenant ID is 0")
		return
	}

	// between 1 and 12 hours
	hoursInt := 0
	fmt.Sscanf(hours, "%d", &hoursInt)
	if hoursInt < 1 || hoursInt > 12 {
		fmt.Println("Invalid hours: " + hours)
		return
	}

	// turn fan on first
	setPower(fanID, "on")

	url := "https://v4.api.cloudgarden.nl/tenants/" + fmt.Sprint(tenantID) + "/sensors/" + fanID + "/command"
	method := "POST"

	formData := "command=tune+set+timer+" + hours

	// get the API key
	apiKey, err := getAPIKey("access_token")
	if err != nil {
		fmt.Println(err)
		return
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, strings.NewReader(formData))

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Authorization", "Bearer "+apiKey)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

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

	// if success = true
	successResponse := SuccessResponse{}
	json.Unmarshal(body, &successResponse)

	if successResponse.Response.Success {
		fmt.Println("Successfully set timer!")
	} else {
		fmt.Println("Failed!")
		fmt.Println("Body: " + string(body))
	}
}

func setOscillation(fanID string, direction string, state string) {
	fmt.Println("Setting oscillation...")

	// get the tenant from the user data
	userData := getUserDataFromFile()
	// get the first tenant that isn't id '44' (this is duux default)
	var tenantID int
	for _, tenant := range userData.User.Tenants {
		if tenant.ID != 44 {
			tenantID = tenant.ID
			break
		}
	}

	// check if tenantID is still 0
	if tenantID == 0 {
		fmt.Println("Failed!")
		fmt.Println("Tenant ID is 0")
		return
	}

	// check if direction is valid
	if direction != "vertical" && direction != "horizontal" {
		fmt.Println("Invalid direction: " + direction)
		return
	}

	url := "https://v4.api.cloudgarden.nl/tenants/" + fmt.Sprint(tenantID) + "/sensors/" + fanID + "/command"
	method := "POST"

	// horizontal: swing
	// vertical: tilt
	if direction == "horizontal" {
		direction = "swing"
	} else if direction == "vertical" {
		direction = "tilt"
	}

	// on/off
	if state == "on" {
		state = "1"
	} else if state == "off" {
		state = "0"
	} else {
		fmt.Println("Invalid state: " + state)
		return
	}

	formData := "command=tune+set+" + direction + "+" + state

	// get the API key
	apiKey, err := getAPIKey("access_token")
	if err != nil {
		fmt.Println(err)
		return
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, strings.NewReader(formData))

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Authorization", "Bearer "+apiKey)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

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

	// if success = true
	successResponse := SuccessResponse{}
	json.Unmarshal(body, &successResponse)

	if successResponse.Response.Success {
		fmt.Println("Successfully set oscillation!")
	} else {
		fmt.Println("Failed!")
		fmt.Println("Body: " + string(body))
	}
}

func getSchedule(fanID string) {
	fmt.Println("Getting schedule...")

	// get the tenant from the user data
	userData := getUserDataFromFile()
	// get the first tenant that isn't id '44' (this is duux default)
	var tenantID int
	for _, tenant := range userData.User.Tenants {
		if tenant.ID != 44 {
			tenantID = tenant.ID
			break
		}
	}

	// check if tenantID is still 0
	if tenantID == 0 {
		fmt.Println("Failed!")
		fmt.Println("Tenant ID is 0")
		return
	}

	url := "https://v4.api.cloudgarden.nl/tenants/" + fmt.Sprint(tenantID) + "/sensors/" + fanID + "/scheduleGroups?includeScheduleItems=true"
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

	sensors := []Sensor{}
	json.Unmarshal(body, &sensors)

	for _, sensor := range sensors {
		fmt.Printf("Sensor ID: %d\n", sensor.SensorID)
		fmt.Printf("Created At: %s\n", sensor.CreatedAt)
		fmt.Printf("Updated At: %s\n", sensor.UpdatedAt)
		fmt.Println("Schedules:")
		for _, schedule := range sensor.SensorSchedules {
			fmt.Printf("\tSchedule ID: %d\n", schedule.ID)

			exprDesc, err := cron.NewDescriptor(
				cron.Use24HourTimeFormat(true),
				cron.DayOfWeekStartsAtOne(false),
				cron.Verbose(false),
				cron.SetLocales(cron.Locale_en),
			)
			if err != nil {
				fmt.Println("failed to create CRON expression descriptor: %s", err)
			}
		
			desc, err := exprDesc.ToDescription(schedule.Cron, cron.Locale_en)
			if err != nil {
				fmt.Println("failed to convert CRON expression to human readable description: %s", err)
			}

			fmt.Printf("\tCron: %s\n", desc)
			fmt.Printf("\tPower: %d\n", schedule.Value.Power)
			// Check if Mode and Speed are not nil before printing
			if schedule.Value.Mode != nil {
				fmt.Printf("\tMode: %d\n", *schedule.Value.Mode)
			}
			if schedule.Value.Speed != nil {
				fmt.Printf("\tSpeed: %d\n", *schedule.Value.Speed)
			}
			fmt.Printf("\tType: %s\n\n", schedule.Type)
		}
		fmt.Println("---------------------")
	}

}

func printUsage() {
	fmt.Println("\nUsage:")
	fmt.Println("  login")
	fmt.Println("  logout")
	fmt.Println("  getfans")
	fmt.Println("  getschedule <fan id>")
	fmt.Println("  setpower <fan id> <on/off>")
	fmt.Println("  setspeed <fan id> <speed, 1-26>")
	fmt.Println("  setmode <fan id> <normal/natural/night>")
	fmt.Println("  settimer <fan id> <hours>")
	fmt.Println("  setoscillation <fan id> <vertical/horizontal> <on/off>")
}

func main() {
	args := os.Args[1:]

	if len(args) > 0 {
		switch args[0] {
		case "login":
			sendLoginCode()
		case "logout":
			logout()
		case "getfans":
			getSensors()
		case "getschedule":
			getSchedule(args[1])
		case "setpower":
			if len(args) < 3 {
				fmt.Println("Not enough arguments")
				printUsage()
				return
			}
			fanID := args[1]
			power := args[2]
			setPower(fanID, power)
		case "setspeed":
			if len(args) < 3 {
				fmt.Println("Not enough arguments")
				printUsage()
				return
			}
			fanID := args[1]
			speed := args[2]
			setSpeed(fanID, speed)
		case "setmode":
			if len(args) < 3 {
				fmt.Println("Not enough arguments")
				printUsage()
				return
			}
			fanID := args[1]
			mode := args[2]
			setMode(fanID, mode)
		case "settimer":
			if len(args) < 3 {
				fmt.Println("Not enough arguments")
				printUsage()
				return
			}
			fanID := args[1]
			hours := args[2]
			setTimer(fanID, hours)
		case "setoscillation":
			if len(args) < 4 {
				fmt.Println("Not enough arguments")
				printUsage()
				return
			}
			fanID := args[1]
			direction := args[2]
			state := args[3]
			setOscillation(fanID, direction, state)
		default:
			fmt.Println("Unknown command: " + args[0])
			printUsage()
		}

	} else {
		fmt.Println("No command specified")
		printUsage()
		return
	}

}
