package main

// Struct for LoginCodeResponse
type LoginCodeResponse struct {
	Success bool `json:"success"`
	Message string `json:"message"`
}

// Struct for AuthTokenResponse
type AuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn int `json:"expires_in"`
	TokenType string `json:"token_type"`
}