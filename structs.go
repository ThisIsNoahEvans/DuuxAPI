package main

import (
	"time"
)

// Struct for LoginCodeResponse
type LoginCodeResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Struct for AuthTokenResponse
type AuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// Struct for UserResponse
type UserResponseSubset struct {
	User struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Tenants  []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"tenants"`
	} `json:"user"`
}

// Struct for SensorResponse
type SensorResponse struct {
	ID          int    `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"displayName"`
}

// General success response
type SuccessResponse struct {
	Response struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	} `json:"response"`
}

type SensorScheduleValue struct {
	Cron  string `json:"cron"`
	Power int    `json:"power"`
	Mode  *int   `json:"mode,omitempty"` 
	Speed *int   `json:"speed,omitempty"`
}

type SensorSchedule struct {
	ID                    int                 `json:"id"`
	SensorID              int                 `json:"SensorId"`
	CreatedAt             time.Time           `json:"createdAt"`
	Cron                  string              `json:"cron"`
	Value                 SensorScheduleValue `json:"value"`
	SensorScheduleGroupID int                 `json:"SensorScheduleGroupId"`
	UpdatedAt             time.Time           `json:"updatedAt"`
	Type                  string              `json:"type"`
}

type Sensor struct {
	SensorID        int              `json:"SensorId"`
	CreatedAt       time.Time        `json:"createdAt"`
	ID              int              `json:"id"`
	UpdatedAt       time.Time        `json:"updatedAt"`
	SensorSchedules []SensorSchedule `json:"SensorSchedules"`
}
