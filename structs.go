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

// Individual sensor response
type SensorResponseIndividual struct {
    ID int `json:"id"`
    Type string `json:"type"`
    Name string `json:"name"`
    DisplayName string `json:"displayName"`
	Colour string `json:"color"`
    LatestData struct {
        FullData struct {
            Mode *int `json:"mode"`
			ModeString *string
            Power *int `json:"power"`
			PowerString *string
            Speed int `json:"speed"`
            Swing int `json:"swing"`
			SwingString *string
            Tilt int `json:"tilt"`
			TiltString *string
            Timer int `json:"timer"`
			TimerString *string
            Sensor string `json:"sensor"`
        } `json:"fullData"`
    } `json:"latestData"`
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
	ID    int
	Cron  string
	Type  string
	Value struct {
		Power       *int
		Mode        *int
		Speed       *int
		PowerString *string
		ModeString  *string
		SpeedString *string
	}
}

type Sensor struct {
	SensorID        int              `json:"SensorId"`
	CreatedAt       time.Time        `json:"createdAt"`
	ID              int              `json:"id"`
	UpdatedAt       time.Time        `json:"updatedAt"`
	SensorSchedules []SensorSchedule `json:"SensorSchedules"`
}
