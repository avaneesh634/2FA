package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"github.com/navaneesh/2FA/controllers"
	"github.com/navaneesh/2FA/db"
	"github.com/navaneesh/2FA/models"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Failed to load .env")
	}
	db.ConnectToDB()
	db.DB.AutoMigrate(&models.User{})
	db.RedisInit()
}

func main() {
	router := gin.Default()
	router.POST("/signup", controllers.SignUpUser)
	router.POST("/login", controllers.Login)
	router.POST("/refreshtoken", controllers.RefreshToken)
	router.POST("/validateotp", controllers.ValidateOTP)
	router.Run()
}
