package controllers

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/badoux/checkmail"
	"github.com/gin-gonic/gin"
	"github.com/go-gomail/gomail"
	"github.com/go-redis/redis"
	"github.com/golang-jwt/jwt"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/navaneesh/2FA/db"
	"github.com/navaneesh/2FA/models"
)

var jwtKey = []byte("secret_key")
var secretKey = "2FA-totp"

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func SendOtp(recipient, otp string) error {
	senderEmail := os.Getenv("Sender_email")
	SenderPass := os.Getenv("Sender_pass")

	smtpServer := os.Getenv("smtpServer")
	smtpPort, err := strconv.Atoi(os.Getenv("smtpPort"))
	if err != nil {
		return errors.New(fmt.Sprintf("Invalid SmtpPort"))
	}

	message := gomail.NewMessage()
	message.SetHeader("From", senderEmail)
	message.SetHeader("To", recipient)
	message.SetHeader("Subject", "Your One-Time Passcode (OTP) for Account Verification")
	message.SetBody("text/plain", fmt.Sprintf("Your one time otp is %s", otp))

	// set up email sending credentials
	dialer := gomail.NewDialer(smtpServer, smtpPort, senderEmail, SenderPass)
	if err := dialer.DialAndSend(message); err != nil {
		return errors.New(fmt.Sprintf("error sending email %s", err.Error()))
	}
	return nil
}

func generateTOTP(secret, email string) (string, error) {
	otp, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "2FA",
		AccountName: email,
		Secret:      []byte(secret),
	})
	if err != nil {
		return "", err
	}

	expiryTime := time.Now().Add(2 * time.Minute)
	otpValue, err := totp.GenerateCode(otp.Secret(), expiryTime)
	if err != nil {
		return "", nil
	}

	return otpValue, nil
}

func SignUpUser(c *gin.Context) {
	var User *models.User

	err := c.Bind(&User)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Failed to sign up": err.Error()})
	}

	if err = checkmail.ValidateFormat(User.Email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Wrong Email Format": err.Error()})
		return
	}

	isValid := govalidator.HasUpperCase(User.Password) && govalidator.MinStringLength(User.Password, "8") &&
		govalidator.MaxStringLength(User.Password, "20")

	if !isValid {
		c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "Password should contain atleast one Upper case letter or should have minimum 8 characters"})
		return
	}

	passwordHash, err := HashPassword(User.Password)

	user := models.User{Password: passwordHash, Email: User.Email, Username: User.Username}

	result := db.DB.Create(&user)

	if result.Error != nil && strings.Contains(result.Error.Error(), "unique constraint violation") {
		c.JSON(http.StatusConflict, gin.H{"status": "fail", "message": "Email already exists, please use another Email address"})
		return
	} else if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": result.Error.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Registered Successfully"})
}

func Login(c *gin.Context) {
	var UserLogin *models.UserLogin

	err := c.Bind(&UserLogin)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Failed to sign up": err.Error()})
	}
	var User models.User
	result := db.DB.First(&User, "email = ?", strings.ToLower(UserLogin.Email))
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "User doesn't exist"})
		return
	}

	if PasswordCheck := CheckPasswordHash(User.Password, UserLogin.Password); !PasswordCheck {
		c.JSON(http.StatusConflict, gin.H{"status": "fail", "message": "Incorrect password"})
		return
	}

	otp, err := generateTOTP(secretKey, UserLogin.Email)
	err = db.RedisClient.Set(UserLogin.Email, otp, 120*time.Second).Err()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": " fail", "message": "Failed to set OTP in redis", "error": err.Error()})
		return
	}
	err = SendOtp(UserLogin.Email, otp)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"status": "fail", "message": "Failed to send otp via email"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "OTP has been sent successfully to your Email"})
}

func ValidateOTP(c *gin.Context) {
	var payload models.OTPInput

	err := c.ShouldBindJSON(&payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "Incorrect input", "error": err.Error()})
		return
	}

	storedSecret, err := db.RedisClient.Get(payload.Email).Result()
	if err == redis.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "OTP is expired"})
		return
	} else if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "error": err.Error()})
	}

	if payload.Token != storedSecret {
		c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "Failed to validate the otp"})
		return
	}

	var User models.User

	db.DB.Find(&User, "email = ?", strings.ToLower(payload.Email))
	expirationTime := time.Now().Add(time.Minute * 5)

	claims := &models.JWTClaim{
		Username: User.Username,
		Email:    User.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "Unable to sign the JWT token"})
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:    "jwt-token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	c.JSON(http.StatusOK, gin.H{"staus": "success", "message": "Successfully Logged in "})
}

func RefreshToken(c *gin.Context) {
	cookie, err := c.Request.Cookie("jwt-token")
	if err != nil {
		if err == http.ErrNoCookie {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "No token is available"})
			return
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "Unauthorized cookie"})
			return
		}
	}
	tokenString := cookie.Value
	claims := &models.JWTClaim{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "Unauthorized token"})
			return
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "Bad request"})
		}
	}

	if !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "Unauthorized"})
		return
	}

	expirationTime := time.Now().Add(time.Minute * 5)

	claims.ExpiresAt = expirationTime.Unix()

	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "fail", "error": err.Error()})
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:    "refreshed-jwt-token",
		Value:   tokenStr,
		Expires: expirationTime,
	})
}
