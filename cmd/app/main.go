package main

import (
	"os"
	"time"

	"github.com/SanyaWarvar/auth/pkg/handler"
	"github.com/SanyaWarvar/auth/pkg/models"
	"github.com/SanyaWarvar/auth/pkg/repository"
	"github.com/SanyaWarvar/auth/pkg/service"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.SetFormatter(new(logrus.JSONFormatter))

	if err := godotenv.Load(".env"); err != nil {
		logrus.Fatalf("Error while load dotenv: %s", err.Error())
	}

	db, err := repository.NewPostgresDB(repository.Config{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		Username: os.Getenv("DB_USER"),
		DBName:   os.Getenv("DB_NAME"),
		SSLMode:  os.Getenv("DB_SSLMODE"),
		Password: os.Getenv("DB_PASSWORD"),
	})

	if err != nil {
		logrus.Fatalf("Error while create connection to db: %s", err.Error())
	}

	repos := repository.NewRepository(db)
	accessTTL, err := time.ParseDuration(os.Getenv("ACCESSTOKENTTL"))
	if err != nil {
		logrus.Fatalf("Error while parse ACCESSTOKENTTL: %s", err.Error())
	}

	config := &service.Config{
		Key:       os.Getenv("SIGNINGKEY"),
		AccessTTL: accessTTL,
		Method:    jwt.SigningMethodHS512,
	}
	smtpSettings := service.NewEmailSettings(os.Getenv("OWNER_EMAIL"), os.Getenv("OWNER_PASSWORD"))

	services := service.NewService(repos, config, smtpSettings)
	handlers := handler.NewHandler(services)
	srv := new(models.Server)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	if err := srv.Run(port, handlers.InitRoutes()); err != nil {
		logrus.Fatalf("Error while running server: %s", err.Error())
	}
}
