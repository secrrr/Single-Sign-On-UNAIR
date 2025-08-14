package main

import (
	"project-crud-golang/routes"

	"project-crud-golang/config"

	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	config.ConnectDB()

	routes.Routerapp(app)

	app.Listen(":3000")
}