package controllers

import "github.com/gofiber/fiber/v2"

func Homefunc(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"message": "Saya sedang Belajar Golang !",
	})
}