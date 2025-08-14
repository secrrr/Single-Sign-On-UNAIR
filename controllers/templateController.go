package controllers

import (
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson"

	"project-crud-golang/config"
	"project-crud-golang/models"

	"context"
	"net/http"
	"time"
)

var templatecollection *mongo.Collection = config.GetCollection("templateModul")

// CreateTemplate handles the creation of a new template
func CreateTemplate(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var template models.Template
	if err := c.BodyParser(&template); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error1": err.Error()})
	}

	// Mengambil waktu lokal Asia/Jakarta
	loc, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error2": err.Error()})
	}
	template.Created_at = primitive.NewDateTimeFromTime(time.Now().In(loc))
	template.Update_at = primitive.NewDateTimeFromTime(time.Now().In(loc))

	// Membuat objek user baru dengan password yang sudah di-hash
	newTemplate := models.Template{
		Jenisuser:   template.Jenisuser,
		Modul:       template.Modul,
		Created_at:  template.Created_at,
		Update_at:   template.Update_at,
	}

	// Insert user ke dalam database
	_, err = templatecollection.InsertOne(ctx, newTemplate)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error3": err.Error()})
	}

	return c.JSON(newTemplate)
}


func GetTemplates(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var template []models.Template
	cursor, err := templatecollection.Find(ctx, bson.M{})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if err = cursor.All(ctx,&template); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(template)
}

func GetTemplateById(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	id := c.Params("id")
	templateId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid ID",
		})
	}

	var template models.Template
	err = templatecollection.FindOne(ctx, bson.M{"_id": templateId}).Decode(&template)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(template)
}

func UpdateTemplateById(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	id := c.Params("id")
	templateId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid ID",
		})
	}

	var template models.Template
	if err := c.BodyParser(&template); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	loc, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	template.Update_at = primitive.NewDateTimeFromTime(time.Now().In(loc))

	update := bson.M{
		"$set": bson.M{
			"jenisuser": template.Jenisuser,
			"modul": 	 template.Modul,
			"update_at": template.Update_at,
		},
	}

	_, err = templatecollection.UpdateOne(ctx, bson.M{"_id": templateId}, update)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Template berhasil diupdate"})
}

// delete modul by id
func DeleteTemplateById(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	id := c.Params("id")
	templateId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid ID",
		})
	}

	_, err = templatecollection.DeleteOne(ctx, bson.M{"_id": templateId})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Template berhasil dihapus"})
}