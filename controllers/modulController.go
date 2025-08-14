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

var modulCollection *mongo.Collection = config.GetCollection("modul")

// CreateModul handles the creation of a new module
func CreateModul(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var modul models.Modul
	if err := c.BodyParser(&modul); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Check if module already exists
	var existingModul models.Modul
	err := modulCollection.FindOne(ctx, bson.M{"nama_modul": modul.Nama_modul}).Decode(&existingModul)
	if err == nil {
		return c.Status(http.StatusConflict).JSON(fiber.Map{
			"error": "Modul sudah ada",
		})
	}

	// Set creation and update time
	loc, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	modul.Created_at = primitive.NewDateTimeFromTime(time.Now().In(loc))
	modul.Update_at = primitive.NewDateTimeFromTime(time.Now().In(loc))

	// Create a new module
	newModul := models.Modul{
		Nama_modul:      	modul.Nama_modul,
		Keterangan_modul: 	modul.Keterangan_modul,
		Alamat:          	modul.Alamat,
		Kategori:        	modul.Kategori,
		Aktif:           	modul.Aktif,
		Urutan:          	modul.Urutan,
		Icon:            	modul.Icon,
		Created_at:      	modul.Created_at,
		Update_at:       	modul.Update_at,
	}

	// Insert the new module into the database
	_, errInsert := modulCollection.InsertOne(ctx, newModul)
	if errInsert != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": errInsert.Error(),
		})
	}

	return c.Status(http.StatusCreated).JSON(fiber.Map{
		"message": "Modul berhasil dibuat",
	})
}

// GetModul handles retrieving all modules
func GetModul(c *fiber.Ctx) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    var modul []models.Modul
    cursor, err := modulCollection.Find(ctx, bson.M{})
    if err != nil {
        return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error":  err.Error()})
    }

    if err = cursor.All(ctx, &modul); err != nil {
        return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
    }

    return c.Status(http.StatusOK).JSON(modul)
}


// GetModulById handles retrieving a single module by ID
func GetModulById(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	modulId := c.Params("id")
	objID, err := primitive.ObjectIDFromHex(modulId)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid ID format",
		})
	}

	var modul models.Modul
	err = modulCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&modul)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "Modul tidak ditemukan",
		})
	}

	return c.Status(http.StatusOK).JSON(modul)
}

// UpdateModulById handles updating a module by ID
func UpdateModulById(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	modulId := c.Params("id")
	objID, err := primitive.ObjectIDFromHex(modulId)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid ID format",
		})
	}

	var modul models.Modul
	if err := c.BodyParser(&modul); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Prepare update data
	update := bson.M{
		"nama_modul":        modul.Nama_modul,
		"keterangan_modul":  modul.Keterangan_modul,
		"alamat":            modul.Alamat,
		"kategori":          modul.Kategori,
		"aktif":             modul.Aktif,
		"urutan":            modul.Urutan,
		"icon":              modul.Icon,
		"update_at":         primitive.NewDateTimeFromTime(time.Now()),
	}

	// Update the module in the database
	_, errUpdate := modulCollection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": update})
	if errUpdate != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": errUpdate.Error(),
		})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "Modul berhasil diupdate",
	})
} 

// DeleteModulById handles deleting a module by ID
func DeleteModulById(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	modulId := c.Params("id")
	objID, err := primitive.ObjectIDFromHex(modulId)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid ID format",
		})
	}

	_, err = modulCollection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "Modul berhasil dihapus",
	})
}