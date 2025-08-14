package controllers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	// "strings"
	"os"
	"path/filepath"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"

	"project-crud-golang/config"
	"project-crud-golang/models"

	"context"
	"net/http"
	"time"
)

var userCollection *mongo.Collection = config.GetCollection("users")

// Payload untuk menyimpan informasi dalam JWT
type Payload struct {
	Username 	string `json:"username"`
	Role_aktif 	string `json:"role_aktif"`
	Exp      	int64  `json:"exp"`
}

// GenerateJWT generates a JWT token
func GenerateJWT(username, role_aktif string ) (string, error) {
    // Define header
    header := map[string]interface{}{
        "alg": "HS256", // Algoritma HMAC SHA-256
        "typ": "JWT",   // Tipe token
    }

    // Encode header to JSON
    headerBytes, _ := json.Marshal(header)
    headerPart := base64.RawURLEncoding.EncodeToString(headerBytes)

    // Define payload
    payload := map[string]interface{}{
        "username":   username,
        "role_aktif": role_aktif,
        "exp":        time.Now().Add(time.Hour * 24).Unix(),
    }

    // Encode payload to JSON
    payloadBytes, _ := json.Marshal(payload)
    payloadPart := base64.RawURLEncoding.EncodeToString(payloadBytes)

    // HMAC SHA-256 signature
    secret := []byte("your_secret_key")
    h := hmac.New(sha256.New, secret)
    h.Write([]byte(headerPart + "." + payloadPart))
    signature := h.Sum(nil)

    // Encode signature to Base64 URL
    signaturePart := base64.RawURLEncoding.EncodeToString(signature)

    // Combine header, payload, and signature
    token := fmt.Sprintf("%s.%s.%s", headerPart, payloadPart, signaturePart)

    return token, nil
}


// Login fungsi untuk autentikasi user dan menghasilkan token
func Login(c *fiber.Ctx) error {
	// Context dengan timeout untuk query MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Struktur untuk menangkap kredensial dari request body
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// Parsing body JSON
	if err := c.BodyParser(&credentials); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Validasi input
	if credentials.Username == "" || credentials.Password == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Username and password are required"})
	}

	// Cari user berdasarkan username di MongoDB
	var user models.Users
	err := userCollection.FindOne(ctx, bson.M{"username": credentials.Username}).Decode(&user)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"}) // Hindari terlalu banyak info
	}

	// Verifikasi password menggunakan bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"})
	}

	// Generate JWT
	token, err := GenerateJWT( user.Username, user.Role_aktif)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate token"})
	}

	// Logika untuk role admin dan civitas
	if user.Role_aktif == "Admin" {
		// Jika Admin, hanya kembalikan token
		return c.Status(http.StatusOK).JSON(fiber.Map{
			"message": "Login successful",
			"token":   token,
		})
	} else if user.Role_aktif != "Admin" {
		// Jika bukan Admin, gunakan `$lookup` untuk mendapatkan modul
		pipeline := mongo.Pipeline{
			{
				{Key: "$match", Value: bson.M{"_id": user.ID}},
			},
			{
				{Key: "$lookup", Value: bson.M{
					"from":         "modul",
					"localField":   "modul",
					"foreignField": "_id",
					"as":           "modul_details",
				}},
			},
			{
				{Key: "$project", Value: bson.M{
					"_id":          0,
					"username":      1,
					"modul_details": bson.M{
						"nama_modul": 1,
						"alamat":     1,
						"icon":       1,
					},
				}},
			},
		}

		// Jalankan aggregation pipeline
		cursor, err := userCollection.Aggregate(ctx, pipeline)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch user modules"})
		}
		defer cursor.Close(ctx)

		var userWithModules []bson.M
		if err := cursor.All(ctx, &userWithModules); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Error decoding user data"})
		}

		// Pastikan data hanya satu user (karena _id harus unik)
		if len(userWithModules) == 0 {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}

		// Kembalikan token dan modul
		return c.Status(http.StatusOK).JSON(fiber.Map{
			"message": "Login successful",
			// "token":   token,
			"modul":    userWithModules, // Data user dengan detail modul
		})
	}

	return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Access restricted for Admin users"})
}


func CreateUser(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user models.Users
	if err := c.BodyParser(&user); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Cek apakah username sudah ada dalam koleksiOperation time over everything that the expiration time.
	var existingUser models.Users
	err := userCollection.FindOne(ctx, bson.M{"username": user.Username}).Decode(&existingUser)
	if err == nil {
		// Jika tidak ada error, artinya username sudah ada
		return c.Status(http.StatusConflict).JSON(fiber.Map{"error": "Username already exists"})
	}

	// Hash password menggunakan bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Error hashing password"})
	}

	// Mengambil waktu lokal Asia/Jakarta
	loc, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	user.Created_at = primitive.NewDateTimeFromTime(time.Now().In(loc))
	user.Update_at = primitive.NewDateTimeFromTime(time.Now().In(loc))


	// Membuat objek user baru dengan password yang sudah di-hash
	newUser := models.Users{
		Username:      user.Username,
		Nm_user:       user.Nm_user,
		Password:      string(hashedPassword), // Simpan password dalam bentuk hash
		Email:         user.Email,
		Role_aktif:    user.Role_aktif,
		Jenis_user:    user.Jenis_user,
		Created_at:    user.Created_at,
		Update_at:     user.Update_at,
		Jenis_Kelamin: user.Jenis_Kelamin,
		Photo:         user.Photo,
		Phone:         user.Phone,
		Pass_2:        user.Pass_2,
		Modul:         user.Modul,
	}

	// Insert user ke dalam database
	_, errInsert := userCollection.InsertOne(ctx, newUser)
	if errInsert != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": errInsert.Error()})
	}

	return c.Status(http.StatusCreated).JSON(fiber.Map{"message": "User created successfully", "user": newUser})
}

func GetUsers(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var users []models.Users
	cursor, err := userCollection.Find(ctx, bson.M{})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if err = cursor.All(ctx, &users); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(users)
}


func GetUsersWithModul(c *fiber.Ctx) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Pipeline untuk aggregation
    pipeline := mongo.Pipeline{
        {
            {Key: "$lookup", Value: bson.M{
                "from":         "modul",
                "localField":   "modul",
                "foreignField": "_id",
                "as":           "modul_details",
            }},
        },
        {
            {Key: "$project", Value: bson.M{
                "username":      1, // Field dari users
                "modul_details": bson.M{
                    "nama_modul": 1,
                    "alamat":     1,
                    "icon":       1,
                },
            }},
        },
    }

    // Jalankan aggregation
    cursor, err := userCollection.Aggregate(ctx, pipeline)
    if err != nil {
        return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
    }
    defer cursor.Close(ctx)

    var users []bson.M
    if err := cursor.All(ctx, &users); err != nil {
        return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
    }

    return c.Status(http.StatusOK).JSON(users)
}

func GetUserByIds(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userId := c.Params("id")
	objId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid ID"})
	}

	var user models.Users
	err = userCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&user)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	return c.Status(http.StatusOK).JSON(user)
}


func GetUserById(c *fiber.Ctx) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Ambil ID pengguna dari parameter
    userId := c.Params("id")
    objId, err := primitive.ObjectIDFromHex(userId)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid ID"})
    }

    // Pipeline untuk aggregation
    		pipeline := mongo.Pipeline{
        {
            {Key: "$match", Value: bson.M{"_id": objId}}, // Filter berdasarkan user ID
        },
        {
            {Key: "$lookup", Value: bson.M{
                "from":         "modul",               // Nama koleksi modul
                "localField":   "modul",               // Field yang ada di user, berisi array ObjectID modul
                "foreignField": "_id",                 // Field yang ada di modul, yang berfungsi sebagai penghubung
                "as":           "modul_details",       // Nama field hasil embed modul
            }},
        },
        // {
        //     {Key: "$project", Value: bson.M{
        //         "username":      1,                    // Field dari user yang ingin ditampilkan
        //         "modul_details": bson.M{
        //             "nama_modul": 1,
        //             "alamat":     1,
        //             "icon":       1,
        //         },                                    // Menampilkan modul terkait dengan username
        //     }},
        // },
    }

    // Jalankan aggregation
    cursor, err := userCollection.Aggregate(ctx, pipeline)
    if err != nil {
        return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
    }
    defer cursor.Close(ctx)

    var users []bson.M
    if err := cursor.All(ctx, &users); err != nil {
        return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
    }

    // Jika user tidak ditemukan
    if len(users) == 0 {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
    }

    // Mengembalikan data user yang ditemukan beserta modul terkait
    return c.Status(http.StatusOK).JSON(users[0])
}


func UpdateUserById(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userId := c.Params("id")
	objId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid ID"})
	}

	var user models.Users
	if err := c.BodyParser(&user); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	update := bson.M{
		"username":      user.Username,
		"nm_user":       user.Nm_user,
		"password":      user.Password, // Pertimbangkan untuk meng-hash password di sini
		"email":         user.Email,
		"role_aktif":    user.Role_aktif,
		"jenis_user":    user.Jenis_user,
		"jenis_kelamin": user.Jenis_Kelamin,
		"photo":         user.Photo,
		"phone":         user.Phone,
		"updated_at":    primitive.NewDateTimeFromTime(time.Now().In(time.Local)),
		"pass_2":        user.Pass_2,
		"modul":         user.Modul,
		
	}

	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": objId}, bson.M{"$set": update})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "User updated successfully"})
}

func UpdatePasswordById(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userId := c.Params("id")
	objId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid ID"})
	}

	// Parsing input dari user
	var input struct {
		OldPassword        string `json:"oldPassword"`
		NewPassword        string `json:"newPassword"`
		ConfirmNewPassword string `json:"confirmNewPassword"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Ambil data user berdasarkan ID
	var user models.Users
	err = userCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&user)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	// Verifikasi old password menggunakan bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.OldPassword))
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Old password is incorrect"})
	}

	// Cek apakah newPassword dan confirmNewPassword sesuai
	if input.NewPassword != input.ConfirmNewPassword {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "New passwords do not match"})
	}

	// Hash new password menggunakan bcrypt
	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Error hashing new password"})
	}

	// Update password di database
	update := bson.M{"password": string(hashedNewPassword)}
	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": objId}, bson.M{"$set": update})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update password"})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Password updated successfully"})
}

func UploadPhotoById(c *fiber.Ctx) error {
	// Menangani file yang diupload
	file, err := c.FormFile("photo")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "File upload failed"})
	}

	// Membuat folder storage jika belum ada
	storageDir := "./storage/images"
	if _, err := os.Stat(storageDir); os.IsNotExist(err) {
		err := os.MkdirAll(storageDir, os.ModePerm)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create storage directory"})
		}
	}

	// Mendapatkan ekstensi file dari file yang diupload
	ext := filepath.Ext(file.Filename)
	// Mendapatkan timestamp saat ini
	timestamp := time.Now().Format("20060102150405.000")

	// Menyusun nama file baru dengan format YYYYMMDDHHmmSSsss.[file extension]
	newFileName := fmt.Sprintf("%s%s", timestamp, ext)
	// Menentukan path file yang akan disimpan
	filePath := filepath.Join(storageDir, newFileName)

	// Menyimpan file ke directory
	if err := c.SaveFile(file, filePath); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save file"})
	}

	// Ambil ID pengguna dari parameter
	userId := c.Params("id")
	objId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	// Update data pengguna dengan path foto yang baru
	update := bson.M{
		"photo": newFileName, // Menyimpan nama file gambar di field "photo"
	}

	// Melakukan update pada database
	_, err = userCollection.UpdateOne(c.Context(), bson.M{"_id": objId}, bson.M{"$set": update})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update user photo"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Photo uploaded successfully", "fileName": newFileName})
}

func DeleteUserById(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userId := c.Params("id")
	objId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid ID"})
	}

	_, err = userCollection.DeleteOne(ctx, bson.M{"_id": objId})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "User deleted successfully"})
}