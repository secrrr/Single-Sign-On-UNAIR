package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// Struktur payload dari token JWT
type Payload struct {
	Username 		string `json:"username"`
	Role_aktif     	string `json:"role_aktif"`
	Exp      		int64  `json:"exp"`
}

// Fungsi ValidateToken
func ValidateToken(c *fiber.Ctx) error {
    authHeader := c.Get("Authorization")
    if authHeader == "" {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Authorization header missing"})
    }

    tokenParts := strings.Split(authHeader, "Bearer ")
    if len(tokenParts) != 2 {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid authorization header format"})
    }

    token := tokenParts[1]
    jwtParts := strings.Split(token, ".")
    if len(jwtParts) != 3 {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token format"})
    }

    headerPart := jwtParts[0]
    payloadPart := jwtParts[1]
    signaturePart := jwtParts[2]

    // Decode and validate payload
    payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadPart)
    if err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token payload"})
    }

    signatureBytes, err := base64.RawURLEncoding.DecodeString(signaturePart)
    if err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token signature"})
    }

    secret := []byte("your_secret_key")
    h := hmac.New(sha256.New, secret)
    h.Write([]byte(headerPart + "." + payloadPart))
    expectedSignature := h.Sum(nil)

    if !hmac.Equal(expectedSignature, signatureBytes) {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token signature"})
    }

    var payload Payload
    if err := json.Unmarshal(payloadBytes, &payload); err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token payload"})
    }

    if time.Now().Unix() > payload.Exp {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Token has expired"})
    }

    c.Locals("username", payload.Username)
    c.Locals("role", payload.Role_aktif)
    return c.Next()
}

// Middleware untuk memeriksa role user
func CheckRole(requiredRole string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Ambil role dari context
		role := c.Locals("role")
		
		if role == nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Access denied: role missing"})
		}

		roleStr, ok := role.(string)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid role type"})
		}

		if roleStr != requiredRole {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Access denied: insufficient permissions"})
		}

		return c.Next()
	}
}


// Middleware untuk memeriksa id_jenis_user
// func CheckJenisUser(db *mongo.Database, requiredJenisUser string) fiber.Handler {
// 	return func(c *fiber.Ctx) error {
// 		// Ambil payload dari context (hasil parsing JWT)
// 		payload, ok := c.Locals("payload").(map[string]interface{})
// 		if !ok {
// 			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
// 				"error": "Invalid token payload",
// 			})
// 		}

// 		// Validasi apakah jenis_user sesuai
// 		jenisUser, ok := payload["jenis_user"].(string)
// 		if !ok || jenisUser != requiredJenisUser {
// 			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
// 				"error": "Access denied: jenis user mismatch",
// 			})
// 		}

// 		// Ambil user ID dari payload
// 		userID, ok := payload["user_id"].(string)
// 		if !ok || userID == "" {
// 			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
// 				"error": "Invalid or missing user_id in token payload",
// 			})
// 		}

// 		// Query untuk mencari user berdasarkan userID di MongoDB
// 		var user struct {
// 			ID    string   `bson:"_id"`
// 			Modul []string `bson:"modul"` // Pastikan ini sesuai dengan struktur MongoDB Anda
// 		}

// 		err := db.Collection("user").FindOne(context.TODO(), bson.M{"_id": userID}).Decode(&user)
// 		if err != nil {
// 			if err == mongo.ErrNoDocuments {
// 				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
// 					"error": "User not found",
// 				})
// 			}
// 			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 				"error": "Database query error",
// 			})
// 		}

// 		// Tambahkan modul milik user ke dalam response atau context
// 		c.Locals("modul", user.Modul)

// 		// Lanjutkan ke handler berikutnya
// 		return c.Next()
// 	}
// }

