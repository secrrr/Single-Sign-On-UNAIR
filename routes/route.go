package routes

import (
	"project-crud-golang/controllers"
	"project-crud-golang/middleware" // Tambahkan import untuk middleware

	"github.com/gofiber/fiber/v2"
)

func Routerapp(app *fiber.App) {
	api := app.Group("/api")

	// user := api.Group("/users")
	// user.Post("/login", controllers.Login) // Route login
	// user.Post("/", middleware.ValidateToken,controllers.CreateUser) // Terapkan middleware
	// user.Get("/", middleware.ValidateToken, controllers.GetUsers)   // Terapkan middleware
	// user.Get("/:id", middleware.ValidateToken, controllers.GetUserById) // Terapkan middleware
	// user.Put("/:id", middleware.ValidateToken, controllers.UpdateUserById) // Terapkan middleware
	// user.Post("/:id/password", middleware.ValidateToken, controllers.UpdatePasswordById)
	// user.Post("/:id/photo", middleware.ValidateToken, controllers.UploadPhotoById)

	admin := api.Group("/admin")
	admin.Post("/login", controllers.Login) // Route login admin
	admin.Post("/create-user", controllers.CreateUser)
	admin.Get("/getuser/:id",middleware.ValidateToken, middleware.CheckRole("Admin"), controllers.GetUserByIds)
	admin.Get("/getallusers", middleware.ValidateToken, middleware.CheckRole("Admin"), controllers.GetUsers)
	admin.Get("/get-all-users", middleware.ValidateToken, middleware.CheckRole("Admin"), controllers.GetUsersWithModul)
	admin.Get("/get-user/:id", middleware.ValidateToken, middleware.CheckRole("Admin"), controllers.GetUserById)
	admin.Put("/update-user/:id", middleware.ValidateToken, middleware.CheckRole("Admin"), controllers.UpdateUserById)
	admin.Post("/update-password/:id", middleware.ValidateToken, middleware.CheckRole("Admin"), controllers.UpdatePasswordById)
	admin.Post("/upload-photo/:id", middleware.ValidateToken, middleware.CheckRole("Admin"), controllers.UploadPhotoById)
	admin.Delete("/delete-user/:id", middleware.ValidateToken, middleware.CheckRole("Admin"), controllers.DeleteUserById)

	// modul
	admin.Post("/create-modul", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.CreateModul)
	admin.Get("/get-all-moduls", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.GetModul)
	admin.Get("/get-modul/:id", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.GetModulById)
	admin.Put("/update-modul/:id", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.UpdateModulById)
	admin.Delete("/delete-modul/:id", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.DeleteModulById)

	// template
	admin.Post("/create-template", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.CreateTemplate)
	admin.Get("/get-all-templates", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.GetTemplates)
	admin.Get("/get-template/:id", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.GetTemplateById)
	admin.Put("/update-template/:id", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.UpdateTemplateById)
	admin.Delete("/delete-template/:id", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.DeleteTemplateById)

}	

// role := admin.Group("/role")
	// role.Post("/", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.CreateRole)
	// role.Get("/", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.GetAllRole)
	// role.Get("/:id", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.GetRoleById)
	// role.Delete("/:id", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.DeleteRoleById)

	// kategori := admin.Group("/kategori")
	// kategori.Post("/", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.CreateKategori)
	// kategori.Get("/", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.GetAllKategori)
	// kategori.Get("/:id", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.GetKategoriByID)
	// kategori.Delete("/:id", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.DeleteKategoriByID)

	// jenisUser := admin.Group("/jenisUser")
	// jenisUser.Post("/", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.CreateJenisUser)
	// jenisUser.Get("/", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.GetAllJenisUser)
	// jenisUser.Get("/:id", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.GetJenisUserByID)
	// jenisUser.Delete("/:id", middleware.ValidateToken, middleware.CheckRole("Admin"),controllers.DeleteJenisUserByID)