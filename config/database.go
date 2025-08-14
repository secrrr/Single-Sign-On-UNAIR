package config

import (
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"context"
	"log"
	"time"
)

var DB *mongo.Database

func ConnectDB() {
	log.Println("Connecting to MongoDB")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb+srv://cavelyogaaa:Cavelbelajar88@kontraktor.fs3bj.mongodb.net/?retryWrites=true&w=majority&appName=Kontraktor"))
	if err != nil {
		log.Fatal("Eror koneksi:", err)
	}

	DB = client.Database("unairsatu")
	log.Println("Connected to MongoDB")
}

func GetCollection(collection string) *mongo.Collection {

	if DB == nil {
		ConnectDB()
	}
	return DB.Collection(collection)
}
