package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Template struct {
	ID          primitive.ObjectID 		`json:"id,omitempty" bson:"_id,omitempty"`
	Jenisuser   string					`json:"jenis_user" bson:"jenis_user"`
	Modul	   	[]primitive.ObjectID    `json:"modul" bson:"modul"`
	Created_at  primitive.DateTime 		`json:"created_at" bson:"created_at"`
	Update_at   primitive.DateTime 		`json:"update_at" bson:"update_at"`
}

type Modul struct {
	ID              	primitive.ObjectID 	`json:"id,omitempty" bson:"_id,omitempty"`
	Nama_modul      	string             	`json:"nama_modul" bson:"nama_modul"`
	Keterangan_modul	string             	`json:"keterangan_modul" bson:"keterangan_modul"`
	Alamat          	string             	`json:"alamat" bson:"alamat"`
	Kategori        	string				`json:"kategori" bson:"kategori"`
	Aktif          		bool               	`json:"aktif" bson:"aktif"`
	Urutan          	int                	`json:"urutan" bson:"urutan"`
	Icon            	string             	`json:"icon" bson:"icon"`
	Created_at      	primitive.DateTime 	`json:"created_at" bson:"created_at"`
	Update_at       	primitive.DateTime 	`json:"update_at" bson:"update_at"`
}

type Users struct {
	ID       		primitive.ObjectID 			`json:"id,omitempty" bson:"_id,omitempty"`
	Username 		string             			`json:"username" bson:"username"`
	Nm_user  		string             			`json:"nm_user" bson:"nm_user"`
	Email    		string             			`json:"email" bson:"email"`
	Password 		string             			`json:"password" bson:"password"`
	Role_aktif 		string          			`json:"role_aktif" bson:"role_aktif"` //disini
	Jenis_user      string				 	 	`json:"jenis_user" bson:"jenis_user"`
	Created_at 		primitive.DateTime          `json:"created_at" bson:"created_at"`
	Update_at 		primitive.DateTime          `json:"update_at" bson:"update_at"`
	Jenis_Kelamin 	string 						`json:"jenis_kelamin" bson:"jenis_kelamin"`
	Photo 			string 						`json:"photo" bson:"photo"`
	Phone 			string 						`json:"phone" bson:"phone"`
	Token 			string 						`json:"token" bson:"token"`
	Pass_2 			string 						`json:"pass_2" bson:"pass_2"`
	Modul 			[]primitive.ObjectID		`json:"modul" bson:"modul"`
}
