package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"net/http"
	"time"
)

type Product struct {
	Db *gorm.DB
}

type IProduct interface {
	SignUp(c *gin.Context)
	SignIn(c *gin.Context)
	Welcome(c *gin.Context)
	Refresh(c *gin.Context)
	newPasswordToken(c *gin.Context)
}

func ConnectDatabase() *gorm.DB {
	dsn := "host=localhost user=postgres password=Namle311 dbname=book port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&Credentials{})
	return db
}

type Credentials struct {
	gorm.Model
	Username string `json:"username"`
	Password string `json:"password"`
}

var jwtKey = []byte("my-secrect-key")

type Claims struct {
	Username string `json:"username"`
	Password string `json:"password"`
	jwt.StandardClaims
}

func (p *Product) SignUp(c *gin.Context) {
	var creds Credentials
	//input json creads
	err := c.BindJSON(&creds)
	creds1 := &Credentials{Username: creds.Username, Password: creds.Password}
	if err != nil {
		c.String(http.StatusBadRequest, "%v", err)
		return
	}
	p.Db.Create(&creds1)

	c.String(http.StatusOK, "%s", "SignUp Successfully!")
}

func (p *Product) SignIn(c *gin.Context) {
	var creds Credentials
	err := c.BindJSON(&creds)
	if err != nil {
		c.String(http.StatusBadRequest, "%v", err)
		return
	}
	e := p.Db.First(&creds, "username=? AND password = ?", creds.Username, creds.Password).Error
	if e != nil {
		c.String(http.StatusBadRequest, "%v", err)
		return
	}

	expirationTime := time.Now().Add(3 * time.Minute)
	claims := Claims{
		Username: creds.Username,
		Password: creds.Password,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.String(http.StatusInternalServerError, "%v", err)
		return
	}

	c.SetCookie("token", tokenString, 3600, "/", "localhost", false, true)
}

func (p *Product) Welcome(c *gin.Context) {
	ck, err := c.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			c.String(http.StatusUnauthorized, "%v", err)
			return
		}
		c.String(http.StatusBadRequest, "%v", err)
		return
	}
	fmt.Println(ck)
	claims := &Claims{}
	tknStr := ck

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			c.String(http.StatusUnauthorized, "%v", err)
			return
		}
		c.String(http.StatusBadRequest, "%v", err)
		return
	}

	if !tkn.Valid {
		c.String(http.StatusUnauthorized, "%v", tkn)
		return
	}
	c.String(http.StatusOK, "Welcome to  %v", claims.Username)
}

func (p *Product) Refresh(c *gin.Context) {
	ck, err := c.Cookie("token")

	if err != nil {
		if err == http.ErrNoCookie {
			c.String(http.StatusUnauthorized, "%v", err)
			return
		}
		c.String(http.StatusBadRequest, "%v", err)
		return
	}

	claims := &Claims{}
	tknStr := ck

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			c.String(http.StatusUnauthorized, "%v", err)
			return
		}
		c.String(http.StatusBadRequest, "%v", err)
		return
	}

	if !tkn.Valid {
		c.String(http.StatusUnauthorized, "%v", tkn)
		return
	}

	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Minute {
		c.String(http.StatusBadRequest, "%v", 400)
		return
	}

	expirationTime := time.Now().Add(3 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.String(http.StatusInternalServerError, "%v", err)
		return
	}

	c.SetCookie("token", tokenString, 3600, "/", "localhost", false, true)
}

func (p *Product) newPasswordToken(c *gin.Context) {

	ck, err := c.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			c.String(http.StatusUnauthorized, "%v", err)

			return
		}
		c.String(http.StatusBadRequest, "%v", err)
		return
	}

	claims := &Claims{}
	tknStr := ck

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			c.String(http.StatusUnauthorized, "%v", err)
			return
		}
		c.String(http.StatusBadRequest, "%v", err)
		return
	}

	if !tkn.Valid {
		c.String(http.StatusUnauthorized, "%v", tkn)
		return
	}
	pw := c.Query("password")
	us := c.Query("username")
	expirationTime := time.Now().Add(3 * time.Minute)
	var item *Credentials
	er := p.Db.Model(&item).Where("username = ?", us).Update("password", pw).Error
	if er != nil {
		c.String(http.StatusBadRequest, "%v", er)
		return
	}
	claims.Password = pw
	claims.ExpiresAt = expirationTime.Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.String(http.StatusInternalServerError, "%v", err)
		return
	}

	c.SetCookie("token", tokenString, 3600, "/", "localhost", false, true)

}

func main() {
	r := gin.Default()
	p := &Product{Db: ConnectDatabase()}
	var i IProduct = p
	r.POST("/signup", func(c *gin.Context) {
		i.SignUp(c)
	})

	r.POST("/signin", func(c *gin.Context) {
		i.SignIn(c)
	})

	r.GET("/welcome", func(c *gin.Context) {
		i.Welcome(c)
	})

	r.POST("/refresh", func(c *gin.Context) {
		i.Refresh(c)
	})

	r.PUT("/password", func(c *gin.Context) {
		i.newPasswordToken(c)
	})

	r.Run(":8000")

}
