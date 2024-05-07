package main

import (
	"github.com/gin-gonic/gin"
	"github.com/lanthora/cucurbita/candy"
	"github.com/lanthora/cucurbita/web"
)

func init() {
	gin.SetMode(gin.ReleaseMode)
}

func main() {
	r := gin.New()
	r.HTMLRender = web.HTMLRender
	r.Use(candy.WebsocketMiddleware(), web.LoginMiddleware())

	r.GET("/", web.Index)
	r.GET("/favicon.ico", web.Favicon)

	r.GET("/login", web.LoginPage)
	r.POST("/login", web.Login)

	r.GET("/domain", web.DomainPage)
	r.GET("/domain/insert", web.InsertDomainPage)
	r.POST("/domain/insert", web.InsertDomain)
	r.GET("/domain/delete", web.DeleteDomain)

	r.GET("/device", web.DevicePage)
	r.GET("/device/delete", web.DeleteDevice)

	r.Run(":80")
}
