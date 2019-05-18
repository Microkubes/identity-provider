package design

// Use . imports to enable the DSL
import (
	. "github.com/keitaroinc/goa/design"
	. "github.com/keitaroinc/goa/design/apidsl"
)

// Define default description and default global property values
var _ = API("identity provider", func() {
	Title("The saml identity provider microservice")
	Description("A service that act as saml identity provider")
	Version("1.0")
	Scheme("http")
	Host("localhost:8080")
})

// Resources group related API endpoints together.
var _ = Resource("idp", func() {
	BasePath("/saml/idp")
	Origin("*", func() {
		Methods("OPTIONS")
	})

	Action("getGoogleMetadata", func() {
		Description("Get Google's metadata")
		Routing(GET("/metadata/google"))
		Response(OK)
	})
	Action("getMetadata", func() {
		Description("Get Jormungandr metadata")
		Routing(GET("/metadata"))
		Response(OK)
	})
	Action("loginUser", func() {
		Description("Login user")
		Routing(GET("/login"))
	})
	Action("serveLoginUser", func() {
		Description("Login user")
		Routing(POST("/login"))
	})
	Action("serveSSO", func() {
		Description("Serve Single Sign On")
		Routing(GET("/sso"))
	})
	Action("serveLogin", func() {
		Description("Creare user session")
		Routing(POST("/sso"))
	})

	Action("addServiceProvider", func() {
		Description("Add new service provider")
		Routing(POST("/services"))
		Response(Created)
		Response(BadRequest, ErrorMedia)
		Response(InternalServerError, ErrorMedia)
	})
	Action("deleteServiceProvider", func() {
		Description("Delete a service provider")
		Routing(DELETE("/services"))
		Payload(DeleteSPPayload)
		Response(OK)
		Response(NotFound, ErrorMedia)
		Response(InternalServerError, ErrorMedia)
	})
	Action("getServiceProviders", func() {
		Description("Get all service providres")
		Routing(GET("/services"))
		Response(OK)
		Response(NotFound, ErrorMedia)
		Response(InternalServerError, ErrorMedia)
	})

	Action("deleteSession", func() {
		Description("Delete a service provider")
		Routing(DELETE("/sessions"))
		Payload(DeleteSessionPayload)
		Response(OK)
		Response(NotFound, ErrorMedia)
		Response(InternalServerError, ErrorMedia)
	})
	Action("getSessions", func() {
		Description("Get all sessions")
		Routing(GET("/sessions"))
		Response(OK)
		Response(NotFound, ErrorMedia)
		Response(InternalServerError, ErrorMedia)
	})

})

// DeleteSPPayload defines the payload for the delete SP action.
var DeleteSPPayload = Type("DeleteSPPayload", func() {
	Description("DeleteSPPayload")

	Attribute("serviceId", String, "ID of service provider")
	Required("serviceId")
})

var DeleteSessionPayload = Type("DeleteSessionPayload", func() {
	Description("DeleteSessionPayload")

	Attribute("sessionId", String, "ID of the session")
	Required("sessionId")
})

var _ = Resource("public", func() {
	Origin("*", func() {
		Methods("GET", "POST")
	})
	Files("/saml/css/*filepath", "public/css")
	Files("/saml/js/*filepath", "public/js")
})

// Swagger UI
var _ = Resource("swagger", func() {
	Description("The API swagger specification")

	Files("swagger.json", "swagger/swagger.json")
	Files("swagger-ui/*filepath", "swagger-ui/dist")
})
