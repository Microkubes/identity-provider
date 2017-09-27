package design

// Use . imports to enable the DSL
import (
	. "github.com/goadesign/goa/design"
	. "github.com/goadesign/goa/design/apidsl"
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

	Action("getGoogleMetadata", func() {
		Description("Get Google's metadata")
		Routing(GET("/metadata/google"))
		Response(OK)
	})
})

// Swagger UI
var _ = Resource("swagger", func() {
	Description("The API swagger specification")

	Files("swagger.json", "swagger/swagger.json")
	Files("swagger-ui/*filepath", "swagger-ui/dist")
})
