# identity-provider

[![Build](https://travis-ci.com/Microkubes/identity-provider.svg?token=UB5yzsLHNSbtjSYrGbWf&branch=master)](https://travis-ci.com/Microkubes/identity-provider)
[![Test Coverage](https://api.codeclimate.com/v1/badges/5b9d9b87dc2f16a60709/test_coverage)](https://codeclimate.com/repos/59d79b8c3887ca028300021a/test_coverage)
[![Maintainability](https://api.codeclimate.com/v1/badges/5b9d9b87dc2f16a60709/maintainability)](https://codeclimate.com/repos/59d79b8c3887ca028300021a/maintainability)


SAML identity provider

## Prerequisite
Create a project directory. Set GOPATH enviroment variable to that project. Add $GOPATH/bin to the $PATH
```
export GOPATH=/path/to/project-workspace
export PATH=$GOPATH/bin:$PATH
```
Install goa and goagen:
```
cd $GOPATH
go get -u github.com/keitaroinc/goa/...
```

## Compile and run the service:
Clone the repo:
```
cd $GOPATH/src
git clone https://github.com/Microkubes/identity-provider.git /path/to/project-workspace/src/github.com/Microkubes/identity-provider
```
Be sure to use the full domain name and resource path here (compatible with ```go get```).


Then compile and run:
```
cd /path/to/project-workspace/src/github.com/Microkubes/identity-provider
go build -o identity-provider
./identity-provider
```

## Change the design
If you change the design then you should regenerate the files. Run:
```
cd /path/to/project-workspace/src/github.com/Microkubes/identity-provider
go generate
```
**NOTE:** If the above command does not update the generated code per the changes in the design,
then run ```goagen bootstrap```:

```bash
goagen bootstrap -d github.com/Microkubes/identity-provider/design -o .
```


Also, recompile the service and start it again:
```
go build -o identity-provider
./identity-provider
```

## Other changes, not related to the design
For all other changes that are not related to the design just recompile the service and start it again:
```
cd $GOPATH/src/github.com/Microkubes/identity-provider
go build -o identity-provider
./identity-provider
```

## Tests
For testing we use controller_test.go files which call the generated test helpers which package that data into HTTP requests and calls the actual controller functions. The test helpers retrieve the written responses, deserialize them, validate the generated data structures (against the validations written in the design) and make them available to the tests. Run:
```
go test -v
```

## Set up MongoDB
Create identity-provider database with default username and password.
See: [Set up MongoDB](https://github.com/Microkubes/jormungandr-infrastructure#mongodb--v346-)
```
export MS_DBNAME=identity-provider
./mongo/run.sh
```
Then install mgo package:
```
cd $GOPATH
go get gopkg.in/mgo.v2
```

## Setting up the secret keys

SAML IdP should use the same saml keys as service providers.

In order to create them create a directory in which you'll keep your key-pair:

```bash
mkdir saml-keys
cd saml-keys
```

IdP must have an self-signed X.509 key pair established. You can generate your own with something like this:

```bash
openssl req -x509 -newkey rsa:2048 -keyout service.key -out service.cert -days 365 -nodes -subj "/CN=myservice.example.com"
```

**NOTE:** Make sure you have service.key and service.cert files in the saml-keys directory

# Docker Builds

First, create a directory for the shh keys:
```bash
mkdir keys
```

Find a key that you'll use to acceess Microkubes organization on github. Then copy the
private key to the directory you created above. The build would use this key to
access ```Microkubes/microservice-tools``` repository.

```bash
cp ~/.ssh/id_rsa keys/
```

**WARNING!** Make sure you don't commit or push this key to the repository!

To build the docker image of the microservice, run the following command:
```bash
docker build -t identity-provider .
```

Also, you can build docker image using Makefile. Run the following command:
```bash
make run ARGS="-e API_GATEWAY_URL=http://192.168.1.10:8001 -e MONGO_URL=192.168.1.10:27017"
```

# Running the microservice

To run the identity-provider microservice you'll need to set up some ENV variables:

 * **SERVICE_CONFIG_FILE** - Location of the configuration JSON file
 * **API_GATEWAY_URL** - Kong API url (default: http://localhost:8001)
 * **MONGO_URL** - Host IP(example: 192.168.1.10:27017)
 * **MS_USERNAME** - Mongo username (default: restapi)
 * **MS_PASSWORD** - Mongo password (default: restapi)
 * **MS_DBNAME** - Mongo database name (default: identity-provider)

Run the docker image:
```bash
docker run identity-provider
```

## Check if the service is self-registering on Kong Gateway

First make sure you have started Kong. See [Jormungandr Infrastructure](https://github.com/Microkubes/jormungandr-infrastructure)
on how to set up Kong locally.

If you have Kong admin endpoint running on http://localhost:8001 , you're good to go.
Build and run the service:
```bash
go build -o identity-provider
./identity-provider
```

To access the identity-provider service, then instead of calling the service on :8080 port,
make the call to Kong:

```bash
curl -v --header "Host: identity-provider.services.jormugandr.org" http://localhost:8000/saml/idp/metadata/google
```

You should see a log on the terminal running the service that it received and handled the request.

## Running with the docker image

Assuming that you have Kong and it is availabel on your host (ports: 8001 - admin, and 8000 - proxy) and
you have build the service docker image (identity-provider), then you need to pass
the Kong URL as an ENV variable to the docker run. This is needed because by default
the service will try http://localhost:8001 inside the container and won't be able to connect to kong.

Find your host IP using ```ifconfig``` or ```ip addr```.
Assuming your host IP is 192.168.1.10, then run:

```bash
docker run -ti -e API_GATEWAY_URL=http://kong:8001 -e MONGO_URL=mongo:27017 identity-provider
```

Also, you can build and run docker image using Makefile. Run:
```bash
make run ARGS="-e API_GATEWAY_URL=http://kong:8001 -e MONGO_URL=mongo:27017"
```

If there are no errors, on a different terminal try calling Kong on port :8000

```bash
curl -v --header "Host: identity-provider.services.jormugandr.org" http://kong:8000/saml/idp/metadata/google
```

You should see output (log) in the container running the service.

# Service configuration

The service loads the gateway configuration from a JSON file /run/secrets/microservice_identity_provider_config.json. To change the path set the
**SERVICE_CONFIG_FILE** env var.
Here's an example of a JSON configuration file:

```json
{
	"microservice":	{
		"name": "identity-provider-microservice",
		"port": 8080,
		"virtual_host": "identity-provider.services.jormugandr.org",
		"hosts": ["localhost", "identity-provider.services.jormugandr.org"],
		"weight": 10,
		"slots": 100
	},
 	"services": {
		"microservice-user": "http://kong:8000/users"
	},
	"client": {
		"redirect-from-login": "http://kong:8000/profiles/me"
	}
}
```

Configuration properties:
 * **name** - ```"identity-provider-microservice"``` - the name of the service, do not change this.
 * **port** - ```8080``` - port on which the microservice is running.
 * **virtual_host** - ```"identity-provider.services.jormugandr.org"``` domain name of the service group/cluster. Don't change if not sure.
 * **hosts** - list of valid hosts. Used for proxying and load balancing of the incoming request. You need to have at least the **virtual_host** in the list.
 * **weight** - instance weight - use for load balancing.
 * **slots** - maximal number of service instances under ```"identity-provider.services.jormugandr.org"```.

# Use SAML IdP to login the user

In order to use SAML IdP to login the user you need to set redirect-from-login property in the config.json file:

```json
	"client": {
		"redirect-from-login": "http://kong:8000/profiles/me"
	}
```

Then redirect user to the http://saml-ipd-url/saml/idp/login. After successfull log in, user will be redirected to the redirect-from-login url
which is specified in the config.json file. Also, cookie called session will be set which is JWT token that contains user information like username, email, userID, roles.  

## Contributing

 For contributing to this repository or its documentation, see the [Contributing guidelines](CONTRIBUTING.md).