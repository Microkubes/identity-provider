package samlidp

import (
	"io/ioutil"
	"os"
	"testing"
)

var privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDHLfyQ75PzFPCN
2Chooc3Je4RTl95d85B91GX8wMhIHal/nDoq8a1f/VPvWjPfr6BDV1HCOoF8iKt6
HH1ISUp51h9acYyHkX8h3tJJhfYwaFBneudIGCPdVbqaIK3i6qSUEjZr6B6AMLs6
SrFCm8KnXUgK4AhzYdeYtkk1DxCPCoSDgaVGoJg7ISafisaWsLJXQxljh3K83fR/
Jwg5Hsi4d75LFFc14aHHDix8e5gevl/MbIaVHqkpqsIoiAhf7YsUL2h8TnO+LoEB
JbNivYX5JD/vWdrqx/Uz/v15aCNnhIRQDJrFehOoJOeTHt3UTsHfvB2Akq2jqG61
9N5vQdtlAgMBAAECggEBALtxOI2BGR+apiMmuCh3lP02wzoT4s1RyLnR58Sr/A95
8qhH8qm1VK7P7WyD2+t3EQAurZ92haMXzyAUrYYYiwELk+f+kfyG3TiXxBgy/JNj
p78qd3tuVFoYMoqXlGzG2ukKFrMH96Q1uAzMe/KuOMpeS80INou3GTj62vwW2ENz
PWPWeszQazKND8HAaDfhJyYEApMtwOak2lzciOnw3EI8iwADVmxXSYv2FG7GrZg7
00wCjzGPKnBvmA64q8C5oiNecwIn3Ju7LWYVRrXlrr8cZSCE4oyob0UBLShesqEx
a5TADdzLyGAER41s7E3Wf/SxUW2bnfBRqGYFiP4NjqECgYEA8h5WtPZOdNTIbcsV
oF5vAf0oNuVJIN5cfXayEVQjG+oaLvaEvkgn9Xy1Cb9KZsfDlIVLQh+DvG07/Vf7
8hZJQPZ/BuHAS80lnrpUaJo4xw8C2g4UR1+Yz3+V9/NDlWQy7H7Y/4wymAo1QrY/
QjiaO1Ltha7kxv8hVyqb8u/QnX0CgYEA0plrHZfwC/f9Cb32u6Jy6bk3L8BCqUQ9
DCa/8ftrR9iV5cfaFN0/cwVcBNQ7lKO1nWIcVd8YlOYQopgeS/ObUfpBYic9E1Fl
bNulPqqZFxt2RshYovDcq9+AfD4dXqYUTavBMhBoah9Hw05QBlrnYtX4yys2L4wk
u1tKLi6WOgkCgYBuWO9xqHRXgQccKxvfLErxoBys8FEk/tMuh2NezHb36PkoAEi9
pIs5si2clKdnMpJr5VhIea6DuVFHBMuaKRgX2IBKdac7pPMJZajEx80qxCerlBEf
+mzd3StPh3p84t7mtGVYCuCgNL7TedZY6w04DnKco/o2y965KH1M+omczQKBgBou
Dj3QjHvAaUlTvx9WM3jQmIasHN1T6U7gZk4blhuJViEJdhfP5TpUOTs0cu+oZkRZ
VPJr2G9yJjFAPcvtTaqkNIqSHCqRnM0qhOFEbeGMfWiRMUuYK6aGEz/erOH+PVnm
dw7VMVW368DgtFwF4uvLc7E1/vdsMYjE8XTKP8yZAoGBALqZbS/Y4odT4tzRE1Rd
7/FtFpKiv0KPA9PwGYfopBvdamL4Vq2KbgTRF28Us1UW15GWJ4uW6MtLxEZpLRTx
P8STkbG6gE2OgwX7a8ZGjWz3v1yw6wDSF8KLSwefrjxHY6nPjOr4lHSF7+WGSbqQ
t52inAoCd06rbZmwqAOHStwn
-----END PRIVATE KEY-----`

var certificate = `-----BEGIN CERTIFICATE-----
MIIC+zCCAeOgAwIBAgIJAOsEqXfoWSrxMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDAeFw0xNzA5MTAyMjI4MjJaFw0xODA5MTAyMjI4MjJaMBQx
EjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAMct/JDvk/MU8I3YKGihzcl7hFOX3l3zkH3UZfzAyEgdqX+cOirxrV/9U+9a
M9+voENXUcI6gXyIq3ocfUhJSnnWH1pxjIeRfyHe0kmF9jBoUGd650gYI91Vupog
reLqpJQSNmvoHoAwuzpKsUKbwqddSArgCHNh15i2STUPEI8KhIOBpUagmDshJp+K
xpawsldDGWOHcrzd9H8nCDkeyLh3vksUVzXhoccOLHx7mB6+X8xshpUeqSmqwiiI
CF/tixQvaHxOc74ugQEls2K9hfkkP+9Z2urH9TP+/XloI2eEhFAMmsV6E6gk55Me
3dROwd+8HYCSraOobrX03m9B22UCAwEAAaNQME4wHQYDVR0OBBYEFNvSl0rxYkGc
xytL22yIGNGCk+s1MB8GA1UdIwQYMBaAFNvSl0rxYkGcxytL22yIGNGCk+s1MAwG
A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAHkyGlRutkJDKLjkAXnS29xc
tpewYrHHv5humO1HoPHEGixn4a1szEZyNKIFs5PnPtNXSfktzal9cpPQSTBmZfTN
Z/xW6aR4GavYMws0j7+WkheGaEqTeGJEzUbaD9jHr1JVIMvEkQt9SnZmsnwU9tJh
x0NFlmVsiCH8UiP/z4O7xNJsRLBgXToTQDCHrYprzrtLiqgEbPvCG4kSVn+MIHgU
kA5G3k/5ZU7ITt+lTQ1wb9P1oweBlsa+KPGCZWxvz2S+kCQFj0d/OAXk0GPyD4+X
laltgoXqD0kLVp1vX5VZ8ojRzdkrrR1ILJzxKR02MDs8xLgkwZuCTY2P1tPUDWM=
-----END CERTIFICATE-----`

func TestNew(t *testing.T) {
	keyFile, err := ioutil.TempFile("", "tmp-key.key")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(keyFile.Name())
	keyFile.WriteString(privateKey)
	keyFile.Sync()

	certFile, err := ioutil.TempFile("", "tmp-cert.cert")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(certFile.Name())
	certFile.WriteString(certificate)
	certFile.Sync()

	_, err = New(keyFile.Name(), certFile.Name())
	if err == nil {
		t.Fatal("Nil error, expected: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched")
	}
}
