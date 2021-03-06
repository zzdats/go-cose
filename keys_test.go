package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

type cert struct {
	Certificate []byte
	PrivateKey  []byte
}

var testKeys = map[string]cert{
	"rsa2048": {
		Certificate: []byte(`-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgIUJNqQEFjSR/LNum4zEMvXVTsMzjwwDQYJKoZIhvcNAQEL
BQAwSTELMAkGA1UEBhMCTFYxDTALBgNVBAgMBFJpZ2ExFDASBgNVBAoMC1NJQSBa
WiBEYXRzMRUwEwYDVQQDDAxnby1jb3NlL3Rlc3QwHhcNMjEwOTI0MTIxMDAzWhcN
MzEwOTIyMTIxMDAzWjBJMQswCQYDVQQGEwJMVjENMAsGA1UECAwEUmlnYTEUMBIG
A1UECgwLU0lBIFpaIERhdHMxFTATBgNVBAMMDGdvLWNvc2UvdGVzdDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIV6VunA2Tf94Zk7Y+i/Vkct6+oFfrE
m0koFzK8NyGKjIjnEM3Bxp/ZDlgpQJrIFCUjtQL49aypcI2L1sLq4/xyKn7cdtHv
XA4ueP5DfEfE+TrcWqQiFBhy720PtO9QQO9DSbx2siNrUlXHKF4qdO7gL/iY1zhs
6FY/QT338yO40SG9xig8+N+czJApFBTCGAppTe4YBA+K8EPYC6epPqB7QWrFizvG
XA11IlpkUuXG1PY0CUjL3owmTnuGbYQOIy/XMgTrftLNjAdOW/dQOKVePfhOE00O
zrNYx5nIVpoNeKnBc5QSrt6nkH9sb1AFSXeyXLPZA92zeg3FmDdK4AcCAwEAAaNT
MFEwHQYDVR0OBBYEFMFk1smJfvDqv0O8hJeGP+dnNEmfMB8GA1UdIwQYMBaAFMFk
1smJfvDqv0O8hJeGP+dnNEmfMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBACMHTOhemCUihxg1T2Qg6iZ8YwBP0CaBSTftmUrm8JLipCRKLLANjq7a
dtLJXtXh72VOdu7lz/TV/F0KLUjL2USHubBqZCgndGILpeBgUIv+GJG+/H1lznXY
sFN5INNlPu7PiBSHD5qzJXQ5TnayIjWzP65E23UIoucKtWufosJ+B1xTfPZ0kkQC
rhhnotvrR1C1Fpgf1I/QGqPgBo+RccmEyve2RYyYYO+wxXccHMwyI7wRcDIIq7nf
0XnHHh39maTcKHgP/ogqPd34ySKX2yzBIqVEdDjvzsmAzu/OSWNNch2pUK16NGZ+
kOOQYPmUAkRdHcet7pWe/2ndlurqcOM=
-----END CERTIFICATE-----`),
		PrivateKey: []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCFelbpwNk3/eG
ZO2Pov1ZHLevqBX6xJtJKBcyvDchioyI5xDNwcaf2Q5YKUCayBQlI7UC+PWsqXCN
i9bC6uP8cip+3HbR71wOLnj+Q3xHxPk63FqkIhQYcu9tD7TvUEDvQ0m8drIja1JV
xyheKnTu4C/4mNc4bOhWP0E99/MjuNEhvcYoPPjfnMyQKRQUwhgKaU3uGAQPivBD
2AunqT6ge0FqxYs7xlwNdSJaZFLlxtT2NAlIy96MJk57hm2EDiMv1zIE637SzYwH
Tlv3UDilXj34ThNNDs6zWMeZyFaaDXipwXOUEq7ep5B/bG9QBUl3slyz2QPds3oN
xZg3SuAHAgMBAAECggEAKYjY5LVMI6VOamNk920w/IYJxTyaX4z9kl1TAZeH0NS+
mHmiffXvFLw1tqY1XipdLUmD7jvrD2U/YftAHXx5B8hC0d1KTEkGET7ew8MbcJx1
naQUfbWRSV4nYNaQqPoqu0lSGVPpcW0BNLwnJme9mHU/rtq+jCO6YOKuip1qWgVO
xtwK8AiOjQk35xiwTHNAKBt0xfP4X/xKmoIc12vZW3iN8ZuH0Kz4/sTxkTnirBPu
VSTP9pHEV9b8IPmRhZSh3XCtDdO8F1tPu4WEFHsAnqERe6Sy3OMMi7yRYxMVQRnU
lBp3NNEE43unW8QLDUr6B8Q5aUB2D1j/xj6PeUKQEQKBgQDjtdyh35gFao7KNZh3
P2/0BVtuMOhl3zBfus/95f8lgVMZyYNuppeIZ64YTFMCMZeSOQnmrCiqDoLTLRoI
lbyOQBsPcDwJwPsmmqkJIyAdAYe/nBB9/52/laANT38V8sB3jdG8S/01BlXqqx3a
RG3/QcvTl9jjOzT62D9QTdsZPwKBgQDaMqQWuGYvpSyVk+McCWe9xwmDf593kOs6
Ylu4OxusTxwCR/SQjy53usULJaR0m8A83CyK6+XB7FHMrfKQWjXGLptl8aJVtYbY
S1j6X9KhxUiEzxX7oxY968drUMHmUMLe3hNlJ9hCqBpAoFnrtHfjfJcYQokAfpbT
erKfdQR/OQKBgQDJlr/7onnwGZTN2ULgFw4ipvd5htzHCx7FMRpfeVU3O9V419h+
hgdS4A7VPgSixYqdDdgBGdpqKqyRDbWlcgJaoNAUC9VrASiW1YbeKvWMGEW4UQ6c
rUZXTLxD7GPi52SSsr/CBjfk0HYRaWnlSH1k5DfxW9XL3SebBwSOME7OewKBgQCu
wYpsbAnjtQ3NSuHFjb7Z3zS+bhPBRn8vhqFhH24dhkqvhQPaV+Lmn966+84IWsoP
tGO0bBTbSTOGk/bHKIkTDjcF4g6bSMUULNy5ws9HI2PegqFfphHlTBau28JAfYRl
zUWJae0qDcrg4czDHAo9V4cINhnWHI0eGZJAZg9Q+QKBgBDqFjNFLHUKHHqW/Uak
WzULaL4M3TjYrP+MpozNrL1Fzba3RwSr/W6cCVM4vUdk2MIrmPiYutBZ0DVlamSy
7IFjozm9WMV72uaXBWXHpOqw35Au9bC4HUnj4N67xBQlAGoLV7C2fC6H8OBDcVEK
SsoyTHlMO+HPRTJY8O2h6nQa
-----END PRIVATE KEY-----`),
	},
	"rsa1024": {
		Certificate: []byte(`-----BEGIN CERTIFICATE-----
MIICbjCCAdegAwIBAgIUe/Kmg1Fq9fjFQOTjOC2nVCRC9wAwDQYJKoZIhvcNAQEL
BQAwSTELMAkGA1UEBhMCTFYxDTALBgNVBAgMBFJpZ2ExFDASBgNVBAoMC1NJQSBa
WiBEYXRzMRUwEwYDVQQDDAxnby1jb3NlL3Rlc3QwHhcNMjEwOTI0MTIxNjE4WhcN
MzEwOTIyMTIxNjE4WjBJMQswCQYDVQQGEwJMVjENMAsGA1UECAwEUmlnYTEUMBIG
A1UECgwLU0lBIFpaIERhdHMxFTATBgNVBAMMDGdvLWNvc2UvdGVzdDCBnzANBgkq
hkiG9w0BAQEFAAOBjQAwgYkCgYEA2FV5/wKDDEXM+GQWMbszYKlJP3o1RvWwIrkX
ZJe5sYKS+Yj7K5165OWaQCufN6AKlFBmP/C1oAzl3bChIuZlOh4MlgqzU9+ZA0ed
CKlWUlMK0gqSrVsCa3F1y6JknnldmHOmKsBiHpX7wm5DAsJDWayI2YpQt+rQOfCg
q75emtcCAwEAAaNTMFEwHQYDVR0OBBYEFL/NFe4DlSUbkc7gbUxGcOKlQLKLMB8G
A1UdIwQYMBaAFL/NFe4DlSUbkc7gbUxGcOKlQLKLMA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQELBQADgYEAhrtr226SpoKK5L6wQyoUS6rlHff/cJpZVnYiYu21
aNtSVahDuOOYUnbimSrndrm+3T4uoYsa56GW0VFj0c4g2WUyANsKo8g6DBtZUr55
25QH7eBIzZgCstuA7kuyThm2DYq9xQPAXq3MQJDzkoHcZD5GlpuK4RI0B3pSMyns
s0M=
-----END CERTIFICATE-----`),
		PrivateKey: []byte(`-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANhVef8CgwxFzPhk
FjG7M2CpST96NUb1sCK5F2SXubGCkvmI+yudeuTlmkArnzegCpRQZj/wtaAM5d2w
oSLmZToeDJYKs1PfmQNHnQipVlJTCtIKkq1bAmtxdcuiZJ55XZhzpirAYh6V+8Ju
QwLCQ1msiNmKULfq0DnwoKu+XprXAgMBAAECgYEAp89eS98R8rIudjuFL9yL1R5c
EF5m931bvQOgzsoXJEgqZGDKnSGSk/468i4kWozNyBC50D2TVezLXnVF+YGI4OgS
5Z5lKRpJNmDYF76Kfohu8Fj/hGhm/WA5LhAmSjfLlSBFKA/v4i6wcbMfF6y/UdvY
W4HOspjWhsshJTojFKkCQQDtcfWsbPfnTfqoUtvrjWFIL+ZeEugFdBYUt+Q5yehh
ZNGIN70oOWlN4Pi/VnRFD7AcHrVHoxHrH7qrv9aEdTJ7AkEA6T0wxo9wnTDMovvL
z5rmV4bBRgXzOuE/VcUEmAip/MUZ3lUC4JZ5zAwFbIysPaVvm334cF8KAVC64iid
dFMIVQJBAN1hZevYQR5AfxZXAsJQs8XpGwDU4czL2haBCWGz1VyQ8ibtyQfq1zqM
KX/DrG4DXXAqVVwwNvGgSJv/JZOj7WcCQQDV+Ykx4I5T510VeSM1xsnjKoFNmE/Y
iKTuLt1UDT7F4p0k16DYIbSDedPQDg5GT+vgHuU5Ujd/lWyd5tzsxvAxAkABoBjw
8vIo2otlGLzezxrDS6vOTZzlzDSd1P8nEk9IlGTaH8fAYqk8V+z1LG4xRqe4mXXb
Pd5E+IuSVEBKlAiq
-----END PRIVATE KEY-----`),
	},
	"ecdsa256": {
		Certificate: []byte(`-----BEGIN CERTIFICATE-----
MIIB5zCCAY2gAwIBAgIUcKF5s9ZlC96S3ASnd0/ciRZ4fG0wCgYIKoZIzj0EAwIw
STELMAkGA1UEBhMCTFYxDTALBgNVBAgMBFJpZ2ExFDASBgNVBAoMC1NJQSBaWiBE
YXRzMRUwEwYDVQQDDAxnby1jb3NlL3Rlc3QwHhcNMjEwOTI0MTIxOTQ1WhcNMzEw
OTIyMTIxOTQ1WjBJMQswCQYDVQQGEwJMVjENMAsGA1UECAwEUmlnYTEUMBIGA1UE
CgwLU0lBIFpaIERhdHMxFTATBgNVBAMMDGdvLWNvc2UvdGVzdDBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABIvwr6pUU+HKKN+D+tmEPgTxmYlPf9sg4g573qRgj3MX
+lOpdTtIt3zPBjnu1/jnvwwMw5FHfmZHzNSo6MZaaGmjUzBRMB0GA1UdDgQWBBQm
4vxwnd6coULDiDnvj2aQz2f/fTAfBgNVHSMEGDAWgBQm4vxwnd6coULDiDnvj2aQ
z2f/fTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIFuTV/h2Hmr9
max06Ou8NS6wPWFkg0dIckwYyEUKSI5HAiEAnujbqva3WTZUAmL/+myptB3c3ZII
VmcaCHhITHhOD2U=
-----END CERTIFICATE-----`),
		PrivateKey: []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5sXIzRtmJuwLuSwd
MpHNzdLPpwMyAYskACDZESc+Q4ahRANCAASL8K+qVFPhyijfg/rZhD4E8ZmJT3/b
IOIOe96kYI9zF/pTqXU7SLd8zwY57tf4578MDMORR35mR8zUqOjGWmhp
-----END PRIVATE KEY-----`),
	},
	"ecdsa256-2": {
		Certificate: []byte(`-----BEGIN CERTIFICATE-----
MIIB6DCCAY2gAwIBAgIUB5LAeSEjICfFNwh1dNMSnnJ7dMMwCgYIKoZIzj0EAwIw
STELMAkGA1UEBhMCTFYxDTALBgNVBAgMBFJpZ2ExFDASBgNVBAoMC1NJQSBaWiBE
YXRzMRUwEwYDVQQDDAxnby1jb3NlL3Rlc3QwHhcNMjEwOTI0MTQxODU4WhcNMzEw
OTIyMTQxODU4WjBJMQswCQYDVQQGEwJMVjENMAsGA1UECAwEUmlnYTEUMBIGA1UE
CgwLU0lBIFpaIERhdHMxFTATBgNVBAMMDGdvLWNvc2UvdGVzdDBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABBGUH+m4oDzY5BUktY/GYKrnZlntbDshrHzdtml/bWZo
//62JRv/jKaLDaEK55s4q52tXfbzWFXvpzxOngRo2BijUzBRMB0GA1UdDgQWBBTq
1J09kqKywGZ2RJ6RSsH/jTyXqjAfBgNVHSMEGDAWgBTq1J09kqKywGZ2RJ6RSsH/
jTyXqjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQDPthxbHPVf
+ioxSIyQaPO2Ro7hksneE7Sc7sddtQApbAIhAOTEJWqmfLFYwsHHD7LFF2+3jIMf
BHDVE2eZQ1TP58CT
-----END CERTIFICATE-----`),
		PrivateKey: []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrCMiINcaP2EnURg1
Xzwt1NI7s1xCFMMhQQXx46c1giChRANCAAQRlB/puKA82OQVJLWPxmCq52ZZ7Ww7
Iax83bZpf21maP/+tiUb/4ymiw2hCuebOKudrV3281hV76c8Tp4EaNgY
-----END PRIVATE KEY-----`),
	},
	"ecdsa384": {
		Certificate: []byte(`-----BEGIN CERTIFICATE-----
MIICJTCCAaqgAwIBAgIUHPl9uh8TRCAmFVMkhRgeG7GprzcwCgYIKoZIzj0EAwIw
STELMAkGA1UEBhMCTFYxDTALBgNVBAgMBFJpZ2ExFDASBgNVBAoMC1NJQSBaWiBE
YXRzMRUwEwYDVQQDDAxnby1jb3NlL3Rlc3QwHhcNMjEwOTI0MTIzNTMwWhcNMzEw
OTIyMTIzNTMwWjBJMQswCQYDVQQGEwJMVjENMAsGA1UECAwEUmlnYTEUMBIGA1UE
CgwLU0lBIFpaIERhdHMxFTATBgNVBAMMDGdvLWNvc2UvdGVzdDB2MBAGByqGSM49
AgEGBSuBBAAiA2IABDhht3IfSaM9Dj+qE62mkWwwakUOCPa7gQqyy73H8oSLJdLG
tSlzkSaWu+cW27vOnAeM4rbwTDTfxPrSlt7IQYlXdY7XHzs6FdxlWTNb44tSooXg
qfk67Dtq87X3+Gmal6NTMFEwHQYDVR0OBBYEFLB17NiUy8LzBrlBcr6B0jdl5lX9
MB8GA1UdIwQYMBaAFLB17NiUy8LzBrlBcr6B0jdl5lX9MA8GA1UdEwEB/wQFMAMB
Af8wCgYIKoZIzj0EAwIDaQAwZgIxAMoCZJL+/dcXMETs4U8u9047glIJYpEgnMu7
5OjAIXO3Q2R0gitJOJIuz62AYI3IFQIxAPsAaKVvbQ8F0vVZ+ffgQNoa0TtzKz/F
9Hb1ioGcPNbkEXboeMKCdDsYEDTr31LgKg==
-----END CERTIFICATE-----`),
		PrivateKey: []byte(`-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDfsZVx1gmBTc00vtQf
xAbYT2C0vXFrc/Hs6MxM3hm/T+WN1kQ6Ns9BSl8CfNcknVihZANiAAQ4YbdyH0mj
PQ4/qhOtppFsMGpFDgj2u4EKssu9x/KEiyXSxrUpc5EmlrvnFtu7zpwHjOK28Ew0
38T60pbeyEGJV3WO1x87OhXcZVkzW+OLUqKF4Kn5Ouw7avO19/hpmpc=
-----END PRIVATE KEY-----`),
	},
	"ecdsa521": {
		Certificate: []byte(`-----BEGIN CERTIFICATE-----
MIICbjCCAdCgAwIBAgIUMLCS4x725fY6aBf4oYV52h/WSDkwCgYIKoZIzj0EAwIw
STELMAkGA1UEBhMCTFYxDTALBgNVBAgMBFJpZ2ExFDASBgNVBAoMC1NJQSBaWiBE
YXRzMRUwEwYDVQQDDAxnby1jb3NlL3Rlc3QwHhcNMjEwOTI0MTMyMTM4WhcNMzEw
OTIyMTMyMTM4WjBJMQswCQYDVQQGEwJMVjENMAsGA1UECAwEUmlnYTEUMBIGA1UE
CgwLU0lBIFpaIERhdHMxFTATBgNVBAMMDGdvLWNvc2UvdGVzdDCBmzAQBgcqhkjO
PQIBBgUrgQQAIwOBhgAEAfYIuDRnIiosjsl0gFgrxGGV513W0vciDLonkFHxeuJd
UaIgRdQcC1ysp29hSveBS31PzNgKsSKe0w5sE5UT1EDTAK9V1d8mE5xLjMYrALsn
ObSb/ZprnVG1+bSM+mUHKzlc+iJQrGMvqt6T6Krvsyw9vbyQpD/rqqQOb8owsklH
NMEco1MwUTAdBgNVHQ4EFgQUWsaB8ESt/5ouiuB6YaEZ5Oy/8sAwHwYDVR0jBBgw
FoAUWsaB8ESt/5ouiuB6YaEZ5Oy/8sAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjO
PQQDAgOBiwAwgYcCQgDlSGKo74LjShE1gQV8kvQFHoMUTb0OIuHcpgUhOAKmeGZB
YG2AOmH+BbLfcd/hqQ7sSyAzuQYER18AEnM/tGWSnAJBUH09Qn+E8hBILSNXJrnk
zccCIZiN3ylZ+DvbU6oQ5vBEVmvwtxGBB057Tu7WDmMd6VvzhQr5fvCgI4W8FT2V
hQk=
-----END CERTIFICATE-----`),
		PrivateKey: []byte(`-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBI7iRvTqbF+tgFi+V
IGNiFeZhZJrYoRmsV/82Z0DKu9TNiR5ssY19bMPXQiyfsZOoVgkxl97bW2+MChtu
NiA/WoihgYkDgYYABAH2CLg0ZyIqLI7JdIBYK8Rhledd1tL3Igy6J5BR8XriXVGi
IEXUHAtcrKdvYUr3gUt9T8zYCrEintMObBOVE9RA0wCvVdXfJhOcS4zGKwC7Jzm0
m/2aa51Rtfm0jPplBys5XPoiUKxjL6rek+iq77MsPb28kKQ/66qkDm/KMLJJRzTB
HA==
-----END PRIVATE KEY-----`),
	},
	"ed25519": {
		Certificate: []byte(`-----BEGIN CERTIFICATE-----
MIIBpzCCAVmgAwIBAgIUVxYW0+hk2qMh8CmpspfvraGGTQMwBQYDK2VwMEkxCzAJ
BgNVBAYTAkxWMQ0wCwYDVQQIDARSaWdhMRQwEgYDVQQKDAtTSUEgWlogRGF0czEV
MBMGA1UEAwwMZ28tY29zZS90ZXN0MB4XDTIxMDkyNDEzMjUzOFoXDTMxMDkyMjEz
MjUzOFowSTELMAkGA1UEBhMCTFYxDTALBgNVBAgMBFJpZ2ExFDASBgNVBAoMC1NJ
QSBaWiBEYXRzMRUwEwYDVQQDDAxnby1jb3NlL3Rlc3QwKjAFBgMrZXADIQC8KbuO
Utf/AgcJVo4Sf8lE7tJjOPnGtumJZNEqkdzPj6NTMFEwHQYDVR0OBBYEFNK3KZqs
UQzKy0IO4lxhnXR8fdMnMB8GA1UdIwQYMBaAFNK3KZqsUQzKy0IO4lxhnXR8fdMn
MA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EAnv0Uodv/tX++0AWMR4y9XLCb3JEe
xxoL/bikmL1CbNijgAW2dn2cWT8XY+XH3PmMncfvvlIODmSfpv8lte23DA==
-----END CERTIFICATE-----`),
		PrivateKey: []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJU9qw1WgePBMaIB9RXQbzFsxje8zAbW6ztWndsc+qTc
-----END PRIVATE KEY-----`),
	},
}

func getPrivateKey(t *testing.T, name string) crypto.PrivateKey {
	key := testKeys[name]
	require.NotNil(t, key)

	block, _ := pem.Decode(key.PrivateKey)
	require.NotNil(t, block)
	require.Equal(t, "PRIVATE KEY", block.Type)

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key
		default:
			t.Fatalf("unsupported private key type: %T", key)
			return nil
		}
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key
	}
	t.Fatal("unsupported private key type")
	return nil
}

func getPublicKey(t *testing.T, name string) crypto.PublicKey {
	key := testKeys[name]
	require.NotNil(t, key)

	block, _ := pem.Decode(key.Certificate)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.NotNil(t, cert)

	return cert.PublicKey
}
