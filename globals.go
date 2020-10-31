package main

import (
	"html/template"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"
)

const (
	// defines maximum number for cryptographic nonce
	maxNonce = 250

	// authentication cookie name
	authenticationName = "0dkZynp3NoRHgFUFbf"
	// number of seconds for authentication cookie expiration
	authenticationExpirationSeconds = 86400

	// challenge cookie name
	challengeName = "Wg9y31L7XZPkl0v4r7"
	// number of seconds for challenge hash expiration
	challengeExpirationSeconds = 60

	// challenge response name
	responseName = "dJzSKzFqxk327Yr3"

	// number of nanoseconds in second
	nanoSecondsInSecond = 1000000000

	// HTTP code for non-authorized request, used in nginx redirects
	unAuthorizedAccess = http.StatusUnauthorized

	// regex for UUIDv4 validation
	regExpUUIDv4 = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[8,9,a,b][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`

	// URL for JS hash library
	defaultJSHashLibraryURL = "https://cdnjs.cloudflare.com/ajax/libs/js-sha1/0.6.0/sha1.min.js"
)

const (
	messageOnlyGetMethod       = "only GET method"
	messageOnlyGetOrPostMethod = "only GET or POST method"
	messageOnlyPostMethod      = "only POST method"

	messageFailedEntropy = "entropy failure"

	messageFailedHTMLRender   = "HTML render failure"
	messageFailedHTTPResponse = "HTTP response failure"

	messageExpiredChallenge = "expired challenge"
	messageInvalidChallenge = "invalid challenge"
	messageInvalidResponse  = "invalid response"

	messageExpiredRecord    = "expired record"
	messageUnknownChallenge = "unknown challenge"

	messageEmptyAuthentication         = "empty authentication"
	messageExpiredAuthentication       = "authentication expired"
	messageInvalidAuthenticationDomain = "invalid authentication domain"
	messageInvalidUserAgent            = "invalid authentication user-agent"
	messageUnknownAuthentication       = "unknown authentication"
	messageValidAuthentication         = "valid authentication"

	messageAllowOptionsRequest = "allow OPTIONS method"
	messageAllowWebFont        = "allow web font"
)

type challengeDBRecord struct {
	// Domain defines valid challenge/authentication domain
	Domain string
	// UserAgent stores UA that originated from HTTP request
	UserAgent string
	// Expires defines challenge/authentication TTL
	Expires time.Time

	// Address stores address that originated from HTTP request
	Address string

	// Nonce defines cryptographic nonce for challenge request
	Nonce string
}

var (
	// challenge HTML template
	challengeTemplate *template.Template
	// challenge Lite HTML template
	challengeLiteTemplate *template.Template

	// in memory key:value db
	db sync.Map

	// mutex for thread-safety
	mu sync.Mutex

	// compiled RegExp for UUIDv4
	reUUID *regexp.Regexp

	// IP:PORT or unix socket path
	cmdAddress string
	// log date/time
	cmdLogDateTime bool
	// enable debug logging
	cmdDebug bool

	// empty favicon.ico
	favicon = []byte{
		0o00, 0o00, 0o01, 0o00, 0o01, 0o00, 0o16, 0o16,
		0o02, 0o00, 0o01, 0o00, 0o01, 0o00, 176, 0o00,
		0o00, 0o00, 0o22, 0o00, 0o00, 0o00, 0o40, 0o00,
		0o00, 0o00, 0o16, 0o00, 0o00, 0o00, 0o32, 0o00,
		0o00, 0o00, 0o01, 0o00, 0o01, 0o00, 0o00, 0o00,
		0o00, 0o00, 128, 0o00, 0o00, 0o00, 0o00, 0o00,
		0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00,
		0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00,
		0o00, 0o00, 255, 255, 255, 0o00, 0o00, 0o00,
		0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00,
		0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00,
		0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00,
		0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00,
		0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00,
		0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00,
		0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 0o00,
		0o00, 0o00, 0o00, 0o00, 0o00, 0o00, 255, 255,
		0o00, 0o00, 255, 255, 0o00, 0o00, 255, 255,
		0o00, 0o00, 255, 255, 0o00, 0o00, 255, 255,
		0o00, 0o00, 255, 255, 0o00, 0o00, 255, 255,
		0o00, 0o00, 255, 255, 0o00, 0o00, 255, 255,
		0o00, 0o00, 255, 255, 0o00, 0o00, 255, 255,
		0o00, 0o00, 255, 255, 0o00, 0o00, 255, 255,
		0o00, 0o00, 255, 255, 0o00, 0o00, 255, 255,
		0o00, 0o00, 255, 255, 0o00, 0o00,
	}

	// Logging levels
	Info  *log.Logger
	Error *log.Logger
	Debug *log.Logger
	Bot   *log.Logger
)
