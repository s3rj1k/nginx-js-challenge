package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/publicsuffix"
)

func faviconHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := w.Write(favicon); err != nil {
		Error.Printf(
			"%d, RAddr:'%s', URL:'%s%s', UA:'%s', %s\n",
			http.StatusInternalServerError,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			r.UserAgent(), messageFailedHTTPResponse,
		)
	}
}

func challengeHandle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		renderHandle(w, r)
	case http.MethodPost:
		validateHandle(w, r)
	case http.MethodOptions:
		// OPTIONS is needed for CORS to function properly, we allow all OPTIONS requests when specific header is passed
		if strings.EqualFold(r.Header.Get("X-Allow-OPTIONS"), "TRUE") {
			Debug.Printf(
				"%d, RAddr:'%s', URL:'%s%s', UA:'%s', %s\n",
				http.StatusAccepted,
				r.Header.Get("X-Real-IP"),
				r.Header.Get("X-Forwarded-Host"),
				r.Header.Get("X-Original-URI"),
				r.UserAgent(), messageAllowOptionsRequest,
			)

			return
		}

		fallthrough
	default:
		Debug.Printf(
			"%d, RAddr:'%s', URL:'%s%s', UA:'%s', %s\n",
			http.StatusMethodNotAllowed,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			r.UserAgent(), messageOnlyGetOrPostMethod,
		)

		// set default allowed headers
		allowHeader := []string{
			http.MethodGet,
			http.MethodPost,
		}

		if strings.EqualFold(r.Header.Get("X-Allow-OPTIONS"), "TRUE") {
			// add OPTIONS to allowed headers
			allowHeader = append(allowHeader, http.MethodOptions)
		}

		// return proper HTTP error with headers
		w.Header().Set(
			"Allow",
			strings.Join(allowHeader, ", "),
		)

		http.Error(w, messageOnlyGetOrPostMethod, http.StatusMethodNotAllowed)

		return
	}
}

func renderHandle(w http.ResponseWriter, r *http.Request) {
	// allow only GET method
	if r.Method != http.MethodGet {
		Debug.Printf(
			"%d, RAddr:'%s', URL:'%s%s', UA:'%s', %s\n",
			http.StatusMethodNotAllowed,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			r.UserAgent(), messageOnlyGetMethod,
		)

		// return proper HTTP error with headers
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, messageOnlyGetMethod, http.StatusMethodNotAllowed)

		return
	}

	// define domain for a cookie
	domain := r.Header.Get("X-Forwarded-Host")

	// compute wildcard domain cookie when appropriate configuration header present
	if strings.EqualFold(r.Header.Get("X-TLDPlusOne"), "TRUE") {
		if val, err := publicsuffix.EffectiveTLDPlusOne(r.Header.Get("X-Forwarded-Host")); err == nil {
			domain = "." + val
		}
	}

	// clean old invalid cookies
	http.SetCookie(w, &http.Cookie{
		Domain:  domain,
		Name:    authenticationName,
		Value:   "",
		Expires: time.Unix(0, 0),
	})
	http.SetCookie(w, &http.Cookie{
		Name:    authenticationName,
		Value:   "",
		Expires: time.Unix(0, 0),
	})

	// set to True when captcha requested with lite template flag
	var isLiteTemplate bool

	// check for lite template header
	if strings.EqualFold(r.Header.Get("X-LiteTemplate"), "TRUE") {
		isLiteTemplate = true
	}

	// generate new nonce
	nonce := genNewNonce()
	// generate challenge hash
	challenge := getStringHash(r.UserAgent(), nonce)
	// set how long cookie is valid
	challengeTTL := time.Duration(challengeExpirationSeconds * nanoSecondsInSecond)
	// generate expire date for challenge hash
	expires := time.Now().Add(challengeTTL)

	Info.Printf(
		"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', Nonce:'%s', Challenge:'%s', TTL:'%s'\n",
		http.StatusOK,
		r.Header.Get("X-Real-IP"),
		r.Header.Get("X-Forwarded-Host"),
		r.Header.Get("X-Original-URI"),
		domain, r.UserAgent(), nonce,
		challenge, challengeTTL,
	)

	// get JS HASH library URL
	jsHashLibraryURL := r.Header.Get("X-JS-Hash-Library-URL")
	if len(jsHashLibraryURL) == 0 {
		jsHashLibraryURL = defaultJSHashLibraryURL
	}

	// populate struct with needed data for template render
	data := struct {
		MaxNonce         string
		ChallengeName    string
		ResponseName     string
		JSHashLibraryURL string
	}{
		MaxNonce:         strconv.Itoa(maxNonce),
		ChallengeName:    challengeName,
		ResponseName:     responseName,
		JSHashLibraryURL: jsHashLibraryURL,
	}

	// store challenge hash to db
	db.Store(challenge,
		challengeDBRecord{
			Domain:    domain,
			UserAgent: r.UserAgent(),
			Expires:   expires,

			Address: r.Header.Get("X-Real-IP"),
			Nonce:   nonce,
		},
	)

	// https://www.fastly.com/blog/clearing-cache-browser
	// https://www.w3.org/TR/clear-site-data/
	// Broken on Google Chrome
	// w.Header().Set("Clear-Site-Data", `"cache"`)

	// set cookie for wildcard domain cookie, domain starts with '.'
	if strings.HasPrefix(domain, ".") {
		http.SetCookie(w, &http.Cookie{
			Domain:   domain,
			Name:     challengeName,
			Value:    challenge,
			Expires:  expires,
			MaxAge:   int(expires.Unix() - time.Now().Unix()),
			Secure:   false,
			HttpOnly: false,
			SameSite: http.SameSiteNoneMode,
		})
	} else { // non-wildcard cookie
		http.SetCookie(w, &http.Cookie{
			Name:     challengeName,
			Value:    challenge,
			Expires:  expires,
			MaxAge:   int(expires.Unix() - time.Now().Unix()),
			Secure:   false,
			HttpOnly: false,
			SameSite: http.SameSiteStrictMode,
		})
	}

	var err error

	// render challenge template
	if isLiteTemplate {
		err = challengeLiteTemplate.Execute(w, data)
	} else {
		err = challengeTemplate.Execute(w, data)
	}

	if err != nil {
		// ignore buffer errors
		if errors.Is(err, syscall.EPIPE) {
			return
		}

		Error.Printf(
			"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', %s\n",
			http.StatusInternalServerError,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			domain, r.UserAgent(),
			messageFailedHTMLRender,
		)

		// return proper HTTP error
		http.Error(w, messageFailedHTMLRender, http.StatusInternalServerError)

		return
	}
}

func validateHandle(w http.ResponseWriter, r *http.Request) {
	// allow only POST method
	if r.Method != http.MethodPost {
		Debug.Printf(
			"%d, RAddr:'%s', URL:'%s%s', UA:'%s', %s\n",
			http.StatusMethodNotAllowed,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			r.UserAgent(), messageOnlyPostMethod,
		)

		// return proper HTTP error with headers
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, messageOnlyPostMethod, http.StatusMethodNotAllowed)

		return
	}

	// define domain for a cookie
	domain := r.Header.Get("X-Forwarded-Host")

	// compute wildcard domain cookie when appropriate configuration header present
	if strings.EqualFold(r.Header.Get("X-TLDPlusOne"), "TRUE") {
		if val, err := publicsuffix.EffectiveTLDPlusOne(r.Header.Get("X-Forwarded-Host")); err == nil {
			domain = "." + val
		}
	}

	// remove challenge for wildcard domain cookie, domain starts with '.'
	if strings.HasPrefix(domain, ".") {
		http.SetCookie(w, &http.Cookie{
			Domain:  domain,
			Name:    challengeName,
			Value:   "",
			Expires: time.Unix(0, 0),
		})
	} else { // non-wildcard cookie
		http.SetCookie(w, &http.Cookie{
			Name:    challengeName,
			Value:   "",
			Expires: time.Unix(0, 0),
		})
	}

	// get challenge value from request
	challenge := r.PostFormValue(challengeName)
	// get challenge response value from request
	response := r.PostFormValue(responseName)

	Debug.Printf(
		"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', Response:'%s', Challenge:'%s'\n",
		http.StatusOK,
		r.Header.Get("X-Real-IP"),
		r.Header.Get("X-Forwarded-Host"),
		r.Header.Get("X-Original-URI"),
		domain, r.UserAgent(),
		response, challenge,
	)

	// https://www.fastly.com/blog/clearing-cache-browser
	// https://www.w3.org/TR/clear-site-data/
	// Broken on Google Chrome
	// w.Header().Set("Clear-Site-Data", `"cache"`)

	// lookup challenge hash in db
	val, ok := db.Load(challenge)
	if !ok {
		Info.Printf(
			"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', Challenge:'%s', %s\n",
			http.StatusSeeOther,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			domain, r.UserAgent(), challenge,
			messageUnknownChallenge,
		)

		// redirect to self
		http.Redirect(w, r, "/", http.StatusSeeOther)

		return
	}

	// check challenge hash record
	record, ok := val.(challengeDBRecord)
	if !ok {
		Error.Printf(
			"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', Challenge:'%s', %s\n",
			http.StatusInternalServerError,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			domain, r.UserAgent(), challenge,
			messageUnknownChallenge,
		)

		// return proper HTTP error
		http.Error(w, messageUnknownChallenge, http.StatusInternalServerError)

		return
	}

	// check that challenge hash is valid for domain
	if !strings.EqualFold(domain, record.Domain) {
		Info.Printf(
			"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', Challenge:'%s', %s\n",
			http.StatusSeeOther,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			domain, r.UserAgent(), challenge,
			messageInvalidChallenge,
		)

		// redirect to self
		http.Redirect(w, r, "/", http.StatusSeeOther)

		return
	}

	// check challenge hash expiration
	if record.Expires.Before(time.Now()) {
		Info.Printf(
			"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', Challenge:'%s', %s\n",
			http.StatusSeeOther,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			domain, r.UserAgent(), challenge,
			messageExpiredChallenge,
		)

		// redirect to self
		http.Redirect(w, r, "/", http.StatusSeeOther)

		return
	}

	// validate challenge response
	if getStringHash(r.UserAgent(), response) != challenge {
		Info.Printf(
			"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', Challenge:'%s', %s\n",
			http.StatusSeeOther,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			domain, r.UserAgent(), challenge,
			messageInvalidResponse,
		)

		// redirect to self
		http.Redirect(w, r, "/", http.StatusSeeOther)

		return
	}

	// generate ID for cookie value
	id, err := genUUID()
	if err != nil {
		Error.Printf(
			"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', %s\n",
			http.StatusInternalServerError,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			domain, r.UserAgent(), messageFailedEntropy,
		)

		// return proper HTTP error
		http.Error(w, messageFailedEntropy, http.StatusInternalServerError)

		return
	}

	// set how long cookie is valid
	authenticationTTL := time.Duration(authenticationExpirationSeconds * nanoSecondsInSecond)
	// generate expire date for authentication hash
	expires := time.Now().Add(authenticationTTL)

	Info.Printf(
		"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', Response:'%s', Challenge:'%s', Auth:'%s', TTL:'%s'\n",
		http.StatusOK,
		r.Header.Get("X-Real-IP"),
		r.Header.Get("X-Forwarded-Host"),
		r.Header.Get("X-Original-URI"),
		domain, r.UserAgent(), response,
		challenge, id, authenticationTTL,
	)

	// challenge is valid, invalidating used challenge hash
	db.Delete(challenge)

	// store challenge authentication hash to db
	db.Store(id,
		challengeDBRecord{
			Domain:    domain,
			UserAgent: r.UserAgent(),
			Expires:   expires,

			Address: r.Header.Get("X-Real-IP"),
		},
	)

	// set cookie for wildcard domain cookie, domain starts with '.'
	if strings.HasPrefix(domain, ".") {
		http.SetCookie(w, &http.Cookie{
			Domain:   domain,
			Name:     authenticationName,
			Value:    id,
			Expires:  expires,
			MaxAge:   int(expires.Unix() - time.Now().Unix()),
			Secure:   false,
			HttpOnly: false,
			SameSite: http.SameSiteNoneMode,
		})
	} else { // non-wildcard cookie
		http.SetCookie(w, &http.Cookie{
			Name:     authenticationName,
			Value:    id,
			Expires:  expires,
			MaxAge:   int(expires.Unix() - time.Now().Unix()),
			Secure:   false,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
	}

	// redirect to self
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func authHandle(w http.ResponseWriter, r *http.Request) {
	// allow web font for '@font-face' request from CSS
	if strings.EqualFold(r.Header.Get("X-Allow-Web-Font"), "TRUE") &&
		isFontInURL(r.Header.Get("X-Original-URI")) {
		Debug.Printf(
			"%d, RAddr:'%s', URL:'%s%s', UA:'%s', %s\n",
			http.StatusOK,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			r.UserAgent(), messageAllowWebFont,
		)

		return
	}

	// get challenge cookie value from request
	auth, err := r.Cookie(authenticationName)
	if err != nil || auth == nil {
		Debug.Printf(
			"%d, RAddr:'%s', URL:'%s%s', UA:'%s', %s\n",
			unAuthorizedAccess,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			r.UserAgent(), messageEmptyAuthentication,
		)

		// return proper HTTP error
		http.Error(w, messageEmptyAuthentication, unAuthorizedAccess)

		return
	}

	// define domain for a cookie
	domain := r.Header.Get("X-Forwarded-Host")

	// compute wildcard domain cookie when appropriate configuration header present
	if strings.EqualFold(r.Header.Get("X-TLDPlusOne"), "TRUE") {
		if val, err := publicsuffix.EffectiveTLDPlusOne(r.Header.Get("X-Forwarded-Host")); err == nil {
			domain = "." + val
		}
	}

	// lookup cookie value in db
	val, ok := db.Load(auth.Value)
	if !ok {
		Debug.Printf(
			"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', Auth:'%s', %s\n",
			unAuthorizedAccess,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			domain, r.UserAgent(), auth.Value,
			messageUnknownAuthentication,
		)

		// return proper HTTP error
		http.Error(w, messageUnknownAuthentication, unAuthorizedAccess)

		return
	}

	// check challenge hash record
	record, ok := val.(challengeDBRecord)
	if !ok {
		Error.Printf(
			"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', Auth:'%s', %s\n",
			unAuthorizedAccess,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			domain, r.UserAgent(), auth.Value,
			messageUnknownAuthentication,
		)

		// return proper HTTP error
		http.Error(w, messageUnknownAuthentication, unAuthorizedAccess)

		return
	}

	// check that cookie is valid for domain
	if !strings.EqualFold(domain, record.Domain) {
		Debug.Printf(
			"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', Auth:'%s', %s (%s)\n",
			unAuthorizedAccess,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			domain, r.UserAgent(), auth.Value,
			messageInvalidAuthenticationDomain,
			record.Domain,
		)

		// when we switch form wildcard to none-wildcard cookie we need to clean DB records for this domain
		if strings.EqualFold(
			strings.TrimPrefix(domain, "."),
			strings.TrimPrefix(record.Domain, "."),
		) {
			db.Delete(auth.Value)
		}

		// return proper HTTP error
		http.Error(w, messageInvalidAuthenticationDomain, unAuthorizedAccess)

		return
	}

	// check that cookie is valid for UA
	if !strings.EqualFold(r.UserAgent(), record.UserAgent) {
		Debug.Printf(
			"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', Auth:'%s', %s (%s)\n",
			unAuthorizedAccess,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			domain, r.UserAgent(), auth.Value,
			messageInvalidUserAgent, record.UserAgent,
		)

		// return proper HTTP error
		http.Error(w, messageInvalidUserAgent, unAuthorizedAccess)

		return
	}

	// check cookie expiration
	if !record.Expires.After(time.Now()) {
		Debug.Printf(
			"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', Auth:'%s', %s\n",
			unAuthorizedAccess,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			domain, r.UserAgent(), auth.Value,
			messageExpiredAuthentication,
		)

		// return proper HTTP error
		http.Error(w, messageExpiredAuthentication, unAuthorizedAccess)
	}

	Debug.Printf(
		"%d, RAddr:'%s', URL:'%s%s', Dom:'%s', UA:'%s', Auth:'%s', %s\n",
		http.StatusOK,
		r.Header.Get("X-Real-IP"),
		r.Header.Get("X-Forwarded-Host"),
		r.Header.Get("X-Original-URI"),
		domain, r.UserAgent(), auth.Value,
		messageValidAuthentication,
	)
}
