package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	jwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var log *zap.SugaredLogger

func init() {
	l, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	log = l.Sugar()
}

type OIDCDiscovery struct {
	Issuer        string `json:"issuer"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
}

func NewOIDCDiscovery(iss string) OIDCDiscovery {
	te, err := url.JoinPath(iss, "token")
	if err != nil {
		log.Fatalf("error joining url: %w", err)
	}
	ju, err := url.JoinPath(iss, "keys")
	if err != nil {
		log.Fatalf("error joining url: %w", err)
	}

	return OIDCDiscovery{
		Issuer:        iss,
		TokenEndpoint: te,
		JWKSURI:       ju,
	}
}

type TokenResponse struct {
	Token string `json:"token"`
}

func main() {
	issuerURL := os.Getenv("ISSUER_URL")
	if issuerURL == "" {
		log.Fatal("ISSUER_URL must be set")
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("error generating key: %w", err)
	}

	jwk := jose.JSONWebKey{
		Algorithm: string(jose.RS256),
		Key:       pk,
		KeyID:     uuid.New().String(),
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jwk.Key,
	}, nil)
	if err != nil {
		log.Fatalf("error creating signer: %w", err)
	}

	mux := http.NewServeMux()

	help := fmt.Sprintf(`checkout the following:
	<br>
	<a href="%s">%s</a>
	<br>
	<a href="%s">%s</a>
	<br>
	<a href="%s">%s</a>
	<br>
	<a href="%s">%s</a>
	<br>
	<a href="%s">%s</a>
	<br>
	<a href="%s">%s</a>
	`,
		issuerURL+"/token", issuerURL+"/token",
		issuerURL+"/token?debug=true", issuerURL+"/token?debug=true",
		issuerURL+"/token?aud=sts.amazonaws.com&likes_dogs=true", issuerURL+"/token?aud=sts.amazonaws.com&likes_dogs=true",
		issuerURL+"/keys", issuerURL+"/keys",
		issuerURL+"/.well-known/openid-configuration", issuerURL+"/.well-known/openid-configuration",
		"https://github.com/chainguard-dev/justtrustme", "https://github.com/chainguard-dev/justtrustme",
	)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, help)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		debug := query.Get("debug")
		claims := make(map[string]interface{})
		for k, v := range query {
			if k == "debug" {
				continue
			}
			s := v[0]
			if s == "true" {
				claims[k] = true
			} else if s == "false" {
				claims[k] = false
			} else {
				claims[k] = s
			}
		}
		now := time.Now()
		tok, err := jwt.Signed(signer).Claims(jwt.Claims{
			Issuer:   issuerURL,
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(30 * time.Minute)),
		}).Claims(claims).CompactSerialize()
		if err != nil {
			log.Errorf("error creating token: %w", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if debug == "true" {
			parts := strings.Split(tok, ".")
			if len(parts) != 3 {
				log.Errorf("error debug decoding token: %w", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for _, part := range parts[:2] {
				s, err := base64.RawStdEncoding.DecodeString(part)
				if err != nil {
					log.Errorf("error debug decoding token: %w", err)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				buf := bytes.NewBuffer([]byte{})
				json.Indent(buf, s, "", "\t")
				fmt.Fprintln(w, buf)
				fmt.Fprintln(w)
			}
			fmt.Fprint(w, parts[2])
		} else {
			if err := json.NewEncoder(w).Encode(TokenResponse{tok}); err != nil {
				log.Errorf("error encoding response: %w", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(NewOIDCDiscovery(issuerURL)); err != nil {
			log.Errorf("error encoding response: %w", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				jwk.Public(),
			},
		}); err != nil {
			log.Errorf("error encoding response: %w", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	log.Infof("starting server on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
