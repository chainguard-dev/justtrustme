package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	Issuer                 string                    `json:"issuer"`
	TokenEndpoint          string                    `json:"token_endpoint"`
	JWKSURI                string                    `json:"jwks_uri"`
	SupportedAlgorithms    []jose.SignatureAlgorithm `json:"id_token_signing_alg_values_supported,omitempty"`
	ClaimsSupported        []string                  `json:"claims_supported,omitempty"`
	ResponseTypesSupported []string                  `json:"response_types_supported,omitempty"`
	SubjectTypesSupported  []string                  `json:"subject_types_supported,omitempty"`
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
		Issuer:                 iss,
		TokenEndpoint:          te,
		JWKSURI:                ju,
		SupportedAlgorithms:    []jose.SignatureAlgorithm{jose.RS256},
		ResponseTypesSupported: []string{"id_token"},
		SubjectTypesSupported:  []string{"public"},
		ClaimsSupported: []string{
			"aud",
			"exp",
			"iat",
			"iss",
			"sub",
		},
	}
}

type TokenResponse struct {
	Token string `json:"token"`
}

func issuer(r *http.Request) string {
	return fmt.Sprintf("https://%s", r.Host)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("error generating key: %w", err)
	}

	kid := uuid.New().String()
	jwk := jose.JSONWebKey{
		Algorithm: string(jose.RS256),
		Key:       pk,
		KeyID:     kid,
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jwk.Key,
	}, &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]interface{}{"kid": kid}})
	if err != nil {
		log.Fatalf("error creating signer: %w", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")

		fmt.Fprintf(w, `checkout the following:
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
			issuer(r)+"/token", issuer(r)+"/token",
			issuer(r)+"/token?debug=true", issuer(r)+"/token?debug=true",
			issuer(r)+"/token?aud=sts.amazonaws.com&likes_dogs=true", issuer(r)+"/token?aud=sts.amazonaws.com&likes_dogs=true",
			issuer(r)+"/keys", issuer(r)+"/keys",
			issuer(r)+"/.well-known/openid-configuration", issuer(r)+"/.well-known/openid-configuration",
			"https://github.com/chainguard-dev/justtrustme", "https://github.com/chainguard-dev/justtrustme",
		)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		debug := query.Get("debug")
		claims := make(map[string]interface{})

		// This is fine even if there's no to body sent.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Errorf("error reading body: %w", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if len(body) > 0 {
			err = json.Unmarshal(body, &claims)
			if err != nil {
				log.Errorf("error unmarshaling: %w", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

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
			Issuer:   issuer(r),
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
				err = errors.New("error debug decoding token")
				log.Error(err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			d := make(map[string]interface{})
			p1, err := base64.RawStdEncoding.DecodeString(parts[0])
			if err != nil {
				log.Errorf("error debug decoding token: %w", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var pj1 map[string]interface{}
			if err := json.NewDecoder(bytes.NewReader(p1)).Decode(&pj1); err != nil {
				log.Error(err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			d["header"] = pj1

			p2, err := base64.RawStdEncoding.DecodeString(parts[1])
			if err != nil {
				log.Errorf("error debug decoding token: %w", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var pj2 map[string]interface{}
			if err := json.NewDecoder(bytes.NewReader(p2)).Decode(&pj2); err != nil {
				log.Error(err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			d["payload"] = pj2

			d["signature"] = parts[2]

			buf := bytes.NewBuffer([]byte{})
			je := json.NewEncoder(buf)
			je.SetIndent("", "\t")
			if err := je.Encode(&d); err != nil {
				log.Error(err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			fmt.Fprintln(w, buf)
		}
		if err := json.NewEncoder(w).Encode(TokenResponse{tok}); err != nil {
			log.Errorf("error encoding response: %w", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(NewOIDCDiscovery(issuer(r))); err != nil {
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
