package chiper

// https://play.golang.org/p/bzpD7Pa9mr

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
)

type rsaPublicKey struct {
	*rsa.PublicKey
}

type rsaPrivateKey struct {
	*rsa.PrivateKey
}

// A Signer is can create signatures that verify against a public key.
type Signer interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Sign(data []byte) ([]byte, error)
}

// A Signer is can create signatures that verify against a public key.
type Unsigner interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Unsign(data []byte, sig []byte) error
}

// Sign signs data with rsa-sha256
// https://tools.ietf.org/html/rfc2313
func (r *rsaPrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, d)
}

// Unsign verifies the message using a rsa-sha256 signature
// https://tools.ietf.org/html/rfc2313
func (r *rsaPublicKey) Unsign(message []byte, sig []byte) error {
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, d, sig)
}

func parsePrivateKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

// parsePublicKey parses a PEM encoded private key.
func parsePublicKey(pemBytes []byte) (Unsigner, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}

	return newUnsignerFromKey(rawkey)
}

func newSignerFromKey(k interface{}) (Signer, error) {
	var sshKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sshKey = &rsaPrivateKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

func newUnsignerFromKey(k interface{}) (Unsigner, error) {
	var sshKey Unsigner
	switch t := k.(type) {
	case *rsa.PublicKey:
		sshKey = &rsaPublicKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

func LoadPrivateKey(theKey []byte) (Signer, error) {
	return parsePrivateKey(theKey)
}

func LoadPublicKey(theKey []byte) (Unsigner, error) {
	return parsePublicKey(theKey)
}

func VerifySignature(signature string, pubKey []byte, data interface{}) error {

	var b []byte

	unsigner, err := LoadPublicKey(pubKey)
	if err != nil {
		return err
	}

	bsign, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	// check real type of "data"
	switch v := data.(type) {
	case string:
		// if its string, doesn't to marshal. Because json marshal byte will be different from original data byte (if string)
		b = []byte(v)
		log.Printf("verifySignature for: %s", v)
	default:
		b, err = json.Marshal(data)
		log.Printf("verifySignature for: %s", v)
	}

	if err != nil {
		return err
	}

	err = unsigner.Unsign(b, bsign)
	return err
}

func GenerateSignature(privKey []byte, data interface{}) (string, error) {

	var b []byte

	signer, err := LoadPrivateKey(privKey)
	if err != nil {
		return "", err
	}

	switch v := data.(type) {
	case string:
		// if its string, doesn't need to marshal it. Because json marshal byte will be different from original data byte
		b = []byte(v)
	default:
		b, err = json.Marshal(data)
		if err != nil {
			return "", err
		}
	}

	signed, err := signer.Sign(b)

	b64Signed := base64.StdEncoding.EncodeToString(signed)

	return b64Signed, nil
}

func GenerateResponseSignature(content interface{}, privKeyPath string) (string, error) {
	bPrivKey, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return "", errors.New("Invalid private key path")
	}
	sign, err := GenerateSignature([]byte(bPrivKey), content)
	if err != nil {
		return "", errors.New("Generate signature error")
	}
	return sign, nil
}
