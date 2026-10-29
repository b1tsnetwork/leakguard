package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// Das Kennwort wird vollständig gespeichert – verschlüsselt mit AES-256-GCM.
// Der Schlüssel wird aus "secret" abgeleitet: Ohne config.yaml/LEAKGUARD_SECRET ist die
// Datenbank allein (Backup, Kopie) wertlos. Wird secret geändert, sind alte Kennwörter nicht mehr lesbar.
func (e *Engine) key() []byte {
	k := sha256.Sum256([]byte("leakguard/password-encryption/v1\x00" + e.cfg.Secret))
	return k[:]
}

func (e *Engine) EncryptPassword(pw string) (string, error) {
	block, err := aes.NewCipher(e.key())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return "v1:" + base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(pw), nil)), nil
}

func (e *Engine) DecryptPassword(enc string) (string, error) {
	if enc == "" {
		return "", errors.New("kein kennwort gespeichert")
	}
	if len(enc) < 3 || enc[:3] != "v1:" {
		return "", errors.New("unbekanntes format")
	}
	raw, err := base64.StdEncoding.DecodeString(enc[3:])
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(e.key())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("daten zu kurz")
	}
	pt, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", errors.New("entschlüsselung fehlgeschlagen (secret geändert?)")
	}
	return string(pt), nil
}
