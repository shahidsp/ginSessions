package ginSessions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Vault is a directory containing multiple sessions where each session is
// represented as a subdirectory. Each session directory has multiple cookie
// files which are encrypted by a Vault. Sessions and cookies cannot be accessed
// directly and instead must be requested from a Vault.
// A default 32-bit key is generated unless one is provided by NewVault
type Vault struct {
	path      string
	key       string
	sessions  []string
	encrypter cipher.AEAD
	nonce     []byte
	perm      int
}

// A session represents a client-server session and is stored as a directory
// under an associated Vault. Each session directory stores the cookies
// associated with a session as a file that is encrypted by the Vault storing the
// session. Each session directory has an associated config file stating
// when the session was started and when it should be deleted. By default, any
// session that has not been accessed in 90 days will be deleted. Each cookie
// associated with a session can still have its own expiration which is checked
// by the Vault when requesting the cookie. If a cookie is expired, the Vault
// will delete the cookie and will not return the cookie when requested
type session struct {
	id      string
	cookies map[string]string
}

// NewVault instantiates a new Vault with the provided path and key. If no path
// is provided, the Vault path will default to the current working directory. If
// no key is provided, a random 32-byte will be generated and used. The key used
// by the vault is stored in the .vault_config.json file generated in the root
// directory of the Vault along with the nonce used for AES encryption. Interval
// sets the interval between cleanup cycles. A value of 0 will default to 30
// minutes, and a value less than 0 deactivates the cleanup cycle
func NewVault(path, key string, perms int, interval time.Duration) (*Vault, error) {
	if path == "" {
		path = "vault/"
	}

	if len([]byte(key)) > 32 {
		return nil, errors.New("key too long")
	}

	var keyBytes, nonce []byte

	var config struct {
		Key   string `json:"key"`
		Nonce string `json:"nonce"`
	}

	if _, err := os.ReadDir(path); errors.Is(err, os.ErrNotExist) {
		err = os.Mkdir(path, os.FileMode(perms))
		if err != nil {
			return nil, err
		}
	}

	configFile, err := os.Open(path + "/.config.json")
	if errors.Is(err, os.ErrNotExist) {
		configFile, err = os.Create(path + "/.config.json")
		if err != nil {
			return nil, err
		}

		nonce = make([]byte, 12)
		_, err = rand.Read(nonce)
		if err != nil {
			return nil, err
		}

		keyBytes, err = pad([]byte(key))
		if err != nil {
			return nil, err
		}

		config.Key = hex.EncodeToString(keyBytes)
		config.Nonce = hex.EncodeToString(nonce)
		if err = json.NewEncoder(configFile).Encode(config); err != nil {
			return nil, err
		}

	} else if err != nil {
		return nil, err
	} else {
		err = json.NewDecoder(configFile).Decode(&config)
		if err != nil {
			return nil, err
		}
		nonce, err = hex.DecodeString(config.Nonce)
		if err != nil {
			return nil, err
		}
		keyBytes, err = hex.DecodeString(config.Key)
		if err != nil {
			return nil, err
		}
	}

	defer configFile.Close()

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	v := &Vault{
		path:     path,
		key:      key,
		sessions: []string{},
		perm:     perms,
		nonce:    nonce,
	}

	v.encrypter, err = cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if _, err = rand.Read(v.nonce); err != nil {
		return nil, err
	}

	dirs, _ := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		err = os.Mkdir(path, 0700)
		if err != nil {
			return nil, err
		}
		dirs, _ = os.ReadDir(path)
	} else if err != nil {
		return nil, err
	} else {
		for _, d := range dirs {
			if d.IsDir() {
				v.sessions = append(v.sessions, d.Name())
			}
		}
	}
	if interval >= time.Duration(0) {
		go v.cleanup(interval)
	}
	return v, nil
}

// NewSession creates a new session directory under the associated Vault
// directory. The id returned should be given to the client and is used to
// request cookies associated with the session. NewSession accepts an expiration
// time as a unix timestamp. If a value of 0 is passed,
// the expiration of the session defaults to 3 months. If a negative value is
// passed, ErrInvalidExpiration is returned.
func (v *Vault) NewSession(expires int64) (id string, err error) {
	if expires < 0 {
		return "", ErrInvalidExpiration{}
	}
	if expires == 0 {
		expires = time.Now().Add(time.Duration(int(7.884e+6)) * time.Second).Unix()
	}

	id = strings.Join(strings.Split(uuid.Must(uuid.NewRandom()).String(), "-"), "")
	var config = struct {
		ID      string `json:"id"`
		Expires int64  `json:"expires"`
	}{
		ID:      id,
		Expires: expires,
	}
	configPath := fmt.Sprintf("%s/%s//.config.json", v.path, id)
	if err = os.Mkdir(fmt.Sprintf("%s/%s", v.path, id), os.FileMode(v.perm)); errors.Is(err, os.ErrExist) {
		return "", err
	}
	configFile, err := os.OpenFile(configPath, os.O_RDWR|os.O_CREATE, os.FileMode(v.perm))
	if err != nil {

		return "", err
	}
	defer configFile.Close()
	err = json.NewEncoder(configFile).Encode(config)
	if err != nil {
		return "", err
	}

	v.sessions = append(v.sessions, id)
	return id, nil
}

// GetSession will return all cookies associated with a session as a slice of
// *http.Cookie. If a cookie has expired, GetSession will delete the cookie
// before returning the slice. If the session does not exist, GetSession will
// return an empty slice and an ErrSessionNotFound error. If no cookies are
// found, an empty slice will be returned without an error
func (v *Vault) GetSession(id string) ([]*http.Cookie, error) {
	if !slices.Contains(v.sessions, id) {
		return nil, ErrSessionNotFound{}
	}
	dirPath := filepath.Join(v.path, id)
	dir, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}
	var cookies []*http.Cookie
	for _, entry := range dir {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		file, err := os.Open(filepath.Join(dirPath, entry.Name()))
		if err != nil {
			continue
		}
		secret, err := io.ReadAll(file)
		if err != nil {
			continue
		}
		data, err := v.encrypter.Open(nil, nil, secret, nil)
		if err != nil {
			continue
		}
		cookie := http.Cookie{}
		if err = json.Unmarshal(data, &cookie); err != nil {
			continue
		}

		if cookie.Expires.Before(time.Now()) {
			continue
		}

		cookies = append(cookies, &cookie)
	}

	return cookies, nil
}

// DeleteSession deletes a requested session. It will not return an error if a
// session is not found. Any remaining cookies belonging to the session will be
// lost.
func (v *Vault) DeleteSession(id string) {
	dirPath := filepath.Join(v.path, id)
	os.RemoveAll(dirPath)
}

// SetCookie writes the given *http.Cookie to a file. If overwrite is true,
// SetCookie will delete any existing cookies with the same name before writing
// the new *http.Cookie. If overwrite is false, SetCookie will return an
// ErrDuplicateCookie error. If the session does not exist, SetCookie will return
// an ErrSessionNotFound error. If no expiration is specified in the
// *http.Cookie, SetCookie will set it to the session's expiration as defined
// when the session was created. SetCookie will still register the cookie even if
// the expiration is before time.Now(). Expirations are checked when GetCookie is
// called.
func (v *Vault) SetCookie(session string, cookie *http.Cookie, overwrite bool) (cookieID string, err error) {
	if cookie == nil {
		return "", ErrCookieIsNil{}
	}

	if (cookie.Expires == time.Time{}) {
		configFilePath := filepath.Join(v.path, session, ".config.json")
		configFile, err := os.Open(configFilePath)
		if err != nil {
			return "", err
		}
		defer configFile.Close()
		var config struct {
			ID      string `json:"id"`
			Expires int    `json:"expires"`
		}
		if err = json.NewDecoder(configFile).Decode(&config); err != nil {
			return "", err
		}
		duration := time.Duration(config.Expires) * time.Second
		cookie.Expires = time.Now().Add(duration)
	}

	data, err := json.Marshal(cookie)
	if err != nil {
		return "", err
	}

	fileName := sha256.Sum256(data)
	filePath := fmt.Sprintf("%s/%s/%s", v.path, session, hex.EncodeToString(fileName[:]))
	secret := v.encrypter.Seal(nil, v.nonce, data, nil)
	var file *os.File
	if overwrite {
		_ = os.Remove(filePath)
	} else {
		if _, err = os.Open(filePath); err == nil {
			return "", ErrDuplicateCookie{}
		}
	}
	file, err = os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, os.FileMode(v.perm))
	if err != nil {
		return "", err
	}

	defer file.Close()
	if _, err = file.Write(secret); err != nil {
		return "", err
	}

	return hex.EncodeToString(fileName[:]), nil
}

// GetCookie returns the *http.Cookie requested. GetCookie can return a
// ErrSessionNotFound or a ErrCookieNotFound error. If the cookie requested is expired,
// an ErrExpiredCookie error will be returned
func (v *Vault) GetCookie(session, cookieID string) (*http.Cookie, error) {
	if cookieID == "" {
		return nil, ErrCookieIsNil{}
	}

	if !slices.Contains(v.sessions, session) {
		return nil, ErrSessionNotFound{}
	}

	filePath := filepath.Join(v.path, session, cookieID)
	file, err := os.OpenFile(filePath, os.O_RDONLY, os.FileMode(v.perm))
	if err != nil {
		return nil, ErrCookieNotFound{}
	}
	defer file.Close()
	secret, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	data, err := v.encrypter.Open(nil, v.nonce, secret, nil)
	if err != nil {
		return nil, err
	}
	cookie := &http.Cookie{}
	if err = json.Unmarshal(data, cookie); err != nil {
		return nil, err
	}

	if cookie.Expires.Before(time.Now()) {
		return nil, ErrExpiredCookie{}
	}

	return cookie, nil
}

// DeleteCookie deletes a requested cookie. It will not return ErrCookieNotFound
// if the cookie does not exist. It will return ErrSessionNotFound if the session
// does not exist
func (v *Vault) DeleteCookie(session, cookieID string) error {
	if cookieID == "" {
		return ErrCookieIsNil{}
	}
	if !slices.Contains(v.sessions, session) {
		return ErrSessionNotFound{}
	}

	filePath := filepath.Join(v.path, session, cookieID)
	os.Remove(filePath)
	return nil
}

// pad takes any []byte src and returns a 32-byte slice. If src is less than
// 32-bytes, the remaining bytes are random. If src is greater than 32, it is
// truncated and returned
func pad(src []byte) ([]byte, error) {
	if len(src) > 32 {
		return src[:32], nil
	}

	neededPadding := 32 - len(src)
	paddedKey := make([]byte, neededPadding)
	_, err := rand.Read(paddedKey)
	if err != nil {
		return nil, err
	}
	return append(paddedKey, src...), nil
}

// Cleanup is called as a go routine during NewVault and takes a time.Duration as
// a parameter. If interval is less than 1, interval defaults to 30 minutes
func (v *Vault) cleanup(interval time.Duration) {
	if interval <= time.Duration(0) {
		interval = 30 * time.Minute
	}

	var (
		configFile, secretFile *os.File
		err                    error
	)

	defer configFile.Close()
	defer secretFile.Close()
	time.Sleep(interval)
	for _, session := range v.sessions {
		sessionPath := filepath.Join(v.path, session)
		var config = struct {
			ID      string `json:"id"`
			Expires int64  `json:"expires"`
		}{}
		configFile, err = os.Open(sessionPath + ".config.json")
		if err != nil {
			continue
		}
		err = json.NewDecoder(configFile).Decode(&config)
		if err != nil {
			continue
		}
		if time.Now().After(time.Unix(config.Expires, 0)) {
			_ = os.RemoveAll(sessionPath)
			continue
		}
		entries, err := os.ReadDir(sessionPath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.Name() == ".config.json" {
				continue
			}
			secretFilePath := filepath.Join(sessionPath, entry.Name())
			secretFile, err = os.Open(secretFilePath)
			if err != nil {
				continue
			}
			var secret []byte
			secret, err = io.ReadAll(secretFile)
			if err != nil {
				continue
			}
			data, err := v.encrypter.Open(nil, v.nonce, secret, nil)
			if err != nil {
				continue
			}
			cookie := http.Cookie{}
			if err = json.Unmarshal(data, &cookie); err != nil {
				continue
			}
			if cookie.Expires.Before(time.Now()) {
				_ = os.RemoveAll(secretFilePath)
			}
		}
	}
}
