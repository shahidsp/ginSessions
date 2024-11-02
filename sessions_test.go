package ginSessions

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"
)

var (
	dummyKey  = "shbsahvdhfafsdbasdfjbahdsf"
	dummyPath = "dummyPath"
)

func TestNewVault(t *testing.T) {
	t.Cleanup(func() {
		os.RemoveAll(dummyPath)
		os.RemoveAll("vault")
	})
	type args struct {
		path string
		key  string
	}
	tests := []struct {
		name string
		args args
	}{
		{name: "no params", args: args{
			path: "",
			key:  "",
		}},

		{
			name: "key only", args: args{
				path: "",
				key:  dummyKey,
			}},

		{
			name: "path only", args: args{
				path: dummyPath,
				key:  "",
			}},

		{
			name: "all params", args: args{
				path: dummyPath,
				key:  dummyKey,
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewVault(tt.args.path, tt.args.key, 0777, -1)
			if err != nil {
				t.Error(err)
			}
			if tt.args.key != "" {
				if v.key != tt.args.key {
					t.Log("key does not match")
					t.Fail()
				}
			}

			if tt.args.path != "" {
				if v.path != tt.args.path {
					t.Log("path does not match")
					t.Fail()
				}
			}

		})
	}
}

func TestVault_NewSession(t *testing.T) {
	t.Cleanup(func() {
		os.RemoveAll(dummyPath)
	})
	tests := []struct {
		name          string
		expires       int64
		expectedError error
	}{
		{
			name:          "default",
			expires:       0,
			expectedError: nil,
		},
		{
			name:          "1 month",
			expires:       time.Now().Add(time.Hour * 24 * 30).Unix(),
			expectedError: nil,
		},
		{
			name:          "1 year",
			expires:       time.Now().Add(time.Hour * 24 * 30 * 12).Unix(),
			expectedError: nil,
		},
		{
			name:          "Expired",
			expires:       -1,
			expectedError: ErrInvalidExpiration{},
		},
	}
	v, err := NewVault(dummyPath, dummyKey, 0777, -1)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := v.NewSession(tt.expires)
			if !errors.Is(err, tt.expectedError) {
				t.Errorf("NewSession() error = %v, wantErr %v", err, tt.expectedError)
				return
			}

			if tt.expires < 0 {
				return
			}

			if tt.expires == 0 {
				tt.expires = time.Now().Add(time.Duration(int(7.884e+6)) * time.Second).Unix()
			}

			f, err := os.Open(dummyPath + "/" + id + "/.config.json")
			if err != nil {
				t.Error(err)
				return
			}
			defer f.Close()
			config := struct {
				ID      string `json:"id"`
				Expires int64  `json:"expires"`
			}{}
			if err = json.NewDecoder(f).Decode(&config); err != nil {
				t.Error(err)
				return
			}

			if config.Expires != tt.expires {
				t.Errorf("config.Expires  = %d, want %d", config.Expires, tt.expires)
			}

			if !slices.Contains(v.sessions, id) {
				t.Errorf("v.sessions does not contains session %v", v.sessions)
			}
		})
	}
}

func TestVault_SetCookie(t *testing.T) {
	t.Cleanup(func() {
		os.RemoveAll(dummyPath)
	})
	type args struct {
		cookie        *http.Cookie
		expectedError error
		overwrite     bool
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Empty Cookie",
			args: args{
				cookie:        &http.Cookie{},
				expectedError: nil,
				overwrite:     true,
			},
		},
		{
			name: "Cookie 1",
			args: args{
				cookie: &http.Cookie{
					Name:  "My cookie",
					Value: "The Best Cookie",
				},
				expectedError: nil,
				overwrite:     true,
			},
		},
		{
			name: "Cookie 2",
			args: args{
				cookie: &http.Cookie{
					Name:  "Your cookie",
					Value: "The Worst Cookie",
				},
				expectedError: nil,
				overwrite:     true,
			},
		},
		{
			name: "Nil cookie",
			args: args{
				cookie:        nil,
				expectedError: ErrCookieIsNil{},
				overwrite:     true,
			},
		},
		{
			name: "Duplicate Cookie",
			args: args{
				cookie:        &http.Cookie{},
				expectedError: ErrDuplicateCookie{},
				overwrite:     false,
			},
		},
	}

	v, err := NewVault(dummyPath, dummyKey, 0777, -1)
	if err != nil {
		t.Fatal(err)
	}

	sessionID, err := v.NewSession(0)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if errors.Is(tt.args.expectedError, ErrDuplicateCookie{}) {
				if _, err := v.SetCookie(sessionID, tt.args.cookie, tt.args.overwrite); err != nil {
					t.Fatalf(err.Error())
				}
			}

			_, err = v.SetCookie(sessionID, tt.args.cookie, tt.args.overwrite)
			if !errors.Is(err, tt.args.expectedError) {
				t.Fatalf("SetCookie() error = %v, wantErr %v", err, tt.args.expectedError)
			}
			if tt.args.expectedError != nil {
				return
			}

			data, err := json.Marshal(tt.args.cookie)
			if err != nil {
				t.Fatal(err)
			}
			fileName := sha256.Sum256(data)
			fileNameString := hex.EncodeToString(fileName[:])
			files, err := os.ReadDir(dummyPath + "/" + sessionID)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, file := range files {
				if fileNameString == file.Name() {
					found = true
				}
			}

			if !found {
				t.Logf("file %s not found", fileName)
				t.Fail()
			}
		})
	}

}

func TestVault_GetCookie(t *testing.T) {
	t.Cleanup(func() {
		os.RemoveAll(dummyPath)
	})

	v, err := NewVault(dummyPath, dummyKey, 0777, -1)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := v.NewSession(0)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		cookie        *http.Cookie
		expectedError error
		cookieID      string
		sessionID     string
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "Empty Cookie",
			args: args{
				cookie: &http.Cookie{
					Name:  "empty",
					Value: "empty",
				},
				expectedError: nil,
			},
		},
		{
			name: "Cookie 1",
			args: args{
				cookie: &http.Cookie{
					Name:  "cookie1",
					Value: "cookie1",
				},
				expectedError: nil,
			},
		},
		{
			name: "Cookie 2",
			args: args{
				cookie: &http.Cookie{
					Name:  "cookie2",
					Value: "cookie2",
				},
				expectedError: nil,
			},
		},
		{
			name: "Nil cookieString",
			args: args{
				cookie: &http.Cookie{
					Name:  "nil_cookie_string",
					Value: "nil_cookie_string",
				},
				expectedError: ErrCookieIsNil{},
				cookieID:      "",
			},
		},
		{
			name: "Nil sessionString",
			args: args{
				cookie: &http.Cookie{
					Name:  "nil_session_string",
					Value: "nil_session_string",
				},
				expectedError: ErrSessionNotFound{},
				sessionID:     "",
			},
		},
		{
			name: "Bad session ID",
			args: args{
				cookie: &http.Cookie{
					Name:  "bad_session_id",
					Value: "bad_session_id",
				},
				expectedError: ErrSessionNotFound{},
				sessionID:     "MySession",
			},
		},
		{
			name: "Bad Cookie ID",
			args: args{
				cookie: &http.Cookie{
					Name:  "bad_cookie_id",
					Value: "bad_cookie_id",
				},
				expectedError: ErrCookieNotFound{},
				cookieID:      "bad cookie",
			},
		},
		{
			name: "Expired Cookie",
			args: args{
				cookie: &http.Cookie{
					Name:    "expired_cookie",
					Value:   "expired_cookie",
					Expires: time.Date(2000, time.January, 18, 0, 0, 0, 0, time.UTC),
				},
				expectedError: ErrExpiredCookie{},
			},
		},
	}
	for _, tt := range tests {
		if tt.name != "Nil sessionString" && tt.name != "Bad session ID" {
			tt.args.sessionID = sessionID
		}

		t.Run(tt.name, func(t *testing.T) {

			cookieID, err := v.SetCookie(sessionID, tt.args.cookie, true)

			if err != nil {
				t.Errorf("Unexpected err setting cookie: %v", err)
				return
			}

			if tt.name != "Bad Cookie ID" && tt.name != "Nil cookieString" {
				tt.args.cookieID = cookieID
			}
			result, err := v.GetCookie(tt.args.sessionID, tt.args.cookieID)

			if !errors.Is(err, tt.args.expectedError) {
				t.Errorf("GetCookie() error = %v, wantErr %v", err, tt.args.expectedError)
				return
			}
			if tt.args.expectedError != nil {
				return
			}
			if !sameCookie(result, tt.args.cookie) {
				t.Errorf("GetCookie() result : \n\t%v, \nwant: \n\t%v", result, tt.args.cookie)
			}

		})
	}
}

func TestPad(t *testing.T) {
	type args struct {
		src []byte
	}
	type test struct {
		name string
		args args
	}

	var tests []test

	s := make([][]byte, 5)
	for _, slice := range s {
		length := mrand.Intn(32)
		slice = make([]byte, length)
		_, err := rand.Read(slice)
		if err != nil {
			t.Fatal(err)
		}

		test := test{
			name: fmt.Sprintf("Slice Length: %v", length),
			args: args{
				src: slice,
			},
		}
		tests = append(tests, test)
	}

	negative := make([]byte, 40)
	_, err := rand.Read(negative)
	if err != nil {
		t.Fatal(err)
	}

	tests = append(tests, test{
		name: "Large Slice",
		args: args{
			src: negative,
		},
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst, err := pad(tt.args.src)
			if err != nil {
				t.Error(err)
			}

			if len(dst) != 32 {
				t.Fail()
			}
		})
	}

}

func sameCookie(c1, c2 *http.Cookie) bool {
	if c1 == nil || c2 == nil {
		return false
	}
	names := c1.Name == c2.Name
	values := c1.Value == c2.Value
	paths := c1.Path == c2.Path
	domains := c1.Domain == c2.Domain
	secure := c1.Secure == c2.Secure
	httpOnly := c1.HttpOnly == c2.HttpOnly
	sameSite := c1.SameSite == c2.SameSite

	return names && values && paths && domains && secure && httpOnly && sameSite
}
