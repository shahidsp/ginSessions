package ginSessions

type ErrSessionNotFound struct{}

func (e ErrSessionNotFound) Error() string {
	return "session not found"
}

type ErrDuplicateCookie struct{}

func (e ErrDuplicateCookie) Error() string {
	return "duplicate cookie"
}

type ErrCookieNotFound struct{}

func (e ErrCookieNotFound) Error() string {
	return "cookie not found"
}

type ErrExpiredCookie struct{}

func (e ErrExpiredCookie) Error() string {
	return "expired cookie"
}

type ErrInvalidExpiration struct{}

func (e ErrInvalidExpiration) Error() string {
	return "invalid expiration"
}

type ErrCookieIsNil struct{}

func (e ErrCookieIsNil) Error() string {
	return "cookie is nil"
}
