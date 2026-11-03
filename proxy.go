package oscore

import (
	"errors"
	"net/url"
	"strings"
)

var errProxyURI = errors.New("oscore: invalid Proxy-Uri")

// splitProxyURI splits a Proxy-Uri value (RFC 8613, Section 4.1.3.3) into
// the Outer Proxy-Uri, made of the scheme and authority, and the Inner
// Uri-Path and Uri-Query options (RFC 7252, Section 6.4).
func splitProxyURI(s string) (string, []Option, error) {
	u, err := url.Parse(s)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return "", nil, errProxyURI
	}
	var opts []Option
	if p := u.EscapedPath(); p != "" && p != "/" {
		for seg := range strings.SplitSeq(strings.TrimPrefix(p, "/"), "/") {
			v, err := url.PathUnescape(seg)
			if err != nil {
				return "", nil, errProxyURI
			}
			opts = append(opts, Option{Number: URIPath, Value: []byte(v)})
		}
	}
	if u.RawQuery != "" {
		for arg := range strings.SplitSeq(u.RawQuery, "&") {
			v, err := url.PathUnescape(arg)
			if err != nil {
				return "", nil, errProxyURI
			}
			opts = append(opts, Option{Number: URIQuery, Value: []byte(v)})
		}
	}
	return u.Scheme + "://" + u.Host, opts, nil
}
