// Package hibp fragt die Pwned-Passwords-API per k-Anonymität ab.
// Es werden nur die ersten 5 Zeichen des SHA-1-Hashes übertragen, niemals das Kennwort.
package hibp

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // von der API vorgegeben
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	url  string
	http *http.Client
}

func New(url string, timeout time.Duration) *Client {
	return &Client{url: url, http: &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}}
}

// Count liefert, wie oft das Kennwort in bekannten Leaks vorkommt.
func (c *Client) Count(ctx context.Context, pw string) (int, error) {
	sum := sha1.Sum([]byte(pw)) //nolint:gosec
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := h[:5], h[5:]
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+prefix, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "LeakGuard")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("pwned passwords: http %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		s, cnt, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(s, suffix) {
			n, _ := strconv.Atoi(cnt)
			return n, nil
		}
	}
	return 0, sc.Err()
}
