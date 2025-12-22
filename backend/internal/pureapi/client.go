package pureapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	baseURL     string
	internalURL string
	apiKey      string
	hc          *http.Client
}

type Error struct {
	Status  int
	Message string
	Detail  any
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("pure-api error (%d)", e.Status)
}

// NewClient(baseURL, apiKey [, internalURL])
// - baseURL: e.g. https://pure-api-xxx.onrender.com
// - internalURL (optional): e.g. http://pure-api:8080 (docker network) OR another base
func NewClient(baseURL, apiKey string, internalURL ...string) *Client {
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		hc: &http.Client{
			Timeout: 25 * time.Second,
		},
	}
	if len(internalURL) > 0 {
		c.internalURL = strings.TrimRight(internalURL[0], "/")
	}
	return c
}

func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.request(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) Post(ctx context.Context, path string, body any, out any) error {
	return c.request(ctx, http.MethodPost, path, body, out)
}

func (c *Client) Put(ctx context.Context, path string, body any, out any) error {
	return c.request(ctx, http.MethodPut, path, body, out)
}

func (c *Client) Delete(ctx context.Context, path string, body any, out any) error {
	return c.request(ctx, http.MethodDelete, path, body, out)
}

func (c *Client) candidates() []string {
	var list []string
	// try internal first (docker / private route), then public base
	if strings.TrimSpace(c.internalURL) != "" {
		list = append(list, c.internalURL)
	}
	if strings.TrimSpace(c.baseURL) != "" {
		list = append(list, c.baseURL)
	}
	return list
}

func (c *Client) request(ctx context.Context, method, path string, body any, out any) error {
	path = normalizePath(path)

	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}

	maxAttempts := 3
	var lastErr error

	bases := c.candidates()
	if len(bases) == 0 {
		return errors.New("pure-api base url is empty")
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		for _, base := range bases {
			url := base + path
			var reqBody io.Reader
			if payload != nil {
				reqBody = bytes.NewReader(payload)
			}

			req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
			if err != nil {
				lastErr = err
				continue
			}
			req.Header.Set("accept", "application/json")
			if payload != nil {
				req.Header.Set("content-type", "application/json")
			}
			if c.apiKey != "" {
				req.Header.Set("x-api-key", c.apiKey)
			}

			resp, err := c.hc.Do(req)
			if err != nil {
				lastErr = err
				if isTransientNetErr(err) && attempt < maxAttempts {
					time.Sleep(backoff(attempt))
					continue
				}
				continue
			}

			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				// retry transient statuses
				if (resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 || resp.StatusCode == 429) && attempt < maxAttempts {
					lastErr = &Error{Status: resp.StatusCode, Message: "Pure API temporary error"}
					time.Sleep(backoff(attempt))
					continue
				}

				var j any
				_ = json.Unmarshal(b, &j)
				msg := extractMessage(j)
				if msg == "" {
					msg = fmt.Sprintf("Pure API error (%d)", resp.StatusCode)
				}
				return &Error{Status: resp.StatusCode, Message: msg, Detail: j}
			}

			if out == nil {
				return nil
			}
			if len(b) == 0 {
				return nil
			}

			// treat "null" as success for void-ish endpoints
			trim := strings.TrimSpace(string(b))
			if trim == "null" || trim == "" {
				return nil
			}

			if err := json.Unmarshal(b, out); err != nil {
				return err
			}
			return nil
		}

		if attempt < maxAttempts {
			time.Sleep(backoff(attempt))
		}
	}

	if lastErr != nil {
		return lastErr
	}
	return errors.New("unknown pure-api error")
}

func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

func backoff(attempt int) time.Duration {
	// 1.2s, 2.4s
	base := 1200 * time.Millisecond
	return base * time.Duration(1<<uint(attempt-1))
}

func isTransientNetErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout() || ne.Temporary()
	}
	return false
}

func extractMessage(j any) string {
	// supports shapes like {error:{message}} or {message} or {error}
	m, ok := j.(map[string]any)
	if !ok {
		return ""
	}
	if msg, _ := m["message"].(string); msg != "" {
		return msg
	}
	if e, ok := m["error"].(map[string]any); ok {
		if msg, _ := e["message"].(string); msg != "" {
			return msg
		}
	}
	if s, _ := m["error"].(string); s != "" {
		return s
	}
	return ""
}
