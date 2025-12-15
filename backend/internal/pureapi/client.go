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
  baseURL string
  apiKey  string
  http    *http.Client
}

func NewClient(baseURL, apiKey string) *Client {
  baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
  return &Client{
    baseURL: baseURL,
    apiKey:  strings.TrimSpace(apiKey),
    http: &http.Client{
      Timeout: 25 * time.Second,
      Transport: &http.Transport{
        Proxy: http.ProxyFromEnvironment,
        DialContext: (&net.Dialer{
          Timeout:   10 * time.Second,
          KeepAlive: 30 * time.Second,
        }).DialContext,
        TLSHandshakeTimeout: 10 * time.Second,
        MaxIdleConns:        100,
        IdleConnTimeout:     90 * time.Second,
      },
    },
  }
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

func (c *Client) Get(ctx context.Context, path string, out any) error {
  return c.request(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) Post(ctx context.Context, path string, body any, out any) error {
  return c.request(ctx, http.MethodPost, path, body, out)
}

func (c *Client) request(ctx context.Context, method, path string, body any, out any) error {
  if c.baseURL == "" {
    return &Error{Status: 500, Message: "PURE_API_BASE_URL is not set"}
  }
  if c.apiKey == "" {
    return &Error{Status: 500, Message: "PURE_API_KEY is not set"}
  }

  url := c.baseURL + "/" + strings.TrimLeft(path, "/")

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

  for attempt := 1; attempt <= maxAttempts; attempt++ {
    var reqBody io.Reader
    if payload != nil {
      reqBody = bytes.NewReader(payload)
    }

    req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
    if err != nil {
      return err
    }
    req.Header.Set("x-api-key", c.apiKey)
    if payload != nil {
      req.Header.Set("content-type", "application/json")
    }

    resp, err := c.http.Do(req)
    if err != nil {
      lastErr = err
      if isTransientNetErr(err) && attempt < maxAttempts {
        time.Sleep(backoff(attempt))
        continue
      }
      if isTransientNetErr(err) {
        return &Error{Status: 503, Message: "Pure API is waking up. Please try again in a moment."}
      }
      return err
    }

    b, _ := io.ReadAll(resp.Body)
    _ = resp.Body.Close()

    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
      // retry transient statuses
      if (resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504) && attempt < maxAttempts {
        lastErr = &Error{Status: resp.StatusCode, Message: "Pure API temporary error"}
        time.Sleep(backoff(attempt))
        continue
      }

      // best-effort parse json
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

    if err := json.Unmarshal(b, out); err != nil {
      return err
    }
    return nil
  }

  if lastErr != nil {
    return lastErr
  }
  return errors.New("unknown pure-api error")
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
  if errors.As(err, &ne) && (ne.Timeout() || ne.Temporary()) {
    return true
  }
  msg := strings.ToLower(err.Error())
  if strings.Contains(msg, "connection refused") || strings.Contains(msg, "connection reset") || strings.Contains(msg, "no such host") {
    return true
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
