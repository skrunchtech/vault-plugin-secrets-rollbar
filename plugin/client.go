package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	hostURL = "https://api.rollbar.com/api/1"
)

type rollbarClient struct {
	client             *http.Client
	hostURL            string
	accountAccessToken string
}

func NewClient(config *RollbarConfig) (*rollbarClient, error) {
	if config == nil {
		return nil, errors.New("client configuration is nil")
	}

	if len(config.AccountAccessToken) == 0 {
		return nil, errors.New("client account access token is not defined")
	}

	return &rollbarClient{
		client:             &http.Client{Timeout: 10 * time.Second},
		hostURL:            hostURL,
		accountAccessToken: config.AccountAccessToken,
	}, nil
}

func (c *rollbarClient) DoRequest(req *http.Request) ([]byte, error) {
	req.Header.Set("X-Rollbar-Access-Token", c.accountAccessToken)

	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %d, body: %s", res.StatusCode, body)
	}

	return body, err
}

func (r *rollbarClient) deleteProjectAccessToken(ctx context.Context, projectID int, pat string) error {
	url := fmt.Sprintf("%s/project/%d/access_token/%s", r.hostURL, projectID, pat)

	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Add("accept", "application/json")

	_, err := r.DoRequest(req)
	if err != nil {
		return err
	}

	return nil
}

func (r *rollbarClient) CreateProjectAccessToken(ctx context.Context, scopes string, projectID int, name string) (*string, error) {

	url := fmt.Sprintf("%s/project/%d/access_tokens", r.hostURL, projectID)
	payload := strings.NewReader("{\"status\":\"enabled\",\"scopes\":[\"" + scopes + "\"],\"name\":\"" + name + "\"}")

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Add("accept", "application/json")
	req.Header.Add("content-type", "application/json")

	resp := struct {
		Result struct {
			AccessToken string `json:"access_token"`
		} `json:"result"`
	}{}

	body, err := r.DoRequest(req)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	return &(resp.Result.AccessToken), nil
}
