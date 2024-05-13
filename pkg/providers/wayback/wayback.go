package wayback

import (
	"context"
	"fmt"
	jsoniter "github.com/json-iterator/go"
	"github.com/lc/gau/v2/pkg/httpclient"
	"github.com/lc/gau/v2/pkg/providers"
	"github.com/sirupsen/logrus"
)

const (
	Name = "wayback"
)

var _ providers.Provider = (*Client)(nil)

type Client struct {
	filters providers.Filters
	config  *providers.Config
}

func New(config *providers.Config, filters providers.Filters) *Client {
	return &Client{filters, config}
}

func (c *Client) Name() string {
	return Name
}

// Updated waybackResult to match expected 2D array structure
type waybackResult [][]string

func (c *Client) Fetch(ctx context.Context, domain string, results chan string) error {
	apiURL := c.formatURL(domain)
	logrus.WithFields(logrus.Fields{"provider": Name}).Infof("fetching %s", domain)
	resp, err := httpclient.MakeRequest(c.config.Client, apiURL, c.config.MaxRetries, c.config.Timeout)
	if err != nil {
		return fmt.Errorf("failed to fetch wayback results: %s", err)
	}

	var result waybackResult
	if err = jsoniter.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("failed to decode wayback results: %s", err)
	}

	if len(result) == 0 {
		return nil
	}

	for _, entry := range result {
		if len(entry) > 0 {
			results <- entry[0]
		}
	}
	return nil
}

func (c *Client) formatURL(domain string) string {
	if c.config.IncludeSubdomains {
		domain = "*." + domain
	}
	filterParams := c.filters.GetParameters(true)
	return fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&collapse=urlkey&fl=original",
		domain,
	) + filterParams
}
