package security

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// NVDResponse represents the response from NVD API 2.0
type NVDResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID               string `json:"id"`
			SourceIdentifier string `json:"sourceIdentifier"`
			Published        string `json:"published"`
			LastModified     string `json:"lastModified"`
			VulnStatus       string `json:"vulnStatus"`
			Descriptions     []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type CVEClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewCVEClient() *CVEClient {
	return &CVEClient{
		BaseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *CVEClient) SearchByKeyword(keyword string) (*NVDResponse, error) {
	url := fmt.Sprintf("%s?keywordSearch=%s", c.BaseURL, keyword)

	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status: %d", resp.StatusCode)
	}

	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, err
	}

	return &nvdResp, nil
}

func (c *CVEClient) GetCVEByID(cveID string) (*NVDResponse, error) {
	url := fmt.Sprintf("%s?cveId=%s", c.BaseURL, cveID)

	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status: %d", resp.StatusCode)
	}

	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, err
	}

	return &nvdResp, nil
}
