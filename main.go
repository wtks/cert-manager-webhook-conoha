package main

import (
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/tidwall/gjson"
	"k8s.io/client-go/rest"
	"os"
	"strings"
	"sync"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
)

var (
	GroupName = os.Getenv("GROUP_NAME")

	Region   = getEnvOrDefault("CONOHA_REGION", "tyo1")
	TenantID = getEnvOrDefault("CONOHA_TENANT_ID", "")
	Username = getEnvOrDefault("CONOHA_USERNAME", "")
	Password = getEnvOrDefault("CONOHA_PASSWORD", "")
)

type Hash map[string]interface{}

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&conohaDNSProviderSolver{},
	)
}

type entry struct {
	domainID string
	recordID string
}

type conohaDNSProviderSolver struct {
	entries     map[string]entry
	entriesLock sync.Mutex
}

func (c *conohaDNSProviderSolver) Name() string {
	return "conoha"
}

func (c *conohaDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	client, err := getClient()
	if err != nil {
		return err
	}

	r, err := client.R().Get("/v1/domains")
	if err != nil {
		return err
	}
	if !r.IsSuccess() {
		return fmt.Errorf("GetDomainList StatusCode: %d", r.StatusCode())
	}
	domainID := gjson.Get(r.String(), fmt.Sprintf(`domains.#(name=="%s").id`, strings.SplitN(ch.ResolvedFQDN, ".", 2)[1])).String()
	if domainID == "" {
		return fmt.Errorf("domain not found")
	}

	r, err = client.R().
		SetPathParam("domainID", domainID).
		SetBody(Hash{
			"name": ch.ResolvedFQDN,
			"type": "TXT",
			"data": ch.Key,
			"ttl":  60,
		}).
		Post("/v1/domains/{domainID}/records")
	if err != nil {
		return err
	}
	if !r.IsSuccess() {
		return fmt.Errorf("CreateRecord StatusCode: %d", r.StatusCode())
	}

	c.entriesLock.Lock()
	c.entries[string(ch.UID)] = entry{
		domainID: domainID,
		recordID: gjson.Get(r.String(), "id").String(),
	}
	c.entriesLock.Unlock()
	return nil
}

func (c *conohaDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	c.entriesLock.Lock()
	e, ok := c.entries[string(ch.UID)]
	c.entriesLock.Unlock()
	if !ok {
		return fmt.Errorf("no uid")
	}

	client, err := getClient()
	if err != nil {
		return err
	}

	r, err := client.R().
		SetPathParams(map[string]string{
			"domainID": e.domainID,
			"recordID": e.recordID,
		}).
		Delete("/v1/domain/{domainID}/records/{recordID}")
	if err != nil {
		return err
	}
	if !r.IsSuccess() {
		return fmt.Errorf("DeleteRecord StatusCode: %d", r.StatusCode())
	}

	c.entriesLock.Lock()
	delete(c.entries, string(ch.UID))
	c.entriesLock.Unlock()
	return nil
}

func (c *conohaDNSProviderSolver) Initialize(_ *rest.Config, _ <-chan struct{}) error {
	return nil
}

func getClient() (*resty.Client, error) {
	client := resty.New()

	r, err := client.R().
		SetBody(Hash{
			"auth": Hash{
				"tenantId": TenantID,
				"passwordCredentials": Hash{
					"username": Username,
					"password": Password,
				},
			},
		}).
		Post(fmt.Sprintf("https://identity.%s.conoha.io/v2.0/tokens", Region))
	if err != nil {
		return nil, err
	}
	if !r.IsSuccess() {
		return nil, fmt.Errorf("GetToken StatusCode: %d", r.StatusCode())
	}

	return client.
		SetHostURL(fmt.Sprintf("https://dns-service.%s.conoha.io", Region)).
		SetHeaders(map[string]string{
			"Accept":       "application/json",
			"Content-Type": "application/json",
			"X-Auth-Token": gjson.Get(r.String(), "access.token.id").String(),
		}), nil
}

func getEnvOrDefault(key string, def string) string {
	s := os.Getenv(key)
	if s == "" {
		return def
	}
	return s
}
