package bitbucket

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxBody = 4 << 20

var (
	// ErrNotFound reports that the repository does not exist.
	ErrNotFound = errors.New("not found")
	// ErrAlreadyExists reports that the repository was already taken, which a
	// retried provision treats as success.
	ErrAlreadyExists = errors.New("already exists")
	// errDuplicateKey reports that the key already grants access to the
	// repository, as opposed to being refused for belonging elsewhere.
	errDuplicateKey = errors.New("key already grants access")
)

// CloneLink is one entry of a repository's clone URLs.
type CloneLink struct {
	Href string `json:"href"`
	Name string `json:"name"`
}

// Repository is the subset of Bitbucket's repository object the wrangler uses.
type Repository struct {
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	State    string `json:"state"`
	Archived bool   `json:"archived"`
	Project  struct {
		Key string `json:"key"`
	} `json:"project"`
	Links struct {
		Clone []CloneLink `json:"clone"`
	} `json:"links"`
}

// SSHCloneURL returns the ssh clone URL, or "" when the repository offers
// none. The clone links arrive in no particular order, so it selects by name.
func (r *Repository) SSHCloneURL() string {
	for _, link := range r.Links.Clone {
		if link.Name == "ssh" {
			return link.Href
		}
	}
	return ""
}

// Client talks to the Bitbucket Server REST API.
type Client struct {
	base   *url.URL
	token  string
	httpC  *http.Client
	logger *slog.Logger
}

// Option configures a Client and returns an Option restoring the previous value.
type Option func(*Client) Option

// WithHTTPClient sets the HTTP client used for requests.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) Option {
		previous := c.httpC
		c.httpC = hc
		return WithHTTPClient(previous)
	}
}

// WithLogger sets the logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Client) Option {
		previous := c.logger
		c.logger = logger
		return WithLogger(previous)
	}
}

// New returns a Client for a Bitbucket Server base URL, e.g.
// https://bitbucket.example.com. token is an HTTP access token.
func New(baseURL, token string, opts ...Option) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse bitbucket url %q: %w", baseURL, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("bitbucket url %q: want scheme and host", baseURL)
	}

	c := &Client{
		base:   parsed,
		token:  token,
		httpC:  &http.Client{Timeout: 30 * time.Second},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	c.Option(opts...)
	return c, nil
}

// Option applies opts and returns an Option restoring the last one.
func (c *Client) Option(opts ...Option) (previous Option) {
	for _, opt := range opts {
		previous = opt(c)
	}
	return previous
}

// GetRepo fetches a repository, returning ErrNotFound when it is absent.
func (c *Client) GetRepo(ctx context.Context, repo Repo) (*Repository, error) {
	path := fmt.Sprintf("/rest/api/1.0/projects/%s/repos/%s", repo.ProjectKey, repo.Slug)

	var out Repository
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, fmt.Errorf("get repo %s/%s: %w", repo.ProjectKey, repo.Slug, err)
	}
	return &out, nil
}

// CreateRepo creates an empty repository, returning ErrAlreadyExists when the
// slug is taken.
func (c *Client) CreateRepo(ctx context.Context, repo Repo) (*Repository, error) {
	path := fmt.Sprintf("/rest/api/1.0/projects/%s/repos", repo.ProjectKey)
	body := map[string]string{"name": repo.Slug, "scmId": "git"}

	var out Repository
	if err := c.do(ctx, http.MethodPost, path, body, &out); err != nil {
		return nil, fmt.Errorf("create repo %s/%s: %w", repo.ProjectKey, repo.Slug, err)
	}
	return &out, nil
}

// AddUserPermission grants a Bitbucket user account access to the repository.
// Bitbucket refuses to register a key that already belongs to a user as a
// repository access key, so for a personal key this is the only way to grant
// push rights.
func (c *Client) AddUserPermission(ctx context.Context, repo Repo, user, permission string) error {
	query := url.Values{"name": {user}, "permission": {permission}}
	path := fmt.Sprintf("/rest/api/1.0/projects/%s/repos/%s/permissions/users?%s", repo.ProjectKey, repo.Slug, query.Encode())

	if err := c.do(ctx, http.MethodPut, path, nil, nil); err != nil {
		return fmt.Errorf("grant %s %s on %s/%s: %w", user, permission, repo.ProjectKey, repo.Slug, err)
	}
	return nil
}

// AddAccessKey registers a standalone ssh key on the repository. A key bound
// to a user account cannot be registered this way; grant that account a
// permission with AddUserPermission instead.
func (c *Client) AddAccessKey(ctx context.Context, repo Repo, publicKey, permission string) error {
	path := fmt.Sprintf("/rest/keys/1.0/projects/%s/repos/%s/ssh", repo.ProjectKey, repo.Slug)
	body := map[string]any{
		"key":        map[string]string{"text": publicKey},
		"permission": permission,
	}

	err := c.do(ctx, http.MethodPost, path, body, nil)
	if err != nil && !errors.Is(err, errDuplicateKey) {
		return fmt.Errorf("add %s access key to %s/%s: %w", permission, repo.ProjectKey, repo.Slug, err)
	}
	return nil
}

type pullRequestRef struct {
	ID         string                `json:"id"`
	Repository pullRequestRepository `json:"repository"`
}

type pullRequestRepository struct {
	Slug    string `json:"slug"`
	Project struct {
		Key string `json:"key"`
	} `json:"project"`
}

type pullRequest struct {
	ID      int            `json:"id"`
	FromRef pullRequestRef `json:"fromRef"`
	ToRef   pullRequestRef `json:"toRef"`
}

func (c *Client) EnsurePullRequest(ctx context.Context, repo Repo, branch, baseBranch, title string) (string, error) {
	repository := pullRequestRepository{Slug: repo.Slug}
	repository.Project.Key = repo.ProjectKey
	from := pullRequestRef{ID: "refs/heads/" + branch, Repository: repository}
	to := pullRequestRef{ID: "refs/heads/" + baseBranch, Repository: repository}
	path := fmt.Sprintf("/rest/api/1.0/projects/%s/repos/%s/pull-requests", repo.ProjectKey, repo.Slug)
	link := func(id int) string {
		return c.base.JoinPath("projects", repo.ProjectKey, "repos", repo.Slug, "pull-requests", fmt.Sprint(id)).String()
	}
	existing, err := c.findPullRequest(ctx, path, from, to)
	if err != nil {
		return "", err
	}
	if existing != nil {
		return link(existing.ID), nil
	}
	body := struct {
		Title   string         `json:"title"`
		FromRef pullRequestRef `json:"fromRef"`
		ToRef   pullRequestRef `json:"toRef"`
	}{Title: title, FromRef: from, ToRef: to}
	var created pullRequest
	if err := c.do(ctx, http.MethodPost, path, body, &created); err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			existing, lookupErr := c.findPullRequest(ctx, path, from, to)
			if lookupErr != nil {
				return "", lookupErr
			}
			if existing != nil {
				return link(existing.ID), nil
			}
		}
		return "", fmt.Errorf("create pull request: %w", err)
	}
	if created.ID <= 0 {
		return "", fmt.Errorf("create pull request: response has no ID")
	}
	return link(created.ID), nil
}

func (c *Client) findPullRequest(ctx context.Context, path string, from, to pullRequestRef) (*pullRequest, error) {
	start := 0
	for {
		query := url.Values{"state": {"OPEN"}, "direction": {"OUTGOING"}, "at": {from.ID}, "start": {fmt.Sprint(start)}}
		var page struct {
			Values        []pullRequest `json:"values"`
			IsLastPage    bool          `json:"isLastPage"`
			NextPageStart int           `json:"nextPageStart"`
		}
		if err := c.do(ctx, http.MethodGet, path+"?"+query.Encode(), nil, &page); err != nil {
			return nil, fmt.Errorf("find pull request: %w", err)
		}
		for _, candidate := range page.Values {
			if candidate.ID > 0 && candidate.FromRef.ID == from.ID && candidate.ToRef.ID == to.ID && candidate.FromRef.Repository.Slug == from.Repository.Slug && strings.EqualFold(candidate.FromRef.Repository.Project.Key, from.Repository.Project.Key) {
				return &candidate, nil
			}
		}
		if page.IsLastPage {
			return nil, nil
		}
		if page.NextPageStart <= start {
			return nil, fmt.Errorf("find pull request: invalid pagination")
		}
		start = page.NextPageStart
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		payload = bytes.NewReader(encoded)
	}

	// JoinPath escapes its arguments, so any query has to be reattached after.
	rawPath, rawQuery, _ := strings.Cut(path, "?")
	target := c.base.JoinPath(rawPath)
	target.RawQuery = rawQuery

	req, err := http.NewRequestWithContext(ctx, method, target.String(), payload)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpC.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, maxBody)
	if resp.StatusCode >= http.StatusBadRequest {
		return statusError(resp.StatusCode, limited)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, limited)
		return nil
	}
	if err := json.NewDecoder(limited).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// bitbucketErrors is the error envelope the REST API returns.
type bitbucketErrors struct {
	Errors []struct {
		Message       string `json:"message"`
		ExceptionName string `json:"exceptionName"`
	} `json:"errors"`
}

func statusError(status int, body io.Reader) error {
	var sentinel error
	switch status {
	case http.StatusNotFound:
		sentinel = ErrNotFound
	case http.StatusConflict:
		sentinel = ErrAlreadyExists
	}

	raw, _ := io.ReadAll(body)
	var envelope bitbucketErrors
	if err := json.Unmarshal(raw, &envelope); err == nil && len(envelope.Errors) > 0 {
		first := envelope.Errors[0]
		// A 409 also covers a key bound to an account, which is a refusal and
		// must not pass for the idempotent repeat.
		if status == http.StatusConflict && strings.Contains(first.ExceptionName, "DuplicateSshKeyException") {
			sentinel = errDuplicateKey
		}
		if sentinel != nil {
			return fmt.Errorf("%s: %w", first.Message, sentinel)
		}
		return fmt.Errorf("bitbucket %d: %s", status, first.Message)
	}
	if sentinel != nil {
		return sentinel
	}
	return fmt.Errorf("bitbucket %d", status)
}
