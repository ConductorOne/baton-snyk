package snyk

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListOrgsUsesPageFromNextLink(t *testing.T) {
	var server *httptest.Server
	var requests []string
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/group/group-id/orgs" {
			http.NotFound(w, r)
			return
		}

		requests = append(requests, r.URL.RawQuery)
		if perPage := r.URL.Query()["perPage"]; len(perPage) != 1 || perPage[0] != "50" {
			http.Error(w, fmt.Sprintf("expected one perPage=50 query param, got %q", perPage), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page") {
		case "":
			w.Header().Set("Link", fmt.Sprintf("<%s%s?page=2&perPage=50>; rel=next", server.URL, r.URL.Path))
			_, _ = w.Write([]byte(`{"orgs":[{"id":"org-1","name":"Org 1"}]}`))
		case "2":
			_, _ = w.Write([]byte(`{"orgs":[{"id":"org-2","name":"Org 2"}]}`))
		default:
			http.Error(w, fmt.Sprintf("unexpected page query: %q", r.URL.Query().Get("page")), http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := NewClient(context.Background(), "group-id", "token", BaseHost, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	nextPageURL := fmt.Sprintf("%s/v1/group/group-id/orgs?page=2&perPage=50", server.URL)

	orgs, nextPageLink, err := client.ListOrgs(context.Background(), NewPaginationVars("", 50))
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(orgs) != 1 || orgs[0].ID != "org-1" {
		t.Fatalf("first page orgs = %#v, want org-1", orgs)
	}
	if nextPageLink == "" {
		t.Fatal("expected next page link")
	}

	orgs, _, err = client.ListOrgs(context.Background(), NewPaginationVars(nextPageURL, 50))
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(orgs) != 1 || orgs[0].ID != "org-2" {
		t.Fatalf("second page orgs = %#v, want org-2", orgs)
	}

	if len(requests) != 2 {
		t.Fatalf("requests = %q, want two requests", requests)
	}
	if requests[1] != "page=2&perPage=50" {
		t.Fatalf("second request query = %q, want page=2&perPage=50", requests[1])
	}
}
