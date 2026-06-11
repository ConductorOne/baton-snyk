package connector

import "testing"

func TestParseLink(t *testing.T) {
	tests := []struct {
		name string
		link string
		want string
	}{
		{
			name: "empty header is end of pagination",
		},
		{
			name: "last link only is end of pagination",
			link: `<https://app.snyk.io/api/v1/group/group-id/orgs?page=3&perPage=50>; rel="last"`,
		},
		{
			name: "quoted next link",
			link: `<https://app.snyk.io/api/v1/group/group-id/orgs?page=2&perPage=50>; rel="next", <https://app.snyk.io/api/v1/group/group-id/orgs?page=3&perPage=50>; rel="last"`,
			want: "https://app.snyk.io/api/v1/group/group-id/orgs?page=2&perPage=50",
		},
		{
			name: "unquoted next link",
			link: `<https://app.snyk.io/api/v1/group/group-id/orgs?page=2&perPage=50>; rel=next`,
			want: "https://app.snyk.io/api/v1/group/group-id/orgs?page=2&perPage=50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLink(tt.link)
			if err != nil {
				t.Fatalf("parseLink returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseLink() = %q, want %q", got, tt.want)
			}
		})
	}
}
