//go:generate go run ../cmd/radius-dict-gen/main.go -package rfc3580 -output generated.go -ref Acct-Terminate-Cause:github.com/talkincode/greenradius/rfc2866 -ref NAS-Port-Type:github.com/talkincode/greenradius/rfc2865 -ref Tunnel-Type:github.com/talkincode/greenradius/rfc2868 dictionary.rfc3580

package rfc3580
