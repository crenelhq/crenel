package core

import (
	"errors"
	"strings"
	"testing"
)

// A provider/admin-API error echoed into a read-back-verify Detail must have its
// secret-shaped bytes masked at the construction boundary (SECURITY.md §6), so a
// failed DNS/edge re-read never prints a token in the clear.
func TestReReadFailedDetailRedactsSecrets(t *testing.T) {
	err := errors.New(`dnscontrol get-zones: exit status 1: Authorization: Bearer sk-supersecrettoken1234567890`)
	out := reReadFailedDetail(err)
	if strings.Contains(out, "sk-supersecrettoken1234567890") {
		t.Errorf("token must be redacted in read-back detail: %s", out)
	}
	if !strings.Contains(out, "re-read failed") {
		t.Errorf("non-secret context should survive redaction: %s", out)
	}
}
