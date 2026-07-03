package model

import "testing"

// TestPersistenceModel_DurabilityClassification locks the three predicates that the
// status/audit/write surfaces key on: Durable (survives a restart), EphemeralWrites
// (live-only, warn), and Classified (declared at all). The empty value is the
// not-applicable case (a mesh edge that refuses mutation) — neither durable nor an
// ephemeral cry-wolf.
func TestPersistenceModel_DurabilityClassification(t *testing.T) {
	cases := []struct {
		m          PersistenceModel
		durable    bool
		ephemeral  bool
		classified bool
	}{
		{PersistDurableConfig, true, false, true},
		{PersistDurableFile, true, false, true},
		{PersistResume, true, false, true},
		{PersistEphemeralAdmin, false, true, true},
		{PersistUnknown, false, true, true}, // declared-unknown is never assumed durable
		{"", false, false, false},           // n/a — not durable, not a warning
	}
	for _, c := range cases {
		if got := c.m.Durable(); got != c.durable {
			t.Errorf("%q.Durable() = %v, want %v", c.m, got, c.durable)
		}
		if got := c.m.EphemeralWrites(); got != c.ephemeral {
			t.Errorf("%q.EphemeralWrites() = %v, want %v", c.m, got, c.ephemeral)
		}
		if got := c.m.Classified(); got != c.classified {
			t.Errorf("%q.Classified() = %v, want %v", c.m, got, c.classified)
		}
	}
}

// TestPersistenceModel_StringNeverBlank ensures the human form is never empty (the
// unset value reads "n/a"), so a status line is never a dangling "Durability: ".
func TestPersistenceModel_StringNeverBlank(t *testing.T) {
	if PersistenceModel("").String() != "n/a" {
		t.Errorf("empty model should render n/a, got %q", PersistenceModel("").String())
	}
	if PersistEphemeralAdmin.String() != "ephemeral-admin" {
		t.Errorf("got %q", PersistEphemeralAdmin.String())
	}
}
