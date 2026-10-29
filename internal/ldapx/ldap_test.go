package ldapx

import (
	"testing"
	"time"
)

func TestFileTime(t *testing.T) {
	// 2024-01-01T00:00:00Z
	got := FileTime("133485408000000000")
	if !got.Equal(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("FileTime = %v", got)
	}
	for _, v := range []string{"0", "9223372036854775807", "", "abc"} {
		if !FileTime(v).IsZero() {
			t.Errorf("FileTime(%q) sollte Zero sein", v)
		}
	}
}

func TestADSubcode(t *testing.T) {
	ok, txt, _ := adSubcode("LDAP Result Code 49 \"Invalid Credentials\": 80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 773, v4563")
	if !ok || txt == "" {
		t.Fatalf("773 sollte als gültiges Kennwort erkannt werden: %v %q", ok, txt)
	}
	ok, _, _ = adSubcode("... data 52e, v4563")
	if ok {
		t.Fatal("52e darf nicht gültig sein")
	}
}

func TestGroupCN(t *testing.T) {
	if g := groupCN("CN=Domain Admins,CN=Users,DC=firma,DC=local"); g != "Domain Admins" {
		t.Fatal(g)
	}
}
