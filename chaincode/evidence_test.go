package main

import "testing"

func TestValidStaffRoles(t *testing.T) {
	valid := []string{"INVESTIGATOR", "ANALYST", "SUPERVISOR", "OBSERVER"}
	for _, role := range valid {
		if !validStaffRole(role) {
			t.Fatalf("expected role %s to be valid", role)
		}
	}
	if validStaffRole("ADMIN") || validStaffRole("UNKNOWN") {
		t.Fatal("unexpected privileged or unknown role accepted as staff role")
	}
}

func TestRoleAllowed(t *testing.T) {
	if !roleAllowed("SUPERVISOR", "INVESTIGATOR", "SUPERVISOR") {
		t.Fatal("supervisor should be allowed")
	}
	if roleAllowed("OBSERVER", "INVESTIGATOR", "SUPERVISOR") {
		t.Fatal("observer must not be allowed to transfer evidence")
	}
}
