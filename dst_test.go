package dst

import (
	"os"
	"testing"
)

func TestUnmarshalDST(t *testing.T) {

	fileHandle, _ := os.Open("tests/test-data.json")
	defer fileHandle.Close()

	dst, err := unmarshalDST(fileHandle)
	if err != nil {
		t.Error("error unmarshalling DST", err)
	}

	if len(dst) != 2 {
		t.Error("Number of packages is not correct")
	}

	pkg, err := dst.Package("389-ds-base")
	if len(dst) != 2 {
		t.Error("Error getting package from dst:", err)
	}

	if pkg["CVE-2012-0833"].Scope != "local" {
		t.Error("Error getting scope from cve:", err)
	}

	pkgs := dst.CVE("CVE-2012-0833")
	if len(pkgs) != 1 {
		t.Error("Error getting cves from dst")
	}

	if pkgs[0] != "389-ds-base" {
		t.Error("Error getting packages from cve")
	}

}
