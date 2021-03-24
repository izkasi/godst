package main

import (
	"log"

	godst "github.com/izkasi/godst"
)

func main() {

	dst, err := godst.NewDST()
	if err != nil {
		log.Fatal(err)
	}

	cve := "CVE-2012-0833"

	pkgs := dst.CVE(cve)

	log.Println(pkgs)

	pkg, err := dst.Package(pkgs[0])

	log.Println(pkg[cve].Releases["buster"].Status)

	apache2, err := dst.Package("apache2")

	for k, v := range apache2 {

		log.Println(k, ":", v.Scope)

	}

}
