package dst

import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

const URL string = "https://security-tracker.debian.org/tracker/data/json"

// NewDST initializes a new instance of Debian Security Tracker data.
// The data of the security tracker is ~10MB in size, so don't load this too often.
// The live DST isn't refreshed that often anyways.
func NewDST() (DST, error) {

	client := http.Client{
		Timeout: time.Second * 10,
	}

	req, err := http.NewRequest(http.MethodGet, URL, nil)
	if err != nil {
		return make(DST), err
	}

	req.Header.Set("User-Agent", "godst")

	res, err := client.Do(req)
	if err != nil {
		return make(DST), err
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	dst, err := unmarshalDST(res.Body)
	if err != nil {
		return make(DST), err
	}

	return dst, nil
}

func unmarshalDST(body io.ReadCloser) (DST, error) {

	data, err := ioutil.ReadAll(body)
	if err != nil {
		return make(DST), errors.New("Error reading data for unmarshalling:" + err.Error())
	}

	var dst DST

	err = json.Unmarshal(data, &dst)
	if err != nil {
		return make(DST), errors.New("Error unmarshalling Debian Security Tracker data:" + err.Error())
	}

	return dst, nil
}

// Package retrieves all information about a specific debian package from the Debian Security Tracker.
func (dst DST) Package(pkg string) (PKG, error) {

	if val, ok := dst[pkg]; ok {
		return val, nil
	}

	return make(PKG), errors.New("package not found")
}

// CVE returns a slice of package names which are affected by the given CVE.
func (dst DST) CVE(cve string) []string {

	var list []string

	for k, v := range dst {

		if _, ok := v[cve]; ok {
			list = append(list, k)
		}

	}

	return list
}
