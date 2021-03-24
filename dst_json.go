package dst

type DST map[string]PKG

type PKG map[string]CVE

type CVE struct {
	Description string
	Scope       string
	Releases    map[string]Release
}

type Release struct {
	Status       string
	FixedVersion string `json:"fixed_version"`
	Repositories map[string]string
	Urgency      string
}
