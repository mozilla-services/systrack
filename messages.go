package systrack

type HostMsg struct {
	Fqdn            string   `json:"fqdn"`
	Dist            string   `json:"dist"`
	Issue           string   `json:"issue"`
	LocalIP         string   `json:"localip"`
	AwsInstanceID   string   `json:"awsinstanceid,omitempty"`
	AwsInstanceType string   `json:"awsinstancetype,omitempty"`
	AwsInstanceTags []string `json:"awsinstancetags,omitempty"`
	AwsAmiID        string   `json:"awsamiid,omitempty"`
}

type PkgMsg struct {
	HostMsg
	PkgName    string `json:"pkgname"`
	PkgVersion string `json:"pkgversion"`
	PkgType    string `json:"pkgtype"`
	PkgArch    string `json:"pkgarch"`
}

func (p *PkgMsg) MarshalFields() map[string]interface{} {
	return map[string]interface{}{
		"fqdn":         p.Fqdn,
		"dist":         p.Dist,
		"issue":        p.Issue,
		"localip":      p.LocalIP,
		"instanceid":   p.AwsInstanceID,
		"instancetype": p.AwsInstanceType,
		"instancetags": p.AwsInstanceTags,
		"ami":          p.AwsAmiID,
		"pkgname":      p.PkgName,
		"pkgversion":   p.PkgVersion,
		"pkgtype":      p.PkgType,
		"pkgarch":      p.PkgArch,
	}
}
