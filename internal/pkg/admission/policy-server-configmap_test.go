package admission

import (
	"encoding/json"
	"testing"
)

func TestArePoliciesEqual(t *testing.T) {
	tests := []struct {
		name               string
		newPoliciesYML     string
		currentPoliciesYML string
		expect             bool
	}{{"same nil settings",
		"{\"privileged-pods\":{\"url\":\"registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5\",\"settings\":null}}",
		"{\"privileged-pods\":{\"url\":\"registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5\",\"settings\":null}}",
		false},
		{"same empty",
			"{}",
			"{}",
			false},
		{"same with settings",
			"{\"privileged-pods\":{\"url\":\"registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5\",\"settings\":{\"name\":\"test\", \"list\":[\"one\",\"two\"]}}}",
			"{\"privileged-pods\":{\"url\":\"registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5\",\"settings\":{\"name\":\"test\", \"list\":[\"one\",\"two\"]}}}",
			false},
		{"same with settings different order",
			"{\"privileged-pods\":{\"url\":\"registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5\",\"settings\":{\"name\":\"test\", \"list\":[\"one\",\"two\"]}}}",
			"{\"privileged-pods\":{\"settings\":{\"name\":\"test\", \"list\":[\"one\",\"two\"]},\"url\":\"registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5\"}}",
			false},
		{"2 policies same different order",
			"{\"privileged-pods\":{\"url\":\"registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5\",\"settings\":null},\"psp-capabilities\":{\"url\":\"registry://ghcr.io/kubewarden/policies/psp-capabilities:v0.1.5\",\"settings\":null}}",
			"{\"psp-capabilities\":{\"url\":\"registry://ghcr.io/kubewarden/policies/psp-capabilities:v0.1.5\",\"settings\":null},\"privileged-pods\":{\"url\":\"registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5\",\"settings\":null}}",
			false},
		{"different",
			"{\"privileged-pods\":{\"url\":\"registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5\",\"settings\":null}}",
			"{\"psp-capabilities\":{\"url\":\"registry://ghcr.io/kubewarden/policies/psp-capabilities:v0.1.5\",\"settings\":null},\"privileged-pods\":{\"url\":\"registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5\",\"settings\":null}}",
			true},
		{"different settings",
			"{\"privileged-pods\":{\"url\":\"registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5\",\"settings\":{\"name\":\"test\", \"list\":[\"one\",\"two\"]}}}",
			"{\"privileged-pods\":{\"url\":\"registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.5\",\"settings\":{\"name\":\"test\", \"list\":[\"one\"]}}}",
			true},
	}
	for _, test := range tests {
		ttest := test // ensure tt is correctly scoped when used in function literal
		t.Run(ttest.name, func(t *testing.T) {
			var currentPoliciesMap map[string]policyServerConfigEntry
			if err := json.Unmarshal([]byte(ttest.newPoliciesYML), &currentPoliciesMap); err != nil {
				t.Errorf("unexpected error %s", err.Error())
			}
			got, err := shouldUpdatePolicyMap(ttest.currentPoliciesYML, currentPoliciesMap)
			if err != nil {
				t.Errorf("unexpected error %s", err.Error())
			}
			if got != ttest.expect {
				t.Errorf("got %t, want %t", got, ttest.expect)
			}
		})
	}
}

func TestShouldUpdateSourcesList(t *testing.T) {
	tests := []struct {
		name              string
		currentSourcesYML string
		newSourcesList    policyServerSourcesEntry
		expect            bool
	}{
		{
			"empty sources",
			"{}",
			policyServerSourcesEntry{},
			false,
		},
		{
			"add insecure_sources",
			"{}",
			policyServerSourcesEntry{InsecureSources: []string{"localhost:5000"}},
			true,
		},
		{
			"remove insecure_sources",
			"{\"insecure_sources\":[\"localhost:5000\"]}",
			policyServerSourcesEntry{},
			true,
		},
		{
			"same insecure_sources",
			"{\"insecure_sources\":[\"localhost:5000\"]}",
			policyServerSourcesEntry{InsecureSources: []string{"localhost:5000"}},
			false,
		},
		{
			"add source_authorities",
			"{}",
			policyServerSourcesEntry{
				InsecureSources: []string{},
				SourceAuthorities: map[string][]policyServerSourceAuthority{
					"host.k3d.internal:5000": {
						policyServerSourceAuthority{
							Type: "Data",
							Data: "pem cert 1",
						},
					},
				},
			},
			true,
		},
		{
			"remove source_authorities",
			"{\"source_authorities\":{\"host.k3d.internal:5000\":[{\"type\": \"Data\",\"data\":\"pem cert 1\"}]}}",
			policyServerSourcesEntry{},
			true,
		},
		{
			"same source_authorities",
			"{\"source_authorities\":{\"host.k3d.internal:5000\":[{\"type\": \"Data\",\"data\":\"pem cert 1\"}]}}",
			policyServerSourcesEntry{
				SourceAuthorities: map[string][]policyServerSourceAuthority{
					"host.k3d.internal:5000": {
						policyServerSourceAuthority{
							Type: "Data",
							Data: "pem cert 1",
						},
					},
				},
			},
			false,
		},
	}
	for _, test := range tests {
		ttest := test // ensure ttest is correctly scoped when used in function literal
		t.Run(ttest.name, func(t *testing.T) {
			got, err := shouldUpdateSourcesList(ttest.currentSourcesYML, ttest.newSourcesList)
			if err != nil {
				t.Errorf("unexpected error %s", err.Error())
			}
			if got != ttest.expect {
				t.Errorf("got %t, want %t", got, ttest.expect)
			}
		})
	}
}
