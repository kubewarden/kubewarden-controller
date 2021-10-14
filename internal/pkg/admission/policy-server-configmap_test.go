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
		tt := test // ensure tt is correctly scoped when used in function literal
		t.Run(tt.name, func(t *testing.T) {
			var currentPoliciesMap map[string]policyServerConfigEntry
			if err := json.Unmarshal([]byte(tt.newPoliciesYML), &currentPoliciesMap); err != nil {
				t.Errorf("unexpected error %s", err.Error())
			}
			got, err := shouldUpdatePolicyMap(tt.currentPoliciesYML, currentPoliciesMap)
			if err != nil {
				t.Errorf("unexpected error %s", err.Error())
			}
			if got != tt.expect {
				t.Errorf("got %t, want %t", got, tt.expect)
			}
		})
	}
}

func TestShouldUpdateSourcesMap(t *testing.T) {
	tests := []struct {
		name                   string
		currentSourcesYML      string
		newInsecureSourcesList []string
		expect                 bool
	}{
		{
			"empty sources",
			"{}",
			nil,
			false,
		},
		{
			"add insecure_sources",
			"{}",
			[]string{"localhost:5000"},
			true,
		},
		{
			"remove insecure_sources",
			"{\"insecure_sources\":[\"localhost:5000\"]}",
			make([]string, 0),
			true,
		},
		{
			"same insecure_sources",
			"{\"insecure_sources\":[\"localhost:5000\"]}",
			[]string{"localhost:5000"},
			false,
		},
	}
	for _, test := range tests {
		tt := test // ensure tt is correctly scoped when used in function literal
		t.Run(tt.name, func(t *testing.T) {
			got, err := shouldUpdateSourcesMap(tt.currentSourcesYML, tt.newInsecureSourcesList)
			if err != nil {
				t.Errorf("unexpected error %s", err.Error())
			}
			if got != tt.expect {
				t.Errorf("got %t, want %t", got, tt.expect)
			}
		})
	}
}
