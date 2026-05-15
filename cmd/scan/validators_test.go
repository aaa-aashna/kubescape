package scan

import (
	"testing"

	"github.com/kubescape/kubescape/v3/cmd/shared"
	"github.com/kubescape/kubescape/v3/core/cautils"
)

// Test_validateControlScanInfo tests how scan info is validated for the `scan control` command
func Test_validateControlScanInfo(t *testing.T) {
	testCases := []struct {
		Description string
		ScanInfo    *cautils.ScanInfo
		Want        error
	}{
		{
			"Empty severity should be valid for scan info",
			&cautils.ScanInfo{FailThresholdSeverity: ""},
			nil,
		},
		{
			"High severity should be valid for scan info",
			&cautils.ScanInfo{FailThresholdSeverity: "High"},
			nil,
		},
		{
			"Unknown severity should be invalid for scan info",
			&cautils.ScanInfo{FailThresholdSeverity: "Unknown"},
			shared.ErrUnknownSeverity,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				var want = tc.Want

				got := validateControlScanInfo(tc.ScanInfo)

				if got != want {
					t.Errorf("got: %v, want: %v", got, want)
				}
			},
		)
	}
}

// Test_validateFrameworkScanInfo tests how scan info is validated for the `scan framework` command
func Test_validateFrameworkScanInfo(t *testing.T) {
	testCases := []struct {
		Description string
		ScanInfo    *cautils.ScanInfo
		Want        error
	}{
		{
			"Empty severity should be valid for scan info",
			&cautils.ScanInfo{FailThresholdSeverity: ""},
			nil,
		},
		{
			"High severity should be valid for scan info",
			&cautils.ScanInfo{FailThresholdSeverity: "High"},
			nil,
		},
		{
			"Unknown severity should be invalid for scan info",
			&cautils.ScanInfo{FailThresholdSeverity: "Unknown"},
			shared.ErrUnknownSeverity,
		},
		{
			"Security view should be invalid for scan info",
			&cautils.ScanInfo{View: string(cautils.SecurityViewType)},
			nil,
		},
		{
			"Empty view should be valid for scan info",
			&cautils.ScanInfo{},
			nil,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				var want = tc.Want

				got := validateFrameworkScanInfo(tc.ScanInfo)

				if got != want {
					t.Errorf("got: %v, want: %v", got, want)
				}
			},
		)
	}
}

func Test_validateCoverageThreshold(t *testing.T) {
	testCases := []struct {
		Description string
		ScanInfo    *cautils.ScanInfo
		Want        error
	}{
		{"0 disables the check and is valid", &cautils.ScanInfo{FailCoverageThreshold: 0}, nil},
		{"50 is a valid threshold", &cautils.ScanInfo{FailCoverageThreshold: 50}, nil},
		{"100 is a valid threshold", &cautils.ScanInfo{FailCoverageThreshold: 100}, nil},
		{"101 is out of range", &cautils.ScanInfo{FailCoverageThreshold: 101}, ErrBadThreshold},
		{"negative value is out of range", &cautils.ScanInfo{FailCoverageThreshold: -1}, ErrBadThreshold},
	}

	for _, tc := range testCases {
		t.Run(tc.Description, func(t *testing.T) {
			got := validateThresholdsOnly(tc.ScanInfo)
			if got != tc.Want {
				t.Errorf("got: %v, want: %v", got, tc.Want)
			}
		})
	}
}

func Test_validateThresholdsOnly_ComplianceAndFail(t *testing.T) {
	testCases := []struct {
		Description string
		ScanInfo    *cautils.ScanInfo
		Want        error
	}{
		{"Compliance threshold above 100 is out of range", &cautils.ScanInfo{ComplianceThreshold: 101}, ErrBadThreshold},
		{"Compliance threshold below 0 is out of range", &cautils.ScanInfo{ComplianceThreshold: -1}, ErrBadThreshold},
		{"Compliance threshold at 0 is valid", &cautils.ScanInfo{ComplianceThreshold: 0}, nil},
		{"Compliance threshold at 100 is valid", &cautils.ScanInfo{ComplianceThreshold: 100}, nil},
		{"Fail threshold above 100 is out of range", &cautils.ScanInfo{FailThreshold: 101}, ErrBadThreshold},
		{"Fail threshold below 0 is out of range", &cautils.ScanInfo{FailThreshold: -1}, ErrBadThreshold},
		{"Fail threshold at 0 is valid", &cautils.ScanInfo{FailThreshold: 0}, nil},
		{"Fail threshold at 100 is valid", &cautils.ScanInfo{FailThreshold: 100}, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.Description, func(t *testing.T) {
			got := validateThresholdsOnly(tc.ScanInfo)
			if got != tc.Want {
				t.Errorf("got: %v, want: %v", got, tc.Want)
			}
		})
	}
}

func Test_validateWorkloadIdentifier(t *testing.T) {
	testCases := []struct {
		Description string
		Input       string
		Want        error
	}{
		{"valid workload identifier should be valid", "deployment/test", nil},
		{"invalid workload identifier missing kind", "deployment", ErrInvalidWorkloadIdentifier},
		{"invalid workload identifier with namespace", "ns/deployment/name", ErrInvalidWorkloadIdentifier},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Description, func(t *testing.T) {
			input := testCase.Input
			want := testCase.Want
			got := validateWorkloadIdentifier(input)

			if got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
	}
}
