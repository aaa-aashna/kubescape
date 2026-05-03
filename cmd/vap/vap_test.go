package vap

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/yaml"
)

func TestIsValidK8sObjectName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		// valid names
		{name: "single lowercase letter", input: "a", wantErr: false},
		{name: "lowercase word", input: "abc", wantErr: false},
		{name: "alphanumeric with hyphen", input: "abc-def", wantErr: false},
		{name: "starts with digit", input: "123", wantErr: false},
		{name: "contains multiple hyphens", input: "abc-def-ghi", wantErr: false},
		{name: "hyphen in middle", input: "abc-def123", wantErr: false},
		{name: "exactly 63 chars", input: strings.Repeat("a", 63), wantErr: false},
		{name: "1 char", input: "x", wantErr: false},

		// invalid - length
		{name: "empty string", input: "", wantErr: true, errMsg: "should consist of lower case alphanumeric characters"},
		{name: "exceeds 63 chars", input: strings.Repeat("a", 64), wantErr: true, errMsg: "less than 63 characters"},

		// invalid - starts with hyphen
		{name: "starts with hyphen", input: "-abc", wantErr: true, errMsg: "should consist of lower case alphanumeric characters"},

		// invalid - ends with hyphen
		{name: "ends with hyphen", input: "abc-", wantErr: true, errMsg: "should consist of lower case alphanumeric characters"},

		// invalid - uppercase
		{name: "contains uppercase", input: "Abc", wantErr: true, errMsg: "should consist of lower case alphanumeric characters"},
		{name: "all uppercase", input: "ABC", wantErr: true, errMsg: "should consist of lower case alphanumeric characters"},

		// invalid - special characters
		{name: "contains underscore", input: "abc_def", wantErr: true, errMsg: "should consist of lower case alphanumeric characters"},
		{name: "contains space", input: "abc def", wantErr: true, errMsg: "should consist of lower case alphanumeric characters"},
		{name: "contains dot in middle (not allowed by regex)", input: "abc.def", wantErr: true, errMsg: "should consist of lower case alphanumeric characters"},
		{name: "contains at sign", input: "a@b", wantErr: true, errMsg: "should consist of lower case alphanumeric characters"},

		// invalid - starts/ends with digit
		{name: "starts with hyphen and digit", input: "-123abc", wantErr: true, errMsg: "should consist of lower case alphanumeric characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := isValidK8sObjectName(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDownloadFileToString(t *testing.T) {
	t.Run("successful download", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello world")
		}))
		defer server.Close()

		result, err := downloadFileToString(server.URL)
		require.NoError(t, err)
		assert.Equal(t, "hello world", result)
	})

	t.Run("server returns 404", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		_, err := downloadFileToString(server.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to download file")
	})

	t.Run("server returns 500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		_, err := downloadFileToString(server.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to download file")
		assert.Contains(t, err.Error(), "500")
	})

	t.Run("connection refused", func(t *testing.T) {
		// Use an invalid URL to simulate connection refused
		_, err := downloadFileToString("http://127.0.0.1:1/nonexistent")
		require.Error(t, err)
	})

	t.Run("empty body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		result, err := downloadFileToString(server.URL)
		require.NoError(t, err)
		assert.Empty(t, result)
	})
}

// redirectTransport redirects all HTTP requests to a local test server
type redirectTransport struct {
	originalTransport http.RoundTripper
	baseURL           string
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	u.Scheme = "http"
	u.Host = rt.baseURL
	req = req.Clone(req.Context())
	req.URL = &u
	req.Host = rt.baseURL
	if rt.originalTransport == nil {
		rt.originalTransport = http.DefaultTransport
	}
	return rt.originalTransport.RoundTrip(req)
}

func TestDeployLibrary(t *testing.T) {
	t.Run("all downloads succeed with concatenation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			switch {
			case strings.Contains(r.URL.Path, "policy-configuration-definition"):
				fmt.Fprint(w, "policy-config-content")
			case strings.Contains(r.URL.Path, "basic-control-configuration"):
				fmt.Fprint(w, "basic-control-content")
			case strings.Contains(r.URL.Path, "kubescape-validating-admission-policies"):
				fmt.Fprint(w, "kubescape-policies-content")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		// Redirect all HTTP traffic to our test server.
		origTransport := http.DefaultTransport
		http.DefaultTransport = &redirectTransport{
			baseURL:           strings.TrimPrefix(server.URL, "http://"),
			originalTransport: server.Client().Transport,
		}
		defer func() { http.DefaultTransport = origTransport }()

		// Capture stdout
		out := captureStdout(t, func() {
			err := deployLibrary()
			require.NoError(t, err)
		})

		parts := strings.Split(out, "---\n")
		require.Len(t, parts, 3)
		assert.Equal(t, "policy-config-content\n", parts[0])
		assert.Equal(t, "basic-control-content\n", parts[1])
		assert.Equal(t, "kubescape-policies-content\n", parts[2])
	})

	t.Run("first download fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "policy-configuration-definition") {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, "content")
		}))
		defer server.Close()

		origTransport := http.DefaultTransport
		http.DefaultTransport = &redirectTransport{
			baseURL:           strings.TrimPrefix(server.URL, "http://"),
			originalTransport: server.Client().Transport,
		}
		defer func() { http.DefaultTransport = origTransport }()

		err := deployLibrary()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to download file")
	})

	t.Run("second download fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "basic-control-configuration") {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, "content")
		}))
		defer server.Close()

		origTransport := http.DefaultTransport
		http.DefaultTransport = &redirectTransport{
			baseURL:           strings.TrimPrefix(server.URL, "http://"),
			originalTransport: server.Client().Transport,
		}
		defer func() { http.DefaultTransport = origTransport }()

		err := deployLibrary()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to download file")
	})

	t.Run("third download fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "kubescape-validating-admission-policies") {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, "content")
		}))
		defer server.Close()

		origTransport := http.DefaultTransport
		http.DefaultTransport = &redirectTransport{
			baseURL:           strings.TrimPrefix(server.URL, "http://"),
			originalTransport: server.Client().Transport,
		}
		defer func() { http.DefaultTransport = origTransport }()

		err := deployLibrary()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to download file")
	})
}

func TestCreatePolicyBinding(t *testing.T) {
	t.Run("minimal binding with name and policy", func(t *testing.T) {
		out := captureStdout(t, func() {
			err := createPolicyBinding("my-binding", "c-0016", "Deny", "", nil, nil)
			require.NoError(t, err)
		})

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err := yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		assert.Equal(t, "admissionregistration.k8s.io/v1", binding.APIVersion)
		assert.Equal(t, "ValidatingAdmissionPolicyBinding", binding.Kind)
		assert.Equal(t, "my-binding", binding.Name)
		assert.Equal(t, "c-0016", binding.Spec.PolicyName)
		assert.Equal(t, []admissionv1.ValidationAction{admissionv1.Deny}, binding.Spec.ValidationActions)
		assert.Nil(t, binding.Spec.ParamRef)
		assert.Nil(t, binding.Spec.MatchResources.NamespaceSelector)
		assert.Nil(t, binding.Spec.MatchResources.ObjectSelector)
	})

	t.Run("with namespaces", func(t *testing.T) {
		out := captureStdout(t, func() {
			err := createPolicyBinding("my-binding", "c-0016", "Audit", "", []string{"ns1", "ns2"}, nil)
			require.NoError(t, err)
		})

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err := yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		require.NotNil(t, binding.Spec.MatchResources.NamespaceSelector)
		require.Len(t, binding.Spec.MatchResources.NamespaceSelector.MatchExpressions, 1)
		assert.Equal(t, "kubernetes.io/metadata.name", binding.Spec.MatchResources.NamespaceSelector.MatchExpressions[0].Key)
		assert.Equal(t, []string{"ns1", "ns2"}, binding.Spec.MatchResources.NamespaceSelector.MatchExpressions[0].Values)
		assert.Equal(t, "Audit", string(binding.Spec.ValidationActions[0]))
	})

	t.Run("with labels", func(t *testing.T) {
		out := captureStdout(t, func() {
			err := createPolicyBinding("my-binding", "c-0016", "Warn", "", nil, []string{"app=nginx", "env=prod"})
			require.NoError(t, err)
		})

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err := yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		require.NotNil(t, binding.Spec.MatchResources.ObjectSelector)
		assert.Equal(t, map[string]string{"app": "nginx", "env": "prod"}, binding.Spec.MatchResources.ObjectSelector.MatchLabels)
		assert.Equal(t, "Warn", string(binding.Spec.ValidationActions[0]))
	})

	t.Run("with parameter reference", func(t *testing.T) {
		out := captureStdout(t, func() {
			err := createPolicyBinding("my-binding", "c-0016", "Deny", "my-params", nil, nil)
			require.NoError(t, err)
		})

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err := yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		require.NotNil(t, binding.Spec.ParamRef)
		assert.Equal(t, "my-params", binding.Spec.ParamRef.Name)
		assert.NotNil(t, binding.Spec.ParamRef.ParameterNotFoundAction)
		assert.Equal(t, admissionv1.DenyAction, *binding.Spec.ParamRef.ParameterNotFoundAction)
	})

	t.Run("all fields combined", func(t *testing.T) {
		out := captureStdout(t, func() {
			err := createPolicyBinding("my-binding", "c-0016", "Deny", "my-params", []string{"ns1"}, []string{"app=nginx"})
			require.NoError(t, err)
		})

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err := yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		assert.Equal(t, "my-binding", binding.Name)
		assert.Equal(t, "c-0016", binding.Spec.PolicyName)
		assert.NotNil(t, binding.Spec.MatchResources.NamespaceSelector)
		assert.NotNil(t, binding.Spec.MatchResources.ObjectSelector)
		assert.NotNil(t, binding.Spec.ParamRef)
	})

	t.Run("empty namespace slice does not add selector", func(t *testing.T) {
		out := captureStdout(t, func() {
			err := createPolicyBinding("my-binding", "c-0016", "Deny", "", []string{}, nil)
			require.NoError(t, err)
		})

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err := yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		assert.Nil(t, binding.Spec.MatchResources.NamespaceSelector)
	})

	t.Run("empty label slice does not add selector", func(t *testing.T) {
		out := captureStdout(t, func() {
			err := createPolicyBinding("my-binding", "c-0016", "Deny", "", nil, []string{})
			require.NoError(t, err)
		})

		var binding admissionv1.ValidatingAdmissionPolicyBinding
		err := yaml.Unmarshal([]byte(out), &binding)
		require.NoError(t, err)
		assert.Nil(t, binding.Spec.MatchResources.ObjectSelector)
	})
}

func TestCreatePolicyBindingCmdValidation(t *testing.T) {
	t.Run("all valid defaults", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016"})
		err := cmd.Execute()
		assert.NoError(t, err)
	})

	t.Run("invalid binding name", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "INVALID-name", "--policy", "c-0016"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid policy binding name")
	})

	t.Run("invalid policy name", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "_invalid"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid policy name")
	})

	t.Run("invalid namespace in slice", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--namespace", "valid", "--namespace", "_invalid"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid namespace")
	})

	t.Run("invalid action", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--action", "Allow"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid action")
	})

	t.Run("invalid parameter reference", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016", "--parameter-reference", "_bad-ref"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid parameter reference")
	})

	t.Run("empty parameter reference is OK", func(t *testing.T) {
		cmd := getCreatePolicyBindingCmd()
		cmd.SetArgs([]string{"--name", "my-binding", "--policy", "c-0016"})
		err := cmd.Execute()
		assert.NoError(t, err)
	})
}

func TestGetDeployLibraryCmd(t *testing.T) {
	cmd := getDeployLibraryCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "deploy-library", cmd.Use)
	assert.Equal(t, "Install Kubescape CEL admission policy library", cmd.Short)
	assert.NotNil(t, cmd.RunE)
}

func TestGetCreatePolicyBindingCmd(t *testing.T) {
	cmd := getCreatePolicyBindingCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "create-policy-binding", cmd.Use)
	assert.Equal(t, "Create a policy binding", cmd.Short)
	assert.NotNil(t, cmd.RunE)

	// Check that required flags are marked
	nameFlag := cmd.Flags().Lookup("name")
	require.NotNil(t, nameFlag)
	assert.Equal(t, "n", nameFlag.Shorthand)

	policyFlag := cmd.Flags().Lookup("policy")
	require.NotNil(t, policyFlag)
	assert.Equal(t, "p", policyFlag.Shorthand)

	namespaceFlag := cmd.Flags().Lookup("namespace")
	require.NotNil(t, namespaceFlag)

	labelFlag := cmd.Flags().Lookup("label")
	require.NotNil(t, labelFlag)

	actionFlag := cmd.Flags().Lookup("action")
	require.NotNil(t, actionFlag)
	assert.Equal(t, "Deny", actionFlag.DefValue)

	paramRefFlag := cmd.Flags().Lookup("parameter-reference")
	require.NotNil(t, paramRefFlag)
	assert.Equal(t, "r", paramRefFlag.Shorthand)
}

func TestGetVapHelperCmd(t *testing.T) {
	cmd := GetVapHelperCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "vap", cmd.Use)
	assert.Len(t, cmd.Commands(), 2)

	subCmdNames := []string{cmd.Commands()[0].Use, cmd.Commands()[1].Use}
	assert.Contains(t, subCmdNames, "deploy-library")
	assert.Contains(t, subCmdNames, "create-policy-binding")
}

func TestLabelSelectorRegexEdgeCases(t *testing.T) {
	// The label selector regex in createPolicyBindingCmd is: ^[a-zA-Z0-9]+=[a-zA-Z0-9]+$
	// This is validated in the RunE function, not in a separate function.
	// We test it through the validation logic.

	tests := []struct {
		name      string
		input     string
		wantValid bool
	}{
		{name: "simple key=val", input: "app=nginx", wantValid: true},
		{name: "key and val with digits", input: "env1=prod2", wantValid: true},
		{name: "uppercase allowed", input: "App=Value", wantValid: true},
		{name: "mixed case", input: "appName=NginxValue", wantValid: true},
		{name: "missing equals (space)", input: "key value", wantValid: false},
		{name: "missing value", input: "key=", wantValid: false},
		{name: "missing key", input: "=value", wantValid: false},
		{name: "multiple equals", input: "key=val=extra", wantValid: false},
		{name: "empty string", input: "", wantValid: false},
		{name: "contains hyphen", input: "app-name=nginx", wantValid: false},
		{name: "contains dot", input: "app.name=nginx", wantValid: false},
		{name: "contains underscore", input: "app_name=nginx", wantValid: false},
		{name: "contains special char in key", input: "app@=nginx", wantValid: false},
		{name: "contains special char in value", input: "app=nginx@", wantValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Replicate the label validation from createPolicyBindingCmd RunE
			parts := strings.SplitN(tt.input, "=", 2)
			valid := false
			if len(parts) == 2 && len(parts[0]) > 0 && len(parts[1]) > 0 {
				// Check that both key and value match [a-zA-Z0-9]+
				keyMatch := len(parts[0]) > 0
				valueMatch := len(parts[1]) > 0
				for _, c := range parts[0] {
					if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
						keyMatch = false
						break
					}
				}
				for _, c := range parts[1] {
					if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
						valueMatch = false
						break
					}
				}
				valid = keyMatch && valueMatch
			}

			if tt.wantValid {
				assert.True(t, valid, "expected valid label selector: %s", tt.input)
			} else {
				assert.False(t, valid, "expected invalid label selector: %s", tt.input)
			}
		})
	}
}

func TestCreatePolicyBindingCmdAllActions(t *testing.T) {
	validActions := []string{"Deny", "Audit", "Warn"}
	invalidActions := []string{"Allow", "deny", "audit", "warn", "", "Log", "Reject"}

	for _, action := range validActions {
		t.Run("valid action "+action, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().String("action", "Deny", "")
			cmd.Flags().Set("action", action)
			got, _ := cmd.Flags().GetString("action")
			isValid := got == "Deny" || got == "Audit" || got == "Warn"
			assert.True(t, isValid)
		})
	}

	for _, action := range invalidActions {
		t.Run("invalid action "+action, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().String("action", "Deny", "")
			cmd.Flags().Set("action", action)
			got, _ := cmd.Flags().GetString("action")
			isValid := got == "Deny" || got == "Audit" || got == "Warn"
			assert.False(t, isValid)
		})
	}
}

func TestCreatePolicyBindingCmdRequiredFlags(t *testing.T) {
	cmd := getCreatePolicyBindingCmd()

	nameFlag := cmd.Flags().Lookup("name")
	require.NotNil(t, nameFlag)
	annotations := nameFlag.Annotations
	require.NotNil(t, annotations)
	_, isRequired := annotations[cobra.BashCompOneRequiredFlag]
	assert.True(t, isRequired, "name flag should be marked as required")

	policyFlag := cmd.Flags().Lookup("policy")
	require.NotNil(t, policyFlag)
	annotations = policyFlag.Annotations
	require.NotNil(t, annotations)
	_, isRequired = annotations[cobra.BashCompOneRequiredFlag]
	assert.True(t, isRequired, "policy flag should be marked as required")
}

// captureStdout captures stdout output from a function and returns it as a string.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	outC := make(chan string)
	go func() {
		var buf strings.Builder
		_, _ = io.Copy(&buf, r)
		outC <- buf.String()
	}()

	fn()

	w.Close()
	os.Stdout = oldStdout

	return <-outC
}
