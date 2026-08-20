// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"testing"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func TestFailurePolicyFail_BlocksOnError(t *testing.T) {
	// Test that when failurePolicy is set to "fail", errors block the request
	pluginConfig := `{
		"directives_map": {
			"default": ["SecRuleEngine On"]
		},
		"default_directives": "default",
		"failure_policy": "fail"
	}`

	opt := proxytest.
		NewEmulatorOption().
		WithVMContext(NewVMContext()).
		WithPluginConfiguration([]byte(pluginConfig))

	host, reset := proxytest.NewHostEmulator(opt)
	defer reset()

	// Start the plugin
	require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

	// Initialize HTTP context
	contextID := host.InitializeHttpContext()

	// Simulate a scenario where we cannot get :authority header
	// and the property also fails - this should trigger handleWAFError
	// We don't set the :authority header, and we don't set the host property
	// This will cause the error path in OnHttpRequestHeaders

	// Call OnHttpRequestHeaders - should fail due to missing authority
	action := host.CallOnRequestHeaders(contextID, [][2]string{
		{":method", "GET"},
		{":path", "/test"},
		// Note: :authority is missing
	}, false)

	// With failure_policy=fail, we expect the request to be blocked
	// The handleWAFError function sends a 500 response and returns ActionPause
	assert.Equal(t, types.ActionPause, action)

	// Verify that a local response was sent
	localResponse := host.GetSentLocalResponse(contextID)
	require.NotNil(t, localResponse, "Expected a local response to be sent when failure policy is fail")
	assert.Equal(t, uint32(500), localResponse.StatusCode, "Expected 500 status code on WAF error with fail policy")

	host.CompleteHttpContext(contextID)
}

func TestFailurePolicyAllow_AllowsOnError(t *testing.T) {
	// Test that when failurePolicy is set to "allow", errors allow traffic through
	pluginConfig := `{
		"directives_map": {
			"default": ["SecRuleEngine On"]
		},
		"default_directives": "default",
		"failure_policy": "allow"
	}`

	opt := proxytest.
		NewEmulatorOption().
		WithVMContext(NewVMContext()).
		WithPluginConfiguration([]byte(pluginConfig))

	host, reset := proxytest.NewHostEmulator(opt)
	defer reset()

	// Start the plugin
	require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

	// Initialize HTTP context
	contextID := host.InitializeHttpContext()

	// Simulate the same error scenario - missing :authority
	action := host.CallOnRequestHeaders(contextID, [][2]string{
		{":method", "GET"},
		{":path", "/test"},
		// Note: :authority is missing
	}, false)

	// With failure_policy=allow, we expect the request to continue despite the error
	assert.Equal(t, types.ActionContinue, action)

	// Verify that NO local response was sent (traffic allowed through)
	localResponse := host.GetSentLocalResponse(contextID)
	assert.Nil(t, localResponse, "Expected no local response when failure policy is allow")

	host.CompleteHttpContext(contextID)
}

func findHeader(headers [][2]string, key string) (string, bool) {
	for _, h := range headers {
		if h[0] == key {
			return h[1], true
		}
	}
	return "", false
}

func findCalloutByPath(callouts []proxytest.HttpCalloutAttribute, path string) (proxytest.HttpCalloutAttribute, bool) {
	for _, c := range callouts {
		if v, ok := findHeader(c.Headers, ":path"); ok && v == path {
			return c, true
		}
	}
	return proxytest.HttpCalloutAttribute{}, false
}

func TestFetchRulesFromCache_AuthorizationHeader(t *testing.T) {
	testCases := []struct {
		name            string
		cacheToken      string
		expectAuthZ     bool
		expectedAuthVal string
	}{
		{
			name:            "authorization header included when cache_token is set",
			cacheToken:      "my-secret-token",
			expectAuthZ:     true,
			expectedAuthVal: "Bearer my-secret-token",
		},
		{
			name:        "authorization header omitted when cache_token is empty",
			cacheToken:  "",
			expectAuthZ: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{
				"directives_map": {
					"default": ["SecRuleEngine On"]
				},
				"default_directives": "default",
				"cache_server_cluster": "outbound|80||cache.example.com",
				"cache_server_instance": "my-instance"`
			if tc.cacheToken != "" {
				config += `,
				"cache_token": "` + tc.cacheToken + `"`
			}
			config += `}`

			opt := proxytest.
				NewEmulatorOption().
				WithVMContext(NewVMContext()).
				WithPluginConfiguration([]byte(config))

			host, reset := proxytest.NewHostEmulator(opt)
			defer reset()

			require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

			// fetchRulesFromCache is called during OnPluginStart when cache_server_cluster is set.
			callouts := host.GetCalloutAttributesFromContext(proxytest.PluginContextID)
			fetchCallout, found := findCalloutByPath(callouts, "/rules/my-instance")
			require.True(t, found, "expected a callout to /rules/my-instance from fetchRulesFromCache")

			assert.Equal(t, "outbound|80||cache.example.com", fetchCallout.Upstream)

			authVal, hasAuth := findHeader(fetchCallout.Headers, "authorization")
			if tc.expectAuthZ {
				require.True(t, hasAuth, "expected authorization header to be present")
				assert.Equal(t, tc.expectedAuthVal, authVal)
			} else {
				assert.False(t, hasAuth, "expected authorization header to be absent")
			}

			authority, _ := findHeader(fetchCallout.Headers, ":authority")
			assert.Equal(t, "cache.example.com", authority)
		})
	}
}

func TestCheckLatestRuleSet_AuthorizationHeader(t *testing.T) {
	testCases := []struct {
		name            string
		cacheToken      string
		expectAuthZ     bool
		expectedAuthVal string
	}{
		{
			name:            "authorization header included when cache_token is set",
			cacheToken:      "reload-token",
			expectAuthZ:     true,
			expectedAuthVal: "Bearer reload-token",
		},
		{
			name:        "authorization header omitted when cache_token is empty",
			cacheToken:  "",
			expectAuthZ: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := `{
				"directives_map": {
					"default": ["SecRuleEngine On"]
				},
				"default_directives": "default",
				"cache_server_cluster": "outbound|80||cache.example.com",
				"cache_server_instance": "my-instance",
				"rule_reload_interval_seconds": 10`
			if tc.cacheToken != "" {
				config += `,
				"cache_token": "` + tc.cacheToken + `"`
			}
			config += `}`

			opt := proxytest.
				NewEmulatorOption().
				WithVMContext(NewVMContext()).
				WithPluginConfiguration([]byte(config))

			host, reset := proxytest.NewHostEmulator(opt)
			defer reset()

			require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

			// OnPluginStart dispatches fetchRulesFromCache; Tick dispatches checkLatestRuleSet.
			host.Tick()

			callouts := host.GetCalloutAttributesFromContext(proxytest.PluginContextID)
			latestCallout, found := findCalloutByPath(callouts, "/rules/my-instance/latest")
			require.True(t, found, "expected a callout to /rules/my-instance/latest from checkLatestRuleSet")

			assert.Equal(t, "outbound|80||cache.example.com", latestCallout.Upstream)

			authVal, hasAuth := findHeader(latestCallout.Headers, "authorization")
			if tc.expectAuthZ {
				require.True(t, hasAuth, "expected authorization header to be present")
				assert.Equal(t, tc.expectedAuthVal, authVal)
			} else {
				assert.False(t, hasAuth, "expected authorization header to be absent")
			}
		})
	}
}

func TestRetrieveAddressInfo(t *testing.T) {
	testCases := map[string]struct {
		address          []byte
		port             []byte
		expectedTargetIP string
		expectedPort     int
	}{
		"empty": {
			expectedTargetIP: "",
			expectedPort:     0,
		},
		"127.0.0.1:8080": {
			address:          []byte("127.0.0.10:8080"),
			expectedTargetIP: "127.0.0.10",
			expectedPort:     8080,
		},
		"127.0.0.1:8080 with port": {
			address:          []byte("127.0.0.11:8080"),
			port:             []byte{5, 10, 0, 0, 0, 0, 0, 0}, // 256*10 + 5
			expectedTargetIP: "127.0.0.11",
			expectedPort:     2565,
		},
	}

	for _, target := range []string{"source", "destination"} {
		t.Run(target, func(t *testing.T) {
			for name, tCase := range testCases {
				t.Run(name, func(t *testing.T) {
					opt := proxytest.
						NewEmulatorOption().
						WithVMContext(NewVMContext())

					host, reset := proxytest.NewHostEmulator(opt)
					defer reset()

					require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

					id := host.InitializeHttpContext()

					if len(tCase.address) > 0 {
						err := host.SetProperty([]string{target, "address"}, []byte(tCase.address))
						require.NoError(t, err)
					}

					if len(tCase.port) > 0 {
						err := host.SetProperty([]string{target, "port"}, []byte(tCase.port))
						require.NoError(t, err)
					}

					targetIP, port := retrieveAddressInfo(debuglog.Noop(), target)
					assert.Equal(t, tCase.expectedTargetIP, targetIP)
					assert.Equal(t, tCase.expectedPort, port)

					host.CompleteHttpContext(id)
				})
			}
		})
	}
}
