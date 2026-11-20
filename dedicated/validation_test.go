package dedicated

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateAdditionalAdmins tests list-level validation of additional admins
func TestValidateAdditionalAdmins(t *testing.T) {
	admin := func(name, path string) *AdditionalAdminRequest {
		a, err := NewAdditionalAdminRequest(name, path, "", false, true)
		require.NoError(t, err)
		return a
	}
	initial, err := NewSignatureKeyRequest("kp-admin.key", "", "ADMIN", false)
	require.NoError(t, err)
	initial.QuorumSigner = true
	threshold, err := NewThresholdRequest(2, 3)
	require.NoError(t, err)

	tests := []struct {
		name        string
		admins      []*AdditionalAdminRequest
		initial     *SignatureKeyRequest
		threshold   *ThresholdRequest
		errContains string
	}{
		{
			name:      "valid",
			admins:    []*AdditionalAdminRequest{admin("ADMIN2", "kp-admin2.key"), admin("ADMIN3", "kp-admin3.key")},
			initial:   initial,
			threshold: threshold,
		},
		{
			name:        "duplicate name",
			admins:      []*AdditionalAdminRequest{admin("ADMIN2", "a.key"), admin("ADMIN2", "b.key")},
			errContains: "duplicate name",
		},
		{
			name:        "duplicate path",
			admins:      []*AdditionalAdminRequest{admin("ADMIN2", "a.key"), admin("ADMIN3", "a.key")},
			errContains: "duplicate key file path",
		},
		{
			name:        "path reuses initial admin key",
			admins:      []*AdditionalAdminRequest{admin("ADMIN2", "kp-admin.key")},
			initial:     initial,
			errContains: "duplicate key file path",
		},
		{
			name:        "name reserved for initial admin",
			admins:      []*AdditionalAdminRequest{admin(initialAdminUsername, "a.key")},
			errContains: "reserved",
		},
		{
			name:        "nil admin",
			admins:      []*AdditionalAdminRequest{nil},
			errContains: "cannot be nil",
		},
		{
			name:        "insufficient admins for threshold",
			admins:      []*AdditionalAdminRequest{admin("ADMIN2", "a.key")},
			initial:     initial,
			threshold:   threshold,
			errContains: "insufficient admins",
		},
		{
			name: "insufficient quorum signers for threshold",
			admins: []*AdditionalAdminRequest{
				admin("ADMIN2", "a.key"),
				{Name: "ADMIN3", FilePath: "b.key"},
			},
			initial:     initial,
			threshold:   threshold,
			errContains: "insufficient quorum signers",
		},
		{
			name:      "initial admin not a quorum signer",
			admins:    []*AdditionalAdminRequest{admin("ADMIN2", "a.key"), admin("ADMIN3", "b.key")},
			initial:   &SignatureKeyRequest{FilePath: "kp-admin.key"},
			threshold: &ThresholdRequest{SignatureThreshold: 2, RevocationThreshold: 2},
		},
		{
			name:        "initial admin not a quorum signer, too few signers",
			admins:      []*AdditionalAdminRequest{admin("ADMIN2", "a.key")},
			initial:     &SignatureKeyRequest{FilePath: "kp-admin.key"},
			threshold:   &ThresholdRequest{SignatureThreshold: 2, RevocationThreshold: 2},
			errContains: "insufficient",
		},
		{
			name:      "quorum signers not required for default threshold",
			admins:    []*AdditionalAdminRequest{{Name: "ADMIN2", FilePath: "a.key"}},
			initial:   &SignatureKeyRequest{FilePath: "kp-admin.key"},
			threshold: &ThresholdRequest{SignatureThreshold: 1, RevocationThreshold: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAdditionalAdmins(tt.admins, tt.initial, tt.threshold)
			if tt.errContains == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

// TestUserExists tests the case-insensitive user lookup used to make adding
// additional admins safe to repeat.
func TestUserExists(t *testing.T) {
	users := []UserInfo{{Username: "ADMIN"}, {Username: "Admin2"}}

	assert.True(t, userExists(users, "ADMIN"))
	assert.True(t, userExists(users, "admin2"))
	assert.False(t, userExists(users, "ADMIN3"))
	assert.False(t, userExists(nil, "ADMIN"))
}

// TestThresholdNeedsSetting tests that the default 1/1 threshold (and a nil
// request) is skipped, and anything above 1 is applied.
func TestThresholdNeedsSetting(t *testing.T) {
	assert.False(t, thresholdNeedsSetting(nil))
	assert.False(t, thresholdNeedsSetting(&ThresholdRequest{SignatureThreshold: 1, RevocationThreshold: 1}))
	assert.True(t, thresholdNeedsSetting(&ThresholdRequest{SignatureThreshold: 2, RevocationThreshold: 2}))
	assert.True(t, thresholdNeedsSetting(&ThresholdRequest{SignatureThreshold: 2, RevocationThreshold: 1}))
	assert.True(t, thresholdNeedsSetting(&ThresholdRequest{SignatureThreshold: 1, RevocationThreshold: 3}))
}

// TestCanSetThreshold tests that only units not yet past 'claimed' are eligible.
func TestCanSetThreshold(t *testing.T) {
	for _, s := range []CryptoUnitState{CryptoUnitStateAvailable, CryptoUnitStateReserved, CryptoUnitStateClaimed} {
		assert.True(t, canSetThreshold(s), string(s))
	}
	for _, s := range []CryptoUnitState{CryptoUnitStateKMSAuthorized, CryptoUnitStateInitialized, CryptoUnitStateKMSInitialized} {
		assert.False(t, canSetThreshold(s), string(s))
	}
}

// TestThresholdsFromUnits tests the conversion of listed crypto units into
// their threshold configuration.
func TestThresholdsFromUnits(t *testing.T) {
	intPtr := func(v int) *int { return &v }
	units := []CryptoUnit{
		{ID: "cu-1", State: CryptoUnitStateKMSInitialized, SignatureThreshold: intPtr(2), RevocationThreshold: intPtr(3)},
		{ID: "cu-2", State: CryptoUnitStateClaimed},
		{ID: "cu-3", State: CryptoUnitStateClaimed, SignatureThreshold: intPtr(0), RevocationThreshold: intPtr(-1)},
	}

	t.Run("all units", func(t *testing.T) {
		got, err := thresholdsFromUnits(units, "")
		require.NoError(t, err)
		require.Len(t, got, 3)

		assert.Equal(t, CryptoUnitThreshold{CryptoUnitID: "cu-1", State: CryptoUnitStateKMSInitialized, SignatureThreshold: 2, RevocationThreshold: 3}, got[0])
		assert.True(t, got[0].Configured())

		// Missing and non-positive values are reported as not configured (0).
		assert.Equal(t, CryptoUnitThreshold{CryptoUnitID: "cu-2", State: CryptoUnitStateClaimed}, got[1])
		assert.False(t, got[1].Configured())
		assert.Equal(t, CryptoUnitThreshold{CryptoUnitID: "cu-3", State: CryptoUnitStateClaimed}, got[2])
		assert.False(t, got[2].Configured())
	})

	t.Run("single unit", func(t *testing.T) {
		got, err := thresholdsFromUnits(units, "cu-1")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "cu-1", got[0].CryptoUnitID)
		assert.Equal(t, 2, got[0].SignatureThreshold)
		assert.Equal(t, 3, got[0].RevocationThreshold)
	})

	t.Run("unknown unit", func(t *testing.T) {
		got, err := thresholdsFromUnits(units, "cu-404")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cu-404 not found")
		assert.Nil(t, got)
	})

	t.Run("no units", func(t *testing.T) {
		got, err := thresholdsFromUnits(nil, "")
		require.NoError(t, err)
		assert.Empty(t, got)
	})
}

// TestCryptoUnitThresholdUnmarshal tests the list-units JSON keys carrying the
// thresholds, including a unit where they are absent.
func TestCryptoUnitThresholdUnmarshal(t *testing.T) {
	body := `[
		{"id": "cu-1", "instanceId": "inst", "state": "kms-initialized", "signatureThreshold": 2, "revocationThreshold": 3},
		{"id": "cu-2", "instanceId": "inst", "state": "claimed"}
	]`

	var units []CryptoUnit
	require.NoError(t, json.Unmarshal([]byte(body), &units))
	require.Len(t, units, 2)

	require.NotNil(t, units[0].SignatureThreshold)
	require.NotNil(t, units[0].RevocationThreshold)
	assert.Equal(t, 2, *units[0].SignatureThreshold)
	assert.Equal(t, 3, *units[0].RevocationThreshold)

	assert.Nil(t, units[1].SignatureThreshold)
	assert.Nil(t, units[1].RevocationThreshold)
}

func TestSplitKeyFileSpec(t *testing.T) {
	p, pw := splitKeyFileSpec("/tmp/a.key#secret")
	assert.Equal(t, "/tmp/a.key", p)
	assert.Equal(t, "secret", pw)

	p, pw = splitKeyFileSpec("/tmp/a.key#")
	assert.Equal(t, "/tmp/a.key", p)
	assert.Empty(t, pw)

	p, pw = splitKeyFileSpec("/tmp/a.key")
	assert.Equal(t, "/tmp/a.key", p)
	assert.Empty(t, pw)
}

func TestSessionUsernames(t *testing.T) {
	assert.Equal(t, "", sessionUsernames(nil))
	assert.Equal(t, "ADMIN,bob", sessionUsernames([]sessionAuth{{User: "ADMIN"}, {User: "bob"}}))
}

func TestQuorumSessionAuths(t *testing.T) {
	admins := []*AdditionalAdminRequest{
		{Name: "a", FilePath: "/k/a", Passphrase: "pa", QuorumSigner: true},
		nil,
		{Name: "b", FilePath: "/k/b"},
		{Name: "c", FilePath: "/k/c", QuorumSigner: true},
	}

	// ADMIN is not a quorum signer: only flagged additional admins.
	initial := &SignatureKeyRequest{FilePath: "/k/admin"}
	assert.Equal(t, []AuthSpec{
		{Username: "a", KeyFile: "/k/a#pa"},
		{Username: "c", KeyFile: "/k/c#"},
	}, quorumSessionAuths(initial, admins, 5))

	// ADMIN is a quorum signer: it comes first.
	initial.QuorumSigner = true
	initial.Passphrase = "pw"
	assert.Equal(t, []AuthSpec{
		{Username: initialAdminUsername, KeyFile: "/k/admin#pw"},
		{Username: "a", KeyFile: "/k/a#pa"},
		{Username: "c", KeyFile: "/k/c#"},
	}, quorumSessionAuths(initial, admins, 5))

	// Surplus signers beyond the limit are dropped, keeping the first ones.
	assert.Equal(t, []AuthSpec{
		{Username: initialAdminUsername, KeyFile: "/k/admin#pw"},
		{Username: "a", KeyFile: "/k/a#pa"},
	}, quorumSessionAuths(initial, admins, 2))

	assert.Empty(t, quorumSessionAuths(nil, nil, 2))
}

func TestRetryWithBackoff(t *testing.T) {
	var waits []time.Duration
	sleep := func(d time.Duration) { waits = append(waits, d) }

	// Succeeds on the third attempt: waits 1s, 2s, 4s.
	calls := 0
	err := retryWithBackoff(5, time.Second, sleep, func() error {
		calls++
		if calls < 3 {
			return errors.New("not ready")
		}
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, 3, calls)
	assert.Equal(t, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}, waits)

	// Never succeeds: all attempts are used and the last error is wrapped.
	waits, calls = nil, 0
	boom := errors.New("boom")
	err = retryWithBackoff(reconnectMaxAttempts, time.Second, sleep, func() error {
		calls++
		return boom
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
	assert.Equal(t, reconnectMaxAttempts, calls)
	assert.Len(t, waits, reconnectMaxAttempts)
	assert.Equal(t, 16*time.Second, waits[4])
}

func TestThresholdMatches(t *testing.T) {
	want := &ThresholdRequest{SignatureThreshold: 2, RevocationThreshold: 3}
	assert.True(t, thresholdMatches(CryptoUnitThreshold{SignatureThreshold: 2, RevocationThreshold: 3}, want))
	assert.False(t, thresholdMatches(CryptoUnitThreshold{SignatureThreshold: 2, RevocationThreshold: 2}, want))
	assert.False(t, thresholdMatches(CryptoUnitThreshold{SignatureThreshold: 3, RevocationThreshold: 3}, want))
	// Not configured (0/0) never matches a real request.
	assert.False(t, thresholdMatches(CryptoUnitThreshold{}, want))
}
