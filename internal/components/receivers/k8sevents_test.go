// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package receivers

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratek8seventsRbacRules(t *testing.T) {
	rules, err := generatek8seventsRbacRules(logr.Logger{}, k8seventsConfig{})
	require.NoError(t, err)
	require.Len(t, rules, 5)

	assert.Equal(t, []string{""}, rules[0].APIGroups)
	assert.Contains(t, rules[0].Resources, "events")
	assert.Contains(t, rules[0].Resources, "namespaces")
	assert.Contains(t, rules[0].Resources, "pods")
	assert.Contains(t, rules[0].Resources, "nodes")
	assert.Contains(t, rules[0].Resources, "services")
	assert.Equal(t, []string{"get", "list", "watch"}, rules[0].Verbs)

	assert.Equal(t, []string{"apps"}, rules[1].APIGroups)
	assert.Contains(t, rules[1].Resources, "daemonsets")
	assert.Contains(t, rules[1].Resources, "deployments")
	assert.Contains(t, rules[1].Resources, "replicasets")
	assert.Contains(t, rules[1].Resources, "statefulsets")

	assert.Equal(t, []string{"extensions"}, rules[2].APIGroups)
	assert.Contains(t, rules[2].Resources, "daemonsets")
	assert.Contains(t, rules[2].Resources, "deployments")
	assert.Contains(t, rules[2].Resources, "replicasets")

	assert.Equal(t, []string{"batch"}, rules[3].APIGroups)
	assert.Contains(t, rules[3].Resources, "jobs")
	assert.Contains(t, rules[3].Resources, "cronjobs")

	assert.Equal(t, []string{"autoscaling"}, rules[4].APIGroups)
	assert.Contains(t, rules[4].Resources, "horizontalpodautoscalers")
}
