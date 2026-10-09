// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { MetricType, type ITelemetryMetric } from "@3sixty/telemetry-models";
import { AUTHORIZATION_METRIC_IDS } from "./authorizationMetricIds.js";

/**
 * Metrics registered by the authorization service.
 */
export const AUTHORIZATION_METRICS: ITelemetryMetric[] = [
	{
		id: AUTHORIZATION_METRIC_IDS.PoliciesAdded,
		label: "Policies added",
		type: MetricType.Counter
	},
	{
		id: AUTHORIZATION_METRIC_IDS.PoliciesRemoved,
		label: "Policies removed",
		type: MetricType.Counter
	},
	{
		id: AUTHORIZATION_METRIC_IDS.RolesAdded,
		label: "Roles added",
		type: MetricType.Counter
	},
	{
		id: AUTHORIZATION_METRIC_IDS.RolesRemoved,
		label: "Roles removed",
		type: MetricType.Counter
	},
	{
		id: AUTHORIZATION_METRIC_IDS.RoleInheritancesAdded,
		label: "Role inheritances added",
		type: MetricType.Counter
	},
	{
		id: AUTHORIZATION_METRIC_IDS.RoleInheritancesRemoved,
		label: "Role inheritances removed",
		type: MetricType.Counter
	}
];
