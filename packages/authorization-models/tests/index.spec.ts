// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { AuthorizationConnectorFactory } from "../src/factories/authorizationConnectorFactory.js";
import { AUTHORIZATION_METRIC_IDS } from "../src/models/authorizationMetricIds.js";
import { AUTHORIZATION_METRICS } from "../src/models/authorizationMetrics.js";

describe("authorization-models", () => {
	test("every metric id appears exactly once in AUTHORIZATION_METRICS", () => {
		const metricIds = AUTHORIZATION_METRICS.map(metric => metric.id);

		for (const id of Object.values(AUTHORIZATION_METRIC_IDS)) {
			expect(metricIds.filter(metricId => metricId === id)).toHaveLength(1);
		}
		expect(metricIds).toHaveLength(Object.values(AUTHORIZATION_METRIC_IDS).length);
	});

	test("AuthorizationConnectorFactory is defined", () => {
		expect(AuthorizationConnectorFactory).toBeDefined();
	});
});
