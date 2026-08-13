// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import {
	AuthorizationConnectorFactory,
	type IAuthorizationConnector
} from "@twin.org/authorization-models";
import { AuthorizationService } from "../src/authorizationService.js";

const TEST_NAMESPACE = "test";

describe("AuthorizationService", () => {
	beforeEach(() => {
		AuthorizationConnectorFactory.register(
			TEST_NAMESPACE,
			() => ({ className: () => TEST_NAMESPACE }) as unknown as IAuthorizationConnector
		);
	});

	afterEach(() => {
		AuthorizationConnectorFactory.unregister(TEST_NAMESPACE);
	});

	test("Can create an instance", async () => {
		const service = new AuthorizationService();
		expect(service).toBeDefined();
	});
});
