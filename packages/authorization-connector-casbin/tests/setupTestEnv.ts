// Copyright 2026 IOTA Stiftung.
// Copyright 2026 3Sixty Trade Ltd.
// SPDX-License-Identifier: Apache-2.0.
import { execSync } from "node:child_process";
import { existsSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Guards } from "@3sixty/core";
import * as dotenv from "dotenv";

console.debug("Setting up test environment from .env and .env.dev files");

dotenv.config({
	path: [path.join(__dirname, ".env.dev"), path.join(__dirname, ".env")],
	quiet: true
});

// Validate required environment variables
Guards.stringValue("TestEnv", "TEST_CASBIN_ENDPOINT", process.env.TEST_CASBIN_ENDPOINT);
Guards.stringValue("TestEnv", "TEST_DOCKER_CONTAINER_NAME", process.env.TEST_DOCKER_CONTAINER_NAME);

const TEST_CONTAINER_NAME = process.env.TEST_DOCKER_CONTAINER_NAME;
const DB_CONTAINER_PATH = "/casdoor.db";

export const TEST_CASBIN_ENDPOINT = process.env.TEST_CASBIN_ENDPOINT;

/**
 * Reads the Casdoor client ID and client secret from the Casdoor database inside the Docker container.
 * @returns An object containing the client ID and client secret.
 */
function readCredentialsFromContainer(): { clientId: string; clientSecret: string } {
	const tmpDb = path.join(tmpdir(), `casdoor-${process.pid}.db`);
	// Newer images use WAL mode, so copy the -wal and -shm files alongside the database when present
	const dbFiles = execSync(`docker exec ${TEST_CONTAINER_NAME} sh -c "ls ${DB_CONTAINER_PATH}*"`, {
		stdio: "pipe"
	})
		.toString()
		.split("\n")
		.map(f => f.trim())
		.filter(f => f.length > 0);
	const tmpFiles = dbFiles.map(f => `${tmpDb}${f.slice(DB_CONTAINER_PATH.length)}`);
	try {
		for (let i = 0; i < dbFiles.length; i++) {
			execSync(`docker cp ${TEST_CONTAINER_NAME}:${dbFiles[i]} "${tmpFiles[i]}"`, {
				stdio: "pipe"
			});
		}
		const db = new DatabaseSync(tmpDb);
		const row = db
			.prepare("SELECT client_id, client_secret FROM application WHERE name = 'app-built-in'")
			.get() as { client_id: string; client_secret: string } | undefined;
		db.close();
		if (!row) {
			throw new Error("app-built-in application not found in Casdoor database");
		}
		return { clientId: row.client_id, clientSecret: row.client_secret };
	} finally {
		for (const tmpFile of tmpFiles) {
			if (existsSync(tmpFile)) {
				unlinkSync(tmpFile);
			}
		}
	}
}

const credentials = readCredentialsFromContainer();
export const TEST_CASBIN_CLIENT_ID = credentials.clientId;
export const TEST_CASBIN_CLIENT_SECRET = credentials.clientSecret;
