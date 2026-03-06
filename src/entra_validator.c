/*
Copyright © contributors to CloudNativePG, established as
CloudNativePG a Series of LF Projects, LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
*/

#include "postgres.h"
#include "fmgr.h"
#include "utils/guc.h"
#include "utils/builtins.h"
#include "common/base64.h"
#include "libpq/oauth.h"
#include <string.h>
#include <ctype.h>

PG_MODULE_MAGIC;

/* -----------------------------------------------------------------------------
 * Configurable parameters via GUC (all use "entra." prefix):
 *
 * entra.expected_issuer   : Optional issuer to verify the JWT "iss" claim.
 *                           Example:
 *                           https://login.microsoftonline.com/TENANT_ID/v2.0
 *
 * entra.identity_claim    : JWT claim to use as the PostgreSQL authn_id.
 *                           Default: "preferred_username"
 *                           Set to "email", "sub", "oid", etc. as needed.
 *
 * entra.required_claim    : JWT claim containing an array to check for
 *                           authorization (e.g., "roles", "groups").
 *                           If NULL, skip authorization check (identity-only).
 *
 * entra.required_values   : Comma-separated list of values. Authorization
 *                           succeeds if the required_claim array contains
 *                           ANY of these values. E.g., "db_user,db_admin"
 *
 * entra.debug             : Enable verbose debug logging (no secrets).
 * --------------------------------------------------------------------------- */

static char *entra_expected_issuer = NULL;
static char *entra_identity_claim  = NULL;
static char *entra_required_claim  = NULL;
static char *entra_required_values = NULL;
static bool  entra_debug           = false;

/* ---------------------------------------------------------------------------
 * base64url_decode_to_str
 *
 * Decodes a base64url-encoded string into a NUL-terminated string.
 * Converts base64url alphabet to standard base64 (- -> +, _ -> /),
 * adds padding, then uses PostgreSQL's built-in base64 decoder.
 *
 * Returns palloc'd string on success, NULL on failure.
 * --------------------------------------------------------------------------- */
static char *
base64url_decode_to_str(const char *in)
{
	size_t  len;
	char   *tmp;
	int     pad;
	int     outlen;
	uint8  *out;
	int     n;

	if (!in || !*in)
		return NULL;

	len = strlen(in);
	tmp = pstrdup(in);

	/* Convert base64url alphabet to standard base64 */
	for (size_t i = 0; i < len; i++)
	{
		if (tmp[i] == '-') tmp[i] = '+';
		else if (tmp[i] == '_') tmp[i] = '/';
	}

	/* Add standard base64 padding */
	pad = (4 - (len % 4)) % 4;
	tmp = repalloc(tmp, len + pad + 1);
	for (int i = 0; i < pad; i++) tmp[len + i] = '=';
	tmp[len + pad] = '\0';

	outlen = pg_b64_dec_len(len + pad);
	out = palloc(outlen + 1);
	n = pg_b64_decode(tmp, (int)(len + pad), out, outlen);
	pfree(tmp);
	if (n < 0)
	{
		pfree(out);
		return NULL;
	}
	((char *) out)[n] = '\0';
	return (char *) out;
}

/* ---------------------------------------------------------------------------
 * jwt_get_claim_string
 *
 * Extracts a string claim value from a JWT payload by its key name.
 * Performs NO signature validation — only decodes and parses the payload.
 *
 * Returns palloc'd string on success, NULL if not found or on error.
 * --------------------------------------------------------------------------- */
static char *
jwt_get_claim_string(const char *token, const char *key)
{
	const char *dot1;
	const char *dot2;
	size_t      payload_len;
	char       *payload_b64;
	char       *payload_json;
	char        pat[128];
	const char *k;
	const char *start;
	size_t      vlen;
	char       *val;

	if (!token || !*token || !key)
		return NULL;

	dot1 = strchr(token, '.');
	if (!dot1) return NULL;
	dot2 = strchr(dot1 + 1, '.');
	if (!dot2) return NULL;

	payload_len  = (size_t)(dot2 - (dot1 + 1));
	payload_b64  = pnstrdup(dot1 + 1, payload_len);
	payload_json = base64url_decode_to_str(payload_b64);
	pfree(payload_b64);
	if (!payload_json) return NULL;

	/* Build search pattern: "key" */
	snprintf(pat, sizeof(pat), "\"%s\"", key);
	k = strstr(payload_json, pat);
	if (!k) { pfree(payload_json); return NULL; }

	k = strchr(k, ':');
	if (!k) { pfree(payload_json); return NULL; }
	k++;
	while (*k && isspace((unsigned char) *k)) k++;
	if (*k != '\"') { pfree(payload_json); return NULL; }
	k++;
	start = k;
	while (*k && *k != '\"') k++;
	vlen = (size_t)(k - start);

	val = (char *) palloc(vlen + 1);
	memcpy(val, start, vlen);
	val[vlen] = '\0';
	pfree(payload_json);
	return val;
}

/* ---------------------------------------------------------------------------
 * issuer_ok
 *
 * Verifies the "iss" claim in a JWT against entra_expected_issuer.
 * If entra_expected_issuer is not set, the check is skipped (returns true).
 *
 * Returns true if issuer matches or check is disabled.
 * --------------------------------------------------------------------------- */
static bool
issuer_ok(const char *token)
{
	if (!entra_expected_issuer)
	{
		if (entra_debug)
			elog(DEBUG1, "entra: issuer_ok: expected_issuer not set -> skip");
		return true;
	}

	const char *dot1;
	const char *dot2;
	size_t      payload_len;
	char       *payload_b64;
	char       *payload_json;
	const char *k;
	const char *start;
	size_t      iss_len;
	bool        ok;

	if (!token || !*token) return false;

	dot1 = strchr(token, '.');
	if (!dot1) return false;
	dot2 = strchr(dot1 + 1, '.');
	if (!dot2) return false;

	payload_len  = (size_t)(dot2 - (dot1 + 1));
	payload_b64  = pnstrdup(dot1 + 1, payload_len);
	payload_json = base64url_decode_to_str(payload_b64);
	pfree(payload_b64);
	if (!payload_json) return false;

	k = strstr(payload_json, "\"iss\"");
	if (!k) { pfree(payload_json); return false; }
	k = strchr(k, ':');
	if (!k) { pfree(payload_json); return false; }
	k++;
	while (*k && isspace((unsigned char) *k)) k++;
	if (*k != '\"') { pfree(payload_json); return false; }
	k++;
	start = k;
	while (*k && *k != '\"') k++;
	iss_len = (size_t)(k - start);

	ok = (iss_len == strlen(entra_expected_issuer) &&
		  strncmp(start, entra_expected_issuer, iss_len) == 0);

	if (entra_debug)
		elog(DEBUG1, "entra: issuer_ok=%s", ok ? "true" : "false");

	pfree(payload_json);
	return ok;
}

/* ---------------------------------------------------------------------------
 * jwt_claim_has_any
 *
 * Checks whether a JWT array claim contains ANY value from a
 * comma-separated list of candidate values.
 *
 * token      : raw JWT (header.payload.signature)
 * claim_name : JSON key whose value must be a JSON array (e.g. "roles")
 * csv_values : comma-separated candidates (e.g. "db_user,db_admin")
 *
 * Returns true if the claim array contains at least one of the candidates.
 * --------------------------------------------------------------------------- */
static bool
jwt_claim_has_any(const char *token, const char *claim_name,
				  const char *csv_values)
{
	const char *dot1;
	const char *dot2;
	size_t      payload_len;
	char       *payload_b64;
	char       *payload_json;
	char        pat[128];
	const char *arr_start;
	const char *arr_end;
	char       *csv_copy;
	char       *saveptr;
	char       *candidate;
	bool        found = false;

	if (!token || !claim_name || !csv_values)
		return false;

	dot1 = strchr(token, '.');
	if (!dot1) return false;
	dot2 = strchr(dot1 + 1, '.');
	if (!dot2) return false;

	payload_len  = (size_t)(dot2 - (dot1 + 1));
	payload_b64  = pnstrdup(dot1 + 1, payload_len);
	payload_json = base64url_decode_to_str(payload_b64);
	pfree(payload_b64);
	if (!payload_json) return false;

	/* Find the claim array: "claim_name": [...] */
	snprintf(pat, sizeof(pat), "\"%s\"", claim_name);
	arr_start = strstr(payload_json, pat);
	if (!arr_start) { pfree(payload_json); return false; }

	arr_start = strchr(arr_start, ':');
	if (!arr_start) { pfree(payload_json); return false; }
	arr_start++;
	while (*arr_start && isspace((unsigned char) *arr_start)) arr_start++;
	if (*arr_start != '[') { pfree(payload_json); return false; }
	arr_start++; /* skip '[' */

	arr_end = strchr(arr_start, ']');
	if (!arr_end) { pfree(payload_json); return false; }

	/* Copy the array region for scanning */
	char *arr_region = pnstrdup(arr_start, (size_t)(arr_end - arr_start));

	/* Iterate over comma-separated candidates */
	csv_copy = pstrdup(csv_values);
	candidate = strtok_r(csv_copy, ",", &saveptr);
	while (candidate && !found)
	{
		/* Trim leading/trailing whitespace from candidate */
		while (*candidate && isspace((unsigned char) *candidate)) candidate++;
		char *end = candidate + strlen(candidate) - 1;
		while (end > candidate && isspace((unsigned char) *end)) { *end = '\0'; end--; }

		if (*candidate == '\0') { candidate = strtok_r(NULL, ",", &saveptr); continue; }

		/* Search for "candidate" (quoted) in the array region */
		char search[256];
		snprintf(search, sizeof(search), "\"%s\"", candidate);
		if (strstr(arr_region, search) != NULL)
			found = true;

		candidate = strtok_r(NULL, ",", &saveptr);
	}

	pfree(csv_copy);
	pfree(arr_region);
	pfree(payload_json);
	return found;
}

/* ---------------------------------------------------------------------------
 * validate_token  (OAuthValidatorCallbacks.validate_cb)
 *
 * Main validator callback. Steps:
 *  1. Verify JWT issuer against entra.expected_issuer (if configured)
 *  2. Extract identity from entra.identity_claim (default: preferred_username)
 *  3. If entra.required_claim + entra.required_values are set, check that
 *     the claim array contains at least one of the required values.
 *     Otherwise authorize unconditionally (identity-only mode).
 * --------------------------------------------------------------------------- */
static bool
validate_token(const ValidatorModuleState *state,
			   const char *token, const char *role,
			   ValidatorModuleResult *res)
{
	const char *identity_claim;

	(void) state;
	(void) role;

	res->authorized = false;
	res->authn_id   = NULL;

	if (!token)
	{
		if (entra_debug)
			elog(DEBUG1, "entra: validate_token: no token -> deny");
		return true;
	}

	if (entra_debug)
		elog(DEBUG1, "entra: validate_token called");

	/* 1. Issuer check */
	if (!issuer_ok(token))
	{
		if (entra_debug)
			elog(DEBUG1, "entra: issuer check failed -> deny");
		return true;
	}

	/* 2. Extract identity */
	identity_claim = entra_identity_claim ? entra_identity_claim : "preferred_username";
	res->authn_id  = jwt_get_claim_string(token, identity_claim);

	if (!res->authn_id)
	{
		if (entra_debug)
			elog(DEBUG1, "entra: identity claim '%s' not found in token -> deny",
				 identity_claim);
		return true;
	}

	if (entra_debug)
		elog(DEBUG1, "entra: identity='%s'", res->authn_id);

	/* 3. Authorization */
	if (entra_required_claim && entra_required_values)
	{
		res->authorized = jwt_claim_has_any(token,
											entra_required_claim,
											entra_required_values);
		if (entra_debug)
			elog(DEBUG1, "entra: claim '%s' has any of '%s' = %s",
				 entra_required_claim, entra_required_values,
				 res->authorized ? "true" : "false");
	}
	else
	{
		/* Identity-only mode: no authz claim check */
		res->authorized = true;
		if (entra_debug)
			elog(DEBUG1, "entra: identity-only mode -> authorized");
	}

	return true;
}

/* ---------------------------------------------------------------------------
 * Module startup / shutdown callbacks
 * --------------------------------------------------------------------------- */
static void
validator_startup(ValidatorModuleState *s)
{
	(void) s;
	if (entra_debug)
		elog(DEBUG1, "entra: validator_startup");
}

static void
validator_shutdown(ValidatorModuleState *s)
{
	(void) s;
	if (entra_debug)
		elog(DEBUG1, "entra: validator_shutdown");
}

static const OAuthValidatorCallbacks ENTRA = {
	.magic       = PG_OAUTH_VALIDATOR_MAGIC,
	.startup_cb  = validator_startup,
	.shutdown_cb = validator_shutdown,
	.validate_cb = validate_token,
};

const OAuthValidatorCallbacks *
_PG_oauth_validator_module_init(void)
{
	return &ENTRA;
}

/* ---------------------------------------------------------------------------
 * _PG_init: Define GUC parameters and reserve "entra" prefix.
 * --------------------------------------------------------------------------- */
void
_PG_init(void)
{
	DefineCustomStringVariable("entra.expected_issuer",
		"Expected JWT issuer (iss claim) for verification (optional)",
		NULL,
		&entra_expected_issuer,
		NULL,
		PGC_SIGHUP, 0, NULL, NULL, NULL);

	DefineCustomStringVariable("entra.identity_claim",
		"JWT claim to use as the PostgreSQL authn_id (default: preferred_username)",
		NULL,
		&entra_identity_claim,
		NULL,
		PGC_SIGHUP, 0, NULL, NULL, NULL);

	DefineCustomStringVariable("entra.required_claim",
		"JWT claim array to check for authorization (e.g. roles, groups)",
		NULL,
		&entra_required_claim,
		NULL,
		PGC_SIGHUP, 0, NULL, NULL, NULL);

	DefineCustomStringVariable("entra.required_values",
		"Comma-separated values; any match in required_claim grants access",
		NULL,
		&entra_required_values,
		NULL,
		PGC_SIGHUP, 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("entra.debug",
		"Enable verbose debug logging (no secrets logged)",
		NULL,
		&entra_debug,
		false,
		PGC_SIGHUP, 0, NULL, NULL, NULL);

	MarkGUCPrefixReserved("entra");
}
