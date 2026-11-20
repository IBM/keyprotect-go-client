#ifndef LIBKPD_HSM_MANAGER_H
#define LIBKPD_HSM_MANAGER_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define ERR_NULL_ARG 2

#define ERR_NO_SESSION 3

#define ERR_AUTH 4

/**
 * Append data to an smbuf string buffer.
 */
extern void smbuf_append(void *buf, const char *data);

/**
 * Initialise the library (called once before any session is created).
 */
extern void library_init(void);

/**
 * Create a new session context.
 */
extern int secsrv_create_session(void **p_context,
                                 char *device,
                                 uint32_t l_device,
                                 uint16_t port,
                                 uint32_t connection_timeout,
                                 uint32_t command_timeout,
                                 char *vendorcert,
                                 uint32_t l_vendorcert,
                                 char *operatorcert,
                                 uint32_t l_operatorcert,
                                 char *customercert,
                                 uint32_t l_customercert);

/**
 * Append authentication credentials to an existing session.
 */
extern int session_append_auth(void *p_context,
                               char *p_name,
                               uint32_t l_name,
                               char *p_token_cstr,
                               char *p_passph,
                               uint32_t l_passph);

/**
 * Zeroize and remove every credential previously appended to the
 * session. Later calls run unauthenticated until
 * `session_append_auth` is called again.
 */
extern int session_clear_auth(void *p_context);

/**
 * Enable/disable additional HTTP headers.
 */
extern int session_headers(void *p_context, int enable);

/**
 * Configure an HTTP/HTTPS endpoint for commands.
 */
extern int session_http(void *p_context, char *endpoint, char *rfu, int enable);

/**
 * Release the session and free all resources.
 * Also frees any cached response buffer held by the session.
 */
extern int session_release(void *p_context);

/**
 * Zeroize and free the session's cached response buffer without
 * releasing the session itself.  Call this after consuming a
 * response returned via `p_answ` / `l_answ`.
 */
extern int session_zeroize_cache(void *p_context);

/**
 * List HSM users. rvflags selects the response format (e.g. RET_FORMAT_JSON = 0x20).
 */
extern int hsm_users_list(void *h_cs,
                          char *p_hdrs,
                          uint32_t l_hdrs,
                          uint32_t rvflags,
                          char **p_answ,
                          uint32_t *l_answ);

/**
 * Add a new HSM user.
 * `c8_mechanism` is one of "hmacpwd", "rsasign", "ecdsa".
 * `p_token` / `l_token` is the public key token (or passphrase for hmacpwd).
 */
extern int hsm_user_add(void *h_cs,
                        char *p_hdrs,
                        uint32_t l_hdrs,
                        char *c255_username,
                        uint32_t permission,
                        char *c8_mechanism,
                        char *p_attributes,
                        uint32_t l_attributes,
                        char *p_token,
                        uint32_t l_token,
                        char **p_answ,
                        uint32_t *l_answ);

/**
 * Delete an HSM user.
 */
extern int hsm_user_delete(void *h_cs,
                           char *p_hdrs,
                           uint32_t l_hdrs,
                           char *c255_username,
                           char **p_answ,
                           uint32_t *l_answ);

/**
 * Generate an RSA key pair.
 * `p_keyspec` / `l_keyspec` — key filename; `keysize_in_bits` — e.g. 2048.
 */
extern int hsm_rsa_key_gen(void *h_cs,
                           char *p_hdrs,
                           uint32_t l_hdrs,
                           char *p_keyspec,
                           uint32_t l_keyspec,
                           uint32_t keysize_in_bits,
                           char *p_owner,
                           uint32_t l_owner,
                           char **p_answ,
                           uint32_t *l_answ);

/**
 * Generate a key pair for any supported algorithm.
 * For ECDSA pass keytype = 2 and p_specifier = curve name (e.g. "NISTP256").
 */
extern int hsm_key_gen(void *h_cs,
                       char *p_hdrs,
                       uint32_t l_hdrs,
                       uint32_t keytype,
                       char *p_keyspec,
                       uint32_t l_keyspec,
                       char *p_specifier,
                       uint32_t l_specifier,
                       char *p_owner,
                       uint32_t l_owner,
                       char **p_answ,
                       uint32_t *l_answ);

/**
 * List MBK (Master Backup Key) keys.
 */
extern int hsm_mbk_keys_list(void *h_cs,
                             char *p_hdrs,
                             uint32_t l_hdrs,
                             uint32_t rvflags,
                             char **p_answ,
                             uint32_t *l_answ);

/**
 * Generate a new MBK key.
 * `c_keytype` is typically "AES"; `keylen` in bytes (16/24/32).
 */
extern int hsm_mbk_key_gen(void *h_cs,
                           char *p_hdrs,
                           uint32_t l_hdrs,
                           char *p_keyspec,
                           uint32_t l_keyspec,
                           char *c_keytype,
                           uint32_t keylen,
                           uint8_t n,
                           uint8_t k,
                           char *c8_keyname,
                           char **p_answ,
                           uint32_t *l_answ);

/**
 * Import an existing MBK key into the given slot.
 */
extern int hsm_mbk_key_import(void *h_cs,
                              char *p_hdrs,
                              uint32_t l_hdrs,
                              char *p_keyspec,
                              uint32_t l_keyspec,
                              uint8_t slot_no,
                              char **p_answ,
                              uint32_t *l_answ);

/**
 * Load an alternate-model signature key (public keyfile or PINpad
 * keyspec) into the HSM.
 */
extern int hsm_alt_mdl_sig_key_load(void *h_cs,
                                    char *p_hdrs,
                                    uint32_t l_hdrs,
                                    char *p_keyspec,
                                    uint32_t l_keyspec,
                                    char **p_answ,
                                    uint32_t *l_answ);

/**
 * Restart the HSM. Thresholds are passed via the
 * `Signature-Threshold` / `Revocation-Threshold` headers.
 */
extern int hsm_restart(void *h_cs, char *p_hdrs, uint32_t l_hdrs, char **p_answ, uint32_t *l_answ);

/**
 * Load a file (by filename) into the HSM.
 */
extern int hsm_file_load(void *h_cs,
                         char *p_hdrs,
                         uint32_t l_hdrs,
                         char *p_filename,
                         uint32_t l_filename,
                         char **p_answ,
                         uint32_t *l_answ);

/**
 * Change a keyfile's encryption passphrase.
 * Does not require an active HSM connection.
 */
extern int hsm_keyfile_pw_change(void *h_cs,
                                 char *p_hdrs,
                                 uint32_t l_hdrs,
                                 uint32_t keytype,
                                 char *p_keyfile,
                                 uint32_t l_keyfile,
                                 char *p_passw,
                                 uint32_t l_passw,
                                 char *p_newpass,
                                 uint32_t l_newpass,
                                 char **p_answ,
                                 uint32_t *l_answ);

/**
 * Retrieve the authentication-state bitmask for the session.
 */
extern int hsm_auth_state_get(void *h_cs,
                              char *p_hdrs,
                              uint32_t l_hdrs,
                              uint32_t *authstate,
                              char **p_answ,
                              uint32_t *l_answ);

/**
 * Create a new HSM session.
 *
 * Returns a non-zero `uintptr_t` handle on success, `0` on failure.
 *
 * # Safety
 * All `*const c_char` parameters must be valid NUL-terminated C strings or NULL.
 */
uintptr_t CreateSessionC(const char *endpoint,
                         int port,
                         const char *instance_id,
                         const char *crypto_unit_id,
                         const char *username,
                         const char *keyfile,
                         const char *passphrase,
                         const char *iam_token);

/**
 * Create a new HSM session that authenticates with several credentials.
 *
 * `credentials_json` is a JSON array, one object per admin:
 *
 * ```json
 * [
 *   {"user":"ADMIN","keyfile":"/keys/kp-admin.key","passphrase":""},
 *   {"user":"ADMIN2","keyfile":"/keys/kp-admin2.key","passphrase":"s3cret-pass"}
 * ]
 * ```
 *
 * `keyfile` and `passphrase` are optional. As with `CreateSessionC`, the
 * credentials are not sent to the HSM here: `prepare_auth` calls
 * `session_append_auth` for each entry, in order, before the first command.
 *
 * Returns a non-zero `uintptr_t` handle on success, `0` on failure
 * (including malformed or empty JSON).
 *
 * # Safety
 * All `*const c_char` parameters must be valid NUL-terminated C strings or NULL.
 */
uintptr_t CreateSessionMultiAuthC(const char *endpoint,
                                  int port,
                                  const char *instance_id,
                                  const char *crypto_unit_id,
                                  const char *credentials_json,
                                  const char *iam_token);

/**
 * Close and release an HSM session.
 *
 * Returns `0` on success, `1` if the handle is unknown.
 */
int CloseSessionC(uintptr_t session_id);

/**
 * Update the IAM token associated with a session.
 *
 * Corresponds to Go's `SetTokenGetterC` — stores the token string so that
 * the next API call will include it in the Authorization header.
 */
int SetTokenGetterC(uintptr_t session_id, const char *token_cstr);

/**
 * Retrieve the authentication state bitmask for a session.
 *
 * Writes the state into `*auth_state_out` and returns `0` on success.
 */
int GetAuthStateC(uintptr_t session_id, int *auth_state_out);

/**
 * List HSM users.
 *
 * # Return codes
 * - `0`: success; `*result` holds the JSON user list.
 * - `2`: `result` is NULL.
 * - `3`: no session for `session_id`.
 * - `4`: auth preparation failed.
 * - any other value: vendor rc; `*result` holds the vendor error text.
 *
 * `*result` is set on success AND on vendor failures, so the caller must
 * call `FreeStringC` whenever `*result` is non-null.  `*result` is left
 * untouched for codes 2/3/4.
 */
int ListUsersC(uintptr_t session_id, char **result);

/**
 * Add a new HSM user.
 *
 * `attributes` is a `"KEY=VALUE;KEY2=VALUE2"` string (semicolon-delimited).
 * `headers` is a `"KEY=VALUE%KEY2=VALUE2"` string (percent-delimited).
 * Writes a status message into `*result`; the caller must free it.
 */
int AddUserC(uintptr_t session_id,
             const char *username,
             const char *user_type,
             const char *credential,
             const char *cred_hash,
             const char *attributes,
             const char *headers,
             char **result);

int DeleteUserC(uintptr_t session_id, const char *username);

/**
 * Generate an RSA key pair locally (no active session required).
 *
 * Returns `0` on success; writes error message into `*result` on failure.
 */
int GenerateRSAKeyC(const char *instance_id,
                    const char *key_spec,
                    uint32_t key_size_bits,
                    const char *owner,
                    const char *passphrase,
                    char **result);

int GenerateECDSAKeyC(const char *instance_id,
                      const char *key_spec,
                      const char *curve,
                      const char *owner,
                      const char *passphrase,
                      char **result);

int ListMBKKeysC(uintptr_t session_id, char **result);

int GenerateMBKC(uintptr_t session_id,
                 const char *keyspec,
                 const char *keytype,
                 int keylen,
                 uint8_t n,
                 uint8_t k,
                 const char *keyname,
                 const char *headers,
                 char **result);

int ImportMBKC(uintptr_t session_id,
               const char *keyspec,
               int slot_no,
               const char *headers,
               char **result);

/**
 * Load an alternate-model signature key (`hsm_alt_mdl_sig_key_load`).
 *
 * `keyspec` is the path to the public keyfile (or a PINpad keyspec).
 * `headers` is a `"KEY=VALUE%KEY2=VALUE2"` string (percent-delimited) of
 * additional HTTP headers; may be NULL or empty.
 * Returns `0` on success and `1` on failure; `*result` receives a status or
 * error message that the caller must release with `FreeStringC`.
 */
int AltMdlSigKeyLoadC(uintptr_t session_id,
                      const char *keyspec,
                      const char *headers,
                      char **result);

/**
 * Load a file into the HSM (`hsm_file_load`).
 *
 * `filename` is the name/path of the file to load.
 * `headers` is a `"KEY=VALUE%KEY2=VALUE2"` string (percent-delimited) of
 * additional HTTP headers; may be NULL or empty.
 * Returns `0` on success and `1` on failure; `*result` receives a status or
 * error message that the caller must release with `FreeStringC`.
 */
int FileLoadC(uintptr_t session_id, const char *filename, const char *headers, char **result);

/**
 * Restart the HSM (`hsm_restart`).
 *
 * `headers` is a `"KEY=VALUE%KEY2=VALUE2"` string (percent-delimited) of
 * additional HTTP headers; may be NULL or empty. Threshold values are
 * supplied by the caller through this string, e.g.
 * `"Signature-Threshold=2%Revocation-Threshold=2"`.
 * Returns `0` on success and `1` on failure; `*result` receives a status or
 * error message that the caller must release with `FreeStringC`.
 */
int RestartC(uintptr_t session_id, const char *headers, char **result);

int ChangeUserPasswordC(uintptr_t session_id,
                        const char *username,
                        const char *old_password,
                        const char *new_password);

int GetCryptoUnitIDC(uintptr_t session_id, char **result);

/**
 * Free a string previously returned by any `*C` function that writes to a
 * `**char` output parameter.
 *
 * This MUST be called from the same language side that received the string.
 * Do NOT call C's `free()` on these pointers.
 *
 * # Safety
 * `str` must be either NULL or a pointer previously returned by this library.
 */
void FreeStringC(char *str);

/**
 * Stub matching the Go implementation.  Per-session error storage is not
 * currently maintained; callers should check return codes and `*result`
 * output strings instead.
 */
int GetLastErrorC(uintptr_t _session_id, char **result);

/**
 * No-op stub — reserved for future initialisation logic.
 */
int InitalizeCryptoUnitC(char **result);

#endif /* LIBKPD_HSM_MANAGER_H */
