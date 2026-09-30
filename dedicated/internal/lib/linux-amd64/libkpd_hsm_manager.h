#ifndef LIBKPD_HSM_MANAGER_H
#define LIBKPD_HSM_MANAGER_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Called by csadm_handler to register the per-call output/error smbuf pointers.
 *
 * # Safety
 * Called from C; no Rust invariants are broken — we only store the raw
 * pointers for the duration of the surrounding C call.
 */
void csadm_set_bufs(void *out, void *err);

/**
 * Output handler called by secsrv_interface (2 args: stream_id, char_buf_ptr).
 * stream_id 0 → stdout, 1|3 → stderr, 2 → no-op.
 *
 * The second arg is a raw NUL-terminated char* (confirmed by hex dump).
 * secsrv_interface handles routing to the dst smbuf internally via csadm_set_bufs;
 * we only need to be a valid, callable non-NULL function.
 */
void csadm_output_handler(int stream_id, void *buf);

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
 * Allocates a C string into `*result`.  The caller must free it with
 * `FreeStringC`.
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
