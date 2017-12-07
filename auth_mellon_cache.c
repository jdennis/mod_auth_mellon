/*
 *
 *   auth_mellon_cache.c: an authentication apache module
 *   Copyright © 2003-2007 UNINETT (http://www.uninett.no/)
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "auth_mellon.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(auth_mellon);
#endif

/*---------------------------------- Defines ---------------------------------*/

#define NAMEID_ENTRY_SIZE 512
#define DIAG_DIR_ENTRY_SIZE 16

#define SESSION_KEY_PREFIX "session_id"
#define NAMEID_KEY_PREFIX "name_id"
#define DIAG_DIR_KEY_PREFIX "diag_dir"

/*--------------------------------- Prototypes -------------------------------*/
/*----------------------------- Internal Functions ---------------------------*/

/**
 * Generate key to lookup session by name_id
 *
 * We need to be able to lookup a session given a name_id. The obvious
 * choice of a key is the string representation of a LassoSaml2NameID
 * object (i.e. it's XML text representation). However the size of the
 * XML text representation of a LassoSaml2NameID is often at least
 * several hundred bytes. Severl socache providers have limitations on
 * the size of keys they can accept (memcache being a good
 * example). Therefore we need to derive a key that will be unique to
 * the NameID but be short enough.
 *
 * A good choice for a short key would be a hash digest of the
 * NameID data.
 *
 * We must also be careful to avoid namespace collisions,
 * our cache may be storing NameID's from multiple IdP's. A name
 * collision would occur if the name was not qualified with a
 * namespace. SAML anticipates this by providing the NameQualifier,
 * SPNameQualifier and SPProvidedID optional elements in the NameID.
 *
 * Taking the digest of the string representation of the complete
 * NameID would capture all the qualifiers. But then we are dependent
 * upon the sending party to send exactly the same NameID data
 * everytime. In theory it should but we would like to be more robust
 * and not depend upon an optional attribute being sent one time and
 * omitted another. But more importantly the NameID may not have any
 * qualifiers specified at all. Simply taking the hash of the
 * presented NameID will not be robust. If we compute a different hash
 * than the one it was stored under we will fail the lookup.
 *
 * Therefore we form a string from pieces of the NameID data and use
 * that string to generate a hash from. The string is:
 *
 * namespace|format|name
 *
 * where | is the string concatenation operator. The above is called
 * the "compendium".
 *
 * If the NameID included a NameQualifier element we utilize that as
 * the namespace value to disambiguate the name, otherwise we use the
 * name of the Issuer as the namespace value. This should be enough to
 * avoid name collisions. The name format is critical to interpreting
 * the name and as such is essential component to avoid name
 * collisions (e.g. two identical names but with different name
 * formats are two uniquely different names)
 *
 * After the compendium is formed a SHA256 digest is computed from it
 * and converted to a hexidecimal string representation. This is our key. 
 *
 * @param[in] r             Current HTTP request
 * @param[in] lasso_name_id The NameID object whose lookup key is
 *                          being computed.
 * @oaran[in] issuer        The NameID object of the entity that
 *                          issued the NameID.
 *
 * @returns
 */
static const char *
am_nameid_key(request_rec *r, LassoSaml2NameID *lasso_name_id,
              LassoSaml2NameID *issuer)
{
    const char *namespace;
    const char *format;
    const char *name_id;
    const char *compendium;
    const char *key;

    if (lasso_name_id == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "lasso_name_id is NULL");
        return NULL;
    }

    if (lasso_name_id->Format != NULL) {
        format = lasso_name_id->Format;
    } else {
        format = LASSO_SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED;
    }

    if (lasso_name_id->NameQualifier != NULL) {
        namespace = lasso_name_id->NameQualifier;
    } else {
        if (issuer != NULL) {
            if (issuer->content != NULL) {
                namespace = issuer->content;
            } else {
                AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                              "name id \"%s\" omitted a name space qualifier "
                              "and the Issuer name id content was NULL. Thus "
                              "the name id is ambiguous because it cannot "
                              "be qualified by Issuer and may collide with "
                              "other unqualified names.",
                              lasso_name_id->content);
                namespace = "<NULL>";
            }
        } else {
            AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                          "name id \"%s\" omitted a name space qualifier, "
                          "and no Issuer was provided. Thus "
                          "the name id is ambiguous because it cannot "
                          "be qualified by Issuer and may collide with "
                          "other unqualified names.",
                          lasso_name_id->content);
            namespace = "<NULL>";
        }
    }

    if (lasso_name_id->content == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "lasso_name_id content is empty");
        return NULL;
    } else {
        name_id = lasso_name_id->content;
    }

    compendium = apr_pstrcat(r->pool,
                             namespace,
                             format,
                             name_id,
                             NULL);
    key = am_sha256_sum(r, (unsigned char *)compendium, strlen(compendium));

    am_diag_log_lasso_node(r, 0, (LassoNode *)lasso_name_id,
                           "compute name_id key, key=%s compendium=%s name_id:",
                           key, compendium);

    return key;
}

/*
 * These key_name() functions exist to enforce a namespace in the
 * cache. The opportunity to store an unintended value under a key
 * name is a potential attack vector we need to guard against. We do
 * this by assuring each type of data stored in the cache is
 * independent of any other data type, hence a key can only access
 * it's own data type and all keys withing a data type have a unique
 * key.
 */

static const char *
session_key_name(request_rec *r, const char *session_id)
{
    return apr_psprintf(r->pool, "%s:%s", SESSION_KEY_PREFIX, session_id);
}

static const char *
name_id_key_name(request_rec *r, LassoSaml2NameID *name_id,
                 LassoSaml2NameID *issuer)
{
    const char *key = NULL;

    key = am_nameid_key(r, name_id, issuer);

    if (key == NULL) {
        return NULL;
    }
    return apr_psprintf(r->pool, "%s:%s", NAMEID_KEY_PREFIX, key);
}

/*------------------------------ Public Functions ----------------------------*/

static apr_status_t
am_destroy_socache(server_rec *s)
{
    am_mod_cfg_rec *mod_cfg = am_get_mod_cfg(s);

    if (mod_cfg->socache_instance) {
        mod_cfg->socache_provider->destroy(mod_cfg->socache_instance, s);
        mod_cfg->socache_instance = NULL;
    }
    return APR_SUCCESS;
}

static apr_status_t
am_destroy_socache_lock(server_rec *s)
{
    am_mod_cfg_rec *mod_cfg = am_get_mod_cfg(s);

    if (mod_cfg->socache_lock) {
        apr_global_mutex_destroy(mod_cfg->socache_lock);
        mod_cfg->socache_lock = NULL;
    }
    return APR_SUCCESS;
}

static apr_status_t
destroy_socache_callback(void *data)
{
    server_rec *s = (server_rec *)data;

    return am_destroy_socache(s);
}

static apr_status_t
destroy_socache_lock_callback(void *data)
{
    server_rec *s = (server_rec *)data;

    return am_destroy_socache_lock(s);
}

apr_status_t
am_get_socache_provider(apr_pool_t *pool, const char *name,
                        ap_socache_provider_t **socache_provider_out,
                        const char **errmsg_out)
{
    apr_status_t apr_status = APR_SUCCESS;
    ap_socache_provider_t *socache_provider = NULL;

    *socache_provider_out = NULL;
    if (errmsg_out) {
        *errmsg_out = NULL;
    }

    socache_provider = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP,
                                          name,
                                          AP_SOCACHE_PROVIDER_VERSION);
    if (socache_provider == NULL) {
        apr_status = APR_NOTFOUND;
        if (errmsg_out) {
            char *errmsg = NULL;
            apr_array_header_t *name_list;
            const char *all_names;

            /* Build a comma-separated list of all registered provider names: */
            name_list = ap_list_provider_names(pool,
                                               AP_SOCACHE_PROVIDER_GROUP,
                                               AP_SOCACHE_PROVIDER_VERSION);
            all_names = apr_array_pstrcat(pool, name_list, ',');

            errmsg = apr_psprintf(pool,
                                  "'%s' session socache not supported "
                                  "(known names: %s). "
                                  "Maybe you need to load the appropriate "
                                  "socache module (mod_socache_%s?).",
                                  name, all_names, name);
            *errmsg_out = errmsg;
        }
        return apr_status;
    }
    
    *socache_provider_out = socache_provider;
    return apr_status;
}

apr_status_t
am_socache_init(apr_pool_t *pool, apr_pool_t *tmp_pool, server_rec *s)
{
    apr_status_t apr_status;
    am_mod_cfg_rec *mod_cfg = am_get_mod_cfg(s);
    struct ap_socache_hints socache_hints;
    const char *errmsg = NULL;

    memset(&socache_hints, 0, sizeof socache_hints);
    socache_hints.avg_id_len = AM_ID_LENGTH;
    socache_hints.avg_obj_size = mod_cfg->socache_session_state_entry_size;;
    socache_hints.expiry_interval = 60000000;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "initializing socache provider_name=\"%s\" "
                 "provider_args=\"%s\" session_state_entry_size=%d",
                 mod_cfg->socache_provider_name,
                 mod_cfg->socache_provider_args,
                 mod_cfg->socache_session_state_entry_size);

    if (mod_cfg->socache_provider == NULL) {
        apr_status = am_get_socache_provider(pool,
                                             mod_cfg->socache_provider_name,
                                             &mod_cfg->socache_provider,
                                             &errmsg);
        if (apr_status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "failed loading socache "
                         "provider_name=%s provider_args=%s errmsg=%s",
                         mod_cfg->socache_provider_name,
                         mod_cfg->socache_provider_args, errmsg);
            return apr_status;
        }
    }

    if (mod_cfg->socache_instance == NULL) {
        errmsg = mod_cfg->socache_provider->create(&mod_cfg->socache_instance,
                                                   mod_cfg->socache_provider_args,
                                                   tmp_pool, pool);
        if (errmsg) {
            apr_status = APR_EGENERAL;
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "failed to create socache provider "
                         "provider_name=%s provider_args=%s errmsg=%s",
                         mod_cfg->socache_provider_name,
                         mod_cfg->socache_provider_args, errmsg);
            return apr_status;
        }
    }

    if (mod_cfg->socache_provider->flags & AP_SOCACHE_FLAG_NOTMPSAFE) {
        apr_status = ap_global_mutex_create(&mod_cfg->socache_lock,
                                            NULL, SOCACHE_ID,
                                            NULL, s, pool, 0);

        if (apr_status != APR_SUCCESS) {
            char buffer[512];
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "mutex_create: Error [%d] \"%s\"",
                         apr_status, apr_strerror(apr_status,
                                                  buffer, sizeof(buffer)));
            return apr_status;
        }

        apr_pool_cleanup_register(pool, (void*)s, destroy_socache_lock_callback,
                                  apr_pool_cleanup_null);
#ifdef AP_NEED_SET_MUTEX_PERMS
        /* On some platforms the mutex is implemented as a file. To
         * allow child processes running as a different user to open
         * it, it is necessary to change the permissions on it. */
        apr_status = ap_unixd_set_global_mutex_perms(mod_cfg->socache_lock);
        if (apr_status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "Failed to set permissions on session lock, "
                         " check User and Group directives");
            return apr_status;
        }
#endif

    }

    apr_status = mod_cfg->socache_provider->init(mod_cfg->socache_instance,
                                         SOCACHE_ID, &socache_hints, s, pool);
    if (apr_status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "failed to initialise %s cache", SOCACHE_ID);
        return apr_status;
    }
    apr_pool_cleanup_register(pool, (void*)s, destroy_socache_callback,
                              apr_pool_cleanup_null);
    return APR_SUCCESS;
}

apr_status_t am_cache_aquire_lock(request_rec *r)
{
    am_mod_cfg_rec *mod_cfg = am_get_mod_cfg(r->server);
    ap_socache_provider_t *socache_provider = mod_cfg->socache_provider;
    apr_status_t rv = APR_SUCCESS;

    if (socache_provider->flags & AP_SOCACHE_FLAG_NOTMPSAFE) {
        if ((rv = apr_global_mutex_lock(mod_cfg->socache_lock)) != APR_SUCCESS) {
            char error_buf[512];
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "apr_global_mutex_lock() failed [%d]: %s",
                          rv, apr_strerror(rv, error_buf, sizeof(error_buf)));
        return rv;
        }
    }
    return APR_SUCCESS;
}

apr_status_t am_cache_release_lock(request_rec *r)
{
    am_mod_cfg_rec *mod_cfg = am_get_mod_cfg(r->server);
    ap_socache_provider_t *socache_provider = mod_cfg->socache_provider;
    apr_status_t rv = APR_SUCCESS;

    if (socache_provider->flags & AP_SOCACHE_FLAG_NOTMPSAFE) {
        if ((rv = apr_global_mutex_unlock(mod_cfg->socache_lock)) != APR_SUCCESS) {
            char error_buf[512];
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "apr_global_mutex_unlock() failed [%d]: %s",
                          rv, apr_strerror(rv, error_buf, sizeof(error_buf)));
        return rv;
        }
    }
    return APR_SUCCESS;
}

static const char *
am_cache_load_session_id_from_name_id(request_rec *r, LassoSaml2NameID *name_id,
                                      LassoSaml2NameID *issuer)
{
    am_mod_cfg_rec *mod_cfg = am_get_mod_cfg(r->server);
    ap_socache_provider_t *socache_provider = mod_cfg->socache_provider;
    ap_socache_instance_t *socache_instance = mod_cfg->socache_instance;
    const char *name_id_key = name_id_key_name(r, name_id, issuer);
    unsigned int name_id_key_len = strlen(name_id_key);
    apr_status_t rv = APR_SUCCESS;

    unsigned int entry_buf_len = NAMEID_ENTRY_SIZE;
    char *entry_buf = NULL;

    am_diag_printf(r, "%s: name_id=%s name_id_key=%s name_id_key_len=%u "
                   "now=%s\n",
                   __func__,
                   am_lasso_name_id_string(r, name_id),
                   name_id_key, name_id_key_len,
                   am_time_t_to_8601(r->pool, apr_time_now()));

    if (name_id == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "name_id was NULL");
        return NULL;
    }

    entry_buf = apr_palloc(r->pool, entry_buf_len + 1);
    if (entry_buf == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to allocate session_id buffer");
        return NULL;
    }

    rv = socache_provider->retrieve(socache_instance, r->server,
                                    (const unsigned char *)name_id_key,
                                    name_id_key_len,
                                    (unsigned char *)entry_buf, &entry_buf_len,
                                    r->pool);
    if (rv == APR_NOTFOUND) {
        am_diag_printf(r, "%s: name_id not found, name_id=%s now=%s\n",
                       __func__,
                       am_lasso_name_id_string(r, name_id),
                       am_time_t_to_8601(r->pool, apr_time_now()));
        return NULL;
    } else if (rv != APR_SUCCESS) {
        char error_buf[512];
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to retrieve name_id=%s now=%s error=[%d]: %s",
                      am_lasso_name_id_string(r, name_id),
                      am_time_t_to_8601(r->pool, apr_time_now()),
                      rv, apr_strerror(rv, error_buf, sizeof(error_buf)));
        return NULL;
    }

    entry_buf[entry_buf_len] = '\0'; /* NULL-terminate */

    am_diag_printf(r, "%s: successfully retrieved %u bytes\n",
                   __func__, entry_buf_len);

    return entry_buf;
}

static const char *
am_cache_load_session_xml_from_session_id(request_rec *r, const char *session_id)
{
    am_mod_cfg_rec *mod_cfg = am_get_mod_cfg(r->server);
    ap_socache_provider_t *socache_provider = mod_cfg->socache_provider;
    ap_socache_instance_t *socache_instance = mod_cfg->socache_instance;
    const char *session_key = session_key_name(r, session_id);
    unsigned int session_key_len = strlen(session_key);
    apr_status_t rv = APR_SUCCESS;

    unsigned int entry_buf_len = mod_cfg->socache_session_state_entry_size;
    char *entry_buf = NULL;

    am_diag_printf(r, "%s: session_id=%s "
                   "session_id_key=%s session_id_key_len=%u "
                   "now=%s\n",
                   __func__, session_id,
                   session_key, session_key_len,
                   am_time_t_to_8601(r->pool, apr_time_now()));

    if (session_id == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "session_id was NULL");
        return NULL;
    }

    entry_buf = apr_palloc(r->pool, entry_buf_len + 1);
    if (entry_buf == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to allocate session xml buffer");
        return NULL;
    }

    rv = socache_provider->retrieve(socache_instance, r->server,
                                    (const unsigned char *)session_key,
                                    session_key_len,
                                    (unsigned char *)entry_buf, &entry_buf_len,
                                    r->pool);

    if (rv == APR_NOTFOUND) {
        am_diag_printf(r, "%s: session not found using session_id=%s now=%s\n",
                       __func__, session_id,
                       am_time_t_to_8601(r->pool, apr_time_now()));
        return NULL;
    } else if (rv != APR_SUCCESS) {
        char error_buf[512];
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to retrieve session_id=%s now=%s error=[%d]: %s",
                      session_id,
                      am_time_t_to_8601(r->pool, apr_time_now()),
                      rv, apr_strerror(rv, error_buf, sizeof(error_buf)));
        return NULL;
    }

    entry_buf[entry_buf_len] = '\0'; /* NULL-terminate */

    am_diag_printf(r, "%s: successfully retrieved %u bytes\n",
                   __func__, entry_buf_len);

    return entry_buf;
}

static apr_status_t
am_cache_store_name_id_entry(request_rec *r,
                             const char *session_id,
                             LassoSaml2NameID *name_id,
                             LassoSaml2NameID *issuer,
                             apr_time_t expiration)
{
    am_mod_cfg_rec *mod_cfg = am_get_mod_cfg(r->server);
    ap_socache_provider_t *socache_provider = mod_cfg->socache_provider;
    ap_socache_instance_t *socache_instance = mod_cfg->socache_instance;
    const char *name_id_key = name_id_key_name(r, name_id, issuer);
    unsigned int name_id_key_len = strlen(name_id_key);
    unsigned int data_len = strlen(session_id);
    apr_status_t rv = APR_SUCCESS;

    /*
     * retrieve will fail if it's not provided with a buffer big
     * enough to receive the data. Worse is the fact the error from
     * some socache providers when the return buffer is too small is
     * APR_NOTFOUND which is not the real reason.
     */

    am_diag_printf(r, "%s: name_id=\"%s\" name_id_key=%s name_id_key_len=%u "
                   "expiration=%s now=%s "
                   "data_len=%u data=\"%s\" \n", __func__, 
                   am_lasso_name_id_string(r, name_id),
                   name_id_key, name_id_key_len,
                   am_time_t_to_8601(r->pool, expiration),
                   am_time_t_to_8601(r->pool, apr_time_now()),
                   data_len, session_id);

    if (data_len > NAMEID_ENTRY_SIZE) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "name_id data size (%u) exceeds maximum "
                      "name_id data size (%u)",
                      data_len, NAMEID_ENTRY_SIZE);
        return APR_FROM_OS_ERROR(EMSGSIZE);
    }

    rv = socache_provider->store(socache_instance, r->server,
                                 (const unsigned char *)name_id_key,
                                 name_id_key_len,
                                 expiration,
                                 (unsigned char *)session_id,
                                 data_len,
                                 r->pool);
    if (rv != APR_SUCCESS) {
        char error_buf[512];
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to store name_id entry "
                      "session_id=%s name_id=%s expiration=%s now=%s "
                      "key=%s error=[%d]: %s",
                      session_id,
                      am_lasso_name_id_string(r, name_id),
                      am_time_t_to_8601(r->pool, expiration),
                      am_time_t_to_8601(r->pool, apr_time_now()),
                      name_id_key,
                      rv, apr_strerror(rv, error_buf, sizeof(error_buf)));
        return rv;
    }

    return APR_SUCCESS;
}

static apr_status_t
am_cache_store_session_id_entry(request_rec *r,
                                const char *session_id,
                                LassoSaml2NameID *name_id,
                                apr_time_t expiration,
                                const char *session_xml)
{
    am_mod_cfg_rec *mod_cfg = am_get_mod_cfg(r->server);
    ap_socache_provider_t *socache_provider = mod_cfg->socache_provider;
    ap_socache_instance_t *socache_instance = mod_cfg->socache_instance;
    const char *session_key = session_key_name(r, session_id);
    unsigned int session_key_len = strlen(session_key);
    unsigned int data_len = strlen(session_xml);
    apr_status_t rv = APR_SUCCESS;

    /*
     * retrieve will fail if it's not provided with a buffer big
     * enough to receive the data. Worse is the fact the error from
     * some socache providers when the return buffer is too small is
     * APR_NOTFOUND which is not the real reason.
     */

    am_diag_printf(r, "%s: session_id=\"%s\" name_id=\"%s\" "
                   "session_key=%s session_key_len=%u "
                   "expiration=%s now=%s "
                   "data_len=%u session_xml:\n%s\n", __func__,
                   session_id, am_lasso_name_id_string(r, name_id),
                   session_key, session_key_len, 
                   am_time_t_to_8601(r->pool, expiration),
                   am_time_t_to_8601(r->pool, apr_time_now()),
                   data_len, session_xml);

    if (data_len > mod_cfg->socache_session_state_entry_size) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "session data size (%u) exceeds maximum "
                      "session data size (%u)",
                      data_len, mod_cfg->socache_session_state_entry_size);
        return APR_FROM_OS_ERROR(EMSGSIZE);
    }

    rv = socache_provider->store(socache_instance, r->server,
                                 (const unsigned char *)session_key,
                                 session_key_len,
                                 expiration,
                                 (unsigned char *)session_xml,
                                 data_len,
                                 r->pool);
    if (rv != APR_SUCCESS) {
        char error_buf[512];
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to store session_id entry "
                      "session_id=%s name_id=%s expiration=%s now=%s "
                      "key=%s error=[%d]: %s",
                      session_id,
                      am_lasso_name_id_string(r, name_id),
                      am_time_t_to_8601(r->pool, expiration),
                      am_time_t_to_8601(r->pool, apr_time_now()),
                      session_key,
                      rv, apr_strerror(rv, error_buf, sizeof(error_buf)));
        return rv;
    }

    return APR_SUCCESS;
}

static apr_status_t
am_cache_delete_name_id_entry(request_rec *r,
                              LassoSaml2NameID *name_id,
                              LassoSaml2NameID *issuer)
{
    am_mod_cfg_rec *mod_cfg = am_get_mod_cfg(r->server);
    ap_socache_provider_t *socache_provider = mod_cfg->socache_provider;
    ap_socache_instance_t *socache_instance = mod_cfg->socache_instance;
    const char *name_id_key = name_id_key_name(r, name_id, issuer);
    unsigned int name_id_key_len = strlen(name_id_key);
    apr_status_t rv = APR_SUCCESS;

    am_diag_printf(r, "%s: name_id=%s name_id_key=%s name_id_key_len=%u "
                   "now=%s\n",
                   __func__,
                   am_lasso_name_id_string(r, name_id),
                   name_id_key, name_id_key_len,
                   am_time_t_to_8601(r->pool, apr_time_now()));

    if (name_id_key == NULL) {
        return APR_EINVAL;
    }

    rv = socache_provider->remove(socache_instance, r->server,
                                  (const unsigned char *)name_id_key,
                                  name_id_key_len,
                                  r->pool);
    if (rv == APR_NOTFOUND) {
        am_diag_printf(r, "%s: name_id not found, name_id=%s now=%s\n",
                       __func__,
                       am_lasso_name_id_string(r, name_id),
                       am_time_t_to_8601(r->pool, apr_time_now()));
        /* If the entry is already absent it's not an error */
        return APR_SUCCESS;
    } else if (rv != APR_SUCCESS) {
        char error_buf[512];
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to delete name_id entry "
                      "name_id=%s now=%s error=[%d]: %s",
                      am_lasso_name_id_string(r, name_id),
                      am_time_t_to_8601(r->pool, apr_time_now()),
                      rv, apr_strerror(rv, error_buf, sizeof(error_buf)));
    }

    return APR_SUCCESS;
}

static apr_status_t
am_cache_delete_session_id_entry(request_rec *r, const char *session_id)
{
    am_mod_cfg_rec *mod_cfg = am_get_mod_cfg(r->server);
    ap_socache_provider_t *socache_provider = mod_cfg->socache_provider;
    ap_socache_instance_t *socache_instance = mod_cfg->socache_instance;
    const char *session_key = session_key_name(r, session_id);
    unsigned int session_key_len = strlen(session_key);
    apr_status_t rv = APR_SUCCESS;

    am_diag_printf(r, "%s: session_id=%s name_id_key=%s name_id_key_len=%u "
                   "now=%s\n",
                   __func__, session_id,
                   session_key, session_key_len,
                   am_time_t_to_8601(r->pool, apr_time_now()));

    rv = socache_provider->remove(socache_instance, r->server,
                                  (const unsigned char *)session_key,
                                  session_key_len,
                                  r->pool);
    if (rv == APR_NOTFOUND) {
        am_diag_printf(r, "%s: session_id not found, session_id=%s now=%s\n",
                       __func__, session_id,
                       am_time_t_to_8601(r->pool, apr_time_now()));
        /* If the entry is already absent it's not an error */
        return APR_SUCCESS;
    } else if (rv != APR_SUCCESS) {
        char error_buf[512];
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to delete session_id entry "
                      "session_id=%s now=%s error=[%d]: %s",
                      session_id, am_time_t_to_8601(r->pool, apr_time_now()),
                      rv, apr_strerror(rv, error_buf, sizeof(error_buf)));
    }

    return APR_SUCCESS;
}

apr_status_t
am_cache_delete_session_entries(request_rec *r,
                                const char *session_id,
                                LassoSaml2NameID *name_id,
                                LassoSaml2NameID *issuer)
{
    apr_status_t session_id_rv = APR_SUCCESS;
    apr_status_t name_id_rv = APR_SUCCESS;
    apr_status_t rv = APR_SUCCESS;

    am_diag_printf(r, "%s: session_id=%s name_id=%s now=%s\n",
                   __func__, session_id,
                   am_lasso_name_id_string(r, name_id),
                   am_time_t_to_8601(r->pool, apr_time_now()));

    if ((rv = am_cache_aquire_lock(r)) != APR_SUCCESS) {
        return rv;
    }

    session_id_rv = am_cache_delete_session_id_entry(r, session_id);
    name_id_rv = am_cache_delete_name_id_entry(r, name_id, issuer);

    rv = session_id_rv != APR_SUCCESS ? session_id_rv : name_id_rv;

    am_cache_release_lock(r);

    return rv;
}

static am_session_state_t *
am_cache_parse_session_xml(request_rec *r, const char *session_xml) {
    xmlDocPtr session_doc = NULL;
    am_session_state_t *session = NULL;

    session_doc = am_get_xml_doc_from_string(r, session_xml);
    if (session_doc == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to parse XML session state text "
                      "into XML document: %s", session_xml);
        return NULL;
    }

    session = am_session_state_from_xml(r, session_doc);
    if (session == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed load session state from XML document");
        return NULL;
    }

    return session;
}

am_session_state_t *
am_cache_load_session_by_session_id(request_rec *r, const char *session_id)
{
    const char *session_xml = NULL;
    am_session_state_t *session = NULL;

    am_diag_printf(r, "%s: lookup session by session _id %s now=%s\n",
                   __func__, session_id,
                   am_time_t_to_8601(r->pool, apr_time_now()));

    if (session_id == NULL) {
        return NULL;
    }

    if (am_cache_aquire_lock(r) != APR_SUCCESS) {
        return NULL;
    }

    session_xml = am_cache_load_session_xml_from_session_id(r, session_id);
    if (session_xml == NULL) {
        am_diag_printf(r, "%s: session not found using session_id, "
                       "session_id=%s now=%s\n",
                       __func__, session_id,
                       am_time_t_to_8601(r->pool, apr_time_now()));
        am_cache_release_lock(r);
        return NULL;
    }

    session = am_cache_parse_session_xml(r, session_xml);

    am_cache_release_lock(r);

    return session;
}

am_session_state_t *
am_cache_load_session_by_name_id(request_rec *r,
                                 LassoSaml2NameID *name_id,
                                 LassoSaml2NameID *issuer)
{
    const char *session_id = NULL;
    const char *session_xml = NULL;
    am_session_state_t *session = NULL;

    am_diag_printf(r, "%s: lookup session by name_id %s, now=%s\n",
                   __func__,
                   am_lasso_name_id_string(r, name_id),
                   am_time_t_to_8601(r->pool, apr_time_now()));

    if (name_id == NULL) {
        return NULL;
    }

    if (am_cache_aquire_lock(r) != APR_SUCCESS) {
        return NULL;
    }

    session_id = am_cache_load_session_id_from_name_id(r, name_id, issuer);
    if (session_id == NULL) {
        am_diag_printf(r, "%s: session not found using name_id, "
                       "name_id=%s now=%s\n",
                       __func__,
                       am_lasso_name_id_string(r, name_id),
                       am_time_t_to_8601(r->pool, apr_time_now()));
        am_cache_release_lock(r);
        return NULL;
    }

    session_xml = am_cache_load_session_xml_from_session_id(r, session_id);
    if (session_xml == NULL) {
        am_diag_printf(r, "%s: session not found using session_id, "
                       "session_id=%s now=%s\n",
                       __func__, session_id,
                       am_time_t_to_8601(r->pool, apr_time_now()));
        am_cache_release_lock(r);
        return NULL;
    }

    am_cache_release_lock(r);

    session = am_cache_parse_session_xml(r, session_xml);

    return session;
}

apr_status_t
am_cache_store_session_entries(request_rec *r,
                               const char *session_id,
                               LassoSaml2NameID *name_id,
                               LassoSaml2NameID *issuer,
                               apr_time_t expiration,
                               const char *session_xml)
{
    apr_status_t session_id_rv = APR_SUCCESS;
    apr_status_t name_id_rv = APR_SUCCESS;
    apr_status_t rv = APR_SUCCESS;

    am_diag_printf(r, "%s: session_id=%s name_id=%s now=%s\n",
                   __func__, session_id,
                   am_lasso_name_id_string(r, name_id),
                   am_time_t_to_8601(r->pool, apr_time_now()));

    if ((rv = am_cache_aquire_lock(r)) != APR_SUCCESS) {
        return rv;
    }

    name_id_rv = am_cache_store_name_id_entry(r, session_id, name_id,
                                              issuer, expiration);
    session_id_rv = am_cache_store_session_id_entry(r, session_id, name_id,
                                                    expiration, session_xml);

    rv = session_id_rv != APR_SUCCESS ? session_id_rv : name_id_rv;

    am_cache_release_lock(r);

    return rv;
}

#ifdef ENABLE_DIAGNOSTICS

static const char *
diag_dir_key_name(request_rec *r, const char *diag_dir)
{
    const char *key = NULL;
    
    key = am_sha256_sum(r, (unsigned char *)diag_dir, strlen(diag_dir));
    return apr_psprintf(r->pool, "%s:%s", DIAG_DIR_KEY_PREFIX, key);
}

apr_status_t
am_cache_store_diag_dir(request_rec *r, const char *diag_dir, const char *data,
                        apr_time_t expiration)
{
    am_mod_cfg_rec *mod_cfg = am_get_mod_cfg(r->server);
    ap_socache_provider_t *socache_provider = mod_cfg->socache_provider;
    ap_socache_instance_t *socache_instance = mod_cfg->socache_instance;
    const char *diag_dir_key = diag_dir_key_name(r, diag_dir);
    unsigned int diag_key_len = strlen(diag_dir_key);
    unsigned int data_len = strlen(data);
    apr_status_t rv = APR_SUCCESS;

    am_diag_printf(r, "%s: diag_dir=\"%s\" "
                   "diag_dir_key=%s diag_key_len=%u "
                   "expiration=%s now=%s data_len=%u data=%s\n", __func__,
                   diag_dir, diag_dir_key, diag_key_len,
                   am_time_t_to_8601(r->pool, expiration),
                   am_time_t_to_8601(r->pool, apr_time_now()),
                   data_len, data);

    if (data_len > DIAG_DIR_ENTRY_SIZE) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "diag_dir data size (%u) exceeds maximum "
                      "diag_dir data size (%u)",
                      data_len, DIAG_DIR_ENTRY_SIZE);
        return APR_FROM_OS_ERROR(EMSGSIZE);
    }

    rv = socache_provider->store(socache_instance, r->server,
                                 (const unsigned char *)diag_dir_key,
                                 diag_key_len,
                                 expiration,
                                 (unsigned char *)data,
                                 data_len,
                                 r->pool);
    if (rv != APR_SUCCESS) {
        char error_buf[512];
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to store diag_dir entry "
                      "diag_dir=%s expiration=%s now=%s "
                      "key=%s error=[%d]: %s",
                      diag_dir,
                      am_time_t_to_8601(r->pool, expiration),
                      am_time_t_to_8601(r->pool, apr_time_now()),
                      diag_dir_key,
                      rv, apr_strerror(rv, error_buf, sizeof(error_buf)));
        return rv;
    }

    return APR_SUCCESS;
}

const char *
am_cache_load_diag_dir(request_rec *r, const char *diag_dir)
{
    am_mod_cfg_rec *mod_cfg = am_get_mod_cfg(r->server);
    ap_socache_provider_t *socache_provider = mod_cfg->socache_provider;
    ap_socache_instance_t *socache_instance = mod_cfg->socache_instance;
    const char *diag_dir_key = diag_dir_key_name(r, diag_dir);
    unsigned int diag_dir_key_len = strlen(diag_dir_key);
    apr_status_t rv = APR_SUCCESS;

    unsigned int entry_buf_len = DIAG_DIR_ENTRY_SIZE;
    char *entry_buf = NULL;

    am_diag_printf(r, "%s: diag_dir=%s diag_dir_key=%s diag_dir_key_len=%u "
                   "now=%s\n",
                   __func__, diag_dir,
                   diag_dir_key, diag_dir_key_len,
                   am_time_t_to_8601(r->pool, apr_time_now()));

    if (diag_dir == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "diag_dir was NULL");
        return NULL;
    }

    entry_buf = apr_palloc(r->pool, entry_buf_len + 1);
    if (entry_buf == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to allocate diag_dir buffer");
        return NULL;
    }

    rv = socache_provider->retrieve(socache_instance, r->server,
                                    (const unsigned char *)diag_dir_key,
                                    diag_dir_key_len,
                                    (unsigned char *)entry_buf, &entry_buf_len,
                                    r->pool);

    if (rv == APR_NOTFOUND) {
        am_diag_printf(r, "%s: diag_dir not found using diag_dir=%s now=%s\n",
                       __func__, diag_dir,
                       am_time_t_to_8601(r->pool, apr_time_now()));
        return NULL;
    } else if (rv != APR_SUCCESS) {
        char error_buf[512];
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to retrieve diag_dir=%s now=%s error=[%d]: %s",
                      diag_dir,
                      am_time_t_to_8601(r->pool, apr_time_now()),
                      rv, apr_strerror(rv, error_buf, sizeof(error_buf)));
        return NULL;
    }

    entry_buf[entry_buf_len] = '\0'; /* NULL-terminate */

    am_diag_printf(r, "%s: successfully retrieved %u bytes\n",
                   __func__, entry_buf_len);

    return entry_buf;
}


#endif
