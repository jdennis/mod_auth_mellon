/*
 *
 *   auth_mellon_session.c: an authentication apache module
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

/*--------------------------------- Prototypes -------------------------------*/

static apr_status_t
am_session_state_free(am_session_state_t *session);

/*--------------------------- XML Serialization ------------------------------*/

/*
 * With XML how do you distinguish between an empty value and NULL?
 *
 * An empty value is a value that was initialized but contains no data
 * (e.g. for string data it would be the empty string ""). A NULL
 * value was never initialized to any value. XML uses the term nil to
 * mean NULL. Nil is indicated by setting the xsi:nil attribute on the
 * element to "true" or "1", "true" is preferred.
 *
 * Either of these two constructs <FOO/>, or <FOO></FOO> would parse
 * FOO's content as the empty string. To indicate FOO was never set to
 * any value (e.g. is NULL) set the xsi:nil attribute on the FOO
 * element like this <FOO xsi:nil="true"/>.
 */

/**
 * Set the xml node to a nil value (e.g. it represents a NULL value)
 *
 * @param[in] node XML node whose attribute will indicate it's a nil value
 *
 * @returns void
 */
void
set_xmlnode_nil(xmlNodePtr node)
{
    xmlNsPtr xsi_ns = NULL;

    xsi_ns = xmlSearchNsByHref(NULL, node, (const xmlChar *)LASSO_XSI_HREF);
    xmlNewNsProp(node, xsi_ns,
                 (const xmlChar *)XSI_NIL, (const xmlChar *)"true");
}

/**
 * Is the xml node nil? (i.e. does it represent a NULL value)
 *
 * @param[in] node XML node to be tested for NIL value
 *
 * @returns true if nil, false if non-nil
 */
bool
is_xmlnode_nil(xmlNodePtr node)
{
    const char *nil = NULL;
    bool result;

    nil = (const char *)xmlGetNsProp(node,
                                     (const xmlChar *)XSI_NIL,
                                     (const xmlChar *)LASSO_XSI_HREF);
    if (nil && (strcasecmp(nil, "true") == 0 || strcmp(nil, "1") == 0)) {
        result = true;
    } else {
        result = false;
    }
    xmlFree((void *)nil);
    return result;
}

static xmlNode *
export_to_xml_lasso_node_dump(request_rec *r, xmlNode *parent, xmlNsPtr ns,
                              const char *name, LassoNode *lasso_node)
{
    xmlNode *xml_node = NULL;
    xmlNode *xml_dump = NULL;

    xml_node = xmlNewChild(parent, ns, (const xmlChar *)name, NULL);
    if (xml_node == NULL) return NULL;

    if (lasso_node == NULL) {
        set_xmlnode_nil(xml_node);
        return xml_node;
    }

    /*
     * 2nd parameter is boolean indicating a dump is desired.  A dump
     * includes non-protocol private needed to restore a lasso object
     * to it's full internal state.
     */
    xml_dump = lasso_node_get_xmlNode(lasso_node, TRUE);
    if (xml_dump == NULL) return NULL;

    xmlAddChild(xml_node, xml_dump);

    return xml_node;
}

/* === Serialize String === */

static xmlNode *
export_to_xml_string(request_rec *r, xmlNode *parent, xmlNsPtr ns,
                     const char *name, const char *string_value)
{
    xmlNode *xml_node = NULL;


    xml_node = xmlNewTextChild(parent, ns,
                               (const xmlChar *)name,
                               (const xmlChar *)string_value);

    if (string_value == NULL) {
        set_xmlnode_nil(xml_node);
    }

    return xml_node;
}

static int
import_from_xml_string(request_rec *r, xmlNode *xml_node,
                       const char **string_out)
{
    const char *string = NULL;

    if (is_xmlnode_nil(xml_node)) {
        *string_out = NULL;
        return OK;
    }

    string = (const char *)xmlNodeGetContent(xml_node);
    *string_out = apr_pstrdup(r->pool, string);
    xmlFree((void *)string);

    return APR_SUCCESS;
}

/* === Serialize CData === */

static xmlNode *
export_to_xml_cdata(request_rec *r, xmlNode *parent, xmlNsPtr ns,
                     const char *name, const char *cdata_value)
{
    xmlNode *xml_node = NULL;
    xmlNode *cdata_node = NULL;

    xml_node = xmlNewChild(parent, ns,
                           (const xmlChar *)name,
                           NULL);

    if (cdata_value == NULL) {
        set_xmlnode_nil(xml_node);
        return xml_node;
    }

    cdata_node = xmlNewCDataBlock(parent->doc,
                                  (const xmlChar *)cdata_value,
                                  strlen(cdata_value));
    xmlAddChild(xml_node, cdata_node);
    return xml_node;
}

static int
import_from_xml_cdata(request_rec *r, xmlNode *xml_node,
                       const char **cdata_out)
{
    const char *cdata = NULL;

    if (is_xmlnode_nil(xml_node)) {
        *cdata_out = NULL;
        return OK;
    }

    cdata = (const char *)xmlNodeGetContent(xml_node);
    *cdata_out = apr_pstrdup(r->pool, cdata);
    xmlFree((void *)cdata);

    return APR_SUCCESS;
}

/* === Serialize Integer === */

static xmlNode *
export_to_xml_int(request_rec *r, xmlNode *parent, xmlNsPtr ns,
                  const char *name, int int_value)
{
    char *int_string = NULL;
    xmlNode *xml_node = NULL;

    int_string = apr_psprintf(r->pool, "%d", int_value);
    xml_node = xmlNewTextChild(parent, ns, (const xmlChar *)name,
                               (const xmlChar *)int_string);
    return xml_node;
}

static int
import_from_xml_int(request_rec *r, xmlNode *xml_node, int *int_out)
{
    const char *int_string = (const char *)xmlNodeGetContent(xml_node);
    int int_value;

    if (is_xmlnode_nil(xml_node)) {
        *int_out = 0;
        xmlFree((void *)int_string);
        return LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND;
    }

    int_value = strtol(int_string, NULL, 10);
    *int_out = int_value;

    xmlFree((void *)int_string);
    return APR_SUCCESS;
}

/* === Serialize Time === */

static xmlNode *
export_to_xml_time(request_rec *r, xmlNode *parent, xmlNsPtr ns,
                   const char *name, apr_time_t time_value)
{
    char *time_string = NULL;
    xmlNode *xml_node = NULL;

    time_string = am_time_t_to_8601(r->pool, time_value);
    xml_node = xmlNewTextChild(parent, ns, (const xmlChar *)name,
                               (const xmlChar *)time_string);
    return xml_node;
}

static int
import_from_xml_time(request_rec *r, xmlNode *xml_node, apr_time_t *time_out)
{
    const char *time_string = (const char *)xmlNodeGetContent(xml_node);
    apr_time_t time_value;

    if (is_xmlnode_nil(xml_node)) {
        *time_out = 0;
        xmlFree((void *)time_string);
        return LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND;
    }

    time_value = am_parse_timestamp(r, time_string);
    *time_out = time_value;

    xmlFree((void *)time_string);
    return APR_SUCCESS;
}

/* === Serialize LassoSaml2NameID === */

static xmlNode *
export_to_xml_lasso_name_id(request_rec *r, xmlNode *parent, xmlNsPtr ns,
                             const char *name, LassoSaml2NameID *lasso_name_id)
{
    return export_to_xml_lasso_node_dump(r, parent, ns, name,
                                         (LassoNode *)lasso_name_id);
}

static int
import_from_xml_lasso_name_id(request_rec *r, xmlNode *xml_node,
                               LassoSaml2NameID **lasso_name_id_out)
{
    LassoSaml2NameID *lasso_name_id = NULL;
    xmlNodePtr lasso_name_id_node = NULL;

    if (is_xmlnode_nil(xml_node)) {
        *lasso_name_id_out = NULL;
        return APR_SUCCESS;
    }

    lasso_name_id_node = am_xml_get_first_child(xml_node, "NameID",
                                                LASSO_SAML2_ASSERTION_HREF);
    if (lasso_name_id_node == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Expected to find LassoSaml2NameID as child of "
                      "XML node \"%s\"", xml_node->name);
        *lasso_name_id_out = NULL;
        return LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND;
    }

    lasso_name_id = (LassoSaml2NameID *)
        lasso_node_new_from_xmlNode(lasso_name_id_node);

    if (! LASSO_IS_SAML2_NAME_ID(lasso_name_id)) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Expected to find LassoSaml2NameID in XML node \"%s\" "
                      "but found lasso node \"%s\"", xml_node->name,
                      lasso_node_get_name((LassoNode *)lasso_name_id));
        return LASSO_XML_ERROR_NODE_NOT_FOUND;
    }
    *lasso_name_id_out = lasso_name_id;

    return APR_SUCCESS;
}

/* === Serialize Environment Attributes === */

static xmlNode *
export_to_xml_env_attrs(request_rec *r, xmlNode *parent, xmlNsPtr ns,
                        const char *node_name, apr_hash_t *env_attrs)
{
    xmlNode *env_attrs_node = NULL;
    apr_hash_index_t *hi;
    char *attr_name;
    apr_array_header_t *values;
    int i;
    char *attr_value;
    xmlNodePtr attr_node;


    env_attrs_node = xmlNewChild(parent, ns, (const xmlChar *)node_name, NULL);
    if (env_attrs_node == NULL) return NULL;

    /*
     * Iterate over hash entries. Entry name is attribute name. Entry value
     * is an array of strings because attributes may be multi-valued.
     */
    for (hi = apr_hash_first(apr_hash_pool_get(env_attrs), env_attrs);
         hi;
         hi = apr_hash_next(hi)) {
        apr_hash_this(hi, (void*)&attr_name, NULL, (void*)&values);

        /* Create an Attribute node and set the attribute name */
        attr_node = xmlNewChild(env_attrs_node, ns,
                                (const xmlChar *)"Attribute", NULL);
        if (attr_node == NULL) return NULL;

        xmlNewNsProp(attr_node, ns, (const xmlChar *)"Name",
                     (const xmlChar *)attr_name);

        /*
         * Iterate over attribute values (if provided) adding an AttributeValue
         * node and it's string value.
         */
        if (values) {
            for (i=0; i < values->nelts; i++) {
                attr_value = APR_ARRAY_IDX(values, i, char *);
                export_to_xml_string(r, attr_node, ns,
                                     "AttributeValue", attr_value);
            }
        }
    }

    return env_attrs_node;
}

static int
import_from_xml_env_attrs(request_rec *r, am_session_state_t *ss,
                          xmlNode *xml_node)
{
    xmlNodePtr attr_node, attr_value_node;
    const char *attr_name = NULL, *attr_value = NULL;
    apr_array_header_t *values = NULL;

    /* Iterate over all Attribute nodes */
    for (attr_node = xml_node->children;
         attr_node;
         attr_node = attr_node->next) {

        if (!IS_NODE(attr_node, "Attribute", SESSION_STATE_NS_HREF)) continue;

        /*
         * Get the attribute name and add this attribute to the session's
         * set of attributes.
         */
        attr_name = (const char *)
            xmlGetNsProp(attr_node,
                         (const xmlChar *)"Name",
                         (const xmlChar *)SESSION_STATE_NS_HREF);
        if (attr_name == NULL) continue;

        values = am_session_set_env_attr_name(r, ss, attr_name);
        if (values == NULL) {
            xmlFree((void *)attr_name);
            return APR_ENOMEM;
        }

        /*
         * Iterate over all the attribute values associated with this
         * attribute adding the value to array of values.
         */
        for (attr_value_node = attr_node->children;
             attr_value_node;
             attr_value_node = attr_value_node->next) {

            if (!IS_NODE(attr_value_node, "AttributeValue",
                         SESSION_STATE_NS_HREF)) continue;

            attr_value = (const char *)xmlNodeGetContent(attr_value_node);
            if (is_xmlnode_nil(attr_value_node)) {
                attr_value = NULL;
            }
            values = am_session_set_env_attr_value(r, ss, attr_name, attr_value);
            if (values == NULL) {
                xmlFree((void *)attr_name);
                xmlFree((void *)attr_value);
                return APR_ENOMEM;
            }
        }
    }
    xmlFree((void *)attr_name);
    xmlFree((void *)attr_value);
    return APR_SUCCESS;
}

/* === Serialize SessionState === */

/**
 * Serialize from an XML document into a session state object.
 *
 * Allocate a session state object. Initialize it's values from the data in the
 * provided XML document object.
 *
 * @param[in] r   Current HTTP request
 * @param[in] doc XML document object containing session state representation
 *
 * @returns Allocated & initialized session state object.
 */

am_session_state_t *
am_session_state_from_xml(request_rec *r, xmlDocPtr doc)
{
    am_session_state_t *ss = NULL;
    xmlNodePtr root_node = NULL;
    const char *session_state_version = NULL;
    xmlNode *attr_node;
    apr_status_t rv;

    if (doc == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "XML document was NULL");
        goto fail;
    }

    if ((ss = am_session_state_new(r)) == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to allocate new session state");
        goto fail;
    }

    root_node = xmlDocGetRootElement(doc);

    /* Check document version so we know how to parse it */
    session_state_version = (const char *)
        xmlGetNsProp(root_node, (const xmlChar *)"Version",
                     (const xmlChar *)SESSION_STATE_NS_HREF);

    if (strcmp(session_state_version, SESSION_STATE_VERSION) != 0) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unsupported session state version: %s",
                      session_state_version);
        goto fail;
    }

    /*
     * Iterate over all top level nodes, each corresponds to a member
     * of the am_session_state_t object.
     */
    for (attr_node = root_node->children;
         attr_node;
         attr_node = attr_node->next) {

        /* SessionID */
        if (IS_NODE(attr_node, "SessionID",
                    SESSION_STATE_NS_HREF)) {
            rv = import_from_xml_string(r, attr_node, &ss->session_id);
            if (rv != APR_SUCCESS) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                              "session import of 'SessionID' element failed");
                goto fail;
            }
        }
        /* NameID */
        else if (IS_NODE(attr_node, "NameID",
                         SESSION_STATE_NS_HREF)) {
            rv = import_from_xml_lasso_name_id(r, attr_node, &ss->lasso_name_id);
            if (rv != APR_SUCCESS) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                              "session import of 'NameID' element failed");
                goto fail;
            }
        }
        /* Issuer */
        else if (IS_NODE(attr_node, "Issuer",
                         SESSION_STATE_NS_HREF)) {
            rv = import_from_xml_lasso_name_id(r, attr_node, &ss->issuer);
            if (rv != APR_SUCCESS) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                              "session import of 'Issuer' element failed");
                goto fail;
            }
        }
        /* Expires */
        else if (IS_NODE(attr_node, "Expires",
                         SESSION_STATE_NS_HREF)) {
            rv = import_from_xml_time(r, attr_node, &ss->expires);
            if (rv != APR_SUCCESS) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                              "session import of 'Expires' element failed");
                goto fail;
            }
        }
        /* LoggedIn */
        else if (IS_NODE(attr_node, "LoggedIn",
                         SESSION_STATE_NS_HREF)) {
            rv = import_from_xml_int(r, attr_node, &ss->logged_in);
            if (rv != APR_SUCCESS) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                              "session import of 'LoggedIn' element failed");
                goto fail;
            }
        }
        /* User */
        else if (IS_NODE(attr_node, "User",
                         SESSION_STATE_NS_HREF)) {
            rv = import_from_xml_string(r, attr_node, &ss->user);
            if (rv != APR_SUCCESS) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                              "session import of 'User' element failed");
                goto fail;
            }
        }
        /* CookieToken */
        else if (IS_NODE(attr_node, "CookieToken",
                         SESSION_STATE_NS_HREF)) {
            rv = import_from_xml_string(r, attr_node, &ss->cookie_token);
            if (rv != APR_SUCCESS) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                              "session import of 'CookieToken' element failed");
                goto fail;
            }
        }
        /* EnvironmentAttributes */
        else if (IS_NODE(attr_node, "EnvironmentAttributes",
                         SESSION_STATE_NS_HREF)) {
            rv = import_from_xml_env_attrs(r, ss, attr_node);
            if (rv != APR_SUCCESS) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                              "session import of 'EnvironmentAttributes' "
                              "element failed");
                goto fail;
            }
        }
        /* SAMLResponse */
        else if (IS_NODE(attr_node, "SAMLResponse",
                         SESSION_STATE_NS_HREF)) {
            rv = import_from_xml_string(r, attr_node, &ss->saml_response);
            if (rv != APR_SUCCESS) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                              "session import of 'SAMLResponse' element failed");
                goto fail;
            }
        }
        /* LassoIdentity */
        else if (IS_NODE(attr_node, "LassoIdentity",
                         SESSION_STATE_NS_HREF)) {
            rv = import_from_xml_cdata(r, attr_node,
                                       &ss->lasso_identity_dump);
            if (rv != APR_SUCCESS) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                              "session import of 'LassoIdentity' "
                              "element failed");
                goto fail;
            }
        }
        /* LassoSession */
        else if (IS_NODE(attr_node, "LassoSession",
                         SESSION_STATE_NS_HREF)) {
            rv = import_from_xml_cdata(r, attr_node, &ss->lasso_session_dump);
            if (rv != APR_SUCCESS) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                              "session import of 'LassoSession' element failed");
                goto fail;
            }
        }
        /* Unknown */
        else {
            /* We permit whitespace, otherwise error */
            if (xmlIsBlankNode(attr_node)) continue;

            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "unknown xml session state node \"%s\"",
                          attr_node->name);
                goto fail;
        }
    }

    xmlFree((void *)session_state_version);
    return ss;

 fail:
    xmlFree((void *)session_state_version);
    return NULL;
}

/**
 * Serialize a session state object into an XML document
 *
 * Given a session state object render it into an XML document representation.
 *
 * @param[in] ss session state object
 *
 * @returns XML document object
 */
xmlDocPtr am_session_state_to_xml(request_rec *r, am_session_state_t *ss)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr root_node = NULL;
    xmlNsPtr mellon_ns = NULL;
    xmlNodePtr node = NULL;

    /* Create document and the root node of the document */
    doc = xmlNewDoc((const xmlChar *)"1.0");
    if (doc == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to allocate new XML document");
        goto fail;
    }

    root_node = xmlNewNode(NULL, (const xmlChar *)SESSION_STATE_NODE_NAME);
    if (root_node == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to allocate root node of XML doc");
        goto fail;
    }

    xmlDocSetRootElement(doc, root_node);

    /* Set XML namespaces */
    mellon_ns = xmlNewNs(root_node,
                         (const xmlChar *)SESSION_STATE_NS_HREF,
                         (const xmlChar *)SESSION_STATE_NS_PREFIX);
    xmlSetNs(root_node, mellon_ns);

    xmlNewNs(root_node,
             (const xmlChar *)LASSO_XSI_HREF,
             (const xmlChar *)LASSO_XSI_PREFIX);

    /* Set document version */
    xmlNewNsProp(root_node, mellon_ns, (const xmlChar *)"Version",
                 (const xmlChar *)SESSION_STATE_VERSION);

    /*
     * Add data to the document.
     */

    /* SessionID */
    node = export_to_xml_string(r, root_node, mellon_ns,
                                "SessionID", ss->session_id);
    if (node == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "session export of 'SessionID' element failed");
        goto fail;
    }

    /* NameID */
    node = export_to_xml_lasso_name_id(r, root_node, mellon_ns,
                                       "NameID", ss->lasso_name_id);
    if (node == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "session export of 'NameID' element failed");
        goto fail;
    }

    /* Issuer */
    node = export_to_xml_lasso_name_id(r, root_node, mellon_ns,
                                       "Issuer", ss->issuer);
    if (node == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "session export of 'Issuer' element failed");
        goto fail;
    }

    /* Expires */
    node = export_to_xml_time(r, root_node, mellon_ns,
                              "Expires", ss->expires);
    if (node == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "session export of 'Expires' element failed");
        goto fail;
    }

    /* LoggedIn */
    node = export_to_xml_int(r, root_node, mellon_ns,
                             "LoggedIn", ss->logged_in);
    if (node == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "session export of 'LoggedIn' element failed");
        goto fail;
    }

    /* User */
    node = export_to_xml_string(r, root_node, mellon_ns,
                                "User", ss->user);
    if (node == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "session export of 'User' element failed");
        goto fail;
    }

    /* CookieToken */
    node = export_to_xml_string(r, root_node, mellon_ns,
                                "CookieToken", ss->cookie_token);
    if (node == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "session export of 'CookieToken' element failed");
        goto fail;
    }

    /* EnvironmentAttributes */
    node = export_to_xml_env_attrs(r, root_node, mellon_ns,
                                   "EnvironmentAttributes", ss->env_attrs);
    if (node == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "session export of 'EnvironmentAttributes' "
                      "element failed");
        goto fail;
    }

    /* SAMLResponse */
    node = export_to_xml_string(r, root_node, mellon_ns,
                                "SAMLResponse", ss->saml_response);
    if (node == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "session export of 'SAMLResponse' element failed");
        goto fail;
    }

    /* LassoIdentity */
    node = export_to_xml_cdata(r, root_node, mellon_ns,
                               "LassoIdentity", ss->lasso_identity_dump);
    if (node == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "session export of 'LassoIdentity' element failed");
        goto fail;
    }

    /* LassoSession */
    node = export_to_xml_cdata(r, root_node, mellon_ns,
                                "LassoSession", ss->lasso_session_dump);
    if (node == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "session export of 'LassoSession' element failed");
        goto fail;
    }

    return doc;

 fail:
    xmlFreeDoc(doc);
    return NULL;
}

/*----------------------- end XML Serialization ------------------------------*/

apr_status_t
am_session_store(request_rec *r, am_session_state_t *session)
{
    apr_status_t rv;
    xmlDocPtr doc;
    const char *session_xml;

    am_diag_printf(r, "%s: store session, session_id=%s, name_id=%s "
                   "issuer=%s expiration=%s now=%s\n",
                   __func__, session->session_id,
                   am_lasso_name_id_string(r, session->lasso_name_id),
                   am_lasso_name_id_string(r, session->issuer),
                   am_time_t_to_8601(r->pool, session->expires),
                   am_time_t_to_8601(r->pool, apr_time_now()));

    doc = am_session_state_to_xml(r, session);
    if (doc == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "unable to convert session state to XML document");
        return APR_EGENERAL;
    }
    session_xml = am_xml_doc_to_string(r, doc, 0);
    if (session_xml == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "unable to convert session XML document to text");
        xmlFreeDoc(doc);
        return APR_EGENERAL;
    }

    rv = am_cache_store_session_entries(r,
                                        session->session_id,
                                        session->lasso_name_id,
                                        session->issuer,
                                        session->expires,
                                        session_xml);
    xmlFreeDoc(doc);
    return rv;
}

static am_session_state_t *
am_session_validate(request_rec *r, am_session_state_t *session)
{
    apr_time_t now = apr_time_now();
    const char *cookie_token_target = am_cookie_token(r);

    if (session == NULL) {
        return NULL;
    }

    am_diag_log_session_state(r, 0, session, "Session State");

    if (session->expires < now) {
        am_diag_printf(r, "session expired, deleting, expiration=%s now=%s\n",
                                  am_time_t_to_8601(r->pool, session->expires),
                                  am_time_t_to_8601(r->pool, now));

        am_cache_delete_session_entries(r, session->session_id,
                                        session->lasso_name_id,
                                        session->issuer);

        return NULL;
    }

    cookie_token_target = am_cookie_token(r);
    if (strcmp(session->cookie_token, cookie_token_target)) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Session cookie parameter mismatch. "
                      "Session created with {%s}, but current "
                      "request has {%s}.",
                      session->cookie_token,
                      cookie_token_target);
        return NULL;
    }

    return session;
}

am_session_state_t *
am_session_get_session_by_session_id(request_rec *r, const char *session_id)
{
    am_session_state_t *session = NULL;

    session = am_cache_load_session_by_session_id(r, session_id);
    if (session == NULL) {
        return NULL;
    }

    return am_session_validate(r, session);
}

am_session_state_t *
am_session_get_session_by_name_id(request_rec *r,
                                  LassoSaml2NameID *name_id,
                                  LassoSaml2NameID *issuer)
{
    am_session_state_t *session = NULL;

    session = am_cache_load_session_by_name_id(r, name_id, issuer);
    if (session == NULL) {
        return NULL;
    }

    return am_session_validate(r, session);
}

/* This function gets the session associated with a user, using a cookie
 *
 * Parameters:
 *  request_rec *r       The request we received from the user.
 *
 * Returns:
 *  The session associated with the user who places the request, or
 *  NULL if we don't have a session yet.
 */
am_session_state_t *am_get_request_session(request_rec *r)
{
    const char *session_id;

    /* Get session id from cookie. */
    session_id = am_cookie_get(r);
    if(session_id == NULL) {
        /* Cookie is unset - we don't have a session. */
        return NULL;
    }

    return am_session_get_session_by_session_id(r, session_id);
}

static apr_status_t
am_session_state_pool_cleanup(void *data)
{
    am_session_state_t *session = (am_session_state_t *)data;

    am_session_state_free(session);

    return APR_SUCCESS;
}

/* This function creates a new session.
 *
 * Parameters:
 *  request_rec *r       The request we are processing.
 *
 * Returns:
 *  The new session, or NULL if we have an internal error.
 */
am_session_state_t *am_new_request_session(request_rec *r)
{
    const char *session_id;
    am_session_state_t *session = NULL;

    /* Generate session id. */
    session_id = am_generate_id(r);
    if(session_id == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error creating session id.");
        return NULL;
    }

    /* Set session id. */
    am_cookie_set(r, session_id);

    const char *cookie_token = am_cookie_token(r);

    am_diag_printf(r, "%s id=%s cookie_token=\"%s\"\n",
                   __func__, session_id, cookie_token);

    session = am_session_state_new(r);
    session->session_id = session_id;
    session->cookie_token = cookie_token;

    /* Set callback to free contents of the returned session object */
    apr_pool_cleanup_register(r->pool, session, am_session_state_pool_cleanup,
                              apr_pool_cleanup_null);


    return session;
}


/* This function releases the session which was returned from
 * am_get_request_session.
 *
 * Parameters:
 *  r              The request we are processing.
 *  session_var    Variable holding pointer to the session we are releasing,
 *                 it will be set to NULL upon return.
 *
 * Returns:
 *  Nothing.
 */
void
am_release_request_session(request_rec *r, am_session_state_t **session_var)
{
    /*
     * Nothing to do here at the moment, the session state and it's
     * contents will be freed when the pool it was allocated from is
     * freed via pool clean up callbacks. We leave this (mostly) stub
     * in place for a few reasons:
     *
     * - It sets the session state pointer to NULL assuring it cannot
     *   be used again.
     *
     * - If any additional locking is needed this would be the
     *   location to unlock the session state.
     */ 

    *session_var = NULL;
}


/* This function releases and deletes the session which was returned from
 * am_get_request_session.
 *
 * Parameters:
 *  request_rec *r              The request we are processing.
 *  am_session_state_t *session The session we are deleting.
 *
 * Returns:
 *  Nothing.
 */
void am_session_delete(request_rec *r, am_session_state_t *session)
{
    am_diag_log_session_state(r, 0, session, "delete session");

    /* Delete the cookie. */
    am_cookie_delete(r);

    if(session == NULL) {
        return;
    }

    /* Delete session from the session store. */
    am_cache_delete_session_entries(r,
                                    session->session_id,
                                    session->lasso_name_id,
                                    session->issuer);
}

/* This function updates the expire-timestamp of a session, if the new
 * timestamp is earlier than the previous.
 *
 * Parameters:
 *  request_rec *r        The request we are processing.
 *  am_session_state_t *t The current session.
 *  apr_time_t expires    The new timestamp.
 *
 * Returns:
 *  Nothing.
 */
void
am_session_update_expires(request_rec *r, am_session_state_t *session,
                          apr_time_t expires)
{
    /* Check if we should update the expires timestamp. */
    if(session->expires == 0 || session->expires > expires) {
        session->expires = expires;
    }
}


/* This function sets the session expire timestamp based on NotOnOrAfter
 * attribute of a condition element.
 *
 * Parameters:
 *  request_rec *r                   The current request. Used to log
 *                                   errors.
 *  am_session_state_t *session      The current session.
 *  LassoSaml2Assertion *assertion   The assertion which we will extract
 *                                   the conditions from.
 *
 * Returns:
 *  Nothing.
 */
void
am_session_set_expriation_from_assertion(request_rec *r,
                                         am_session_state_t *session,
                                         LassoSaml2Assertion *assertion)
{
    GList *authn_itr;
    LassoSaml2AuthnStatement *authn;
    const char *not_on_or_after;
    apr_time_t t;

    for(authn_itr = g_list_first(assertion->AuthnStatement); authn_itr != NULL;
        authn_itr = g_list_next(authn_itr)) {

        authn = authn_itr->data;
        if (!LASSO_IS_SAML2_AUTHN_STATEMENT(authn)) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Wrong type of AuthnStatement node.");
            continue;
        }

        /* Find timestamp. */
        not_on_or_after = authn->SessionNotOnOrAfter;
        if(not_on_or_after == NULL) {
            am_diag_printf(r, "%s failed to find"
                           " Assertion.AuthnStatement.SessionNotOnOrAfter\n",
                           __func__);
            continue;
        }


        /* Parse timestamp. */
        t = am_parse_timestamp(r, not_on_or_after);
        if(t == 0) {
            continue;
        }

        am_diag_printf(r, "%s Assertion.AuthnStatement.SessionNotOnOrAfter:"
                       " %s\n",
                       __func__, am_time_t_to_8601(r->pool, t));

        /* Updates the expires timestamp if this one is earlier than the
         * previous timestamp.
         */
        am_session_update_expires(r, session, t);
    }
}

/* Add all the attributes from an assertion to the session data for the
 * current user.
 *
 * Parameters:
 *  am_session_state_t *s           The current session.
 *  request_rec *r                  The current request.
 *  LassoSaml2NameID *name_id       The name identifier we received from
 *                                  the IdP.
 *  LassoSaml2Assertion *assertion  The assertion.
 *
 * Returns:
 *  HTTP_BAD_REQUEST if we couldn't find the session id of the user, or
 *  OK if no error occured.
 */
int
am_session_add_attributes_from_assertion(am_session_state_t *session,
                                         request_rec *r,
                                         LassoSaml2NameID *name_id,
                                         LassoSaml2NameID *issuer,
                                         LassoSaml2Assertion *assertion)
{
    am_dir_cfg_rec *dir_cfg;
    GList *atr_stmt_itr;
    LassoSaml2AttributeStatement *atr_stmt;
    GList *atr_itr;
    LassoSaml2Attribute *attribute;
    GList *value_itr;
    LassoSaml2AttributeValue *value;
    GList *any_itr;
    char *content;
    char *dump;

    dir_cfg = am_get_dir_cfg(r);

    /* Set expires to whatever is set by MellonSessionLength. */
    if(dir_cfg->session_length == -1) {
        /* -1 means "use default. The current default is 86400 seconds. */
        am_session_update_expires(r, session, apr_time_now()
                                  + apr_time_make(86400, 0));
    } else {
        am_session_update_expires(r, session, apr_time_now()
                                  + apr_time_make(dir_cfg->session_length, 0));
    }

    /* Save session information. */
    lasso_assign_gobject(session->lasso_name_id, name_id);
    if (!am_session_set_env_attr_value(r, session, "NAME_ID",
                                       name_id->content)) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    lasso_assign_gobject(session->issuer, issuer);

    /* Update expires timestamp of session. */
    am_session_set_expriation_from_assertion(r, session, assertion);

    /* assertion->AttributeStatement is a list of
     * LassoSaml2AttributeStatement objects.
     */
    for(atr_stmt_itr = g_list_first(assertion->AttributeStatement);
        atr_stmt_itr != NULL;
        atr_stmt_itr = g_list_next(atr_stmt_itr)) {

        atr_stmt = atr_stmt_itr->data;
        if (!LASSO_IS_SAML2_ATTRIBUTE_STATEMENT(atr_stmt)) {
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                          "Wrong type of AttributeStatement node.");
            continue;
        }

        /* atr_stmt->Attribute is list of LassoSaml2Attribute objects. */
        for(atr_itr = g_list_first(atr_stmt->Attribute);
            atr_itr != NULL;
            atr_itr = g_list_next(atr_itr)) {

            attribute = atr_itr->data;
            if (!LASSO_IS_SAML2_ATTRIBUTE(attribute)) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                              "Wrong type of Attribute node.");
                continue;
            }

            if (attribute->Name == NULL) {
                AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                              "SAML 2.0 attribute without name.");
                continue;
            }

            /* attribute->AttributeValue is a list of
             * LassoSaml2AttributeValue objects.
             */
            for(value_itr = g_list_first(attribute->AttributeValue);
                value_itr != NULL;
                value_itr = g_list_next(value_itr)) {


                value = value_itr->data;
                if (!LASSO_IS_SAML2_ATTRIBUTE_VALUE(value)) {
                    AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                                  "Wrong type of AttributeValue node.");
                    continue;
                }

                /* value->any is a list with the child nodes of the
                 * AttributeValue element.
                 *
                 * We assume that the list contains a single text node.
                 */
                if(value->any == NULL) {
                    AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                                  "AttributeValue element was empty.");
                    continue;
                }

                content = "";
                for (any_itr = g_list_first(value->any);
                     any_itr != NULL;
                     any_itr = g_list_next(any_itr)) {
                        /* Verify that this is a LassoNode object. */
                        if(!LASSO_NODE(any_itr->data)) {
                            AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                                          "AttributeValue element contained an "
                                          " element which wasn't a Node.");
                            continue;
                        }
                        dump = lasso_node_dump(LASSO_NODE(any_itr->data));
                        if (!dump) {
                            AM_LOG_RERROR(APLOG_MARK, APLOG_WARNING, 0, r,
                                          "AttributeValue content dump failed.");
                            continue;
                        }
                        /* Use the request pool, no need to free results */
                        content = apr_pstrcat(r->pool, content, dump, NULL);
                        g_free(dump);
                }
                /* Decode and save the attribute. */

                am_diag_printf(r, "%s name=%s value=%s\n",
                               __func__, attribute->Name, content);

                if (!am_session_set_env_attr_value(r, session, attribute->Name, content)) {
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
            }
        }
    }

    return OK;
}

/*----------------------------- Session State --------------------------------*/

/**
 * Allocate and return a new session state structure
 *
 * A am_session_state_t struct is allocated from the request pool.
 * The pool is recorded in the session state to be used for all future
 * allocations needed by the session state. The entry is zeroed out and
 * then complex structures are initialized (e.g. the environment variables
 * table).
 *
 * @param[in] r Current HTTP request
 *
 * @returns initialized am_session_state_t struct
 */

am_session_state_t *
am_session_state_new(request_rec *r)
{
    am_session_state_t *ss;

    if ((ss = apr_pcalloc(r->pool, sizeof(am_session_state_t))) == NULL) {
        return NULL;
    }

    ss->pool = r->pool;
    if ((ss->env_attrs = apr_hash_make(ss->pool)) == NULL) {
        AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, 0, r,
                      "unable to create env_attrs table");
        return NULL;
    }

    ss->expires = MAX_APR_TIME_T; /* Far far into the future. */

    return ss;
}

/**
 * Frees session state resources
 *
 * description
 *
 * @param[in] session The session state to free
 *
 * @returns status result
 */
static apr_status_t
am_session_state_free(am_session_state_t *session)
{
    if (session == NULL) {
        return APR_SUCCESS;
    }

    lasso_release_gobject(session->lasso_name_id);
    lasso_release_gobject(session->issuer);

    return APR_SUCCESS;
}

/**
 * Adds environment attribute to session state
 *
 * Environment attributes are indexed by name which must be unique.
 * Each environment attribute has zero or more string values.  This
 * function first checks to see if the attribute under the given name
 * exists yet, if not an empty array is created to hold it's values
 * and is entered into the environment attribute table. The array of values
 * associated with the attribute is returned.
 *
 * @param[in] r    Current HTTP request
 * @param[in] ss   session state whose environment attribute is being updated.
 * @param[in] name Attribute name
 *
 * @returns attribute values array associated with attribute
 */

apr_array_header_t *
am_session_set_env_attr_name(request_rec *r, am_session_state_t *ss,
                                const char *name)
{
    apr_array_header_t *values = NULL;

    if ((values = am_session_get_env_attr_values(r, ss, name)) == NULL) {
        /*
         * Attribute does not yet exist.
         * Create values array and set it as the value of this attribute.
         */
        values = apr_array_make(apr_hash_pool_get(ss->env_attrs), 1,
                                sizeof(char *));

        apr_hash_set(ss->env_attrs,
                     apr_pstrdup(apr_hash_pool_get(ss->env_attrs), name),
                     APR_HASH_KEY_STRING, values);
    }

    return values;
}


/**
 * Is value a member in the array of values?
 *
 * Search for the value in the array of values, returns true if found.
 *
 * @param[in] values Array of attribute values
 * @param[in] value  Value being tested for membership
 *
 * @returns true if found, false otherwise
 */
bool
am_session_env_attr_values_has_value(apr_array_header_t *values,
                                         const char *value)
{
    int i;
    const char *array_value;

    if (values == NULL) {
        return false;
    }

    for (i=0; i < values->nelts; i++) {
        array_value = APR_ARRAY_IDX(values, i, char *);
        if (strcmp(value, array_value)== 0) {
            return true;
        }
    }

    return false;
}

/**
 * Does the environment attribute have a specific value?
 *
 * Envionment attributes are multi-valued. Determine if @value is a member
 * of the existing values associated with this environment variable.
 * If the environment variable does not exist false is returned.
 *
 * @param[in] r     Current HTTP request
 * @param[in] ss    session state whose environment attribute is being
 *                  interrogated.
 * @param[in] name  Attribute name
 * @param[in] value Attribute value
 *
 * @returns true if the attribute exists and the value is a member
 *          of attribute's values.
 */
bool
am_session_env_attr_has_value(request_rec *r, am_session_state_t *ss,
                                  const char *name, const char *value)
{
    apr_array_header_t *values = NULL;

    values = am_session_get_env_attr_values(r, ss, name);
    return am_session_env_attr_values_has_value(values, value);
}

/**
 * Creates an environment attribute and adds a value to it's array of values
 *
 * If the attribute does not yet exist it is added to the table of
 * environment attributes. The @value is added to the attributes array
 * of values if it does not already exist, comparison is case sensitive.
 * Hence each value in the array is unique.
 *
 * @param[in] r     Current HTTP request
 * @param[in] ss    session state whose environment attribute is being updated.
 * @param[in] name  Attribute name
 * @param[in] value Attribute value
 *
 * @returns attribute values array associated with attribute
 */
apr_array_header_t *
am_session_set_env_attr_value(request_rec *r, am_session_state_t *ss,
                              const char *name, const char *value)
{
    apr_array_header_t *values = NULL;
    char **array_entry = NULL;

    values = am_session_set_env_attr_name(r, ss, name);

    if (!am_session_env_attr_values_has_value(values, value)) {
        array_entry = apr_array_push(values);
        *array_entry = apr_pstrdup(apr_hash_pool_get(ss->env_attrs), value);
    }

    return values;
}

/**
 * Lookup an environment attribute, return it's array of values
 *
 * Lookup an environment attribute, return it's array of values.
 * If the attribute does not exist return NULL.
 *
 * @param[in] r     Current HTTP request
 * @param[in] ss    session state whose environment attribute is being updated.
 * @param[in] name  Attribute name
 *
 * @returns array of attribute values, NULL if attribute does not exist.
 */
apr_array_header_t *
am_session_get_env_attr_values(request_rec *r, am_session_state_t *ss,
                        const char *name)
{
    apr_array_header_t *values;

    values = apr_hash_get(ss->env_attrs, name, APR_HASH_KEY_STRING);

    return values;
}

/**
 * Lookup environment attribute, return it's first value
 *
 * Environment attributes are multi-valued, lookup the
 * attribute. Return NULL if the attribute is not found return or if
 * the attributes's array of attributes is empty. Otherwise
 * return the first value in the attribute's array of values.
 *
 * @param[in] r     Current HTTP request
 * @param[in] ss    session state whose environment attribute is being updated.
 * @param[in] name  Attribute name
 *
 * @returns First attribute value, NULL if attribute does not exist or
 *          if attribute has no values.
 */
const char *
am_session_get_first_env_attr_value(request_rec *r, am_session_state_t *ss,
                                    const char *name)
{
    apr_array_header_t *values = NULL;

    values = am_session_get_env_attr_values(r, ss, name);
    return FIRST_ATTR_VALUE(values);
}


/**
 * Set Apache environment variables derived from current session.
 *
 * Set the request environment variables as well as other request variables
 * associated with this user. The values are are derived from the users
 * session information. The majority of the request environment variables
 * are derived from the SAML assertion attributes received from the IdP.
 * The SAML attribute name may be mapped to a different environment
 * variable name depending on the curent Mellon configuration. Attribute
 * values may be multi-valued, in addtion to mapping the a new name
 * this function also controls how multi-valued values are presented in the
 * environment.
 *
 * @param[in]     r  Current HTTP request
 * @param[in,out] ss session state object
 *
 * @returns void
 */
void am_session_export_env(request_rec *r, am_session_state_t *ss)
{
    am_dir_cfg_rec *dir_cfg = am_get_dir_cfg(r);
    int i;
    apr_hash_index_t *hi;
    const char *attr_name;
    const char *mapped_name;
    const char *attr_value;
    apr_array_header_t *attr_values;
    bool merge_env_vars;
    int exported_index;
    const char *exported_name;
    const char *exported_value;
    const char *prefixed_name = NULL;

    /*
     * Set flag which controls if we merge multi-valued values or
     * enumerate them individually.
     */
    merge_env_vars = dir_cfg->merge_env_vars && dir_cfg->merge_env_vars[0];

    /*
     * Iterate over each variable stored in the session that will be
     * added to the environment
     */
    for (hi = apr_hash_first(apr_hash_pool_get(ss->env_attrs), ss->env_attrs);
         hi;
         hi = apr_hash_next(hi)) {

        /* Get the name of the variable and its array of values */
        apr_hash_this(hi, (void*)&attr_name, NULL, (void*)&attr_values);

        /* Map to new name and get prefixed version of name for export */
        mapped_name = am_mapped_env_attr_name(r, attr_name, &prefixed_name);
        /*
         * Set the username. The username comes from one of the SAML
         * attribute names, the attribute name used to set the username
         * is defined by the userattr configuration variable. We first try
         * the original SAML attribute name and then the mapped name.
         * The name is case insenstive.
         */
        if (ss->user == NULL) {
            if (strcasecmp(attr_name, dir_cfg->userattr) == 0 ||
                strcasecmp(mapped_name, dir_cfg->userattr) == 0) {
                attr_value = FIRST_ATTR_VALUE(attr_values);
                if (attr_value) {
                    ss->user = apr_pstrdup(r->pool, attr_value);
                }
            }
        }

        /* Does the variable have one or more values? */
        if (attr_values && attr_values->nelts) {
            /* Add the variable without a suffix. */
            exported_name = prefixed_name;
            exported_value = APR_ARRAY_IDX(attr_values, 0, char *);
            apr_table_set(r->subprocess_env, exported_name, exported_value);

            if (merge_env_vars) {
                /*
                 * Multiple values are merged together into a single value
                 * by joining them together with a separator
                 */
                exported_value = am_str_join(r->pool, attr_values,
                                             dir_cfg->merge_env_vars);
                apr_table_set(r->subprocess_env, exported_name, exported_value);
            } else {
                /*
                 * Multiple values are enumerated separately by appending an
                 * an index to the name
                 */
                for (i=0; i < attr_values->nelts; i++) {
                    if (dir_cfg->env_vars_index_start > -1) {
                        exported_index = dir_cfg->env_vars_index_start + i;
                    } else {
                        exported_index = i;
                    }
                    exported_name = apr_psprintf(r->pool, "%s_%d",
                                                 prefixed_name, exported_index);
                    exported_value = APR_ARRAY_IDX(attr_values, i, char *);
                    apr_table_set(r->subprocess_env,
                                  exported_name, exported_value);
                }
            }
        } else {
            /* Empty value */
            apr_table_set(r->subprocess_env, prefixed_name, NULL);
        }

        /*
         * Optionally add a variable indicating the number of values
         *  this attribute has by appending a count to the variable name
         */
        if (dir_cfg->env_vars_count_in_n > 0) {
            exported_name = apr_psprintf(r->pool, "%s_N", prefixed_name);
            exported_value = apr_psprintf(r->pool, "%d",
                                          attr_values ? attr_values->nelts : 0);
            apr_table_set(r->subprocess_env, exported_name, exported_value);
        }

    } /* end foreach attr */

    /* Update the request rec with the user and auth_type */
    if (ss->user) {
        r->user = apr_pstrdup(r->pool, ss->user);
        r->ap_auth_type = apr_pstrdup(r->pool, "Mellon");
    } else {
        /* We don't have a user-"name". Log error. */
        AM_LOG_RERROR(APLOG_MARK, APLOG_NOTICE, 0, r,
                      "Didn't find the attribute \"%s\" in the attributes"
                      " which were received from the IdP. Cannot set a user"
                      " for this request without a valid user attribute.",
                      dir_cfg->userattr);
    }

}
