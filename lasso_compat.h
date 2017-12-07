#ifdef HAVE_LASSO_UTILS_H

#include <lasso/utils.h>

/*
 * Why is lasso_log here? In 2010 Benjamin Dauvergne moved logging
 * function and macros to their own module. This necessitated adding
 * this block to the top of every language binding file to prevent an
 * unresolved reference to lasso_log. Seems to me this is broken, but
 * we can't fix it so we'll have to live with it for the time being.
 */

#if defined(__GNUC__)
#  define lasso_log(level, filename, line, function, format, args...) \
        g_log("Lasso", level, "%s:%i:%s" format, filename, line, function, ##args)
#elif defined(HAVE_VARIADIC_MACROS)
#  define lasso_log(level, format, line, function, ...)  \
        g_log("Lasso", leve, "%s:%i:%s" format, filename, line, function, __VA_ARGS__)
#else
static inline void lasso_log(GLogLevelFlags level, const char *filename,
    int line, const char *function, const char *format, ...)
{
	va_list ap;
	char s[1024];
	va_start(ap, format);
	g_vsnprintf(s, 1024, format, ap);
	va_end(ap);
    g_log("Lasso", level, "%s:%i:%s %s", filename, line, function, s);
}
#define lasso_log lasso_log
#endif


#else

#define lasso_assign_string(dest,src)           \
{                                               \
    char *__tmp = g_strdup(src);                \
    lasso_release_string(dest);                 \
    dest = __tmp;                               \
}

#define lasso_release_string(dest)              \
	lasso_release_full(dest, g_free)

#define lasso_release_full(dest, free_function) \
{                                               \
    if (dest) {                                 \
        free_function(dest); dest = NULL;       \
    }                                           \
}

#define lasso_check_type_equality(a,b)

#define lasso_release_full2(dest, free_function, type)  \
{                                                       \
    lasso_check_type_equality(dest, type);              \
    if (dest) {                                         \
        free_function(dest); dest = NULL;               \
    }                                                   \
}

#define lasso_release_list(dest)                        \
	lasso_release_full2(dest, g_list_free, GList*)

#define lasso_release_list_of_full(dest, free_function)         \
{                                                               \
    GList **__tmp = &(dest);                                    \
    if (*__tmp) {                                               \
        g_list_foreach(*__tmp, (GFunc)free_function, NULL);     \
        lasso_release_list(*__tmp);                             \
    }                                                           \
}

#define lasso_release_list_of_strings(dest)     \
	lasso_release_list_of_full(dest, g_free)


#endif

#ifndef LASSO_SAML2_ECP_PROFILE_WANT_AUTHN_SIGNED
#define LASSO_SAML2_ECP_PROFILE_WANT_AUTHN_SIGNED "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp:2.0:WantAuthnRequestsSigned"
#endif

#ifndef LASSO_SAML2_CONDITIONS_DELEGATION
#define LASSO_SAML2_CONDITIONS_DELEGATION "urn:oasis:names:tc:SAML:2.0:conditions:delegation"
#endif

#ifndef LASSO_SAML_EXT_CHANNEL_BINDING
#define LASSO_SAML_EXT_CHANNEL_BINDING "urn:oasis:names:tc:SAML:protocol:ext:channel-binding"
#endif
