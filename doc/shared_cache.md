# Mellon's Shared Cache

Author: John Dennis <jdennis@redhat.com>

## Introduction

Mellon functions as an authentication and authorization provider for
clients accessing resources on an Apache web server. As such it must
maintain persistent state. Foremost among the persistent state data
is the session information bound to a specific principal. The
persistent state data is generically referred to as Mellon's cache.

## Historical Background and Motivation For a Shared Cache

The original cache implementation allocated a block of shared memory
to be used as Mellon's cache. The block of shared memory was fixed in
size at Apache start-up and could not be altered. The initial cache
size was the multiplicative product of two Mellon configuration
directives `MellonCacheSize` and `MellonCacheEntrySize`.

> `MellonCacheSize` sets the maximum number of sessions which can be
> active at once. When mod_auth_mellon reaches this limit, it will
> begin removing the least recently used sessions.

> `MellonCacheEntrySize` sets the maximum size for a single session entry in
> bytes. When mod_auth_mellon reaches this limit, it cannot store any more
> data in the session and will return an error.

### Deprecated Mellon Cache Configuration Directives

The following Mellon configuration directives related to the prior
cache implementation are now deprecated because they no longer apply
to the new socache implementation. Or if they could be applied to the
new socache implementation their meaning would be different so best to
avoid their use altogether.

* MellonCacheSize
* MellonCacheEntrySize
* MellonLockFile

An unknown Apache module directive will cause Apache to fail to load
and start. To be friendly during the transition period where these
directives may remain in configuration files Mellon will not treat these
directives as unknown. Instead if one of these directives are
encountered Mellon will emit a deprecation warning in the Apache error
log and otherwise ignore the directive.

**The shared cache implementation is a drop-in replacement for the
  previous implmentation** with the caveat you may get deprecation
  warnings.

**The default `shmcb` Apache Shared Object Cache provider utilizes the
  same APR shared memory API as did the prior cache
  implementation therefore it has the same exposure profile.**
  

### Who could access the shared memory block?

Apache is a MPM (Multi-Processing Modules) HTTP server. In a typical
Apache deployment the main Apache process forks multiple child
processes. To improve throughput and achieve parallelism the parent
Apache process will dispatch an incoming request to one of it's child
processes to handle. The parent Apache process and it's child
processes form a process group and as such can share the shared memory
block. Other processes executing on the same host could also access
the shared memory block but there is little point in this because you
could just increase the number of Apache child processes in a single
Apache instance.

### Downsides to the historical shared memory block

There are a number of restrictions that arise from the historical
implementation:

* The cache entries are local to the Apache instance.
* The cache size is fixed.
* The number of cache entries is fixed.
* The amount of session data in a cache entry has a hard limit. If an
  IdP sends a large amount of per user attribute information it may
  exceed the cache entry size, the fail over is not graceful.
* The cache implementation is a custom implementation that does not
  leverage existing libraries.
* Heavily based on memory pointers and offsets into the shared memory
  segment which have no meaning outside the process space.
* The historical implementation did not maintain a clean separation
  between the code that managed the session and the code that managed
  the cache entries belonging to the session.

### High Availability, Load Balancing and Protected Networks

Running a single Apache instance is often insufficient to meet the
needs of enterprises who need to assure their site is continuously up,
provides fast responses under load, directs traffic to regional data
centers to improve response time and isolates their servers on
protected networks for enhanced security. In this common deployment
scenario there are many Apache instances running on different compute
nodes. The problem is if these otherwise isolated Apache instances are
serving the same content to the same user(s) they *must* share the
same user authentication and authorization data. This is where the
historical Mellon cache implementation falls short. Because Mellon's
cache and hence user session is available only to the Apache instance
that performed the authentication no other Apache instance
participating in the high availability deployment can successfully
service the HTTP request. The historical solution to this was to
assign a user to a single Apache instance, thus the user session
information is always available. But this defeats one of the primary
motivations behind high availability deployments, instead of any one
of a number of Apache instances servicing an incoming request the
request must be directed to exactly one Apache instance.

The typical solution to these types of issues in high availability
deployments is to share data between Apache instances. The data
sharing is accomplished by establishing a network connection to a
common resource data server. There are many types and many different
implementations of these common resource servers.

Mellon's session data needs to be stored in a common resource server
that can be accessed by a collection of independent Apache instances.

## The Apache Shared Object Cache

Mellon should not dictate the common resource server it utilizes for
it's cache data, that is a site deployment decision. Mellon's use of a
common shared resource server should be an abstraction which permits
any number of possible resource servers. Fortunately Apache has
addressed the issue of a shared resource server abstraction because
the need for it arises so often. The [Apache Shared Object Cache
module](https://httpd.apache.org/docs/2.4/socache.html) provides an
abstracted API which permits a number of popular shared resource
servers to be used as `providers`. Thus instead of Mellon storing it's
cache data locally in it's own Apache instance Mellon will instead
utilize the Apache Shared Object Cache which is a distributed
resource.

### New Mellon SoCache Configuration Directives

Two new Mellon configuration directives have been added:

* `MellonSoCache`
* `MellonSoCacheSessionStateEntrySize`

The cache configuration parameters are no longer a property of Mellon
because Mellon no longer owns or implements the cache, rather Mellon
is a client of the cache. You specify the Apache Shared Object Cache
provider you want to use in the `MellonSoCache` configuration
directive. Each Apache Shared Object Cache provider has it's own
unique configuration parameters which are defined in the provider's
documentation. The `MellonSoCache` directive is of the form
`name:args`, where `name` is the name of the Apache Shared Object
Cache provider and `args` are any (optional) provider specific
initialization parameters you want to pass to the provider. Mellon
does not inspect, alter or manipulate those optional socache provider
parameters in any fashion, they merely pass through when the socache
provider is initialized for Mellon's use.

When Mellon retrieves data from the socache it provides the buffer for
the socache provider to write the cache entry data into. That buffer
must be large enough to hold the entire cache entry or the socache
provider will return an error. The
`MellonSoCacheSessionStateEntrySize` directive is used to allocate a
buffer of sufficient size to hold the session state data.
See [Apache Shared Object Cache Warts](#apache-shared-object-cache-warts)
for a more in-depth discussion of this issue.

### Socache Implementation

The following is a discussion of how Mellon's socache was implemented
and any issues related to that implementation. 

#### Goals

1. Provide a cache that can be shared by cooperating Apache instances.
2. Drop-in replacement for previous cache implementation (deprecation
   warnings considered acceptable for deprecated directives).
3. No loss of functionality.
4. Utilize as much existing technology as possible that is widely
   available, robust, efficient and receives regular bug and security
   fixes outside the context of Mellon. At the same time we want to
   avoid custom code to the greatest extent possible instead
   leveraging external libraries.
5. Be flexible and extensible to address future changes.
6. Provide clean separation of responsibilities.
7. Provide extensive logging of all operations to aid in debugging.
8. Simplicity and robustness are paramount, any performance
   optimizations can be addressed later.

#### Data Format

The Apache socache API permits you to write and retrieve a block of
binary data for a cache entry. That flexibility allows a tremendous
number of options of how the data is formatted. We know the data must
be structured. The structured data must allow for nesting and
aggregate collections (e.g. lists, sets of key/value pairs, scalars,
etc.). Goals 4 and 5 imply we utilize one of the existing data
exchange formats (e.g. JSON, XML, YAML, etc.) all of which are backed
by multiple open source implementation libraries.

We observe that inherently SAML is XML based. As a consequence the
SAML library Mellon utilizes, Lasso is also XML based. Lasso provides
many API entry points related to XML data. Lasso utilizes `libxml2`
and it's sister library `xmlsec` for it's XML implementation and XML
signature processing respectively. Therefore Mellon will cause these
libraries to be linked and loaded when Mellon is loaded. Given the
extensive use of XML in SAML and the extensive support available to
Mellon to handle XML data and that XML data is quite flexible, robust
and field proven technology it makes XML the logical choice for the
structured data in a cache entry.

##### XML Serialization of Session State Data

auth_mellon_session.c is responsible for serializing session state
into and out of XML as opposed to the cache code in
auth_mellon_cache.c because the cache code only deals with storing and
loading data, it's agnostic with respect to the content.

Lasso has excellent support for serializing complex data structures
into and out of XML via the LassoNode class. The original coding plan
was to derive a session state object from the LassoNode class and let
Lasso manage all the serialization. Unfortunately not all the entry
points and data types needed are publicly exported from Lasso so
instead auth_mellon_session.c contains a minimal amount of code to
needed to serialize a am_session_state_t object. A am_session_state_t
object is the only object currently serialized to XML for cache
storage.

The top level of the session state XML document is essentially a set
of key/value pairs along with a version attribute to identify the
format. The key names (e.g. the XML child elements of the root) map
directly to the members of the am_session_state_t struct. The value is
the data for the struct member. The serialization supports just a few
necessary data types (e.g. string, int, timestamp, etc.) For each
basic data type there are a pair of functions, one to serialize into
XML and one to serialize from XML. The am_session_state_t object is
serialized simply by calling the appropriate data type serialization
function for each member of the struct.

#### Multiple Types of Cache Entries

Currently there are 3 types of cache entries Mellon manages:

* Session State
* Name Identifiers
* Diagnostic logging state

In the future it is entirely possible (and probable) other cache
entries will be added.

The most important cache entry is the session state bound to a
principal. Mellon refers to this as session data and is indexed by a
session key (random string) that is returned in a Mellon cookie to the
user agent. The user agent will send this session key back to Mellon
which then uses the session key to lookup the session data in the
cache.

However session state sometimes needs to be retrieved by a key other
than the session key. This occurs with the SAML logout profile. The
asserting IdP does not know the Service Providers (SP) session
key. Also the user session on the IdP might be spread across multiple
SP's each of which would have it's own session id unknown to the
IdP. Therefore the SAML logout profile does not use an SP specific
session id to communicate a logout request. Instead the logout profile
uses the principal's SAML Name Identifier originally passed in the
SAML Assertion when the IdP authenticated the principal. Thus a user's
session state needs to be retrieved by either the session key (most
common) or the NameID (much less frequent).

The problem is the Apache Shared Object Cache API only permits a
single key to point to a cache entry. The obvious choice for session
state key is Mellon's session id. Then how do we lookup session state
using a key other than the session id?

One possible solution is to utilize the Apache Shared Object Cache
iteration API. We would iterate over all the cache entries looking for
a match on the NameID in the session state. This is fundamentally how
the original Mellon cache implementation worked. But cache entry
iteration has problems:

* Not all Apache Shared Object Cache providers implement
  iteration. The API does not provide any indication of iteration support,
  you're forced to attempt an iteration and see if you get a
  "Not Implemented" error response. Furthermore what is Mellon
  supposed to do in this case? Mellon would have to implement some type of
  fallback solution and by the time you've done that what is the point
  of trying to use the iteration API in the first place?

* Iteration over a network connection is inefficient and
  slow. Iterating over data in process memory as was originally done
  has a vastly different performance profile than iteration involving a
  data on a remote server.

* Iteration is inherently a sub-optimal algorithm to retrieve data.

* The number of cache entries in a distributed deployment may be quite
  large exacerbating the performance problem.

The other solution to session state lookup by a key other than the
session id is to utilize "pointers" or "references" in the cache. In
this technique a different type of cache entry is used. The cache key
is the key we want to lookup by and the value for the cache entry is
the session key. Thus a lookup by a key other than the session key
involves two cache lookups, one to obtain the session key and then a
subsequent lookup using the retrieved session key to obtain the
session state. Adding one extra cache lookup is much more efficient
than iteration. Another advantage is the cache data used to point to
the session id is quite small, just the size of the session id.

Cache references as described above is the approach we adopt. The
downside is Mellon's cache implementation must manage two distinct
cache entries for one piece of session state. When a new session state
cache entry is added to the cache it's NameID reference must be
entered at the same time. Likewise when a session state cache entry is
deleted it's matching NameID reference must also be deleted. The good
news is that managing pairs of cache entries in Mellon is not
difficult.

##### What About Referential Integrity When Multiple Cache Entries Must be Managed?

The Apache Shared Object Cache interface does not make any claims on
operation ordering, transaction grouping, cache eviction, etc. It's
purely on a best effort basis. Plus when there are multiple cache
clients (i.e. multiple Apache instances running Mellon) there is
always an opportunity for a race condition or an incomplete
transaction (i.e one Mellon Apache instance has a fault and never
completes the second cache operation). Such occurrences, albeit rare
could leave us with either a dangling reference or the inability to
fetch a session state entry via a different key. But is this actually
a problem? I don't think so for the following reasons. The cache is
simply a cache, it is not a guarantee. Like most any cache it's a best
effort to quickly provide data. Cache entries are stored with
expiration lifetimes, a cache entry may expire and be reaped by the
cache provider. If Mellon detects any cache inconsistency it responds
by indicating the cache entry is absent. During the authorization
phase of Mellon a missing session state entry simply triggers a
request to the IdP. If the IdP has an active session for the principle
it immediately responds with the Assertion which would have been found
in the session cache without involving the user. If the session had
expired on the IdP the principal would have needed to re-authenticate
anyway and in particular Mellon would have detected this situation
anyway even if the session entry was present in the cache because the
session state returned by the cache would have indicated the
session had expired. The worse scenario is we leave a cache entry
orphaned in the cache because we no longer have a key to access it
by. However cache entries have an expiration so the lifetime of the
orphaned cache entry will be short and the cache provider will
eventually reclaim it.

The addition of socache functionality to Mellon brings with it other
opportunities to take advantage of inter-process data sharing. There
is no need to limit the socache to session state data only. For
example the diagnostics log can become quite verbose because it emits
static data more than once. This occurs because Apache forks multiple
child processes which share common configuration and a common log
file. However each child worker is ignorant of what it's sibling
processes have emitted. The most verbose of this static configuration
data is the per-directory configuration data. The diagnostics now
stores in the common socache which directories have had their
configuration logged thus avoiding redundant logging the same
data. There are opportunities to use the socache for other purposes
yet to be explored.

#### Key Formats and Key Namespaces

Each type of cache entry must be isolated from other types of cache
entries to avoid a potential key collision should the possibility
arise the two different types share a key. Keys within a key type are
always guaranteed to be unique. Although it is unlikely in practice
there could be a key collision between types a malicious agent could
craft data that would cause a collision. In any event it's best to
assure cache entries of a given type are partitioned into their own
collection inside the socache. To achieve this we prefix key names
with their type namespace. The namespace prefixes are defined in
auth_mellon_cache.cache as constants of the form \*\__KEY\__PREFIX.

Some socache providers have limitations on the size of the keys they
can handle. The memcache provider is a good example. Although the
session id key is relatively short some of the key names Mellon uses
have the potential to be long. Examples would be NameID keys (which in
addition to the arbitrary ID itself also includes SAML namespace
qualifiers to prevent collisions between IdP's issuing similar
names. Another example of a potentially long key name would be the
directory path information maintained by the diagnostics code.

Whenever a key name has the potential to be long the Mellon socache
code will hash the concatenation of the type prefix with the key name
(e.g. type_prefix|key_name) and use the resulting digest as the
key. Thus the actual key presented to the socache provider may bear
little resemblance to the key otherwise used by Mellon.

#### Locking

Apache Shared Object Cache providers have a flag indicating if they
require inter-process locking to work properly. If the selected
provider does require locking Mellon will create a mutex and provide
locks around socache operations. This occurs only between the Apache
processes on a given host. Any locking between remote clients of a
socache provider occurs at the discretion of the socache provider,
Mellon is not involved. Mellon makes no attempt to synchronize writes
to a cache entry by distinct remote clients. The socache provider will
guarantee the entire write is completed before another client writes
the same entry, thus the entry will not be corrupted but there is the
potential that new data written by the current process may be
over-written by older data from a remote peer (a race). Preventing
this race condition between remote peers would be non-trivial. Because
session state cache entries are only written once when the session
state is initially created after receiving an Assertion from the IdP
and because they are not updated on each access the session state
data should be the same no matter which Mellon instance received the
Assertion from the IdP. Thus it's unlikely this would ever cause a problem
in practice.

## Security

The data written into the socache includes sensitive authentication
and authorization data which needs to be protected. If a rouge actor
were able to gain access to the cache data it could impersonate any
user with an active session. Even if the session token is not stolen
and used merely have access to a user's attributes, sites visited,
etc. can be a significant advantage for nefarious actions.

It is essential to prevent access to the shared cache by anyone other
than Mellon. However this is a deployment issue, it depends upon the
socache provider selected and as such is outside the scope of Mellon.

**IMPORTANT:** Apache's default socache provider is `shmcb`
(socache_shmcb_module) which uses the same type of shared memory
segment Mellon's original cache implementation utilized
(e.g. `apr_shm_create()`) therefore is you allow Mellon to use it's
default `MellonSoCache` value or explicitly set it to `shmcb` you will
get a cache with nearly identical security characteristics as the
original cache implementation. `shmcb` cannot be used by remote
instances, it's only useful on the local node. 

## Apache Shared Object Cache Warts

I ran into several issues when trying to use the Apache Shared Object
Cache API.

* In general the API is under-specified.

  * There is no clear definition of which errors are to be returned
    for specific circumstances. Instead each socache provider makes
    their own decision. As a consequence you get different behavior
    depending on which provider is configured.

  * There is no requirement for what must be implemented nor is there
    any mechanism to deterime what methods a provider implements
    (the iterate method being the primary culprit in this regard).

  * There is no specification of what the maximum key size nor entry
    size is. Nor is there any mechanism to query individual providers
    for their implementation limits. You're force to dig through the
    source code.

* It's impossible to know a prori what size the data buffer needs to
  be for returned values. The socache provider does not allocate the
  buffer out of a pool, instead it writes into a caller provided
  buffer, the caller passes the size of the buffer as one of the
  parameters. Because the API does not define what the error returns
  are supposed to be you get different behavior depending on the
  specific provider. For example here is what the different providers
  return when the data buffer for the retrieve method is too small to
  hold the returned data:


  | Provider             | Error Return |
  |----------------------|--------------|
  | mod_socache_dbm      | APR_ENOSPC   |
  | mod_socache_dc       | APR_ENOSPC   |
  | mod_socache_memcache | APR_ENOMEM   |
  | mod_socache_redis    | APR_ENOMEM   |
  | mod_socache_shmcb    | APR_NOTFOUND |


  The APR_NOTFOUND result from mod_socache_shmcb is the most
  pernicious because you cannot distinuish between the key being
  absent in the cache or whether the key exists but the value is too
  big for the return buffer. At least if you consistently got
  APR_ENOSPC (preferred) or APR_ENOMEM you could reallocate
  the buffer and try again. Or even better would be if the API
  demanded both a specific error (e.g. APR_NOSPC) *and* the buffer
  size was passed as a pointer which the provider writes the necessary
  size (many API's work like this). It's especially pernicious
  because `shmcb` is the default provider *and* a NOT_FOUND error has
  nothing to do with the actual problem. Therefore it's best to over
  allocate despite the obvious inefficiency.

  This issue is the **only** reason the
  `MellonSoCacheSessionStateSize` directive exists.

## Future Enhancements

Here are a few thoughts about possible enhancements, things which are
not essential now but could be beneficial down the road.

### Cache Data Filters

Just prior to when data is written into the cache and just after when
data is read from the cache would be a good place to invoke routines
to transform the data. Potential data filters are:

* Compression: The XML representation of the session state data can be
  verbose. Standard ZLib compression would significantly reduce the
  size of the cache entry. ZLib is already linked in because Lasso
  depends on it. Some socache providers may offer this feature.

* Encryption: Sensitive authentication data at rest should be
  protected. Some socache providers may offer this feature.
