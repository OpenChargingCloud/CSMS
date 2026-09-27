# CSMS

One EV Charging Station Management System, with a web interface in front of it:
a C# HTTP backend built on [Hermod](https://github.com/Vanaheimr/Hermod), and a
frontend of HTML, SCSS and TypeScript bundled by webpack and embedded into the
assembly - so the CSMS is one binary to deploy and needs nothing installed
beside it.

Below it is [WWCP_Node](https://github.com/OpenChargingCloud/WWCP_Node): what
every one of these programs is before it is anything in particular - the log,
the configuration file, name resolution and the time, a certificate store, the
accounts, and the HTTP server with the web interface behind it. The vehicle of
[EV](https://github.com/OpenChargingCloud/EV) is one of those with a battery,
[ChargingStation](https://github.com/OpenChargingCloud/ChargingStation) one
with EVSEs; this CSMS is one with a server on a port of its own for the
charging stations, the OCPI endpoints its roaming partners call, and the OCPP
node it speaks through.

Nothing is rendered on the server. The browser loads one bundle and talks to the
CSMS over a JSON API and one Server-Sent Events stream.

```
  browser  ──  GET  /                       the SPA stub and the bundle
           ──  POST /api/v1/auth/login      the session cookie
           ──  GET  /api/v1/configuration   what the CSMS is made of
           ──  GET  /api/v1/logs            what happened up to now
           ──  GET  /api/v1/events          and everything from now on (SSE)
           ──       /ext/...                the HTTPExt API: accounts, API keys
```

A CSMS sits above the charging stations and the local controllers that dial into
it, and is the thing they are all pointed at. That is what the web interface is
for: it is the one place where somebody can see which of them got in, which were
turned away and why, without reading a log file over somebody else's shoulder.

Beside that it is a charge point operator in OCPI: the e-mobility service
providers whose customers charge at those stations are peered with it, it
publishes the locations its stations stand at, and it takes what the partners
push. Two protocols and one box - separate ports, separate identities, separate
stores - and what ties them together is that an operator with no stations has
nothing to publish and an operator with no partners has nobody to publish it to.

This is built the same way as
[ChargingStation](https://github.com/OpenChargingCloud/ChargingStation) and
[LocalController](https://github.com/OpenChargingCloud/LocalController). The
DNS and NTS configuration, the clock and the event log are the node's below,
and so the very code the station runs; the charging station server, the
certificate and trust stores and the station logins are the same thing done at
the other end of the same connection.


## Who may open it: `HTTPExtAPI`

A CSMS is the back end of an estate: the people who read it are not the people
who configure it, the machines that call it are not people at all, and both
outlive any one of its operators. So the HTTP server of this CSMS carries
Hermod's `HTTPExtAPI` - accounts, groups, organizations and API keys, kept in a
directory of its own - at `/ext`, beside the JSON API at `/api` and the web
interface at `/`.

The vehicle, the charging station and the local controller sign in against the
same thing, and their roles are groups in it with names that overlap on purpose:
all four have `systemadmin` and `viewer`, three of them have `cpo`. So handing
one `HTTPExtAPI` to several of them makes one sign-in open all of them, with
each still deciding for itself what a role permits - which is what
[EVChargingTestEnvironment](https://github.com/OpenChargingCloud/EVChargingTestEnvironment)
does with `--shared`.

One HTTP server, one port, three things registered on it: the accounts and the
web interface by the node below, the JSON API by the CSMS. A request goes to the
most specific of them, so the single-page-application catch-all only ever gets
what neither of the other two claims - `AnUnknownAPIPathAnswersJSONAndNotTheStub`
says so.

```csharp
var csms = new CSMS(HTTPPort: IPPort.Parse(2351));

csms.HTTPServer   // the one server everything is registered within
csms.ExtAPI       // the accounts at /ext
csms.API          // the JSON API at /api
csms.Node         // the OCPP 2.1 CSMS node
```

The OCPP node's own HTTP APIs are switched off on purpose. Left alone an
`ACSMSNode` builds a second HTTP server and a second `HTTPExtAPI` on a port it
picks itself; one CSMS should be one address to point a browser at, so the
server and the HTTPExt API are the node's below, made where the listening
address, the port and the moment of starting are decided, and the OCPP node is
handed a role rather than a socket.


## What it can be told

| Page | What it changes | Permission |
|------|-----------------|------------|
| Configuration | nothing - it answers "what am I running" | `configuration:read` |
| DNS client | the name servers, how they are asked and what each is held to; a test lookup, of all of them or of one | `dns:edit`, `dns:run` |
| NTS client | the time servers of the group, what it and each of them is held to; a synchronisation, and a test of each server | `nts:edit`, `nts:run` |
| Certificate store | the roots and the server certificates this CSMS believes, and what each is for | `certificates:edit` |
| Charging station server | the port, TLS, the security profiles it accepts | `stations:edit` |
| Server certificates | the keys and chains this CSMS presents | `certificates:edit` |
| Client trust | the chains a station's certificate may come from | `certificates:edit` |
| Station logins | who may sign in, and with what | `stations:edit` |
| OCPI | nothing - who this operator is and where its partners find it | `roaming:read` |
| Roaming partners | the EMSPs it is peered with, and the peering itself | `roaming:edit` |
| Locations | the charging locations it publishes | `locations:edit` |
| Roaming data | nothing - what travels between it and its partners | `roaming:read` |
| Logs | nothing - it reads | anybody signed in |

Looking at a page takes `read` on the resource in its column: `dns:read` for
the DNS client, `stations:read` for the charging station server. The clock, the
log and the event stream are for anybody signed in. Which roles hold what is
under "Who may open it" below.

Everything on the DNS and NTS pages takes effect the moment it is saved, for
everything inside the CSMS that resolves a name or reads a clock, and is written
to `configuration.json` in the same breath - the file first, because a change
that was applied but not written down disappears at the next start without
anybody noticing.

The node below reads the sections every one of these programs has - `dns`,
`nts` and `certificates` - and the CSMS reads its own - `ocpp`, `ocppServer`
and `ocpi` - from the same document; each passes over what is the other's.
Beside the file the node keeps its certificate store, in `certificates/`, and
what it believed each server with, in `known-servers.json`. What the CSMS
presents to the charging stations and believes of them is its charging station
server's, in stores of its own beside the file: the keys it presents in
`ocpp-server-keys/`, and the chains it trusts them by in `ocpp-client-trust/`.

What this CSMS says it is in OCPP - its node id, vendor, model, serial number -
is read from the `ocpp` section of that file at the start and is deliberately
*not* changeable while running: an identification is what a charging station
knows this CSMS by, and changing it under live connections would not rename the
CSMS, it would make it a second one nobody is talking to.

The same goes for the `ocpi` section - the country code, the party
identification, the business name and the versions offered. Those are what every
roaming partner wrote into its credentials, and they have nothing to do with the
OCPP identification above. The partners themselves are *not* in that file: the
OCPI library keeps them, and what they sent, in append-only files of its own
below an `ocpi/` directory beside the configuration, one set per version, and
reads them back at every start.


## Certificates, and where they live

Two sets of stores, because they face two different ways. What this CSMS
presents to the charging stations, and the chains it lets them in by, are its
charging station server's: `ocpp-server-keys/` and `ocpp-client-trust/`, the
Server certificates and the Accepted chains pages. Everything else it believes
is in the node's store below - WWCP_Node's `CertificateStore`, a directory of
files with an `index.json` beside them, in `certificates/` beside the
configuration file - and is addressed by a short handle rather than by a path.
The Certificate store page manages it, and so do CSMSCLI's
`--import-certificate` and `--list-certificates`.

A CSMS keeps seven of the node's eleven kinds, `CSMS.CertificateKinds`: the
vehicle's credentials are no business of the back end's.

A **root** is what this CSMS believes. `tlsRoot` is for a server it connects
to - a time server, or a name server over TLS or HTTPS - and is believed beside
the roots of the machine it runs on, not instead of them. `v2gRoot`, `moRoot`
and `oemRoot` are ISO 15118's, for a station's chain, a contract's and a
provisioning chain. They are kept apart because one bag of roots would let an
OEM root vouch for a contract, and they are kept for what is to come: nothing
in this CSMS checks a chain against them yet. Any number of each may be
switched on at once, and all of them are believed.

A **server certificate** - `tlsServer` - is what a server this CSMS connects to
shows, kept so that the server can be held to it by its fingerprint, and never
with a private key, which would be that server's key in the wrong place. The
page shows these as a third group, what the CSMS *recognises*. `clientRoot` and
`tlsIdentity` are kept as well, and nothing in the CSMS uses them yet. An
identity is told the listeners it is shown on where a kind of node names some;
a CSMS names none, so the page offers an identity nothing to be told.

A TLS root and a server certificate are told what they are for: the time
servers (`nts`), the name servers (`dns`), or - with nothing said - every use.
The page asks at the upload and again with **Uses**, because one root may vouch
for both, and a root kept for the name servers alone vouches for no time. What
a server is held to is said in its own entry, on the NTS and the DNS page,
where its dialog offers the ones kept for it.

The store holds private keys **unencrypted** - of these kinds only a
`tlsIdentity` has one: a PKCS#12 is opened with its password once, at import,
and written back without one. The file system is what guards them, and the
CSMS says so at every start and at every import. A file copied into the
directory by hand is adopted at the next start, or at once with **Reload** on
the page.


## Running it

From the repository that has this one as a submodule
([CSMSCLI](https://github.com/OpenChargingCloud/CSMSCLI)):

```
dotnet run --project CSMSCLI
```

At the first start there are no accounts, so the CSMS makes one up - `root`,
under `accounts/` beside the configuration - and prints its password once:

```
  ┌─ First start: there were no accounts, so one was made up for you ─────────
  │  user      root
  │  password  QBDD77Lc7HseB-xORuuw8RpX
  │  It is shown here once and kept only as a hash. Write it down.
  └───────────────────────────────────────────────────────────────────────────
```

Then open http://127.0.0.1:2351/ and sign in. Signing in happens at Hermod's
HTTPExt API, mounted under `/ext` - the same door the charging station and the
local controller use.

Port 2351 and not 2348 or 2350: an OpenChargingCloud charging station uses 2348
and 2349 and a local controller 2350, and all three are routinely tried out on
the same bench.


## Building

`dotnet build` builds the frontend too: `CSMS.csproj` runs `npm ci` (only when
`Frontend/node_modules` is missing) and `npm run build` (only when something
under `Frontend/src` changed), then embeds every file of `Frontend/dist` as a
manifest resource named `cloud.charging.open.CSMS.HTTPRoot.<path>` - which is
what Hermod's `EmbeddedContentSource` reads and `MapSinglePageApplication`
serves.

```
dotnet build                            the whole thing
dotnet build -p:SkipFrontendBuild=true  backend only, reusing the existing dist/ -
                                        and where there is none, no web interface
                                        at all, which is a warning and not an error
npm run watch     (in Frontend/)        rebuild the bundle as it is edited
npm run typecheck (in Frontend/)        tsc --noEmit
```

While editing the frontend, start the CSMS with `--frontend
libs/CSMS/CSMS/Frontend/dist` so that it serves the directory `npm run watch`
writes into: a reload in the browser then shows the change, without rebuilding
the C# side.


## The tests

```
dotnet test libs/CSMS/CSMSTests
```

They start real CSMSs and talk to them over HTTP the way the browser does: the
bundle is served, the sign-in works, a change to the name servers reaches both
the shared DNS client and the file, the log filters, the event stream delivers,
and a CSMS that is told to stop stops. `CSMSAccessTests` reads the one permission
every route of the API asks for off the refusal an account in no role is given,
and the certificate store is filled, told what a root is for and told again
over the API, as the page does it. What the node below does on its own -
the file's sections, the log, the time servers, the certificate store, the
accounts' roles and the ports - is tested once more in WWCP_Node's own
`WWCP_Node_Tests`, against a node of no particular kind.

Each test gets a CSMS of its own, on a port the operating system has just
confirmed is free and with its own directory for what a CSMS writes: its
accounts, its configuration file, and beside that the stores of the charging
station server - so they neither fight with each other nor with a CSMS
somebody has running on 2351 while they work.

**They never touch the network.** The configuration written before each CSMS is
built switches the time client off, which is what stops the clock check from
being scheduled at all, and the DNS client is asked what it is configured as -
or, once, a name server on the loopback address that nothing listens at. A test
suite that needs a name server to answer is a test suite that fails on a train.


## The clock

`CSMS` takes a `TimeProvider` as its last constructor parameter and hands it to
everything of its own that asks what time it is: the timestamp of every log
entry, `CreatedAt`, the uptime the status resource reports, and the sessions -
through Hermod's `SessionStore`, which takes one too. The system clock by
default; an NTS-disciplined or a fake one where a test says so.

It is assigned first - by the node below, before the event log is built -
because the log stamps its entries with it: a clock set afterwards would leave
the log reading the system one, which is a log that cannot be held against
anything.

```csharp
sealed class FixedClock(DateTimeOffset Start) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = Start;
    public override DateTimeOffset GetUtcNow() => Now;
}

var clock = new FixedClock(new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero));
var csms  = new CSMS(TimeProvider: clock);

csms.Sessions.TryLogin("root", password, out var session);   // 1 live session
clock.Now = clock.Now.AddHours(13);                          // past the 12 hour idle timeout
var gone  = csms.Sessions.Count;                             // 0
```

**The clock is never set from NTS.** Every fifteen minutes the CSMS asks its time
servers what time it is, measures the difference and reports it - and leaves its
own clock exactly where it was. Everything connected to this CSMS is stamped
against this clock, so a jump backwards would put two meter readings out of order
in a record written somewhere else entirely, with nothing in it to say why.

**It asks a group, not a server.** `nts.servers` is a list, and by default it is
the PTB's four, of which `nts.minServers` - two - have to answer before the group
has a time at all. One host being rebooted no longer leaves this CSMS without a
check, and two servers that agree catch what one server cannot: one that is
wrong rather than absent. What the check reports is what the servers that
answered and authenticated agree on, with a line for each of them, so a failure
says which of the four failed and how.

Every key of the `nts` section, and what it is when absent:

| Key | Default | |
|---|---|---|
| `enabled` | `true` | whether to ask at all |
| `servers` | the PTB's four | a list, see below |
| `minServers` | `2`, or all of them when fewer | how many must answer for the group to have a time |
| `maxDeviationSeconds` | `60` | how far apart they may be before it is written down |
| `hostname` | - | one server instead of a list |
| `ntsKEPort`, `ntpPort` | `4460`, `123` | for that one server |
| `timeoutSeconds` | `10` | per request |
| `checkEverySeconds` | `900` | how often the clock is checked |
| `legalTimeAuthority` | - | who the operator says stands behind it |
| `legalTimeToleranceSeconds` | `1` | how far off the clock may be |
| `legalTimeMaxAgeSeconds` | `3600` | how old the last check may be |

Servers sharing a priority are **one band** and are asked together; a lower
priority is asked first. The four it asks by default share one, because they are
peers - putting them in separate bands would say something about them that is not
true. An entry may be a bare host name or an object saying more:
`{ "hostname": "time.local", "priority": 0, "ntsKEPort": 4460, "enabled": true }`.

Servers that disagree by more than `nts.maxDeviationSeconds` are written down
rather than acted on. The disagreement belongs in the log, and the time is still a
time.

A section naming a single `hostname` and no list becomes a group of one, which is
what every file written before there were groups says, and it keeps working. A
group of one is held to a quorum of one, and a section asking two of it is
refused. A list without `minServers` is held to two, as the default four are, or
to all of its servers when it has fewer switched on.

A section mentioning neither leaves the servers alone rather than quietly reducing
four to one - the switch on the NTS page sends nothing but `enabled` - and one
mentioning nothing but `minServers` or `maxDeviationSeconds` holds the servers the
CSMS already has to it. A quorum those servers could never reach is refused: at
the start, before anything is asked, and over the API, before anything is written
into the file. A new interval, and switching NTS off or on, reach a running check
at once.

A host name written back into the file carries the root label -
`ptbtime1.ptb.de.` - because that is the absolute form it was parsed into, and not
a stray character. What the CSMS prints for somebody to read drops it again.

An entry of `dns.servers` is an address or a host name, as a string or as the
object the DNS page writes the list back in:

```json
{ "address": "9.9.9.9", "port": 853, "transport": "TLS", "queryTimeoutSeconds": 2 }
```

Without a port, the transport's own is used. `udp://9.9.9.9:53` is how the log and
the banner name a name server, and not a form the file takes: a file saying it is
refused at the start, and the page refuses it the same way, with the entry named.

`GET /api/v1/configuration/time` is that measurement, and the one word it never
guesses is "legal": that needs a claim the operator wrote into
`nts.legalTimeAuthority`, a check against that very server, a recent one, and a
small difference. Any of those missing and the answer says `unverified` and names
which one in `why`.


## One server at a time

A time server, and a name server asked over TLS or HTTPS, can be held to a
certificate or a root, and the NTS and the DNS page are where that is said: a
server's dialog takes SHA-256 fingerprints one to a line, adds the one the
server showed last or one the certificate store keeps for it with a click, and
says what a mismatch comes to and whether the server is held to what it is
first believed with. Its row says what was made of its certificate the last
time - believed, used although it did not match, or refused, and why - what it
is held to, and when it showed another certificate than before. How a
certificate is judged, what trust on first use learns and what
`known-servers.json` remembers are the node's, and written down once in
[WWCP_Node's README](https://github.com/OpenChargingCloud/WWCP_Node#name-resolution-and-the-time).

Each server can be asked on its own, too. The NTS page tests one time server
step by step, down to the SHA-256 fingerprint of the certificate it showed -
`POST /api/v1/configuration/nts/test` with a `host` - and measures the clock
without stepping it. The DNS page asks the name servers the way everything in
the CSMS does, or one of them alone - `POST /api/v1/configuration/dns/query`
with a `server`, its place in the list counted from 0 - because the lookup
that fails for everybody is the one where somebody wants to know which server
is not answering. A place with no server at it is an answer that says so, and
something that is not a place is refused rather than read as "all of them".

The whole list goes to the CSMS at every save, so every server goes with what
it is held to, and the pages' `ntsServers.ts`, `dnsServers.ts` and `pins.ts`
are where that is decided and tested: a list sent without the pins of the
servers nobody touched would let go of them, the ones learned on first use
included. A name server switched to a transport that shows no certificate lets
go of its pins when it is saved - the CSMS would refuse them - and its row says
so first. Holding a server to a fingerprint is `dns:edit` or `nts:edit`, with
the rest of the server, and so the CPO's: a pin cannot make the CSMS believe a
certificate that chains to nothing this machine or its store holds, and what
goes into the store stays the administrators'.


## The log

Every entry carries a timestamp, a level (`debug`, `info`, `notice`, `warning`,
`error`, `critical`) and any number of tags (`http`, `ocpp`, `dns`, `nts`, `web`,
`auth`, `station`, ...). The Logs page filters on both - the level counts as a
tag, so `critical` and `ocpp` can be picked together. The log is the node's, and
so are its three listeners - the console, the file and the debug bridge; the
entries about the CSMS itself are tagged `csms`, and a day's file is
`csms-2026-09-25.log`.

Anything in the CSMS can write to it:

```csharp
csms.Log.Warning("A charging station was turned away.", "ocpp", "station");
```

What the libraries below write through Illias' `DebugX` lands there too, tagged
`trace` plus whatever the CSMS's own table, `CSMS.TraceTags`, recognises in the
text - OCPP and which side of it a line is about, rather than the vehicle's
ISO 15118 the node's default table leans towards. That works in a debug
build only: `Debug.WriteLine` carries `[Conditional("DEBUG")]`, so a release
build of those libraries compiles the calls away. `--no-trace` switches the
bridge off.

The entries are numbered and the number only ever grows. A browser loads a
snapshot from `/api/v1/logs`, which says how far it reaches, and then applies
everything newer from `/api/v1/events` - so a reconnect that replays a few cached
events costs bytes and nothing else.

Three places keep it, because they answer different questions. The console
shows it to whoever started the CSMS, at the level they chose; the Logs page
keeps the last two thousand entries; and a `LogPath` handed to the constructor
writes every entry, down to the debug ones, into one file per UTC day below it.
CSMSCLI does that unless told `--no-log-file`, since the other two are gone with
the process. A file that cannot be written is said once on stderr, and the file
says how many entries it missed once it can be written again.

A program that reads commands on the same console hands the log a way to write
around the line being typed, so that an entry arriving mid-word neither lands
inside the command nor waits for it:

```csharp
csms.ShareConsoleWith(cli.WriteBlock);   // line off, entry whole, line back
```


## Who may open it

One answer, and it is Hermod's: the accounts of the **HTTPExt API** at `/ext`,
under `accounts/`, with every password kept as a PBKDF2-SHA256 PHC string and
never in the clear. Signing in happens there; this CSMS's own API only reads
what that door set.

What somebody may do comes from the groups they are in. Each group is one role,
under the same name, and a role is a list of permissions, each an operation on a
resource - written `dns:edit`. That is the model of every node, described in
[WWCP_Node](https://github.com/OpenChargingCloud/WWCP_Node) under "Who may sign
in"; the operations are `read`, `edit` and `run`, and the resources are the
node's `configuration`, `dns`, `nts` and `certificates` and the three a CSMS
adds: `stations`, the charging station server and which stations may sign in;
`locations`, the locations it publishes; and `roaming`, who it is in OCPI and
the partners it is peered with.

| Role | May |
|------|-----|
| `viewer` | read everything: `*:read` |
| `cpo` | that, and run the charging stations: change the name and time servers and ask them (`dns` and `nts`, `edit` and `run`), and change the charging stations and the locations (`stations:edit`, `locations:edit`) |
| `systemadmin` | everything this CSMS can be told, the certificates and the roaming included |

The viewer and the administrators are the node's, the CPO is the CSMS's - see
`CSMSAccess.cs`. The certificates and the roaming are the two resources only
the administrators may change: somebody who can add a certificate authority can
let in a charging station that nobody issued a password to, or make this CSMS
believe a time server nobody else would, and who this operator is peered with
is a contract with somebody else.

The `roles` section of `configuration.json` adds roles, or says differently what
one of them may do - and a role there that names a resource this CSMS does not
have stops the start, rather than quietly granting nothing:

```json
"roles": { "support": [ "dns:read", "stations:read" ] }
```

The groups are made at every start rather than only the first, because they are
this CSMS's vocabulary and not somebody's data: a group deleted by hand would
otherwise leave a role nobody could ever hold again. A group that is none of
these, and none the file names, grants nothing - a role this CSMS has never
heard of is a role it cannot enforce. Membership is asked of the groups on every
request rather than remembered at the sign-in, so taking somebody out of one
takes effect on their next request instead of at their next sign-in. The
permissions travel to the browser, spelt out resource by resource, so a page can
grey out what somebody may not do - a courtesy, not a lock: every request is
checked again on arrival.


## Your participation

This software is Open Source under the **Affero GPL 3.0 license**.
We appreciate your participation in this ongoing project, and your help to
improve it and the e-mobility ICT in general. If you find bugs, want to
request a feature or send us a pull request, feel free to use the normal
GitHub features to do so. For this please read the Contributor License
Agreement carefully and send us a signed copy or use a similar free and
open license.
