# CSMS

One EV Charging Station Management System, with a web interface in front of it:
a C# HTTP backend built on [Hermod](https://github.com/Vanaheimr/Hermod), and a
frontend of HTML, SCSS and TypeScript bundled by webpack and embedded into the
assembly - so the CSMS is one binary to deploy and needs nothing installed
beside it.

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
[LocalController](https://github.com/OpenChargingCloud/LocalController), and
everything below - the DNS and NTS configuration, the charging station server,
the certificate and trust stores, the station logins, the event log - is the
same code doing the same thing at the other end of the same connection.


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

One HTTP server, one port, three things registered on it in that order: the most
specific first, the single-page-application catch-all last.

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
server and the HTTPExt API are made where the listening address, the port and
the moment of starting are decided, and the node is handed a role rather than a
socket.


## What it can be told

| Page | What it changes | Permission |
|------|-----------------|------------|
| Configuration | nothing - it answers "what am I running" | `readConfiguration` |
| DNS client | the name servers and how they are asked; a test lookup | `changeNetworkSettings`, `runDiagnostics` |
| NTS client | the time server and how it is asked; a synchronisation | `changeNetworkSettings`, `runDiagnostics` |
| Charging station server | the port, TLS, the security profiles it accepts | `changeStationSettings` |
| Server certificates | the keys and chains this CSMS presents | `manageCertificates` |
| Client trust | the chains a station's certificate may come from | `manageCertificates` |
| Station logins | who may sign in, and with what | `changeStationSettings` |
| OCPI | nothing - who this operator is and where its partners find it | `readConfiguration` |
| Roaming partners | the EMSPs it is peered with, and the peering itself | `manageRoamingPartners` |
| Locations | the charging locations it publishes | `manageLocations` |
| Roaming data | nothing - what travels between it and its partners | `readConfiguration` |
| Logs | nothing - it reads | `readConfiguration` |

Everything on the DNS and NTS pages takes effect the moment it is saved, for
everything inside the CSMS that resolves a name or reads a clock, and is written
to `configuration.json` in the same breath - the file first, because a change
that was applied but not written down disappears at the next start without
anybody noticing.

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
and a CSMS that is told to stop stops.

Each test gets a CSMS of its own, on a port the operating system has just
confirmed is free and with its own directory for the files a CSMS writes - so
they neither fight with each other nor with a CSMS somebody has running on 2351
while they work.

**They never touch the network.** The configuration written before each CSMS is
built switches the time client off, which is what stops the clock check from
being scheduled at all, and the DNS client is only ever asked what it is
configured as. A test suite that needs a name server to answer is a test suite
that fails on a train.


## The clock

`CSMS` takes a `TimeProvider` as its last constructor parameter and hands it to
everything of its own that asks what time it is: the timestamp of every log
entry, `CreatedAt`, the uptime the status resource reports, and the sessions -
through Hermod's `SessionStore`, which takes one too. The system clock by
default; an NTS-disciplined or a fake one where a test says so.

It is assigned first in the constructor, before the event log is built, because
the log stamps its entries with it - a clock set afterwards would leave the log
reading the system one, which is a log that cannot be held against anything.

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
server what time it is, measures the difference and reports it - and leaves its
own clock exactly where it was. Everything connected to this CSMS is stamped
against this clock, so a jump backwards would put two meter readings out of order
in a record written somewhere else entirely, with nothing in it to say why.

`GET /api/v1/configuration/time` is that measurement, and the one word it never
guesses is "legal": that needs a claim the operator wrote into
`nts.legalTimeAuthority`, a check against that very server, a recent one, and a
small difference. Any of those missing and the answer says `unverified` and names
which one in `why`.


## The log

Every entry carries a timestamp, a level (`debug`, `info`, `notice`, `warning`,
`error`, `critical`) and any number of tags (`http`, `ocpp`, `dns`, `nts`, `web`,
`auth`, `station`, ...). The Logs page filters on both - the level counts as a
tag, so `critical` and `ocpp` can be picked together.

Anything in the CSMS can write to it:

```csharp
csms.Log.Warning("A charging station was turned away.", "ocpp", "station");
```

What the libraries below write through Illias' `DebugX` lands there too, tagged
`trace` plus whatever `TraceBridge` recognises in the text. That works in a debug
build only: `Debug.WriteLine` carries `[Conditional("DEBUG")]`, so a release
build of those libraries compiles the calls away. `--no-trace` switches the
bridge off.

The entries are numbered and the number only ever grows. A browser loads a
snapshot from `/api/v1/logs`, which says how far it reaches, and then applies
everything newer from `/api/v1/events` - so a reconnect that replays a few cached
events costs bytes and nothing else.

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

What somebody may do comes from the groups they are in, one per role:

| Role | May |
|------|-----|
| `viewer` | read the configuration and the log |
| `cpo` | that, and change the name and time servers, and test them |
| `systemadmin` | everything this CSMS can be told |

The groups are made at every start rather than only the first, because they are
this CSMS's vocabulary and not somebody's data: a group deleted by hand would
otherwise leave a role nobody could ever hold again. Membership is asked of the
groups on every request rather than remembered at the sign-in, so taking
somebody out of one takes effect on their next request instead of at their next
sign-in. The permissions travel to the browser so a page can grey out what
somebody may not do - a courtesy, not a lock: every request is checked again on
arrival.
