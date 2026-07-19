# Analyse & Härtung: Hermod HTTP/1.1 WebSocket Server & Client

Datum: 2026-07-19 (aktualisiert) · Basis: `libs/Hermod` @ `4c07a48c` (graphdefined-Merge `7fa61011`) · RFC 6455 / 7692 / 8441

## 1. Zusammenfassung

Die Hermod-WebSocket-Implementierung (`libs/Hermod/Hermod/WebSocket`) wurde statisch
analysiert, gegen die **Autobahn-Testsuite** (crossbario/autobahn-testsuite, Docker/WSL2)
getestet, gehärtet und um **permessage-deflate (RFC 7692)** erweitert. Endstand:

| | vor den Fixes | **nach den Fixes** |
|---|---|---|
| **Server** (301 Fälle, Sekt. 1–10) | 200 OK / **98 FAILED** | **296 OK / 0 FAILED** / 2 NON-STRICT / 3 INFO |
| **Client** (247 Fälle, Sekt. 1–7, 10) | 146 OK / **97 FAILED** | **242 OK / 0 FAILED** / 2 NON-STRICT / 3 INFO |
| **Server**, Kompression (Sekt. 12/13) | — (nicht implementiert) | **126 OK / 0 FAILED** / 18 UNIMPLEMENTED¹ |
| **Client**, Kompression (Sekt. 12/13) | — (nicht implementiert) | **126 OK / 0 FAILED** / 18 UNIMPLEMENTED¹ |
| Close-Verhalten Server | 96 FAILED / 11 WRONG CODE | **298 OK / 0 FAILED** |
| Close-Verhalten Client | 100 FAILED / 29 UNCLEAN | **244 OK / 0 FAILED / 0 UNCLEAN** |

(NON-STRICT = 6.4.3/6.4.4, „fail fast on invalid UTF-8" — nur eine MAY-Anforderung,
gilt als bestanden. INFORMATIONAL sind keine Fehler.
¹ = 13.3.\* `server_max_window_bits` < 15: bewusst abgelehnt, da .NETs `DeflateStream`
die DEFLATE-Fenstergröße nicht konfigurieren kann; RFC 7692 erlaubt das Ablehnen.)

Alle Änderungen sind im Hermod-Submodul **committet und gepusht** (GitHub `origin`
sowie graphdefined `git1`/`git2`):

- `9a27ae20` — RFC-6455-Konformitäts- und Robustheits-Fixes (C1–C9, S1–S5)
- `fe4e943e` — Nachrichten-Limits (S6), Server-Handshake-Validierung (S7), asynchroner Empfangspfad (S8/C4)
- `608b826e` — permessage-deflate (RFC 7692)
- `4c07a48c` — Härtung: Pong-Timeout/Zombie-Erkennung + N1–N5 (siehe Abschnitt 5)

Einbettung in die Remote-Historie (zwei zeitweise divergente Linien, inzwischen
zusammengeführt):

- `8a1ae83` — Merge der ersten drei Commits mit dem DNS-Underscore-Fix (`9d3eb764`)
- `7fa61011` — Merge von `4c07a48c` mit der graphdefined-Linie (DNSSEC-Fixes, neuer
  SMTP-Stack `3d3e1a53`); `git1`/`git2` stehen auf `7fa61011`, GitHub `origin` auf `4c07a48c`
  (Vorfahre von `7fa61011`) — der CSMS-Pointer löst von beiden Remotes auf.
- CSMS-Hauptrepo: Submodul-Zeiger-Commit `1bb8eb5` (zeigt auf `4c07a48c`;
  zuvor `ca87cf9` → `8a1ae83`), gepusht nach graphdefined SSH.

Abgesichert durch die Autobahn-Suiten und die NUnit-Tests (23/23 WebSocket-Tests grün;
27/28 im breiteren Filter — der eine Ausfall ist der vorbestehende TLS-Fixture-Bug,
s. Abschnitt 5). Der Endstand wurde per Code-Review (2026-07-19) gegen den committeten
Stand re-verifiziert.

## 2. Behobene Bugs (Familie „Funktionsfehler im Client")

**C1 — Frames direkt nach dem Handshake wurden verschluckt.** `WaitForHTTPResponse()` las
in 2-KB-Blöcken über das HTTP-Header-Ende hinaus und verwarf dabei WebSocket-Frames, die
der Server direkt nach dem `101` sendete. Fix: byteweises Lesen bis `\r\n\r\n`.

**C2 — TCP-Abbruch der Gegenstelle wurde nie erkannt.** Ein TCP-FIN/RST ist über
`DataAvailable`-Polling prinzipiell unsichtbar. Fix: neues Property
`WebSocketClientConnection.IsRemoteTCPConnectionClosed` (`Socket.Poll(SelectRead)` +
`Available == 0`), Auswertung in der Empfangsschleife, Event `OnCloseMessageReceived`
mit 1006/`AbnormalClosure`. Verifiziert: Erkennung in 19 ms; 3 s Idle ohne False-Positive.

**C6 — Query-String der Ziel-URL ging beim Handshake verloren.** `SendHTTPRequest()`
übernahm nur `RemoteURL.Path`. Fix: `QueryString`-Übernahme in den Request-Builder.

**C7 — Sends an eine gestaute Gegenstelle blockierten dauerhaft (Client & Server).**
`Stream.WriteTimeout` gilt nur für synchrone Writes; `WriteAsync` blockierte unbegrenzt,
hielt die Write-Semaphore und deadlockte damit auch `Close()`. Fix in beiden
Connection-Klassen: Semaphore-Wait mit Timeout, asynchrone Writes über
`CancellationTokenSource.CancelAfter(WriteTimeout, Default 30 s)` begrenzt (Timeout ⇒
`SentStatus.FatalError`), Close-Frame-Versand auf 5 s begrenzt (`DefaultCloseTimeout`).
Verifiziert gegen einen Peer, der nach dem Handshake nie liest: Send `FatalError` nach
~2 s (konfigurierter WriteTimeout), `Close()` kehrt in ~2 s zurück (vorher: nie).

**C8 — Close-Frames des Clients waren unmaskiert.** `WebSocketClientConnection.Close()`
sendete Close-Frames ohne Maske — ein RFC-Verstoß (Client→Server MUSS maskieren), den
jede strikte Gegenstelle als Protokollfehler wertet. Ursache der meisten
„UNCLEAN/FAILED"-Close-Bewertungen. Fix: Maskierung ergänzt.

**C9 — Frame-Bursts deadlockten die Client-Empfangsschleife.** Nach dem Parsen des ersten
Frames eines Batches folgte ein *blockierender* Read, bevor bereits gepufferte Frames
verarbeitet wurden — wartete die Gegenstelle auf unsere Antwort (Ping zwischen Fragmenten,
Pong-Fluten), stand die Verbindung bis zum Timeout. Fix: erst den Puffer leerparsen,
nur bei unvollständigen Frames nachlesen (`needMoreData`).

## 3. Behobene Konformitätslücken (RFC 6455)

**S1 — UTF-8-Validierung (größter Autobahn-Block, ~75–79 Fälle je Seite).** Text-Payloads
wurden mit `Encoding.UTF8.GetString` dekodiert (ersetzt ungültige Sequenzen statt
abzulehnen). Fix: `Utf8.IsValid` für komplette Nachrichten plus neue Klasse
`IncrementalUtf8Validator` (Rune-basiert) für fragmentierte Nachrichten mit Fail-fast
über Fragmentgrenzen hinweg; Verstoß ⇒ 1007 (Server & Client).

**S2 — Parser unterscheidet jetzt „unvollständig" von „Protokollfehler".** Neues
`WebSocketFrame.Parse(...)` mit `ParseResult` (Success / IncompleteData /
ProtocolViolation) und `SuggestedCloseCode` (1002/1007/1009); das alte `TryParse`
delegiert kompatibel. Vorher führten harte Protokollfehler (fragmentierte Kontrollframes,
Kontrollframes > 125 B, Übergrößen) zu hängenden Verbindungen statt zu 1002/1009.

**S3 — Reservierte Opcodes (0x3–0x7, 0xB–0xF) und RSV-Bits werden abgelehnt** (1002).
RSV1 ist nur zulässig, wenn permessage-deflate ausgehandelt wurde, und nur auf dem
ersten Frame einer Datennachricht; RSV2/RSV3 sind immer unzulässig.

**S4 — Close-Handling vollständig.** Close-Payload der Länge 1, ungültige Statuscodes
(0–999, 1004–1006, 1015–2999, ≥5000; gültig: 1000–1003, 1007–1014, 3000–4999) und
ungültiges UTF-8 in der Close-Reason werden abgelehnt (`IsValidCloseCode`, Prüfung im
Parser); beim Close-Handshake wird der empfangene Statuscode gespiegelt statt pauschal
1000 zu senden.

**S5 — Strikte Fragmentierungs-Zustandsmaschine.** Ein neues Text-/Binary-Frame während
einer offenen fragmentierten Nachricht sowie verwaiste Continuation-Frames failen die
Verbindung mit 1002 (vorher: stiller Puffer-Overwrite bzw. nur Logging im Client).

**Zusätzlich (Server): Maskierungs-Pflicht wird durchgesetzt.** Unmaskierte
Client-Frames failen die Verbindung mit 1002 (RFC 6455 § 5.1) — von Autobahn nicht
getestet, im Code-Review verifiziert.

## 4. Umgesetzte Architektur- und Sicherheitsthemen (vormals „offene Punkte")

**S6 — Nachrichten-Limits (Commit `fe4e943e`).** `MaxTextMessageSizeIn`/
`MaxBinaryMessageSizeIn` werden jetzt durchgesetzt — auf Einzel-Frames *und* auf die
akkumulierte Größe fragmentierter Nachrichten, geprüft **vor** dem Puffern (bounded
memory, 1009 bei Verstoß). Zusätzlich begrenzt `DefaultMaxPayloadSize` (64 MB) jedes
Einzel-Frame im Parser.

**S7 — Server-Handshake-Validierung (Commit `fe4e943e`).** `Upgrade: websocket` und
`Connection: Upgrade` (Token-Listen, case-insensitive), `Sec-WebSocket-Key`
(Base64, exakt 16 Bytes) ⇒ sonst `400 Bad Request`; `Sec-WebSocket-Version` ≠ 13 ⇒
`426 Upgrade Required` mit `Sec-WebSocket-Version: 13` (RFC 6455 § 4.2/4.4).

**S8/C4 — Asynchroner Empfangspfad (Commit `fe4e943e`).** Busy-Polling
(`DataAvailable` + `Task.Delay`) durch `ReadAsync` mit CancellationToken ersetzt
(Server: Timeout = Ping-Intervall; Client: 1-s-Wake-up zur Zustandsprüfung).

**permessage-deflate (RFC 7692, Commit `608b826e`).** Neue Klasse
`WebSocketPerMessageDeflate` (Negotiation + Compress/Decompress) und Integration in
Server & Client (`EnablePerMessageDeflate`, Default: aus):

- Ausgehende Nachrichten enden mit einem **Sync-Flush** (Trailer `00 00 ff ff` wird
  entfernt), *nicht* mit einem Final-Block — ein Final-Block (BFINAL=1, wie ihn
  `DeflateStream.Dispose()` schreibt) würde den persistenten Inflater einer
  Gegenstelle mit Context-Takeover terminieren. Leere Nachricht ⇒ `0x00`.
- Eingehende Nachrichten: Sync-Flush-Trailer wird angehängt, Inflation ist gegen
  **Dekompressions-Bomben** begrenzt (`MaxDecompressedSize`).
- RSV1-Handling im Parser (`AllowRsv1`), UTF-8-Validierung erst **nach** der
  Dekompression, Größen-Limits gelten für die dekomprimierte Nachricht.
- Es wird immer `client_no_context_takeover; server_no_context_takeover`
  ausgehandelt (RFC-konform), da `DeflateStream` weder Fenstergröße noch
  persistenten Kompressions-Kontext anbietet. Offers, die ein kleineres
  Server-Fenster *verlangen* (`server_max_window_bits < 15`), werden abgelehnt.

## 5. Härtungsdurchgang vom 2026-07-19 (Pong-Timeout + N1–N5, umgesetzt)

Nach dem Re-Review wurden die dort gefundenen kleineren Punkte sowie eine
Zombie-Erkennung umgesetzt. Alle vier Autobahn-Suiten blieben danach unverändert
grün (Client core 242 OK, Client deflate 126 OK, Server core 296 OK, Server deflate
126 OK — je 0 FAILED), und 27/28 WebSocket-Unit-Tests bestehen (der eine Ausfall,
`WebSocketTLSClientTests.Test_AnonymousAccess`, ist ein **vorbestehender
Test-Fixture-Bug**: im `[SetUp]` ist der `ServerCertificateSelector` auskommentiert,
d. h. der TLS-Test-Client verbindet gegen einen Klartext-Server und läuft in den
Connect-Timeout — unabhängig vom Produktivcode).

- **Pong-Timeout / Zombie-Erkennung (Server & Client).** RFC 6455 definiert nur die
  Ping/Pong-*Frames*, nicht die *Policy*. Neu: `MaxOutstandingPings` (Default 3).
  Kommt über so viele Ping-Intervalle **kein** Frame (Daten oder Pong) zurück, gilt
  die Verbindung als tot (halboffene NAT-Verbindung, die `Socket.Poll` nicht sieht)
  und wird lokal abgebaut — **ohne** Close-Frame (1006 ist reserviert und darf nicht
  gesendet werden, § 7.4.1); der Client meldet lokal `OnCloseMessageReceived` mit
  1006. Greift nur bei aktivierten Pings; `MaxOutstandingPings = 0` schaltet es ab.
- **N1 — Client validiert die 101-Antwort vollständig** (RFC 6455 § 4.1): `Upgrade`
  muss den Token `websocket`, `Connection` den Token `Upgrade` enthalten (zusätzlich
  zu Status 101 und `Sec-WebSocket-Accept`).
- **N2 — Client lehnt unaufgeforderte Extensions/Subprotokolle ab** (§ 4.1 Schritte
  5/6): Akzeptiert der Server eine nicht angebotene Extension oder wählt ein nicht
  angebotenes Subprotokoll, wird der Handshake abgebrochen.
- **N3 — CSPRNG.** `Sec-WebSocket-Key` und alle Masking-Keys stammen jetzt aus
  `RandomExtensions.SecureRandomBytes` (`RandomNumberGenerator`) statt
  `Random.Shared` (RFC 6455 § 5.3/§ 10.3, „strong source of entropy").
- **N4 — RFC-7692-Negotiation gehärtet.** Server: ein `server_max_window_bits`-Offer
  wird nur bei exakt 15 (bzw. fehlend) angenommen, sonst übersprungen. Client: eine
  Antwort, die `client_max_window_bits < 15` verlangt, wird abgelehnt (wir
  komprimieren stets mit 15-Bit-Fenster).
- **N5 — Close-Code bei Dekompressionsfehler.** Korrupte DEFLATE-Daten schließen jetzt
  mit 1007 (Invalid Payload Data); 1009 (Message Too Big) bleibt den echten
  Größen-Limit-Verstößen vorbehalten (RFC 7692 § 8).

## 6. Zweiter Härtungsdurchgang: N6 + Auto-Reconnect (umgesetzt, Commit `335f4ae6`)

- **N6 — Subprotokoll-Strictness (Server).** Neue settable Property
  `RequireMatchingSubprotocol` (Default aus). Bietet der Client Subprotokolle an,
  von denen keines in `SecWebSocketProtocols` ist, lehnt der Server den Handshake
  mit `400 Bad Request` ab, statt (RFC 6455 § 4.1) mit 101 *ohne*
  `Sec-WebSocket-Protocol` zu antworten. Greift nur, wenn der Server überhaupt
  Subprotokolle deklariert; ein Client ohne Subprotokoll-Angebot wird nie abgelehnt.
- **Auto-Reconnect im Client** (`WebSocketClientReconnectPolicy`, Opt-in).
  Exponentieller Backoff mit Jitter, vollständig durch den Client-Ersteller
  parametrisierbar: `InitialDelay`, `MaxDelay`, `BackoffFactor`, `JitterRatio`
  (Thundering-Herd-Schutz), `MaxAttempts` (null = unbegrenzt). `ReconnectPolicy`
  = null (Default) = kein Reconnect; das ersetzt das bisherige, nicht abschaltbare
  Reconnect-Verhalten der Verbindungsschleife durch ein sauberes Opt-in. Ein
  sauberes `Close()` und Protokollverletzungen (`ClientCloseMessage` gesetzt)
  triggern nie einen Reconnect; der Backoff-Zähler (`ReconnectAttempts`) wird bei
  jeder erfolgreichen (Wieder-)Verbindung auf 0 zurückgesetzt. Event `OnReconnecting`
  für Observability. Abgesichert durch 5 Policy-Unit-Tests (Backoff-Werte,
  Jitter-Grenzen, MaxDelay-Cap, Clamping) und 3 N6-Integrationstests (400/101).

## 7. Verbleibende Punkte (bewusst offen)

- **Handshake-Härtung** (nächster geplanter Schritt): Handshake-Timeout,
  Max-Header-Größe, Per-IP-Verbindungslimits (Slowloris), optionale
  `Origin`-Allowlist (CSWSH; nur für browserzugängliche Endpunkte relevant).
- **Backpressure-Limits à la uWebSockets** (danach geplant): Sende-Queue-Limit
  mit Drop-/Close-Policy statt nur Write-Timeout.
- **PROXY protocol v2** (De-facto-Standard) — Client-IP-Erhalt hinter L4-Loadbalancern.

Bewusst außerhalb des Scopes: **WebSocket über HTTP/2 (RFC 8441)** und **HTTP/3
(RFC 9220)** — für OCPP (HTTP/1.1 + TLS) ohne praktischen Nutzen; **WebTransport**
(QUIC, W3C-Draft) als möglicher Langfrist-Nachfolger, aber ohne Nutzen für
Embedded-OCPP-Stacks; `server_max_window_bits`/`client_max_window_bits` < 15
(Framework-Limitierung von `DeflateStream`).

Verhaltensänderung zur Kenntnis: Protokollverletzungen führen jetzt RFC-konform zum
Verbindungsabbau (vorher tolerant). Für OCPP-Gegenstellen mit fehlerhaften Stacks
ggf. relevant; `CloseConnectionOnUnexpectedFrames` hat kaum noch Bedeutung. Ebenso
reconnectet der Client seit dem zweiten Härtungsdurchgang nur noch bei gesetzter
`ReconnectPolicy` (vorher lief die Verbindungsschleife unbegrenzt weiter).

## 8. Testabdeckung / Reproduktion

Autobahn-Regressionslauf (2026-07-19, nach Pong-Timeout + N1–N5) — alle grün;
für N6 + Auto-Reconnect nicht erneut gefahren, da beide keinen Wire-Framing-Pfad
berühren (N6 ist handshake-only/Default aus; der Reconnect-Block läuft im normalen
Fall nicht, da am Verbindungsende `ClientCloseMessage` gesetzt ist). Abgesichert
über die NUnit-Suite (siehe unten):

| Autobahn-Suite | Ergebnis |
|---|---|
| Client core (Sekt. 1–8, 10) | 242 OK / **0 FAILED** / 2 NON-STRICT / 3 INFO |
| Client deflate (12.\*, 13.1–13.3) | 126 OK / **0 FAILED** / 18 UNIMPLEMENTED |
| Server core (Sekt. 1–10) | 296 OK / **0 FAILED** / 2 NON-STRICT / 3 INFO |
| Server deflate (12.\*, 13.1–13.3) | 126 OK / **0 FAILED** / 18 UNIMPLEMENTED |

- Autobahn-Server-Suite: Echo-Harness (`AutobahnHarness server 9002`, mit
  `EnablePerMessageDeflate = true`) + `wstest -m fuzzingclient` (Docker/WSL,
  `--network=host`, Host via 172.17.80.1). Sektionen 1–10 sowie 12/13.
- Autobahn-Client-Suite: `wstest -m fuzzingserver` (Port 9001) +
  `AutobahnHarness client ws://127.0.0.1:9001 Hermod`.
- Spezialtests im Harness: `closetest` (TCP-Abbruch-Erkennung), `hangtest`
  (gestauter Peer, Write-/Close-Timeouts), `deflatetest`/`negtest` (RFC 7692).
- HTML-Reports: `scratchpad/autobahn/reports/{server,client,server-deflate,client-deflate}/index.html`
- Unit-Tests: `dotnet test --filter FullyQualifiedName~WebSocket`. Nach N6 +
  Auto-Reconnect zusätzlich 8 neue Tests (5 Reconnect-Policy, 3 N6-Integration);
  WebSocket-Regression 33/33 grün (ohne den langsamen TLS-Fixture-Bug und
  Load-Tests). Der TLS-Fixture-Ausfall besteht unverändert fort (s. Abschnitt 5).

Geänderte/neue Dateien (in `libs/Hermod/Hermod/WebSocket/`, sofern nicht anders angegeben):
`WebSocketFrame.cs` (Parser, ParseResult, IsValidCloseCode, AllowRsv1, TextRaw),
`IncrementalUtf8Validator.cs` (neu),
`WebSocketPerMessageDeflate.cs` (neu; N4-Negotiation-Härtung, N5-Fehlersignal),
`Server/AWebSocketServer.cs` (async Empfangsschleife, Handshake-Validierung, Limits,
Fragmentierung, UTF-8, Close-Echo, Masken-Pflicht, Deflate, Zombie-Erkennung, N5,
N6-Subprotokoll-Strictness),
`Server/WebSocketServerConnection.cs` (Send-/Close-Timeouts, ReadAsync, Deflate),
`Client/WebSocketClient.cs` (Header-Lesen, QueryString, async Empfangsschleife,
Abbruch-Erkennung, Limits, Deflate, N1/N2-Handshake-Validierung, N3-CSPRNG,
Zombie-Erkennung, N5, Auto-Reconnect + `OnReconnecting`),
`Client/WebSocketClientConnection.cs` (Poll-Erkennung, Send-/Close-Timeouts,
Close-Maskierung, ReadAsync, Deflate, N3-CSPRNG),
`Client/WebSocketClientReconnectPolicy.cs` (neu — Backoff/Jitter-Policy),
`Client/IWebSocketClient.cs` (`OnWebSocketClientReconnectingDelegate`),
`README.md` (Modul-Dokumentation; N6 + Reconnect ergänzt).
Tests (in `libs/Hermod/HermodTests/WebSocket/`):
`WebSocketClientReconnectPolicyTests.cs` (neu), `WebSocketSubprotocolStrictnessTests.cs` (neu).
Außerhalb WebSocket: `libs/Styx/Styx/Illias/ExtensionMethods/RandomExtensions.cs`
(vorhandenes `SecureRandomBytes` für N3 genutzt — keine Änderung nötig).
