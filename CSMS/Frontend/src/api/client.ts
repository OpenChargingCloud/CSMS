import { config } from '../config';


// What the JSON API answers. Everything below /api/v1 except the sign-in needs
// the session cookie, which the browser sends by itself because every request
// here is same-origin.

/** How loudly a log entry asks to be read. */
export type LogLevel = 'debug' | 'info' | 'notice' | 'warning' | 'error' | 'critical';

/** The levels in the order the CSMS defines them, quietest first. */
export const logLevels: LogLevel[] = ['debug', 'info', 'notice', 'warning', 'error', 'critical'];

/** One thing that happened inside the CSMS. */
export interface LogEntry {
    /** A number that only ever grows, so the page can tell what it has seen. */
    id:         number;
    timestamp:  string;
    level:      LogLevel;
    /** What it is about: "ocpp", "http", "dns", ... - without the level. */
    tags:       string[];
    message:    string;
    /** Whatever else belongs to it, when there is more than one line to say. */
    data?:      unknown;
}

/** What a page of the log brings back. */
export interface LogPage {
    /** The newest id of the whole log, whatever this page was filtered by. */
    lastId:    number;
    capacity:  number;
    tags:      string[];
    entries:   LogEntry[];
}

/**
 * What somebody signed in to this CSMS may do.
 *
 * A copy of what the CSMS enforces, not the enforcement: it is here so a
 * page can grey out what this person may not do instead of offering it and
 * letting them find out by being refused. Every request is checked again on
 * arrival, so editing this list in a browser buys a button that answers 403.
 */
export type Permission = 'readConfiguration'
                       | 'changeNetworkSettings'
                       | 'runDiagnostics'
                       | 'changeStationSettings'
                       | 'manageCertificates'
                       | 'manageLocations'
                       | 'manageRoamingPartners';

/** Who is signed in to the web interface. */
export interface Me {
    username:     string;
    roles:        string[];
    permissions:  Permission[];
}

/** How the CSMS is doing right now. */
export interface Status {
    service:    string;
    version:    string;
    ocppId:     string;
    hermod:     string | null;
    timestamp:  string;
    startedAt:  string;
    uptime:     string;
    sessions:   number;
    log:        { entries: number; capacity: number; lastId: number; tags: string[] };
}

/**
 * What the CSMS is made of. Only the shape the Configuration page
 * relies on is named; the rest is rendered from whatever the CSMS sends,
 * so that a new section on the server needs no change here.
 */
export interface Configuration {
    CSMS:  Record<string, unknown>;
    http:        Record<string, unknown>;
    web:         Record<string, unknown>;
    log:         Record<string, unknown>;
    time:        Record<string, unknown>;
    ocpp:        Record<string, unknown>;
    ocpi:        Record<string, unknown>;
    assemblies:  Record<string, unknown>[];
}


/** One name server this CSMS asks. */
export interface DNSServer {
    /** An IP address or a host name. */
    address:              string;
    port:                 number;
    transport:            string;
    queryTimeoutSeconds:  number | null;
}

/** What may be changed about the name resolution while the CSMS runs. */
export interface DNSSettings {
    queryTimeoutSeconds:  number;
    /** null leaves it to the server's own default. */
    recursionDesired:     boolean | null;
    useCache:             boolean;
    dnssecOK:             boolean;
    followCNAMEs:         boolean;
    maxCNAMEFollows:      number;
    maxRetries:           number;
}

/** How this CSMS resolves names. */
export interface DNSConfiguration {
    enabled:    boolean;
    servers:    DNSServer[];
    settings:   DNSSettings;
    /** What was decided when the client was made, and is not on offer. */
    fixed:      Record<string, unknown>;
    limits: {
        maxServers:       number;
        maxQueryTimeout:  number;
        transports:       string[];
        recordTypes:      string[];
    };
    file:       string;
}

/** What a PUT to the DNS configuration may carry; everything is optional. */
export interface DNSUpdate {
    enabled?:              boolean;
    servers?:              DNSServer[];
    queryTimeoutSeconds?:  number;
    recursionDesired?:     boolean | null;
    useCache?:             boolean;
    dnssecOK?:             boolean;
    followCNAMEs?:         boolean;
    maxCNAMEFollows?:      number;
    maxRetries?:           number;
}

/** One resource record a test query brought back. */
export interface DNSRecord {
    name:        string;
    type:        string;
    timeToLive:  number;
    value:       string;
}

/** What a test query brought back. */
export interface DNSQueryResult {
    name:           string;
    recordTypes:    string[];
    ok:             boolean;
    error?:         string;
    responseCode?:  string;
    server?:        string;
    runtime_ms?:    number;
    authoritative?: boolean;
    truncated?:     boolean;
    dnssec?:        string | null;
    timedOut?:      boolean;
    answers:        DNSRecord[];
    more?:          number;
}


/** One line of what happened while a time server was being asked. */
export interface TimeServerTestStep {
    at_ms:  number;
    level:  'info' | 'notice' | 'warning' | 'error';
    text:   string;
}

/** What came of asking one time server everything. */
export interface TimeServerTest {
    host:        string;
    ok:          boolean;
    runtime_ms:  number;
    steps:       TimeServerTestStep[];
}

/**
 * What may be changed about the time servers while the CSMS runs. What is
 * left out stays as it is; the list of servers is one value and replaces the
 * CSMS's whole.
 */
export interface NTSUpdate {
    enabled?:              boolean;
    servers?:              NTSServerEntry[];
    minServers?:           number;
    maxDeviationSeconds?:  number;
    checkEverySeconds?:    number;
    timeoutSeconds?:       number;
}

/**
 * One time server as the configuration names it. Whatever is left out is the
 * usual: priority 0, the usual ports, switched on.
 */
export interface NTSServerEntry {
    hostname:    string;
    priority?:   number;
    ntsKEPort?:  number;
    ntpPort?:    number;
    enabled?:    boolean;
}

/** How one synchronisation went, step by step. */
export interface NTSSyncResult {
    ok:           boolean;
    server:       string;
    at:           string;
    error?:       string;
    step?:        string;
    runtime_ms?:  number;
    offset_ms?:   number | null;

    /** What the group concluded: the median, how many answered, how far apart. */
    group?:       {
        name:               string;
        answered:           number;
        required:           number;
        offset_ms:          number | null;
        spread_ms:          number | null;
        deviationExceeded:  boolean;
    };

    /** One entry per server asked, answered or not. */
    servers?:     NTSServerResult[];

    /** Only from the detailed test of a single server. */
    ntske?:       Record<string, unknown>;
    ntp?:         Record<string, unknown>;
}

/** What one time server of a group said. */
export interface NTSServerResult {
    hostname:       string;
    ok:             boolean;
    offset_ms?:     number | null;
    roundTrip_ms?:  number | null;
    authenticated?: boolean | null;
    keyExchange?:   string;
    error?:         string | null;
}

/** One server of this CSMS's group, and what its key exchange is doing. */
export interface NTSTimeSource {
    hostname:       string;
    priority:       number;
    ntsKEPort:      number;
    ntpPort:        number;
    enabled:        boolean;
    cookies?:       number | null;
    lastExchange?:  string | null;
    aeadAlgorithm?: string | null;

    /**
     * The root CA the certificate chain of the last key exchange ended at -
     * the chain this CSMS built, so the root it judged the certificate by -
     * or null before the first exchange.
     */
    rootCA?:        NTSRootCA | null;
}

/** A root CA, by a name to call it, its subject, and its SHA-256 fingerprint. */
export interface NTSRootCA {
    name:         string;
    subject:      string;
    fingerprint:  string;
}

/** Where this CSMS gets the time from, and how its key exchange is doing. */
export interface NTSConfiguration {
    enabled:   boolean;

    /**
     * Every server this CSMS has, switched on or not, in the order they
     * were configured - and the rules for believing them.
     */
    timeSources?:  NTSTimeSource[];
    group?:        { name: string; minServers: number; maxDeviationSeconds: number };

    /**
     * What may be changed about the group and the test. The quorum is the one
     * wanted; the group's own can be lower while it has fewer servers on.
     */
    settings:  {
        timeoutSeconds:       number | null;
        checkEverySeconds:    number;
        minServers:           number;
        maxDeviationSeconds:  number;
    };
    /** What any new client starts with, the group's and the test's alike. */
    policy:    Record<string, unknown>;
    lastSync:  NTSSyncResult | null;
    limits:    {
        maxTimeout:        number;
        minCheckEvery:     number;
        maxCheckEvery:     number;
        minDeviation:      number;
        maxDeviation:      number;
        defaultNTSKEPort:  number;
        defaultNTPPort:    number;
    };
    file:      string;
    /** Only on the answer to a synchronisation, which carries both. */
    result?:   NTSSyncResult;
}

/**
 * What time it is here, and what that is worth.
 *
 * Two different questions the CSMS keeps apart: `now` is its own system
 * clock, and everything under `nts` is what happened when it last asked a
 * server that knows. The clock is not set from that answer - see the C# side -
 * so `offset_ms` is the whole of the result.
 *
 * `legal` is decided by the CSMS and never by this page: whether a time
 * may be called legal depends on a claim the operator made, on the check being
 * recent and on the difference being small, and `why` names whichever of those
 * is missing.
 */
export interface Clock {
    now:        string;
    /** Always "system": said out loud, because the check below did not set it. */
    source:     string;
    nts: {
        enabled:       boolean;
        /** The group the clock is checked against, its servers switched on in the order they are asked, and its quorum - null while NTS is off. */
        group:         string | null;
        servers:       string[] | null;
        minServers:    number | null;
        /** The one server, for a group of one. */
        server:        string | null;
        lastServer:    string | null;
        checkedAt:     string | null;
        ageSeconds:    number | null;
        offset_ms:     number | null;
        everySeconds:  number;
    };
    legal:            boolean;
    authority:        string | null;
    /** null while legal; otherwise "notClaimed", "ntsOff", "neverChecked", "stale" or "offBy". */
    why:              string | null;
    toleranceSeconds: number;
    maxAgeSeconds:    number;
}


/** What of the charging station server ends up in the event log. */
export interface OCPPServerLogging {
    connections:     boolean;
    authentication:  boolean;
    messages:        boolean;
    payloads:        boolean;
    /** When the contents stop being logged again; null while they are not. */
    payloadsUntil:   string | null;
    /** Whether they are being logged at this moment - the switch and the window together. */
    payloadsNow:     boolean;
    pings:           boolean;
}

/** The server the charging stations below this CSMS connect to. */
export interface OCPPServerConfiguration {
    enabled:                     boolean;
    address:                     string | null;
    port:                        number;
    /** 1, 2 and 3 - the OCPP security profiles a station may connect with. */
    securityProfiles:            number[];
    subprotocols:                string[];
    /** The names and addresses the stations dial; what a certificate must cover. */
    reachableAs:                 string[];
    minTLSVersion:               string;
    checkCertificateRevocation:  boolean;
    maxConnections:              number;
    pingEverySeconds:            number;
    logging:                     OCPPServerLogging;
    state: {
        running:            boolean;
        tls:                boolean;
        url:                string;
        connections:        number;
        stationLogins:      number;
        trustedChains:      number;
        hasCertificate:     boolean;
        /**
         * The fields that were changed but are not in effect: the socket is
         * decided when the server is built. Empty when everything saved is
         * already doing something.
         */
        waitingForARestart: string[];
    };
    limits: {
        subprotocols:                   string[];
        securityProfiles:               number[];
        tlsVersions:                    string[];
        maxConnections:                 number;
        maxReachableAs:                 number;
        suggestedPayloadWindowSeconds:  number;
    };
    file:  string;
}

/** What a PUT to the charging station server may carry; everything is optional. */
export interface OCPPServerUpdate {
    enabled?:                     boolean;
    address?:                     string;
    port?:                        number;
    securityProfiles?:            number[];
    subprotocols?:                string[];
    reachableAs?:                 string[];
    minTLSVersion?:               string;
    checkCertificateRevocation?:  boolean;
    maxConnections?:              number;
    pingEverySeconds?:            number;
    logging?: {
        connections?:     boolean;
        authentication?:  boolean;
        messages?:        boolean;
        payloads?:        boolean;
        payloadsUntil?:   string | null;
        pings?:           boolean;
    };
}

/** A kind of key this CSMS will make for itself. */
export interface KeyAlgorithm {
    id:           string;
    name:         string;
    /** What somebody choosing it should know. */
    remark:       string;
    /**
     * Whether this platform is known to be able to present a certificate with
     * such a key, or absent while nobody has tried. Found out by doing a TLS
     * handshake, not from a list - it depends on the operating system, the
     * runtime and the year.
     */
    presentable?: boolean;
}

/** One key of this CSMS, and the certificate it was given. */
export interface ServerCertificate {
    /** Where the public key hashes to; what the signing request is filed under. */
    id:              string;
    algorithm:       string;
    createdAt:       string;
    subject:         string;
    hasCertificate:  boolean;
    /**
     * Whether this machine can hold this certificate up to a charging station
     * during a TLS handshake. A different question from whether the certificate
     * is any good: an Ed448 or an ML-DSA key makes a perfectly valid one that
     * this platform's TLS stack will not serve.
     */
    canBePresented:  boolean;
    /** Whether this is the one being presented to the charging stations. */
    inUse:           boolean;
    warnings:        string[];
    certificate?: {
        subject:          string;
        issuer:           string;
        serialNumber:     string;
        thumbprint:       string;
        notBefore:        string;
        notAfter:         string;
        subjectAltNames:  string[];
        intermediates:    number;
        /** "pending" before its window, "valid" inside it, "expired" after. */
        state:            'pending' | 'valid' | 'expired';
        daysRemaining:    number;
    };
}

/** The keys and certificates this CSMS presents. */
export interface ServerCertificates {
    directory:             string;
    /** By the CSMS's own clock, which is what decides the windows below. */
    now:                   string;
    servedId:              string | null;
    entries:               ServerCertificate[];
    algorithms:            KeyAlgorithm[];
    /** Always false, and said out loud: a private key is made here and never arrives. */
    canImportPrivateKeys:  boolean;
}

/** One chain a charging station's certificate may lead to. */
export interface TrustedChain {
    id:             string;
    name:           string;
    addedAt:        string;
    enabled:        boolean;
    subject:        string;
    issuer:         string;
    serialNumber:   string;
    thumbprint:     string;
    notBefore:      string;
    notAfter:       string;
    /** Whether it can vouch for others at all, or only for itself. */
    isCA:           boolean;
    intermediates:  number;
    warnings:       string[];
    state:          'pending' | 'valid' | 'expired';
    daysRemaining:  number;
}

/** Which chains a charging station's own certificate may lead to. */
export interface ClientTrust {
    directory:   string;
    now:         string;
    enabled:     number;
    maxEntries:  number;
    entries:     TrustedChain[];
}

/** A way a charging station can prove who it is. */
export type AuthMethod = 'basic' | 'totp' | 'certificate';

/**
 * What a charging station needs in order to be let in with a one-time token.
 *
 * The shared secret is never in here: it is the one credential the CSMS
 * has to keep readable, so it is handed out once when it is set and never put
 * into the list this page reads.
 */
export interface TOTPSettings {
    validitySeconds:  number;
    length:           number;
    alphabet:         string;
    hashAlgorithm:    'SHA256' | 'SHA384' | 'SHA512';
}

/** One charging station that may sign in. */
export interface StationLogin {
    id:           string;
    group:        string;
    enabled:      boolean;
    addedAt:      string;
    hasPassword:  boolean;
    hasTOTP:      boolean;
    totp?:        TOTPSettings;
    note?:        string;
}

/** A group of logins, and what its members are allowed to do. */
export interface LoginGroup {
    id:                string;
    name:              string;
    enabled:           boolean;
    builtIn:           boolean;
    addedAt:           string;
    authMethods:       AuthMethod[];
    securityProfiles:  number[];
    members:           number;
    note?:             string;
}

/** Which charging stations may sign in, and with what. */
export interface StationLogins {
    file:               string;
    enabled:            number;
    maxStations:        number;
    maxGroups:          number;
    minPasswordLength:  number;
    minSecretLength:    number;
    defaultGroup:       string;
    groups:             LoginGroup[];
    stations:           StationLogin[];
}

/** What a group may be changed to. */
export interface LoginGroupUpdate {
    id?:               string;
    name:              string;
    enabled:           boolean;
    authMethods:       AuthMethod[];
    securityProfiles:  number[];
    note?:             string;
}

/** What a one-time token may be set to. */
export interface TOTPUpdate {
    sharedSecret?:     string;
    validitySeconds?:  number;
    length?:           number;
    alphabet?:         string;
    hashAlgorithm?:    string;
    group?:            string;
    note?:             string;
}



// OCPI

/** Where one OCPI version is: its endpoints as absolute URLs a partner is told. */
export interface OCPIVersionEndpoints {
    version:      string;
    details:      string;
    credentials:  string;
    modules:      Record<string, string>;
}

/** The OCPI side of this CSMS: which operator it is, where it is, how much it holds. */
export interface OCPIConfiguration {
    party: {
        countryCode:  string;
        partyId:      string;
        id:           string;
        role:         string;
        name:         string;
        website:      string | null;
    };
    endpoints: {
        base:         string;
        versions:     string;
        externalURL:  string | null;
        byVersion:    OCPIVersionEndpoints[];
    };
    versions:       string[];
    knownVersions:  string[];
    settings: {
        locationsAsOpenData:  boolean;
        tariffsAsOpenData:    boolean;
        allowDowngrades:      boolean;
        logRequests:          boolean;
        logPayloads:          boolean;
    };
    counts: {
        partners:   number;
        locations:  number;
        tokens:     number;
        tariffs:    number;
        sessions:   number;
        cdrs:       number;
    };
    directory:  string;
    file:       string;
}

/**
 * One roaming partner. The tokens are present only for whoever may manage
 * partners; everybody else sees that there is one.
 */
export interface Partner {
    version:           string;
    id:                string;
    countryCode:       string;
    partyId:           string;
    role:              string;
    name:              string;
    website:           string | null;
    status:            string;
    ourToken:          string | null;
    hasOurToken:       boolean;
    ourTokenStatus:    string | null;
    theirToken:        string | null;
    hasTheirToken:     boolean;
    theirVersionsURL:  string | null;
    remoteStatus:      string | null;
    selectedVersion:   string | null;
    /** Whether this operator holds a token of theirs and a place to send it. */
    canRegister:       boolean;
    /** Whether the peering is complete in both directions. */
    registered:        boolean;
    created:           string;
    lastUpdated:       string;
}

/** Every roaming partner, and what the add form may choose from. */
export interface Partners {
    partners:        Partner[];
    versions:        string[];
    roles:           string[];
    ourVersionsURL:  string;
}

/** What it takes to add a roaming partner. */
export interface PartnerSpec {
    version:       string;
    countryCode:   string;
    partyId:       string;
    role:          string;
    name:          string;
    website?:      string;
    /** Empty means "make one up"; it comes back in the answer. */
    ourToken?:     string;
    /** Both or neither: with both, this operator can start the peering itself. */
    theirToken?:   string;
    versionsURL?:  string;
}

/** One location this operator publishes, as OCPI writes it, with the version added. */
export interface Location {
    version:       string;
    id:            string;
    name?:         string;
    address?:      string;
    city?:         string;
    postal_code?:  string;
    country?:      string;
    coordinates?:  { latitude: string; longitude: string };
    evses?:        unknown[];
    publish?:      boolean;
    last_updated:  string;
    [other: string]: unknown;
}

/** Every location, and what the form may choose from. */
export interface Locations {
    locations:  Location[];
    versions:   string[];
    operator:   string;
    partyId:    string;
    /** Whether anybody may read them without a token. */
    openData:   boolean;
}

/** What it takes to publish a location. */
export interface LocationSpec {
    version:     string;
    id:          string;
    name:        string;
    address:     string;
    city:        string;
    postalCode:  string;
    country:     string;
    latitude:    number;
    longitude:   number;
    timeZone:    string;
    publish?:    boolean;
}

/** What travels between this operator and its partners, other than the locations. */
export type RoamingDataKind = 'tokens' | 'tariffs' | 'sessions' | 'cdrs';

/** One object as OCPI writes it, with the version added. */
export type RoamingItem = { version: string } & Record<string, unknown>;

export interface RoamingData {
    kind:      RoamingDataKind;
    versions:  string[];
    items:     RoamingItem[];
}


export class ApiError extends Error {

    constructor(public readonly status:  number,
                message:                 string,
                public readonly body?:   unknown) {
        super(message);
        this.name = 'ApiError';
    }

    get isUnauthorized(): boolean {
        return this.status === 401;
    }

}


let unauthorizedHandler: (() => void) | null = null;

/** Called whenever the API answers 401, i.e. the session is gone. */
export function onUnauthorized(handler: () => void): void {
    unauthorizedHandler = handler;
}


/**
 * Sign in at the HTTPExt API and answer with who is now signed in.
 *
 * Two requests rather than one, and that is not a detour. The HTTPExt API is
 * the only place that can check a password - the store it reads is private to
 * it - but it answers in its own shape and knows nothing of this CSMS's
 * roles. So it sets the session cookie, and "me" is asked afterwards for the
 * roles and permissions this frontend actually works from.
 *
 * Form-urlencoded because that is what its sign-in route accepts, and the
 * field is called "login" rather than "username".
 */
async function signIn(username: string, password: string): Promise<Me> {

    const response = await fetch(config.extBase + '/login', {
                               method:       'POST',
                               headers:      {
                                                 'Content-Type':  'application/x-www-form-urlencoded',
                                                 'Accept':        'application/json'
                                             },
                               credentials:  'same-origin',
                               body:         new URLSearchParams({ login: username, password }).toString()
                           });

    if (!response.ok) {

        // Its refusals carry a "description"; ours carry an "error". Both are
        // shown to somebody who just typed a password, so both are read.
        let message = `${response.status} ${response.statusText}`;

        try {
            const json = JSON.parse(await response.text());
            if (typeof json === 'object' && json !== null) {
                if      ('description' in json && typeof json.description === 'string')  message = json.description;
                else if ('error'       in json && typeof json.error       === 'string')  message = json.error;
            }
        }
        catch { /* the status line says enough */ }

        throw new ApiError(response.status, message, null);

    }

    return request<Me>('GET', '/auth/me');

}


async function request<T>(method: string, path: string, body?: unknown): Promise<T> {

    const headers: Record<string, string> = { 'Accept': 'application/json' };

    if (body !== undefined)
        headers['Content-Type'] = 'application/json';

    // Same origin, so the session cookie travels with every request.
    const response = await fetch(config.apiBase + path, {
                               method,
                               headers,
                               credentials: 'same-origin',
                               body: body !== undefined ? JSON.stringify(body) : undefined
                           });

    if (response.status === 401)
        unauthorizedHandler?.();

    if (response.status === 204) {
        // Nothing to read, but reading it lets the browser finish the request
        // cleanly instead of aborting an unconsumed body.
        await response.arrayBuffer();
        return undefined as T;
    }

    const text = await response.text();
    let json: unknown = null;

    try {
        json = text.length > 0 ? JSON.parse(text) : null;
    }
    catch {
        if (response.ok)
            throw new ApiError(response.status, `Invalid JSON in the response of ${method} ${path}`, text);
    }

    if (!response.ok) {

        const message = typeof json === 'object' && json !== null && 'error' in json && typeof json.error === 'string'
                            ? json.error
                            : `${response.status} ${response.statusText}`;

        throw new ApiError(response.status, message, json);

    }

    return json as T;

}


export const api = {

    /** The Server-Sent Events stream; the browser sends the session cookie along. */
    eventsURL: `${config.apiBase}/events`,

    auth: {
        me:      ()                                    => request<Me>  ('GET',  '/auth/me'),
        login:   signIn,
        logout:  ()                                    => request<void>('POST', '/auth/logout')
    },

    status:         () => request<Status>       ('GET', '/status'),
    configuration:  () => request<Configuration>('GET', '/configuration'),

    /** What time it is here and what that is worth; cheap, and safe to poll. */
    clock:          () => request<Clock>        ('GET', '/configuration/time'),

    dns: {
        get:   ()                    => request<DNSConfiguration>('GET', '/configuration/dns'),
        /** Only the fields given are changed; the answer is the whole configuration as it now stands. */
        save:  (update: DNSUpdate)   => request<DNSConfiguration>('PUT', '/configuration/dns', update),
        /** Make the CSMS look a name up. A POST because it sends traffic. */
        query: (name: string, recordTypes: string[]) =>
                   request<DNSQueryResult>('POST', '/configuration/dns/query', { name, recordTypes })
    },

    nts: {
        get:   ()                    => request<NTSConfiguration>('GET', '/configuration/nts'),
        save:  (update: NTSUpdate)   => request<NTSConfiguration>('PUT', '/configuration/nts', update),
        /**
         * Ask one time server everything: the name, the key exchange, the
         * authenticated NTP request, each one written down as it happens.
         *
         * @param host  which server, on the ports it is configured with, or
         *              undefined for the configured one.
         */
        test:  (host?: string)       => request<TimeServerTest>('POST', '/configuration/nts/test', { host }),
        /** Ask every server of the group, with every step in the log. */
        sync:  ()                    => request<NTSConfiguration>('POST', '/configuration/nts/sync', {})
    },

    /**
     * The OCPI side: which charge point operator this CSMS is, its roaming
     * partners, the locations it publishes, and what travels between them.
     */
    ocpi: {

        configuration: () => request<OCPIConfiguration>('GET', '/configuration/ocpi'),

        partners: {

            get:       ()                     => request<Partners>('GET', '/ocpi/partners'),

            /**
             * Add a partner. The answer carries the token this operator made
             * up for them - the one thing that has to be handed over by hand.
             */
            add:       (spec: PartnerSpec)    => request<{ message: string; id: string; version: string; ourToken: string; partners: Partners }>(
                                                     'POST', '/ocpi/partners', spec),

            /** Start the peering from here: fetch their versions, POST our credentials. */
            register:  (version: string, id: string) =>
                           request<{ ok: boolean; message: string; partners: Partners }>(
                               'POST', `/ocpi/partners/${encodeURIComponent(version)}/${encodeURIComponent(id)}/register`, {}),

            remove:    (version: string, id: string) =>
                           request<Partners>('DELETE', `/ocpi/partners/${encodeURIComponent(version)}/${encodeURIComponent(id)}`)

        },

        locations: {

            get:     ()                    => request<Locations>('GET', '/ocpi/locations'),

            add:     (spec: LocationSpec)  => request<{ message: string; id: string; version: string; locations: Locations }>(
                                                  'POST', '/ocpi/locations', spec),

            remove:  (version: string, id: string) =>
                         request<Locations>('DELETE', `/ocpi/locations/${encodeURIComponent(version)}/${encodeURIComponent(id)}`)

        },

        /** One kind of what travels between this operator and its partners. */
        data: (kind: RoamingDataKind) => request<RoamingData>('GET', `/ocpi/${kind}`)

    },

    /**
     * The charging station server: its socket, the certificates it presents,
     * the chains it accepts and the stations that may sign in.
     */
    ocppServer: {

        get:   ()                          => request<OCPPServerConfiguration>('GET', '/configuration/ocpp-server'),
        /** Only the fields given are changed; the answer is the whole thing as it now stands. */
        save:  (update: OCPPServerUpdate)  => request<OCPPServerConfiguration>('PUT', '/configuration/ocpp-server', update),

        certificates: {

            get:     ()  => request<ServerCertificates>('GET', '/configuration/ocpp-server/certificates'),

            /** Generate a key and the signing request that goes with it; the key never leaves. */
            create:  (subject: string, algorithm: string) =>
                         request<{ id: string; csr: string }>('POST', '/configuration/ocpp-server/certificates',
                                                              { subject, algorithm }),

            /** Where the signing request can be downloaded; a plain file, not JSON. */
            csrURL:  (id: string) => `${config.apiBase}/configuration/ocpp-server/certificates/${encodeURIComponent(id)}/csr`,

            /** Take in the certificate that answers a request, with its intermediates. */
            upload:  (id: string, pem: string) =>
                         request<{ id: string; warnings: string[] }>('PUT',
                             `/configuration/ocpp-server/certificates/${encodeURIComponent(id)}`, { pem }),

            remove:  (id: string) =>
                         request<ServerCertificates>('DELETE',
                             `/configuration/ocpp-server/certificates/${encodeURIComponent(id)}`)

        },

        trust: {

            get:      ()  => request<ClientTrust>('GET', '/configuration/ocpp-server/trust'),

            add:      (pem: string, name: string) =>
                          request<{ id: string; warnings: string[] }>('POST', '/configuration/ocpp-server/trust', { pem, name }),

            update:   (id: string, change: { enabled?: boolean; name?: string }) =>
                          request<ClientTrust>('PUT', `/configuration/ocpp-server/trust/${encodeURIComponent(id)}`, change),

            remove:   (id: string) =>
                          request<ClientTrust>('DELETE', `/configuration/ocpp-server/trust/${encodeURIComponent(id)}`)

        },

        stations: {

            get:      ()  => request<StationLogins>('GET', '/configuration/ocpp-server/stations'),

            /**
             * Add a station or give one a new password. An empty password means
             * "make one up", and the made-up one comes back here and nowhere
             * else: it is kept only as a hash.
             */
            save:     (id: string, password: string, group: string, note: string) =>
                          request<{ id: string; password?: string; stations: StationLogins }>(
                              'POST', '/configuration/ocpp-server/stations', { id, password, group, note }),

            enable:   (id: string, enabled: boolean) =>
                          request<StationLogins>('PUT', `/configuration/ocpp-server/stations/${encodeURIComponent(id)}`, { enabled }),

            move:     (id: string, group: string) =>
                          request<StationLogins>('PUT', `/configuration/ocpp-server/stations/${encodeURIComponent(id)}`, { group }),

            remove:   (id: string) =>
                          request<StationLogins>('DELETE', `/configuration/ocpp-server/stations/${encodeURIComponent(id)}`),

            /**
             * Give a station what it needs to be let in with a one-time token.
             * An empty shared secret means "make one up", and it comes back
             * here - the only place it is ever handed out.
             */
            saveTOTP: (id: string, update: TOTPUpdate) =>
                          request<{ id: string; sharedSecret?: string; stations: StationLogins }>(
                              'PUT', `/configuration/ocpp-server/stations/${encodeURIComponent(id)}/totp`, update),

            removeTOTP:     (id: string) =>
                          request<StationLogins>('DELETE', `/configuration/ocpp-server/stations/${encodeURIComponent(id)}/totp`),

            removePassword: (id: string) =>
                          request<StationLogins>('DELETE', `/configuration/ocpp-server/stations/${encodeURIComponent(id)}/password`)

        },

        groups: {

            /** Everything about the group is replaced, not merged. */
            save:     (update: LoginGroupUpdate) =>
                          update.id === undefined
                              ? request<StationLogins>('POST', '/configuration/ocpp-server/groups', update)
                              : request<StationLogins>('PUT',  `/configuration/ocpp-server/groups/${encodeURIComponent(update.id)}`, update),

            remove:   (id: string) =>
                          request<StationLogins>('DELETE', `/configuration/ocpp-server/groups/${encodeURIComponent(id)}`)

        }

    },

    /**
     * A page of the log, oldest of the returned entries first.
     *
     * @param limit  at most this many entries
     * @param after  only what is newer than this id
     * @param tag    only entries carrying this tag - a level counting as one
     */
    logs: (limit?: number, after?: number, tag?: string) => {

        const query = new URLSearchParams();

        if (limit !== undefined)  query.set('limit', String(limit));
        if (after !== undefined)  query.set('after', String(after));
        if (tag)                  query.set('tag',   tag);

        const suffix = query.size > 0 ? `?${query}` : '';

        return request<LogPage>('GET', `/logs${suffix}`);

    }

};
