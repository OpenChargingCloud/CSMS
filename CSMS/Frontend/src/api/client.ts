import { apiURL,
         nodeAPI,
         request,
         type CertificateStore   as NodeCertificateStore,
         type NodeConfiguration,
         type NodeMe,
         type NodeResource,
         type NodeStatus,
         type Operation }  from '@node/api/client';


// What every node answers - the log, name resolution, the time, the store,
// who is signed in - and how it is asked are WWCP_Node's, and every page here
// reads them from this module as before. What follows is what a CSMS adds:
// its resources, what its status and its configuration say beyond every
// node's, and its own routes - the charging station server and OCPI.
export * from '@node/api/client';


/**
 * What a role may be allowed to touch on this CSMS: what every node has, and
 * what a CSMS adds to it.
 */
export type Resource = NodeResource | 'stations' | 'locations' | 'roaming';

/** What somebody signed in to this CSMS may do: an operation on a resource, written "dns:edit". */
export type Permission = `${Resource}:${Operation}`;

/** Who is signed in to the web interface. */
export type Me = NodeMe<Resource>;

/** How the CSMS is doing right now: every node's, and its OCPP identity. */
export interface Status extends NodeStatus {
    ocppId:  string;
}

/**
 * What the CSMS is made of: every node's sections, and its own. Only the
 * shape the Configuration page relies on is named; the fields of each
 * section are rendered from whatever the CSMS sends, and which sections
 * there are is the page's to say.
 */
export interface Configuration extends NodeConfiguration {
    CSMS:        Record<string, unknown>;
    ocpp:        Record<string, unknown>;
    ocpi:        Record<string, unknown>;
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
    /** OCPP over SSH, on this CSMS's SSH server, beside the WebSocket port. */
    ssh:                         OCPPServerSSH;
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
        minMaxMessageSize?:             number;
        maxMaxMessageSize?:             number;
        suggestedPayloadWindowSeconds:  number;
    };
    file:  string;
}

/** OCPP over SSH: the subsystem the stations ask for on this CSMS's SSH server. */
export interface OCPPServerSSH {
    enabled:           boolean;
    /** Null where the WebSocket port's are offered. */
    subprotocols:      string[] | null;
    maxMessageSize:    number;
    pingEverySeconds:  number;
    subsystem:         string;
    state: {
        /** Whether a station can connect over SSH right now. */
        served:            boolean;
        /** Whether this CSMS's SSH server is on at all. */
        sshServer:         boolean;
        url:               string | null;
        /** "ssh-ed25519 SHA256:...", what a station pins. */
        hostKey:           string | null;
        connections:       number;
        stationsWithAKey:  number;
    };
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
    ssh?: {
        enabled?:  boolean;
    };
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

/** One certificate found in a text or a file, and the key of this CSMS it is for. */
export interface ServerCertificateFound {
    id:             string;
    thumbprint:     string;
    label:          string;
    subject:        string;
    issuer:         string;
    notBefore:      string;
    notAfter:       string;
    chainLength:    number;
    /** Whether it came with its private key - which is refused: none arrives here. */
    hasPrivateKey:  boolean;
    /** The key of this CSMS it belongs to, by its public key; null for none. */
    keyId:          string | null;
    /** Why it would not be taken in, as far as can be said before trying; null where nothing speaks against it. */
    refusal:        string | null;
}

/** What an upload of several certificates did, one by one. */
export interface ServerCertificatesUploaded {
    taken:    { id: string; label: string; warnings: string[] }[];
    refused:  { label: string; error: string }[];
    error?:   string;
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
export type AuthMethod = 'basic' | 'totp' | 'certificate' | 'sshkey';

/** An SSH public key a charging station signs in with for OCPP over SSH. Nothing about it is secret. */
export interface StationSSHKey {
    /** "SHA256:...", as OpenSSH writes it: what the key is known by. */
    fingerprint:  string;
    /** The authorized_keys line it was given as, its options in front. */
    line:         string;
    label?:       string;
    created:      string;
    createdBy?:   string;
    isDisabled?:  boolean;
}

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
    hasSSHKey?:   boolean;
    sshKeys?:     StationSSHKey[];
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


/**
 * An SSH key's fingerprint as it goes into a URL: without "SHA256:", and in
 * the URL-safe Base64 alphabet, where '/' would be read as a path - as the
 * CSMS reads it back.
 */
export function fingerprintInURL(fingerprint: string): string {
    return fingerprint.replace(/^SHA256:/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * The routes every node has, typed with what a CSMS says its own of them are.
 * The certificate store is typed as every node's: the node's page is the only
 * one that reads it, and takes the kinds from what the store says.
 */
const node = nodeAPI<{ me: Me; status: Status; configuration: Configuration; kind: string; store: NodeCertificateStore }>();

export const api = {

    ...node,

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
    /**
     * Where the CSRs of the charging stations' SignCertificate requests go -
     * the EST server of a PKI - and what became of the latest.
     */
    certificateSigning: {

        get:   ()                                  => request<CertificateSigning>('GET', '/configuration/certificate-signing'),
        /** What is named is changed, null removes it, what is not named stays: the API key above all. */
        save:  (update: CertificateSigningUpdate)  => request<CertificateSigning>('PUT', '/configuration/certificate-signing', update),
        /** Ask a connected station with TriggerMessage for a new certificate of that kind, now. */
        renew: (station: string, certificateType: string) =>
                   request<CertificateRenewal>('POST', '/configuration/certificate-signing/renew', { station, certificateType }),
        /** Forget a station's certificate: it is not renewed any more, until the station signs in with it or is signed a new one. */
        forget: (station: string, certificateType: string) =>
                   request<CertificateSigning>('DELETE',
                       `/configuration/certificate-signing/certificates/${encodeURIComponent(station)}/${encodeURIComponent(certificateType)}`)

    },

    stationRoots: {

        get:      ()  => request<StationRoots>('GET', '/configuration/station-roots'),
        add:      (pem: string, certificateType: string, everywhere: boolean) =>
                      request<StationRoots>('POST', '/configuration/station-roots', { pem, certificateType, everywhere }),
        /** The roots the EST servers of the PKI name, added. */
        fromPKI:  ()  => request<StationRoots & { added: StationRoot[]; problems: string[] }>('POST', '/configuration/station-roots/from-pki', {}),
        setEverywhere: (root: StationRoot, everywhere: boolean) =>
                      request<StationRoots>('PUT', `/configuration/station-roots/${encodeURIComponent(root.certificateType)}/${encodeURIComponent(root.id)}`, { everywhere }),
        remove:   (root: StationRoot) =>
                      request<StationRoots>('DELETE', `/configuration/station-roots/${encodeURIComponent(root.certificateType)}/${encodeURIComponent(root.id)}`),
        /** On the station named, or on every one connected where none is. */
        install:  (root: StationRoot, station: string | null) =>
                      request<StationRoots & { results: StationRootResult[] }>('POST',
                          `/configuration/station-roots/${encodeURIComponent(root.certificateType)}/${encodeURIComponent(root.id)}/install`,
                          station === null ? {} : { station }),
        /** What a station has: it is asked, with GetInstalledCertificateIds. */
        installedOn: (station: string) =>
                      request<{ station: string; installed: InstalledCertificate[] }>('GET', `/configuration/station-roots/stations/${encodeURIComponent(station)}`),
        deleteFrom: (station: string, certificate: InstalledCertificate) =>
                      request<{ answer: string; detail: string | null }>('POST', `/configuration/station-roots/stations/${encodeURIComponent(station)}/delete`, {
                          certificateType:  certificate.certificateType,
                          hashAlgorithm:    certificate.hashAlgorithm,
                          issuerNameHash:   certificate.issuerNameHash,
                          issuerKeyHash:    certificate.issuerKeyHash,
                          serialNumber:     certificate.serialNumber
                      })

    },

    ocppServer: {

        get:   ()                          => request<OCPPServerConfiguration>('GET', '/configuration/ocpp-server'),
        /** Only the fields given are changed; the answer is the whole thing as it now stands. */
        save:  (update: OCPPServerUpdate)  => request<OCPPServerConfiguration>('PUT', '/configuration/ocpp-server', update),

        certificates: {

            get:     ()  => request<ServerCertificates>('GET', '/configuration/ocpp-server/certificates'),

            /**
             * Generate a key and the signing request that goes with it; the key
             * never leaves.
             *
             * Given three minutes rather than the half of one any other write
             * gets, because an RSA key is a search for two primes that takes as
             * long as it takes: an RSA 4096 key can take seconds on a desktop,
             * and a CSMS may well run on a machine many times slower than that.
             */
            create:  (subject: string, algorithm: string) =>
                         request<{ id: string; csr: string }>('POST', '/configuration/ocpp-server/certificates',
                                                              { subject, algorithm }, 3 * 60_000),

            /** Where the signing request can be downloaded; a plain file, not JSON. */
            csrURL:  (id: string) => apiURL(`/configuration/ocpp-server/certificates/${encodeURIComponent(id)}/csr`),

            /** Take in the certificate that answers a request, with its intermediates. */
            upload:  (id: string, pem: string) =>
                         request<{ id: string; warnings: string[] }>('PUT',
                             `/configuration/ocpp-server/certificates/${encodeURIComponent(id)}`, { pem }),

            remove:  (id: string) =>
                         request<ServerCertificates>('DELETE',
                             `/configuration/ocpp-server/certificates/${encodeURIComponent(id)}`),

            /** What a text or a file holds, and which key of this CSMS each certificate is for - nothing taken in. */
            inspect: (what: { pem?: string; content?: string; password?: string }) =>
                         request<{ certificates: ServerCertificateFound[]; pem: string }>('POST',
                             '/configuration/ocpp-server/certificates/inspect', what),

            /** Every certificate of a text or a file taken in under the key it is for. */
            uploadAll: (what: { pem?: string; content?: string; password?: string }) =>
                         request<ServerCertificatesUploaded>('POST',
                             '/configuration/ocpp-server/certificates/upload', what)

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
                          request<StationLogins>('DELETE', `/configuration/ocpp-server/stations/${encodeURIComponent(id)}/password`),

            /**
             * Give a station an SSH key for OCPP over SSH - one line of an
             * authorized_keys file - adding the station where it is not listed
             * yet. A public key: nothing secret goes either way.
             */
            addSSHKey: (id: string, line: string, label: string, group: string, note: string) =>
                          request<{ id: string; fingerprint: string; stations: StationLogins }>(
                              'POST', `/configuration/ocpp-server/stations/${encodeURIComponent(id)}/sshKeys`, { line, label, group, note }),

            /** Take a key away; a session it opened ends. */
            removeSSHKey: (id: string, fingerprint: string) =>
                          request<StationLogins>('DELETE',
                              `/configuration/ocpp-server/stations/${encodeURIComponent(id)}/sshKeys/${fingerprintInURL(fingerprint)}`)

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

    }

};


/** What became of one SignCertificate request of a charging station. */
export interface CertificateSigningEntry {
    at:               string;
    station:          string;
    certificateType:  string;
    /** At the PKI; taken by the station; refused here; not signed by the PKI; not taken by the station. */
    outcome:          'signing' | 'signed' | 'rejected' | 'failed' | 'notTaken';
    detail:           string | null;
    /** The SHA-256 fingerprint of the certificate signed. */
    certificate:      string | null;
    notAfter:         string | null;
}

/** A root certificate the CSMS installs on its charging stations. */
export interface StationRoot {
    /** The SHA-256 fingerprint. */
    id:               string;
    /** CSMSRootCertificate, V2GRootCertificate, MORootCertificate, ManufacturerRootCertificate, OEMRootCertificate. */
    certificateType:  string;
    subject:          string;
    serialNumber:     string;
    notAfter:         string;
    added:            string;
    /** Installed on every station that starts without it. */
    everywhere:       boolean;
    pem:              string;
}

/** A root installed on a station, or a certificate deleted from one. */
export interface StationRootChange {
    at:               string;
    station:          string;
    action:           'install' | 'delete';
    certificateType:  string;
    /** The subject of the root installed; the serial number of the certificate deleted. */
    certificate:      string;
    answer:           string;
    detail:           string | null;
    automatic:        boolean;
}

export interface StationRoots {
    roots:             StationRoot[];
    certificateTypes:  string[];
    connected:         string[];
    changes:           StationRootChange[];
}

/** What one station answered to InstallCertificate. */
export interface StationRootResult {
    station:  string;
    answer:   string;
    detail:   string | null;
}

/** A certificate a station says it has, and the root of the CSMS it is, where it is one. */
export interface InstalledCertificate {
    certificateType:  string;
    hashAlgorithm:    string;
    issuerNameHash:   string;
    issuerKeyHash:    string;
    serialNumber:     string;
    /** How many certificates below it, for a V2G certificate chain. */
    children:         number;
    root:             string | null;
    subject:          string | null;
}

/** What became of one GetCertificateStatus request of a charging station. */
export interface CertificateStatusEntry {
    at:            string;
    station:       string;
    /** Of the certificate asked about, in hexadecimal. */
    serialNumber:  string;
    /** The OCSP responder the station named. */
    responder:     string;
    /** As the responder said; or answered of another certificate; not sent on; not answered. */
    outcome:       'good' | 'revoked' | 'unknown' | 'answered' | 'refused' | 'failed';
    detail:        string | null;
    /** Until when the answer holds, where the responder says so. */
    nextUpdate:    string | null;
}

/** A certificate a charging station has, as the CSMS knows of it, and what came of asking it to renew. */
export interface StationCertificate {
    station:          string;
    certificateType:  string;
    /** The SHA-256 fingerprint. */
    fingerprint:      string;
    /** Not known of the certificates noted before it was kept. */
    notBefore:        string | null;
    notAfter:         string;
    /** Signed here and taken by the station; or what the station signed in with. */
    source:           'signed' | 'presented';
    noted:            string;
    renewalAsked:     string | null;
    /** "Accepted", "Rejected", "NotImplemented" - or "failed". */
    renewalAnswer:    string | null;
    /** From when it is renewed; null where none is. */
    renewsFrom:       string | null;
    /** It holds for less than twice the days it is renewed before, and is renewed halfway instead. */
    halfway:          boolean;
    /** Whether it is to be renewed now. */
    due:              boolean;
    connected:        boolean;
}

/** What a station answered when it was asked by hand to renew. */
export interface CertificateRenewal {
    answer:  string;
    detail:  string | null;
}

/** Where the CSRs of the charging stations go: the EST server of a PKI for each kind of certificate. */
export interface CertificateSigning {
    chargingStationCertificate:  string | null;
    v2gCertificate:              string | null;
    /** Whether there is an API key; the key itself is never read back. */
    apiKey:                      boolean;
    /** How many days before a certificate runs out the station is asked for a new one; 0 for never. */
    renewDaysBefore:             number;
    /** The OCSP responders a station may have asked, beside those on the host of an EST server. */
    ocspResponders:              string[];
    certificates:                StationCertificate[];
    requests:                    CertificateSigningEntry[];
    /** The latest GetCertificateStatus requests, the newest first. */
    statusRequests:              CertificateStatusEntry[];
}

/** A change of it: what is named is changed, null removes it. */
export interface CertificateSigningUpdate {
    chargingStationCertificate?:  string | null;
    v2gCertificate?:              string | null;
    apiKey?:                      string | null;
    renewDaysBefore?:             number | null;
    ocspResponders?:              string[] | null;
}
