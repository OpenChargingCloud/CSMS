import { apiURL,
         nodeAPI,
         request,
         type CertificateStore   as NodeCertificateStore,
         type NodeConfiguration,
         type NodeMe,
         type NodeResource,
         type NodeStatus,
         type Operation }  from '@node/api/client';
import type { I18NString }  from '@ocpp/api/i18n';


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
export type Resource = NodeResource | 'stations' | 'locations' | 'roaming' | 'commissioning';

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

/**
 * How a client may authenticate at a WebSocket server: by HTTP authentication
 * without TLS or over it, or by its TLS client certificate - OCPP's security
 * profiles 1, 2 and 3.
 */
export type ClientAuthentication = 'httpAuthWithoutTLS' | 'httpAuthOverTLS' | 'tlsClientCertificate';

/** The server the charging stations below this CSMS connect to. */
export interface OCPPServerConfiguration {
    enabled:                     boolean;
    address:                     string | null;
    port:                        number;
    /** How a client may authenticate: what OCPP calls its security profiles 1, 2 and 3. */
    clientAuthentication:        ClientAuthentication[];
    subprotocols:                string[];
    /** The names and addresses the stations connect to; what a certificate must cover. */
    reachableAs:                 string[];
    minTLSVersion:               string;
    checkCertificateRevocation:  boolean;
    maxConnections:              number;
    pingEverySeconds:            number;
    logging:                     OCPPServerLogging;
    /** OCPP-over-SSH, on this CSMS's SSH server, beside the WebSocket port. */
    ssh:                         OCPPServerSSH;
    state: {
        running:            boolean;
        tls:                boolean;
        url:                string;
        connections:        number;
        webSocketLogins:      number;
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
        clientAuthentication:           ClientAuthentication[];
        tlsVersions:                    string[];
        maxConnections:                 number;
        maxReachableAs:                 number;
        minMaxMessageSize?:             number;
        maxMaxMessageSize?:             number;
        suggestedPayloadWindowSeconds:  number;
    };
    file:  string;
}

/** OCPP-over-SSH: the subsystem the stations ask for on this CSMS's SSH server. */
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
    clientAuthentication?:        ClientAuthentication[];
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

/** An SSH public key a charging station signs in with for OCPP-over-SSH. Nothing about it is secret. */
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
    /** There, and true, where the token has to be bound to the TLS session of its connection. */
    tlsChannelBinding?: boolean;
}

export { inEnglish, textOf, type I18NString } from '@ocpp/api/i18n';

/** One charging station that may sign in. */
export interface WebSocketLogin {
    login:        string;
    group:        string;
    enabled:      boolean;
    addedAt:      string;
    hasPassword:  boolean;
    hasTOTP:      boolean;
    totp?:        TOTPSettings;
    hasSSHKey?:   boolean;
    sshKeys?:     StationSSHKey[];
    description?: I18NString;
    /** A local controller's login: it may send in the name of the stations behind it. */
    localController?: boolean;
    /** A gateway's login: like a local controller's, it may send in the name of the stations behind it. */
    gateway?: boolean;
}

/** A group of logins, and what its members are allowed to do. */
export interface LoginGroup {
    id:                string;
    name:              string;
    enabled:           boolean;
    builtIn:           boolean;
    addedAt:           string;
    authMethods:       AuthMethod[];
    /** How its members may authenticate - OCPP's security profiles 1, 2 and 3. */
    clientAuthentication:  ClientAuthentication[];
    /** What its stations have over their SSH connection besides OCPP: the names of SSH subsystems. */
    sshChannels?:      string[];
    members:           number;
    description?:      I18NString;
}

/** Which charging stations may sign in, and with what. */
export interface WebSocketLogins {
    file:               string;
    enabled:            number;
    maxLogins:        number;
    maxGroups:          number;
    minPasswordLength:  number;
    minSecretLength:    number;
    defaultGroup:       string;
    groups:             LoginGroup[];
    logins:             WebSocketLogin[];
}

/** What a group may be changed to. */
export interface LoginGroupUpdate {
    id?:               string;
    name:              string;
    enabled:           boolean;
    authMethods:       AuthMethod[];
    /** How its members may authenticate - OCPP's security profiles 1, 2 and 3. */
    clientAuthentication:  ClientAuthentication[];
    /** Replaced like everything else about a group: left out, its stations have OCPP alone. */
    sshChannels?:      string[];
    description?:      I18NString;
}

/** What a one-time token may be set to. */
export interface TOTPUpdate {
    sharedSecret?:     string;
    validitySeconds?:  number;
    length?:           number;
    alphabet?:         string;
    hashAlgorithm?:    string;
    group?:            string;
    description?:      I18NString;
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

        trust: {

            get:      ()  => request<ClientTrust>('GET', '/configuration/ocpp-server/trust'),

            add:      (pem: string, name: string) =>
                          request<{ id: string; warnings: string[] }>('POST', '/configuration/ocpp-server/trust', { pem, name }),

            update:   (id: string, change: { enabled?: boolean; name?: string }) =>
                          request<ClientTrust>('PUT', `/configuration/ocpp-server/trust/${encodeURIComponent(id)}`, change),

            remove:   (id: string) =>
                          request<ClientTrust>('DELETE', `/configuration/ocpp-server/trust/${encodeURIComponent(id)}`)

        },

        logins: {

            get:      ()  => request<WebSocketLogins>('GET', '/configuration/ocpp-server/logins'),

            /**
             * Add a station or give one a new password. An empty password means
             * "make one up", and the made-up one comes back here and nowhere
             * else: it is kept only as a hash.
             */
            save:     (login: string, password: string, group: string, description?: I18NString) =>
                          request<{ login: string; password?: string; logins: WebSocketLogins }>(
                              'POST', '/configuration/ocpp-server/logins', { login, password, group, description }),

            enable:   (login: string, enabled: boolean) =>
                          request<WebSocketLogins>('PUT', `/configuration/ocpp-server/logins/${encodeURIComponent(login)}`, { enabled }),

            move:     (login: string, group: string) =>
                          request<WebSocketLogins>('PUT', `/configuration/ocpp-server/logins/${encodeURIComponent(login)}`, { group }),

            /**
             * Mark a login as a local controller's, which may send in the
             * name of the stations behind it - or no longer.
             */
            markLocalController: (login: string, localController: boolean) =>
                          request<WebSocketLogins>('PUT', `/configuration/ocpp-server/logins/${encodeURIComponent(login)}`, { localController }),

            /**
             * Mark a login as a gateway's, which may send in the name of the
             * stations behind it - or no longer. Marked as the one, a login is
             * no longer the other.
             */
            markGateway: (login: string, gateway: boolean) =>
                          request<WebSocketLogins>('PUT', `/configuration/ocpp-server/logins/${encodeURIComponent(login)}`, { gateway }),

            remove:   (login: string) =>
                          request<WebSocketLogins>('DELETE', `/configuration/ocpp-server/logins/${encodeURIComponent(login)}`),

            /**
             * Give a station what it needs to be let in with a one-time token.
             * An empty shared secret means "make one up", and it comes back
             * here - the only place it is ever handed out.
             */
            saveTOTP: (login: string, update: TOTPUpdate) =>
                          request<{ login: string; sharedSecret?: string; logins: WebSocketLogins }>(
                              'PUT', `/configuration/ocpp-server/logins/${encodeURIComponent(login)}/totp`, update),

            /**
             * Whether a station's token has to be bound to the TLS session of
             * its connection. Its secret stays as it is.
             */
            bindTOTP:       (login: string, bound: boolean) =>
                          request<WebSocketLogins>(
                              'PUT', `/configuration/ocpp-server/logins/${encodeURIComponent(login)}/totp/binding`,
                              { tlsChannelBinding: bound }),

            removeTOTP:     (login: string) =>
                          request<WebSocketLogins>('DELETE', `/configuration/ocpp-server/logins/${encodeURIComponent(login)}/totp`),

            removePassword: (login: string) =>
                          request<WebSocketLogins>('DELETE', `/configuration/ocpp-server/logins/${encodeURIComponent(login)}/password`),

            /**
             * Give a station an SSH key for OCPP-over-SSH - one line of an
             * authorized_keys file - adding the station where it is not listed
             * yet. A public key: nothing secret goes either way.
             */
            addSSHKey: (login: string, line: string, label: string, group: string, description?: I18NString) =>
                          request<{ login: string; fingerprint: string; logins: WebSocketLogins }>(
                              'POST', `/configuration/ocpp-server/logins/${encodeURIComponent(login)}/sshKeys`, { line, label, group, description }),

            /** Take a key away; a session it opened ends. */
            removeSSHKey: (login: string, fingerprint: string) =>
                          request<WebSocketLogins>('DELETE',
                              `/configuration/ocpp-server/logins/${encodeURIComponent(login)}/sshKeys/${fingerprintInURL(fingerprint)}`)

        },

        groups: {

            /** Everything about the group is replaced, not merged. */
            save:     (update: LoginGroupUpdate) =>
                          update.id === undefined
                              ? request<WebSocketLogins>('POST', '/configuration/ocpp-server/groups', update)
                              : request<WebSocketLogins>('PUT',  `/configuration/ocpp-server/groups/${encodeURIComponent(update.id)}`, update),

            remove:   (id: string) =>
                          request<WebSocketLogins>('DELETE', `/configuration/ocpp-server/groups/${encodeURIComponent(id)}`)

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
