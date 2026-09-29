import './styles/app.scss';

// FontAwesome: the CSS ends up in the extracted stylesheet, the referenced
// font files become hashed assets below /assets/.
import '@fortawesome/fontawesome-free/css/fontawesome.css';
import '@fortawesome/fontawesome-free/css/solid.css';

import { toURL } from '@node/basePath';
import { html } from '@node/html';
import { nodeMenu, startNode } from '@node/start';

import { configurationPage }      from './pages/configuration';
import { ocppServerPage }         from './pages/ocppServer';
import { stationLoginsPage }      from './pages/stationLogins';
import { serverCertificatesPage } from './pages/serverCertificates';
import { clientTrustPage }        from './pages/clientTrust';
import { ocpiPage }               from './pages/ocpi';
import { partnersPage }           from './pages/partners';
import { locationsPage }          from './pages/locations';
import { roamingDataPages }       from './pages/roamingData';

// What a CSMS has pages for beside what every node has: the server its
// charging stations connect to, and its side of OCPI - who it is to its
// roaming partners, the partners, the locations it publishes and what travels
// between them. The sign-in, the log, the name servers, the time servers, the
// certificate store, the frame and following the log while somebody is signed
// in are every node's - see WWCP_Node's start.ts.
startNode({

    name:  'CSMS',
    icon:  'fa-sitemap',

    menu: [
        nodeMenu.configuration([
            nodeMenu.dns,
            nodeMenu.nts,
            { ...nodeMenu.certificates,                         label: 'Certificate store',   icon: 'fa-vault'                                                  },
            { path: '/configuration/ocpp-server',               label: 'Charging stations',   icon: 'fa-charging-station',  permission: [ 'stations:read' ]     },
            { path: '/configuration/ocpp-server/logins',        label: 'Logins and groups',   icon: 'fa-users-gear',        permission: [ 'stations:read' ]     },
            { path: '/configuration/ocpp-server/certificates',  label: 'Server certificates', icon: 'fa-certificate',       permission: [ 'certificates:read' ] },
            { path: '/configuration/ocpp-server/trust',         label: 'Accepted chains',     icon: 'fa-user-shield',       permission: [ 'certificates:read' ] },
            { path: '/configuration/ocpi',                      label: 'OCPI',                icon: 'fa-plug',              permission: [ 'roaming:read' ]      },
            { path: '/configuration/ocpi/partners',             label: 'Roaming partners',    icon: 'fa-handshake',         permission: [ 'roaming:read' ]      },
            { path: '/configuration/ocpi/locations',            label: 'Locations',           icon: 'fa-map-location-dot',  permission: [ 'locations:read' ]    }
        ]),
        {
            path:        '/roaming',
            label:       'Roaming data',
            icon:        'fa-database',
            permission:  [ 'roaming:read' ],
            children:    [
                { path: '/roaming/tokens',    label: 'Tokens',                 icon: 'fa-id-card',       permission: [ 'roaming:read' ] },
                { path: '/roaming/tariffs',   label: 'Tariffs',                icon: 'fa-tags',          permission: [ 'roaming:read' ] },
                { path: '/roaming/sessions',  label: 'Charging sessions',      icon: 'fa-bolt',          permission: [ 'roaming:read' ] },
                { path: '/roaming/cdrs',      label: 'Charge detail records',  icon: 'fa-file-invoice',  permission: [ 'roaming:read' ] }
            ]
        },
        nodeMenu.logs
    ],

    // "Certificate store", because there is a page called "Server certificates"
    // as well - the charging station server's, which the words under what
    // this CSMS presents link to. And what it believes beside the TLS roots
    // every node keeps: the roots of ISO 15118. Not a client root, which a CSMS
    // does not keep: the words under what it believes link to the authorities
    // its charging stations are vouched for by instead.
    certificates: {
        title:  'Certificate store',
        hints:  {
            believes:  html`
                Trust anchors. Every switched-on root of a kind is believed at once. A TLS root kept for the
                name servers or the time servers is what a server of theirs may chain to beside the roots
                this machine trusts; the roots of ISO 15118 are the V2G root the charging stations'
                certificates chain to, and the roots of the contracts and the vehicles charged here.
                Not the authorities a charging station connecting here may be vouched for by, which have a
                page of their own: <a href="${toURL('/configuration/ocpp-server/trust')}">Accepted chains</a>.
            `,
            presents:  html`
                What this CSMS shows in TLS, with its private key. Not the key the charging station server
                shows the stations, which has a page of its own:
                <a href="${toURL('/configuration/ocpp-server/certificates')}">Server certificates</a>.
            `
        }
    },

    // "/" is every node's: the first page of the menu the person signed in may
    // open - the configuration for whoever may read it, and the roaming data,
    // say, for an account that may read only that, where the configuration's
    // own page had answered 403 (found by the charging station and the
    // gateway).
    pages: {

        '/configuration':                           configurationPage,

        '/configuration/ocpp-server':               ocppServerPage,
        '/configuration/ocpp-server/logins':        stationLoginsPage,
        '/configuration/ocpp-server/certificates':  serverCertificatesPage,
        '/configuration/ocpp-server/trust':         clientTrustPage,

        '/configuration/ocpi':                      ocpiPage,
        '/configuration/ocpi/partners':             partnersPage,
        '/configuration/ocpi/locations':            locationsPage,

        '/roaming':                                 roamingDataPages.tokens,
        '/roaming/tokens':                          roamingDataPages.tokens,
        '/roaming/tariffs':                         roamingDataPages.tariffs,
        '/roaming/sessions':                        roamingDataPages.sessions,
        '/roaming/cdrs':                            roamingDataPages.cdrs

    }

});
