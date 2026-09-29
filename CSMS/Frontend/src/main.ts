import './styles/app.scss';

// FontAwesome: the CSS ends up in the extracted stylesheet, the referenced
// font files become hashed assets below /assets/.
import '@fortawesome/fontawesome-free/css/fontawesome.css';
import '@fortawesome/fontawesome-free/css/solid.css';

import { nodeMenu, startNode } from '@node/start';

import { configurationPage }      from './pages/configuration';
import { dnsPage }                from './pages/dns';
import { ntsPage }                from './pages/nts';
import { certificateStorePage }   from './pages/certificateStore';
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
// between them. The sign-in, the log, the frame and following the log while
// somebody is signed in are every node's - see WWCP_Node's start.ts.
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

    pages: {

        // "/" is the configuration, and is a page of its own rather than a
        // redirect to /configuration: the sign-in remembers where somebody was
        // going, and for the first visit that is "/".
        '/':                                        configurationPage,
        '/configuration':                           configurationPage,
        '/configuration/dns':                       dnsPage,
        '/configuration/nts':                       ntsPage,
        '/configuration/certificates':              certificateStorePage,

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
