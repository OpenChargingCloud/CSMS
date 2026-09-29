/**
 * What the CSMS's own pages are held to: what every page of every kind of
 * node is, by the rules of WWCP_Node's test/pages.ts.
 *
 * Run with `npm test`. "@node/.." is WWCP_Node/Frontend, where the rules are.
 */

import { everyPageIn } from '@node/../test/pages.ts';


everyPageIn(new URL('./', import.meta.url), {

    withForms: [
        'clientTrust.ts',
        'locations.ts',
        'ocppServer.ts',
        'partners.ts',
        'serverCertificates.ts',
        'stationLogins.ts'
    ]

});
