/**
 * Who this CSMS is to its roaming partners drawn, in a document of happy-dom,
 * against a stand-in CSMS: every card as markup, and Reload draws what the
 * CSMS says then into the cards it drew before.
 */

import { open, until, type Asked } from '../../test/csms.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { OCPIConfiguration } from '../api/client.ts';

const { ocpiPage } = await import('./ocpi.ts');


let partners = 1;

function csms({ path }: Asked): unknown {

    if (path === '/configuration/ocpi')
        return {
            party:          { countryCode: 'DE', partyId: 'GEF', id: 'DE*GEF', role: 'CPO', name: 'GraphDefined CPO', website: null },
            endpoints:      { base: '/ext', versions: 'http://127.0.0.1/ext/versions', externalURL: null,
                              byVersion: [ { version: '2.2.1', details: 'http://127.0.0.1/ext/versions/2.2.1',
                                             credentials: 'http://127.0.0.1/ext/v2.2.1/credentials',
                                             modules: { locations: 'http://127.0.0.1/ext/v2.2.1/cpo/locations' } } ] },
            versions:       [ '2.2.1' ],
            knownVersions:  [ '2.1.1', '2.2.1' ],
            settings:       { locationsAsOpenData: false, tariffsAsOpenData: false, allowDowngrades: false, logRequests: true, logPayloads: false },
            counts:         { partners, locations: 2, tokens: 0, tariffs: 0, sessions: 0, cdrs: 0 },
            directory:      'ocpi',
            file:           'configuration.json'
        } satisfies OCPIConfiguration;

    return undefined;

}


describe('the OCPI page', () => {

    it('draws its cards as markup, and Reload what the CSMS says then into the same cards', async () => {

        partners = 1;

        const root = await open(ocpiPage, '/configuration/ocpi', [ 'roaming:read' ],
                                csms, root => root.querySelector('.cards') !== null);

        assert.equal(root.querySelectorAll('.cards > section.card').length, 5);
        assert.doesNotMatch(root.textContent!, /<section|<tr/, 'a card was taken as text');
        assert.match(root.textContent!, /cpo\/locations/);

        const first = root.querySelector('.cards > section.card');
        const count = () => root.querySelector<HTMLAnchorElement>('a[href$="/configuration/ocpi/partners"]')!.textContent;

        assert.equal(count(), '1');

        partners = 2;
        root.ownerDocument.querySelector<HTMLButtonElement>('#reload')!.click();

        await until(() => count() === '2', 'Reload did not draw what the CSMS says then');

        assert.ok(root.querySelector('.cards > section.card') === first, 'the card was made anew');

    });

});
