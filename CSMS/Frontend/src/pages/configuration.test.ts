/**
 * The configuration drawn, in a document of happy-dom, against a stand-in
 * CSMS: its cards - html.ts's, in a template of view.ts - stand as the
 * markup they are, and Reload draws them again with what the CSMS says
 * then.
 */

import { open, until, type Asked } from '../../test/csms.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

const { configurationPage } = await import('./configuration.ts');


let uptime = '1 minute';

function csms({ path }: Asked): unknown {

    if (path === '/status')
        return { service: 'CSMS', version: '1.0', hermod: null, timestamp: '2026-10-04T12:00:00Z',
                 startedAt: '2026-10-04T11:59:00Z', uptime, sessions: 1, log: { entries: 0, capacity: 100, lastId: 0, tags: [] },
                 ocppId: 'csms001' };

    if (path === '/configuration')
        return { CSMS: { ocppId: 'csms001' }, ocpp: { version: '2.1', role: 'CSMS' }, ocpi: { role: 'CPO' },
                 http: { port: 8080 }, web: {}, log: {}, time: {},
                 assemblies: [ { name: 'CSMS', version: '1.0', commit: 'abc1234' } ] };

    return undefined;

}


describe('the configuration', () => {

    it('draws its cards as markup, and again on Reload', async () => {

        uptime = '1 minute';

        const root = await open(configurationPage, '/configuration', [ 'configuration:read' ],
                                csms, root => root.querySelector('.cards') !== null);

        assert.equal(root.querySelectorAll('.cards > section.card').length, 8);
        assert.match(root.querySelector('.cards')!.textContent!, /OCPP 2\.1 - CSMS/);
        assert.match(root.querySelector('.cards')!.textContent!, /OCPI - CPO/);
        assert.match(root.querySelector('.cards')!.textContent!, /Uptime\s+1 minute/);
        assert.doesNotMatch(root.textContent!, /<section/, 'a card was taken as text');

        uptime = '2 minutes';
        root.querySelector<HTMLButtonElement>('#reload')!.click();

        await until(() => /Uptime\s+2 minutes/.test(root.textContent!), 'Reload did not draw what the CSMS says then');

        assert.equal(root.querySelectorAll('.cards > section.card').length, 8);

    });

});
