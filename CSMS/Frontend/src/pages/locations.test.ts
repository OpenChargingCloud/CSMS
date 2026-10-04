/**
 * The locations drawn, in a document of happy-dom, against a stand-in CSMS:
 * a location half typed in - and its focus - outlives another one withdrawn,
 * the rows keep their elements by their key, a location published empties
 * the form and says what the CSMS said, and Reload asks before it throws a
 * location half typed in away.
 */

import { asked, field, open, refused, said, submit, type, until, type Asked } from '../../test/csms.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { Location, Locations } from '../api/client.ts';

const { locationsPage } = await import('./locations.ts');


function aLocation(id: string, version = '2.2.1'): Location {
    return {
        version, id, name: `Site ${id}`, address: 'Main Street 1', postal_code: '07743', city: 'Jena', country: 'DEU',
        coordinates: { latitude: '50.927054', longitude: '11.589707' }, evses: [], publish: true,
        last_updated: '2026-10-04T12:00:00Z'
    };
}

let held: Locations;

/** Refuses a withdrawal where told to. */
let refuseWithdrawals = false;

function csms({ method, path, body }: Asked): unknown {

    if (path === '/ocpi/locations' && method === 'GET')
        return held;

    if (path === '/ocpi/locations' && method === 'POST') {
        const spec = body as { version: string; id: string };
        held = { ...held, locations: [ ...held.locations, aLocation(spec.id, spec.version) ] };
        return { message: `'${spec.id}' is published.`, id: spec.id, version: spec.version, locations: held };
    }

    const one = /^\/ocpi\/locations\/([^/]+)\/(.+)$/.exec(path);

    if (one && method === 'DELETE') {
        if (refuseWithdrawals)
            return refused(409, 'a charging session is still running there');
        held = { ...held, locations: held.locations.filter(location => !(location.version === one[1] && location.id === one[2])) };
        return held;
    }

    return undefined;

}

async function opened(): Promise<HTMLElement> {
    held              = { locations: [ aLocation('L1'), aLocation('L2') ], versions: [ '2.1.1', '2.2.1' ],
                          operator: 'GraphDefined CPO', partyId: 'DE*GEF', openData: false };
    refuseWithdrawals = false;
    return open(locationsPage, '/configuration/ocpi/locations', [ 'locations:read', 'locations:edit' ],
                csms, root => root.querySelector('#location-form') !== null && root.querySelector('.location-remove') !== null);
}

const rowOf      = (root: HTMLElement, id: string) => root.querySelector<HTMLButtonElement>(`.location-remove[data-id="${id}"]`)?.closest('tr') ?? null;
const withdraw   = (root: HTMLElement, id: string) => root.querySelector<HTMLButtonElement>(`.location-remove[data-id="${id}"]`)!.click();


describe('the locations', () => {

    it('keep a location half typed in, and its focus, while another is withdrawn', async () => {

        const root = await opened();
        const name = field(root, '#location-form', 'name');

        name.value = 'Car park';
        name.focus();

        withdraw(root, 'L1');
        await until(() => rowOf(root, 'L1') === null, 'the location withdrawn is still drawn');

        assert.ok(field(root, '#location-form', 'name') === name, 'the field was made anew');
        assert.equal(name.value, 'Car park');
        assert.ok(document.activeElement === name, 'the focus went');

    });

    it('keep the row of a location by its key when another goes', async () => {

        const root   = await opened();
        const second = rowOf(root, 'L2');

        withdraw(root, 'L1');
        await until(() => rowOf(root, 'L1') === null, 'the location withdrawn is still drawn');

        assert.ok(rowOf(root, 'L2') === second, 'the row of the location left was made anew');

    });

    it('say why a withdrawal was refused, and still show the location', async () => {

        const root = await opened();

        refuseWithdrawals = true;
        withdraw(root, 'L2');

        await until(() => said.some(text => /still running/.test(text)), 'the refusal was not said');
        await until(() => asked.filter(one => one.method === 'GET' && one.path === '/ocpi/locations').length === 2,
                    'the page did not ask what the CSMS has after the refusal');

        assert.ok(rowOf(root, 'L2') !== null, 'the location refused to be withdrawn is gone from the page');

    });

    it('empty the form once a location is published, and say what the CSMS said', async () => {

        const root = await opened();

        const values: Record<string, string> = {
            id: 'L3', name: 'Car park', address: 'Side Street 2', postalCode: '07745', city: 'Jena',
            country: 'deu', timeZone: 'Europe/Berlin', latitude: '50.9', longitude: '11.6'
        };

        for (const [name, value] of Object.entries(values))
            field(root, '#location-form', name).value = value;

        submit(root, '#location-form');
        await until(() => rowOf(root, 'L3') !== null, 'the location published was not drawn');

        const sent = asked.find(one => one.method === 'POST')?.body as Record<string, unknown>;

        assert.equal(sent['id'],        'L3');
        assert.equal(sent['country'],   'DEU', 'the country was not sent in capitals');
        assert.equal(sent['latitude'],  50.9);
        assert.equal(sent['version'],   '2.2.1', 'the newest version was not the one chosen');
        assert.equal(sent['publish'],   true);

        assert.equal(field(root, '#location-form', 'id').value,    '', 'what was published is still in the form');
        assert.equal(field(root, '#location-form', 'name').value,  '');
        assert.match(root.querySelector('#location-note')!.textContent!, /'L3' is published/);

    });

    // Whether it asks where nothing is typed is not asked here: happy-dom
    // takes the version's chosen option for one somebody chose, as it keeps
    // no defaultSelected. In Chrome it asks nothing then.
    it('ask before Reload throws a location half typed in away, and then ask the CSMS again', async () => {

        const root = await opened();

        type(field(root, '#location-form', 'name'), 'Car park');

        const before = asked.length;

        root.querySelector<HTMLButtonElement>('.page-actions #reload')!.click();

        await until(() => asked.slice(before).some(one => one.method === 'GET' && one.path === '/ocpi/locations'),
                    'the CSMS was not asked again');

        assert.equal(said.length, 1, `asked ${said.length} times before the location half typed in was thrown away`);
        assert.match(said[0]!, /not been told about/);

        // Thrown away, as was agreed to: a draw by comparing would have kept it.
        await until(() => root.querySelector('#location-form') !== null, 'the form was not drawn again');

        assert.equal(field(root, '#location-form', 'name').value, '', 'Reload kept what it was allowed to throw away');

    });

});
