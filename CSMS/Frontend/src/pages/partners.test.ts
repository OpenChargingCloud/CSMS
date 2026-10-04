/**
 * The roaming partners drawn, in a document of happy-dom, against a stand-in
 * CSMS: a partner half typed in - and its focus - outlives the tokens being
 * shown and another partner removed, the fields for starting the peering from
 * here come and go with their box without the rest of the form, a partner
 * added empties the form, and a registration says it is under way where it
 * was asked for.
 */

import { asked, change, field, open, submit, until, type Asked } from '../../test/csms.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { Partner, Partners } from '../api/client.ts';

const { partnersPage } = await import('./partners.ts');


function aPartner(id: string, canRegister = false): Partner {
    return {
        version: '2.2.1', id, countryCode: 'DE', partyId: id.slice(-3), role: 'EMSP', name: `Partner ${id}`,
        website: null, status: 'ENABLED', ourToken: `token-of-${id}`, hasOurToken: true, ourTokenStatus: 'ENABLED',
        theirToken: canRegister ? `their-${id}` : null, hasTheirToken: canRegister,
        theirVersionsURL: canRegister ? `https://${id}.example.org/versions` : null, remoteStatus: null,
        selectedVersion: null, canRegister, registered: false, created: '2026-10-01T00:00:00Z', lastUpdated: '2026-10-01T00:00:00Z'
    };
}

let held: Partners;

/** What a registration waits for before it is answered. */
let registered: Promise<void> = Promise.resolve();

async function csms({ method, path, body }: Asked): Promise<unknown> {

    if (path === '/ocpi/partners' && method === 'GET')
        return held;

    if (path === '/ocpi/partners' && method === 'POST') {
        const spec = body as { countryCode: string; partyId: string; version: string };
        const id   = `${spec.countryCode}-${spec.partyId}`;
        held = { ...held, partners: [ ...held.partners, aPartner(id) ] };
        return { message: 'added', id, version: spec.version, ourToken: 'made-up-token', partners: held };
    }

    const register = /^\/ocpi\/partners\/([^/]+)\/([^/]+)\/register$/.exec(path);

    if (register && method === 'POST') {
        await registered;
        held = { ...held, partners: held.partners.map(partner => partner.id === register[2] ? { ...partner, registered: true } : partner) };
        return { ok: true, message: `Registered with '${register[2]}'.`, partners: held };
    }

    const one = /^\/ocpi\/partners\/([^/]+)\/([^/]+)$/.exec(path);

    if (one && method === 'DELETE') {
        held = { ...held, partners: held.partners.filter(partner => partner.id !== one[2]) };
        return held;
    }

    return undefined;

}

async function opened(): Promise<HTMLElement> {
    held       = { partners: [ aPartner('DE-AAA'), aPartner('DE-BBB', true) ], versions: [ '2.1.1', '2.2.1' ],
                   roles: [ 'CPO', 'EMSP' ], ourVersionsURL: 'http://127.0.0.1/ext/versions' };
    registered = Promise.resolve();
    return open(partnersPage, '/configuration/ocpi/partners', [ 'roaming:read', 'roaming:edit' ],
                csms, root => root.querySelector('#partner-form') !== null && root.querySelector('.partner-remove') !== null);
}

const rowOf = (root: HTMLElement, id: string) => root.querySelector<HTMLButtonElement>(`.partner-remove[data-id="${id}"]`)?.closest('tr') ?? null;


describe('the roaming partners', () => {

    it('keep a partner half typed in, and its focus, while the tokens are shown and another partner is removed', async () => {

        const root  = await opened();
        const name  = field(root, '#partner-form', 'name');
        const other = rowOf(root, 'DE-BBB');

        name.value = 'Example Charging';
        name.focus();

        root.querySelector<HTMLButtonElement>('#reveal')!.click();
        await until(() => root.textContent!.includes('token-of-DE-AAA'), 'the tokens were not shown');

        root.querySelector<HTMLButtonElement>('.partner-remove[data-id="DE-AAA"]')!.click();
        await until(() => rowOf(root, 'DE-AAA') === null, 'the partner removed is still drawn');

        assert.ok(field(root, '#partner-form', 'name') === name, 'the field was made anew');
        assert.equal(name.value, 'Example Charging');
        assert.ok(document.activeElement === name, 'the focus went');
        assert.ok(rowOf(root, 'DE-BBB') === other, 'the row of the partner left was made anew');

    });

    it('show the fields for starting the peering here with their box, and leave the rest of the form alone', async () => {

        const root      = await opened();
        const name      = field(root, '#partner-form', 'name');
        const theirs    = field(root, '#partner-form', 'theirToken');
        const fields    = root.querySelector<HTMLElement>('#start-here')!;

        name.value = 'Example Charging';

        assert.equal(fields.hidden,   true);
        assert.equal(theirs.disabled, true, 'a hidden field would hold up the form');

        change(field(root, '#partner-form', 'startHere'), true);
        await until(() => !fields.hidden, 'the fields for starting here were not shown');

        assert.equal(theirs.disabled, false);
        assert.ok(document.activeElement === theirs, 'the first of them was not given the focus');
        assert.ok(field(root, '#partner-form', 'name') === name, 'the field above was made anew');
        assert.equal(name.value, 'Example Charging');

        change(field(root, '#partner-form', 'startHere'), false);
        await until(() => fields.hidden === true, 'the fields for starting here were not hidden again');

        assert.equal(theirs.disabled, true);

    });

    it('empty the form once a partner is added, and hide what starting here asked for', async () => {

        const root = await opened();

        field<HTMLSelectElement>(root, '#partner-form', 'role').value  = 'EMSP';
        field(root, '#partner-form', 'countryCode').value              = 'de';
        field(root, '#partner-form', 'partyId').value                  = 'ccc';
        field(root, '#partner-form', 'name').value                     = 'Example Charging';

        change(field(root, '#partner-form', 'startHere'), true);
        await until(() => !root.querySelector<HTMLElement>('#start-here')!.hidden, 'the fields for starting here were not shown');

        field(root, '#partner-form', 'theirToken').value   = 'theirs';
        field(root, '#partner-form', 'versionsURL').value  = 'https://ccc.example.org/versions';

        submit(root, '#partner-form');
        await until(() => rowOf(root, 'DE-CCC') !== null, 'the partner added was not drawn');

        const sent = asked.find(one => one.method === 'POST')?.body as Record<string, unknown>;

        assert.equal(sent['countryCode'],  'DE');
        assert.equal(sent['partyId'],      'CCC');
        assert.equal(sent['theirToken'],   'theirs');
        assert.equal(sent['versionsURL'],  'https://ccc.example.org/versions');

        assert.equal(field(root, '#partner-form', 'name').value, '', 'what was added is still in the form');
        assert.equal(field(root, '#partner-form', 'startHere').checked, false);
        assert.equal(root.querySelector<HTMLElement>('#start-here')!.hidden, true, 'the fields for starting here are still shown');
        assert.equal(field(root, '#partner-form', 'theirToken').disabled, true);
        assert.match(root.querySelector('.notice.ok')!.textContent!, /made-up-token/);

    });

    it('say a registration is under way on its button, keep the row, and say how it went', async () => {

        const root = await opened();
        const row  = rowOf(root, 'DE-BBB');

        let cue = (): void => undefined;
        registered = new Promise(resolve => { cue = resolve; });

        const button = root.querySelector<HTMLButtonElement>('.partner-register[data-id="DE-BBB"]')!;
        button.click();

        await until(() => button.disabled && /Registering/.test(button.textContent!), 'the button did not say the registration is under way');

        cue();

        await until(() => /Registered with 'DE-BBB'/.test(root.textContent!), 'how the registration went was not said');

        assert.ok(rowOf(root, 'DE-BBB') === row, 'the row was made anew');
        assert.ok(root.querySelector('.partner-register[data-id="DE-BBB"]') === button, 'the button was made anew');
        assert.equal(button.disabled, false);
        assert.match(button.textContent!, /Register again/);

    });

});
