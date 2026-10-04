/**
 * What travels between this operator and its partners drawn, in a document of
 * happy-dom, against a stand-in CSMS: a row opened to its JSON stays open, and
 * keeps its elements, when Reload draws the list again in another order.
 */

import { open, until, type Asked } from '../../test/csms.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { RoamingItem } from '../api/client.ts';

const { roamingDataPages } = await import('./roamingData.ts');


function aToken(uid: string, partyId = 'AAA'): RoamingItem {
    return { version: '2.2.1', uid, country_code: 'DE', party_id: partyId, type: 'RFID', contract_id: `DE-${partyId}-${uid}`,
             valid: true, whitelist: 'ALLOWED', last_updated: '2026-10-04T12:00:00Z' };
}

let held: RoamingItem[] = [];

function csms({ path }: Asked): unknown {

    if (path === '/ocpi/tokens')
        return { kind: 'tokens', versions: [ '2.2.1' ], items: held };

    return undefined;

}

const rawOf    = (root: HTMLElement, contract: string) =>
    [ ...root.querySelectorAll<HTMLTableRowElement>('tr.raw') ].find(row => row.textContent!.includes(contract)) ?? null;

const buttonOf = (root: HTMLElement, contract: string) =>
    rawOf(root, contract)?.previousElementSibling?.querySelector<HTMLButtonElement>('.show-raw') ?? null;


describe('the tokens', () => {

    it('keep a row opened to its JSON open, and its elements, when Reload draws them again in another order', async () => {

        held = [ aToken('0001'), aToken('0002'), aToken('0001', 'BBB') ];

        const root = await open(roamingDataPages.tokens, '/roaming/tokens', [ 'roaming:read' ],
                                csms, root => root.querySelector('tr.raw') !== null);

        // Two partners' tokens share the uid 0001: each is a row of its own.
        assert.equal(root.querySelectorAll('tr.raw').length, 3);

        const raw    = rawOf(root, 'DE-AAA-0002')!;
        const button = buttonOf(root, 'DE-AAA-0002')!;

        assert.equal(raw.hidden, true);

        button.click();
        await until(() => !raw.hidden, 'the row was not opened');

        assert.match(button.textContent!, /Hide/);

        held = [ aToken('0002'), aToken('0001', 'BBB'), aToken('0001'), aToken('0003') ];
        root.ownerDocument.querySelector<HTMLButtonElement>('#reload')!.click();

        await until(() => root.querySelectorAll('tr.raw').length === 4, 'Reload did not draw the tokens again');

        assert.ok(rawOf(root, 'DE-AAA-0002') === raw, 'the opened row was made anew');
        assert.equal(raw.hidden, false, 'the opened row was closed');
        assert.match(buttonOf(root, 'DE-AAA-0002')!.textContent!, /Hide/);
        assert.equal(rawOf(root, 'DE-BBB-0001')!.hidden, true, 'a row nobody opened is open');

        // One partner's token opened is not another's with the same uid.
        buttonOf(root, 'DE-BBB-0001')!.click();
        await until(() => !rawOf(root, 'DE-BBB-0001')!.hidden, 'the row was not opened');

        assert.equal(rawOf(root, 'DE-AAA-0001')!.hidden, true, "another partner's token with the same uid was opened with it");

    });

});
