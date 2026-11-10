/**
 * The roots of the charging stations, drawn in a document of happy-dom
 * against a stand-in CSMS: a root added from a PEM, one set to every station,
 * one installed on every station connected; what a station has, asked of it,
 * and a certificate deleted from it - and none of that for an account that
 * may only read.
 */

import { asked, field, open, submit, until, type Asked } from '../../test/csms.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { InstalledCertificate, StationRoots } from '../api/client.ts';

const { stationRootsPage } = await import('./stationRoots.ts');


let held:      StationRoots;
let installed: InstalledCertificate[];

const aRoot = {
    id:               'ab'.repeat(32),
    certificateType:  'CSMSRootCertificate',
    subject:          'CN=CSMS Root',
    serialNumber:     '01AB',
    notAfter:         '2036-11-09T10:00:00Z',
    added:            '2026-11-09T10:00:00Z',
    everywhere:       false,
    pem:              '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'
};

function csms({ method, path, body }: Asked): unknown {

    if (path === '/configuration/station-roots' && method === 'GET')
        return held;

    if (path === '/configuration/station-roots' && method === 'POST') {
        const { pem, certificateType, everywhere } = body as { pem: string; certificateType: string; everywhere: boolean };
        held = { ...held, roots: [ ...held.roots, { ...aRoot, id: 'cd'.repeat(32), pem, certificateType, everywhere, subject: 'CN=V2G Root' } ] };
        return held;
    }

    if (path === `/configuration/station-roots/CSMSRootCertificate/${aRoot.id}` && method === 'PUT') {
        held = { ...held, roots: held.roots.map(root => root.id === aRoot.id ? { ...root, everywhere: (body as { everywhere: boolean }).everywhere } : root) };
        return held;
    }

    if (path === `/configuration/station-roots/CSMSRootCertificate/${aRoot.id}/install` && method === 'POST') {
        const station = (body as { station?: string }).station;
        return { ...held, results: (station ? [ station ] : held.connected).map(one => ({ station: one, answer: one === 'cs002' ? 'Rejected' : 'Accepted',
                                                                                        detail: one === 'cs002' ? "'cs002' answered Rejected." : null })) };
    }

    if (path === '/configuration/station-roots/stations/cs001' && method === 'GET')
        return { station: 'cs001', installed };

    if (path === '/configuration/station-roots/stations/cs001/delete' && method === 'POST') {
        installed = installed.filter(one => one.serialNumber !== (body as { serialNumber: string }).serialNumber);
        return { answer: 'Accepted', detail: null };
    }

    return undefined;

}

function aCSMS(): StationRoots {
    return {
        roots:             [ { ...aRoot } ],
        certificateTypes:  [ 'CSMSRootCertificate', 'V2GRootCertificate', 'MORootCertificate', 'ManufacturerRootCertificate', 'OEMRootCertificate' ],
        connected:         [ 'cs001', 'cs002' ],
        changes:           [ { at: '2026-11-09T11:00:00Z', station: 'cs001', action: 'install', certificateType: 'CSMSRootCertificate',
                               certificate: 'CN=CSMS Root', answer: 'Accepted', detail: null, automatic: true } ]
    };
}

const editor = [ 'stations:read', 'certificates:read', 'certificates:edit' ];


describe('the station roots page', () => {

    it('adds a root, sets one for every station, and installs one on every station connected', async () => {

        held = aCSMS();

        const root = await open(stationRootsPage, '/configuration/ocpp-server/roots', editor,
                                csms, root => root.querySelector('#roots tr[data-type="CSMSRootCertificate"]') !== null);

        assert.match(root.querySelector('#changes')!.textContent!, /installed, for every station/);

        field(root, '#root-form', 'pem').value = '-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----';
        root.querySelector<HTMLSelectElement>('#root-form select[name="certificateType"]')!.value = 'V2GRootCertificate';
        root.querySelector<HTMLInputElement>('#root-form input[name="everywhere"]')!.checked = true;

        submit(root, '#root-form');

        await until(() => root.querySelector('#roots tr[data-type="V2GRootCertificate"]') !== null, 'the root added is not shown');

        assert.deepEqual(asked.find(one => one.method === 'POST')!.body,
                         { pem: '-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----', certificateType: 'V2GRootCertificate', everywhere: true });

        const everywhere = root.querySelector<HTMLInputElement>('#roots tr[data-type="CSMSRootCertificate"] .root-everywhere')!;
        everywhere.checked = true;
        everywhere.dispatchEvent(new Event('change'));

        await until(() => asked.some(one => one.method === 'PUT'), 'nothing was changed');
        assert.deepEqual(asked.find(one => one.method === 'PUT')!.body, { everywhere: true });

        root.querySelector<HTMLButtonElement>('#roots tr[data-type="CSMSRootCertificate"] .root-install')!.click();

        await until(() => /Accepted by 1 of 2/.test(root.querySelector('#roots-note')?.textContent ?? ''), 'it did not say what the stations answered');

        assert.match(root.querySelector('#roots-error')!.textContent!, /cs002' answered Rejected/);
        assert.deepEqual(asked.find(one => one.path.endsWith('/install'))!.body, {}, 'every station connected');

    });

    it('asks a station what it has, and deletes a certificate from it once it was asked whether to', async () => {

        held      = aCSMS();
        installed = [ { certificateType: 'CSMSRootCertificate', hashAlgorithm: 'SHA256', issuerNameHash: 'aa', issuerKeyHash: 'bb', serialNumber: '1ab',
                        children: 0, root: aRoot.id, subject: 'CN=CSMS Root' },
                      { certificateType: 'ManufacturerRootCertificate', hashAlgorithm: 'SHA256', issuerNameHash: 'cc', issuerKeyHash: 'dd', serialNumber: '77',
                        children: 0, root: null, subject: null } ];

        const root = await open(stationRootsPage, '/configuration/ocpp-server/roots', editor,
                                csms, root => root.querySelector('#look-form') !== null);

        field(root, '#look-form', 'station').value = 'cs001';
        submit(root, '#look-form');

        await until(() => root.querySelector('#installed tr[data-serial="77"]') !== null, 'what the station has is not shown');

        assert.match(root.querySelector('#installed tr[data-serial="1ab"]')!.textContent!, /CN=CSMS Root/);
        assert.match(root.querySelector('#installed tr[data-serial="77"]')!.textContent!,  /none of the roots here/);

        const yes = window.confirm;

        try
        {

            window.confirm = () => false;
            root.querySelector<HTMLButtonElement>('#installed tr[data-serial="77"] .installed-delete')!.click();
            assert.ok(!asked.some(one => one.path.endsWith('/delete')), 'deleted although it was not to be');

            window.confirm = () => true;
            root.querySelector<HTMLButtonElement>('#installed tr[data-serial="77"] .installed-delete')!.click();

            await until(() => root.querySelector('#installed tr[data-serial="77"]') === null, 'what was deleted is still shown');

        }
        finally
        {
            window.confirm = yes;
        }

        assert.deepEqual(asked.find(one => one.path.endsWith('/delete'))!.body,
                         { certificateType: 'ManufacturerRootCertificate', hashAlgorithm: 'SHA256', issuerNameHash: 'cc', issuerKeyHash: 'dd', serialNumber: '77' });

        await until(() => /Deleted from 'cs001'/.test(root.querySelector('#station-note')?.textContent ?? ''), 'it did not say it deleted');

    });

    it('changes nothing for an account that may only read', async () => {

        held      = aCSMS();
        installed = [];

        const root = await open(stationRootsPage, '/configuration/ocpp-server/roots', [ 'stations:read' ],
                                csms, root => root.querySelector('#roots tr[data-type="CSMSRootCertificate"]') !== null);

        assert.equal(root.querySelector('#root-form'),   null);
        assert.equal(root.querySelector('.root-install'), null);
        assert.equal(root.querySelector('.root-remove'),  null);
        assert.ok(root.querySelector<HTMLInputElement>('.root-everywhere')!.disabled);

        field(root, '#look-form', 'station').value = 'cs001';
        submit(root, '#look-form');

        await until(() => /has no certificate installed/.test(root.querySelector('#station')?.textContent ?? ''), 'what the station has is not shown');

        assert.equal(root.querySelector('.installed-delete'), null);

    });

});
