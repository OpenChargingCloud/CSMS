/**
 * Where the CSRs of the charging stations go, drawn in a document of
 * happy-dom against a stand-in CSMS: the addresses and the requests as the
 * CSMS says them, an API key never sent where nothing was typed, an address
 * emptied sent as none - and no form for an account that may not change it.
 */

import { asked, field, open, submit, until, type Asked } from '../../test/csms.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { CertificateSigning } from '../api/client.ts';

const { certificateSigningPage } = await import('./certificateSigning.ts');


let held: CertificateSigning;

function csms({ method, path, body }: Asked): unknown {

    if (path === '/configuration/certificate-signing' && method === 'GET')
        return held;

    if (path === '/configuration/certificate-signing' && method === 'PUT') {
        const update = body as Record<string, string | null>;
        held = { ...held,
                 chargingStationCertificate:  'chargingStationCertificate' in update ? update['chargingStationCertificate']! : held.chargingStationCertificate,
                 v2gCertificate:              'v2gCertificate'             in update ? update['v2gCertificate']!             : held.v2gCertificate,
                 apiKey:                      'apiKey'                     in update ? update['apiKey'] !== null              : held.apiKey };
        return held;
    }

    return undefined;

}

function aCSMS(): CertificateSigning {
    return {
        chargingStationCertificate:  'https://pki.example.org/.well-known/est/stations',
        v2gCertificate:              null,
        apiKey:                      true,
        requests:                    [ { at: '2026-11-09T10:00:00Z', station: 'cs001', certificateType: 'ChargingStationCertificate', outcome: 'signed',
                                         detail: null, certificate: 'ab'.repeat(32), notAfter: '2027-11-09T10:00:00Z' },
                                       { at: '2026-11-09T09:00:00Z', station: 'cs002', certificateType: 'ChargingStationCertificate', outcome: 'rejected',
                                         detail: "The CSR is for 'cs001', and the certificate of a charging station names the station itself: 'cs002'.",
                                         certificate: null, notAfter: null } ]
    };
}


describe('the certificate signing page', () => {

    it('shows where the CSRs go and what became of them, and keeps the API key nobody typed', async () => {

        held = aCSMS();

        const root = await open(certificateSigningPage, '/configuration/ocpp-server/signing', [ 'stations:read', 'certificates:read', 'certificates:edit' ],
                                csms, root => root.querySelector('#signing-form') !== null);

        assert.equal(field(root, '#signing-form', 'chargingStationCertificate').value, 'https://pki.example.org/.well-known/est/stations');
        assert.equal(field(root, '#signing-form', 'apiKey').value, '', 'the key is never shown');
        assert.match(field(root, '#signing-form', 'apiKey').placeholder, /kept/);
        assert.match(root.querySelector('tr[data-station="cs001"]')!.textContent!, /signed/);
        assert.match(root.querySelector('tr[data-station="cs002"]')!.textContent!, /rejected.*names the station itself/s);

        field(root, '#signing-form', 'v2gCertificate').value              = 'https://pki.example.org/.well-known/est/secc';
        field(root, '#signing-form', 'chargingStationCertificate').value  = '';

        submit(root, '#signing-form');

        await until(() => asked.some(one => one.method === 'PUT'), 'nothing was saved');

        const sent = asked.find(one => one.method === 'PUT')!.body as Record<string, unknown>;

        assert.deepEqual(sent, { chargingStationCertificate: null, v2gCertificate: 'https://pki.example.org/.well-known/est/secc' },
                         'no API key where none was typed');

        await until(() => /Saved/.test(root.querySelector('#signing-note')?.textContent ?? ''), 'it did not say it saved');

    });

    it('has no form to save for an account that may only read', async () => {

        held = aCSMS();

        const root = await open(certificateSigningPage, '/configuration/ocpp-server/signing', [ 'stations:read' ],
                                csms, root => root.querySelector('#signing-form') !== null);

        assert.equal(root.querySelector('#signing-form button[type="submit"]'), null);
        assert.ok(field(root, '#signing-form', 'chargingStationCertificate').disabled);

    });

});
