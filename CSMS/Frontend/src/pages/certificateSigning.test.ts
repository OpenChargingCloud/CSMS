/**
 * Where the CSRs of the charging stations go, drawn in a document of
 * happy-dom against a stand-in CSMS: the addresses and the requests as the
 * CSMS says them, an API key never sent where nothing was typed, an address
 * emptied sent as none - and no form for an account that may not change it.
 * And the certificates of the stations, renewed by hand, and forgotten; and
 * what the stations asked of the OCSP responder.
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
        const update = body as Record<string, string | number | null>;
        held = { ...held,
                 chargingStationCertificate:  'chargingStationCertificate' in update ? update['chargingStationCertificate'] as string | null : held.chargingStationCertificate,
                 v2gCertificate:              'v2gCertificate'             in update ? update['v2gCertificate']             as string | null : held.v2gCertificate,
                 apiKey:                      'apiKey'                     in update ? update['apiKey'] !== null                            : held.apiKey,
                 renewDaysBefore:             'renewDaysBefore'            in update ? update['renewDaysBefore']            as number        : held.renewDaysBefore,
                 ocspResponders:              'ocspResponders'             in update ? update['ocspResponders'] as unknown  as string[]      : held.ocspResponders };
        return held;
    }

    if (path === '/configuration/certificate-signing/renew' && method === 'POST') {
        const { station, certificateType } = body as { station: string; certificateType: string };
        held = { ...held,
                 certificates: held.certificates.map(one => one.station === station && one.certificateType === certificateType
                                                              ? { ...one, renewalAsked: '2026-11-09T11:00:00Z', renewalAnswer: 'Accepted' }
                                                              : one) };
        return { answer: 'Accepted', detail: null };
    }

    const forgotten = /^\/configuration\/certificate-signing\/certificates\/([^/]+)\/([^/]+)$/.exec(path);
    if (forgotten && method === 'DELETE') {
        held = { ...held,
                 certificates: held.certificates.filter(one => !(one.station === decodeURIComponent(forgotten[1]!) &&
                                                                 one.certificateType === decodeURIComponent(forgotten[2]!))) };
        return held;
    }

    return undefined;

}

function aCSMS(): CertificateSigning {
    return {
        chargingStationCertificate:  'https://pki.example.org/.well-known/est/stations',
        v2gCertificate:              null,
        apiKey:                      true,
        renewDaysBefore:             30,
        ocspResponders:              [],
        certificates:                [ { station: 'cs001', certificateType: 'ChargingStationCertificate', fingerprint: 'ab'.repeat(32), notAfter: '2026-11-20T10:00:00Z',
                                         notBefore: '2025-11-20T10:00:00Z', renewsFrom: '2026-10-21T10:00:00Z', halfway: false,
                                         source: 'signed', noted: '2025-11-20T10:00:00Z', renewalAsked: null, renewalAnswer: null, due: true, connected: true },
                                       { station: 'cs003', certificateType: 'ChargingStationCertificate', fingerprint: 'cd'.repeat(32), notAfter: '2026-12-09T10:00:00Z',
                                         notBefore: '2026-11-09T09:00:00Z', renewsFrom: '2026-11-24T09:30:00Z', halfway: true,
                                         source: 'presented', noted: '2026-11-09T09:00:00Z', renewalAsked: null, renewalAnswer: null, due: false, connected: false } ],
        requests:                    [ { at: '2026-11-09T10:00:00Z', station: 'cs001', certificateType: 'ChargingStationCertificate', outcome: 'signed',
                                         detail: null, certificate: 'ab'.repeat(32), notAfter: '2027-11-09T10:00:00Z' },
                                       { at: '2026-11-09T09:00:00Z', station: 'cs002', certificateType: 'ChargingStationCertificate', outcome: 'rejected',
                                         detail: "The CSR is for 'cs001', and the certificate of a charging station names the station itself: 'cs002'.",
                                         certificate: null, notAfter: null } ],
        statusRequests:              [ { at: '2026-11-09T12:00:00Z', station: 'cs001', serialNumber: '1a2b3c', responder: 'http://pki.example.org/api/v1/pki/ocsp',
                                         outcome: 'revoked', detail: null, nextUpdate: '2026-11-10T12:00:00Z' },
                                       { at: '2026-11-09T11:00:00Z', station: 'cs002', serialNumber: '4d5e', responder: 'http://evil.example.com/',
                                         outcome: 'refused', detail: "'http://evil.example.com/' is no OCSP responder this CSMS asks.", nextUpdate: null } ]
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
        assert.match(root.querySelector('#signing-requests tr[data-station="cs001"]')!.textContent!, /signed/);
        assert.match(root.querySelector('#signing-requests tr[data-station="cs002"]')!.textContent!, /rejected.*names the station itself/s);

        field(root, '#signing-form', 'v2gCertificate').value              = 'https://pki.example.org/.well-known/est/secc';
        field(root, '#signing-form', 'chargingStationCertificate').value  = '';

        submit(root, '#signing-form');

        await until(() => asked.some(one => one.method === 'PUT'), 'nothing was saved');

        const sent = asked.find(one => one.method === 'PUT')!.body as Record<string, unknown>;

        assert.deepEqual(sent, { chargingStationCertificate: null, v2gCertificate: 'https://pki.example.org/.well-known/est/secc', renewDaysBefore: 30, ocspResponders: [] },
                         'no API key where none was typed');

        await until(() => /Saved/.test(root.querySelector('#signing-note')?.textContent ?? ''), 'it did not say it saved');

    });

    it('asks a connected station for a new certificate, and not one that is away', async () => {

        held = aCSMS();

        const root = await open(certificateSigningPage, '/configuration/ocpp-server/signing', [ 'stations:read', 'certificates:read', 'certificates:edit' ],
                                csms, root => root.querySelector('#station-certificates tr[data-station="cs001"]') !== null);

        const due  = root.querySelector('#station-certificates tr[data-station="cs001"]')!;
        const away = root.querySelector('#station-certificates tr[data-station="cs003"]')!;

        assert.match(due.textContent!,  /due/);
        assert.match(away.textContent!, /signed in with/);
        assert.ok(away.querySelector<HTMLButtonElement>('.certificate-renew')!.disabled, 'a station that is not connected cannot be asked');

        due.querySelector<HTMLButtonElement>('.certificate-renew')!.click();

        await until(() => asked.some(one => one.method === 'POST'), 'nothing was asked');

        assert.deepEqual(asked.find(one => one.method === 'POST')!.body, { station: 'cs001', certificateType: 'ChargingStationCertificate' });

        await until(() => /about to send its CSR/.test(root.querySelector('#renew-note')?.textContent ?? ''), 'it did not say what the station answered');

        assert.match(root.querySelector('#station-certificates tr[data-station="cs001"]')!.textContent!, /Accepted/);

    });

    it('shows what the stations asked of the OCSP responder, and sends the responders named one per line', async () => {

        held = aCSMS();

        const root = await open(certificateSigningPage, '/configuration/ocpp-server/signing', [ 'stations:read', 'certificates:read', 'certificates:edit' ],
                                csms, root => root.querySelector('#status-requests tr[data-serial="1a2b3c"]') !== null);

        assert.match(root.querySelector('#status-requests tr[data-serial="1a2b3c"]')!.textContent!, /revoked/);
        assert.match(root.querySelector('#status-requests tr[data-serial="4d5e"]')!.textContent!,   /not sent on.*no OCSP responder/s);

        const responders = root.querySelector<HTMLTextAreaElement>('#signing-form textarea[name="ocspResponders"]')!;
        responders.value = '  http://ocsp.example.com/ \n\n http://ocsp.example.net/a  ';

        submit(root, '#signing-form');

        await until(() => asked.some(one => one.method === 'PUT'), 'nothing was saved');

        assert.deepEqual((asked.find(one => one.method === 'PUT')!.body as Record<string, unknown>)['ocspResponders'],
                         [ 'http://ocsp.example.com/', 'http://ocsp.example.net/a' ]);

        await until(() => root.querySelector<HTMLTextAreaElement>('#signing-form textarea[name="ocspResponders"]')!.value ===
                          'http://ocsp.example.com/\nhttp://ocsp.example.net/a', 'the responders saved are not shown');

    });

    it('says from when a certificate is renewed, and halfway where it holds too short for the days configured', async () => {

        held = aCSMS();

        const root = await open(certificateSigningPage, '/configuration/ocpp-server/signing', [ 'stations:read' ],
                                csms, root => root.querySelector('#station-certificates tr[data-station="cs001"]') !== null);

        const year  = root.querySelector('#station-certificates tr[data-station="cs001"]')!;
        const month = root.querySelector('#station-certificates tr[data-station="cs003"]')!;

        assert.match(year.querySelector('.renews-from')!.textContent!, /renewed from/);
        assert.doesNotMatch(year.textContent!, /halfway/);
        assert.match(month.querySelector('.renews-from')!.textContent!, /halfway/);

    });

    it('forgets a certificate once it was asked whether to', async () => {

        held = aCSMS();

        const root = await open(certificateSigningPage, '/configuration/ocpp-server/signing', [ 'stations:read', 'certificates:read', 'certificates:edit' ],
                                csms, root => root.querySelector('#station-certificates tr[data-station="cs003"]') !== null);

        const said = [] as string[];
        const yes  = window.confirm;

        try
        {

            window.confirm = (text?: string) => { said.push(String(text)); return false; };
            root.querySelector<HTMLButtonElement>('#station-certificates tr[data-station="cs003"] .certificate-forget')!.click();

            assert.match(said[0] ?? '', /Forget the ChargingStationCertificate of 'cs003'/);
            assert.ok(!asked.some(one => one.method === 'DELETE'), 'forgotten although it was not to be');

            window.confirm = () => true;
            root.querySelector<HTMLButtonElement>('#station-certificates tr[data-station="cs003"] .certificate-forget')!.click();

            await until(() => /is forgotten/.test(root.querySelector('#renew-note')?.textContent ?? ''), 'it did not say it forgot');

        }
        finally
        {
            window.confirm = yes;
        }

        assert.equal(asked.find(one => one.method === 'DELETE')!.path, '/configuration/certificate-signing/certificates/cs003/ChargingStationCertificate');
        assert.equal(root.querySelector('#station-certificates tr[data-station="cs003"]'), null);
        assert.ok(root.querySelector('#station-certificates tr[data-station="cs001"]'));

    });

    it('has no form to save for an account that may only read', async () => {

        held = aCSMS();

        const root = await open(certificateSigningPage, '/configuration/ocpp-server/signing', [ 'stations:read' ],
                                csms, root => root.querySelector('#signing-form') !== null);

        assert.equal(root.querySelector('#signing-form button[type="submit"]'), null);
        assert.equal(root.querySelector('.certificate-renew'), null, 'no station is asked by an account that may only read');
        assert.equal(root.querySelector('.certificate-forget'), null);
        assert.equal(root.querySelector('#renew-form'), null);
        assert.ok(field(root, '#signing-form', 'chargingStationCertificate').disabled);

    });

});
