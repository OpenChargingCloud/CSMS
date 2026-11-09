import { api, type CertificateSigning, type CertificateSigningUpdate } from '../api/client';
import { auth } from '../auth';
import type { Page } from '@node/router';
import { mayButNot, reloadButton, shell } from '@node/shell';
import { errorMessage, field, formatTimestamp, isChecked } from '@node/ui';
import { anyFormTypedSinceDrawn, unsaved } from '@node/unsaved';
import { html, nothing, render, type TemplateResult } from '@node/view';

/**
 * Where the CSRs of the charging stations go: a station's SignCertificate
 * request - its own certificate, or its SECC certificate of ISO 15118 - is
 * sent on to the EST server of a PKI, and the certificate that comes back is
 * handed to the station with CertificateSigned.
 *
 * Read at the stations' permission, changed at the certificates': where the
 * CSRs go is who signs the certificates the stations sign in with. The API
 * key is never shown again, only whether there is one.
 */
export const certificateSigningPage: Page = {

    title: 'Certificate signing',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/ocpp-server/signing',
            title:     'Certificate signing',
            subtitle:  'Where the CSRs of the charging stations go, and what became of them.',
            actions:   reloadButton(() => load())
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        const mayChange  = auth.can('certificates', 'edit');
        let   held: CertificateSigning | null = null;
        let   cancelled  = false;

        function outcomeChip(outcome: string): TemplateResult {
            switch (outcome) {
                case 'signed':    return html`<span class="chip ok">signed</span>`;
                case 'signing':   return html`<span class="chip">at the PKI</span>`;
                case 'rejected':  return html`<span class="chip warn">rejected</span>`;
                case 'notTaken':  return html`<span class="chip warn">not taken</span>`;
                default:          return html`<span class="chip warn">not signed</span>`;
            }
        }

        function draw(): void {

            const signing = held!;

            render(content, html`

                <div class="cards">

                    <section class="card">

                        <h2><i class="fa-solid fa-file-signature"></i> The EST server of the PKI</h2>

                        ${mayChange ? nothing : html`<p class="hint">${mayButNot('look at where the CSRs go', 'change it')}</p>`}

                        <form id="signing-form" class="form-stack" @submit=${save}>

                            <label>Charging station certificates
                                <input type="url" name="chargingStationCertificate" placeholder="https://pki.example.org/.well-known/est/stations"
                                       .defaultValue=${signing.chargingStationCertificate ?? ''} ?disabled=${!mayChange} />
                            </label>
                            <span class="hint">
                                A station's own certificate, which it signs in with at security profile 3. Its common name
                                is the station's identity: a CSR for any other is refused here.
                            </span>

                            <label>V2G certificates
                                <input type="url" name="v2gCertificate" placeholder="https://pki.example.org/.well-known/est/secc"
                                       .defaultValue=${signing.v2gCertificate ?? ''} ?disabled=${!mayChange} />
                            </label>
                            <span class="hint">
                                The SECC certificate of ISO 15118-2, at the label of the CPO sub-CA of the PKI. Empty for
                                none: the station is told this CSMS signs none.
                            </span>

                            <label>API key
                                <input type="password" name="apiKey" autocomplete="new-password"
                                       placeholder=${signing.apiKey ? 'kept - type a new one to replace it' : 'none'} ?disabled=${!mayChange} />
                            </label>
                            ${signing.apiKey && mayChange ? html`
                                <label class="checkbox">
                                    <input type="checkbox" name="removeAPIKey" /> Remove the API key
                                </label>` : nothing}
                            <span class="hint">
                                Of an account of the PKI in its <code>registrar</code> role. It goes over HTTPS only, or to
                                the loopback address, and is not shown again.
                            </span>

                            ${mayChange ? html`
                                <div class="form-actions">
                                    <button type="submit" class="btn primary">Save</button>
                                    <span id="signing-note"  class="form-notice" role="status"></span>
                                    <span id="signing-error" class="form-error"  role="alert"></span>
                                </div>` : nothing}

                        </form>

                    </section>

                    <section class="card wide" id="signing-requests">

                        <h2><i class="fa-solid fa-list-check"></i> The latest requests</h2>

                        ${signing.requests.length === 0 ? html`<p class="hint">No charging station has asked for a certificate since the start.</p>` : html`
                            <div class="table-scroll">
                                <table class="records">
                                    <thead><tr><th>When</th><th>Station</th><th>Certificate</th><th>Outcome</th><th>Until</th><th></th></tr></thead>
                                    <tbody>
                                        ${signing.requests.map(entry => html`
                                            <tr data-station="${entry.station}">
                                                <td>${formatTimestamp(entry.at)}</td>
                                                <td>${entry.station}</td>
                                                <td>${entry.certificateType}</td>
                                                <td>${outcomeChip(entry.outcome)}</td>
                                                <td>${entry.notAfter ? formatTimestamp(entry.notAfter) : ''}</td>
                                                <td>${entry.detail ?? (entry.certificate ? html`<code title=${entry.certificate}>${entry.certificate.slice(0, 16)}...</code>` : '')}</td>
                                            </tr>
                                        `)}
                                    </tbody>
                                </table>
                            </div>`}

                    </section>

                </div>

            `);

        }

        async function save(event: SubmitEvent): Promise<void> {

            event.preventDefault();

            const form    = event.currentTarget as HTMLFormElement;
            const note    = content.querySelector<HTMLElement>('#signing-note');
            const error   = content.querySelector<HTMLElement>('#signing-error');

            const station = field(form, 'chargingStationCertificate', false).trim();
            const v2g     = field(form, 'v2gCertificate', false).trim();
            const apiKey  = field(form, 'apiKey', false).trim();
            const remove  = form.querySelector('[name="removeAPIKey"]') !== null && isChecked(form, 'removeAPIKey');

            const update: CertificateSigningUpdate = {
                chargingStationCertificate:  station.length > 0 ? station : null,
                v2gCertificate:              v2g.length     > 0 ? v2g     : null,
                ...(apiKey.length > 0 ? { apiKey } : remove ? { apiKey: null } : {})
            };

            if (note)   note.textContent  = 'Saving ...';
            if (error)  error.textContent = '';

            try
            {
                held = await api.certificateSigning.save(update);
                if (cancelled)
                    return;
                draw();
                form.reset();
                const saved = content.querySelector<HTMLElement>('#signing-note');
                if (saved)
                    saved.textContent = 'Saved.';
            }
            catch (problem)
            {
                if (cancelled)
                    return;
                if (note)   note.textContent  = '';
                if (error)  error.textContent = errorMessage(problem);
            }

        }

        async function load(): Promise<void> {

            try
            {
                const loaded = await api.certificateSigning.get();
                if (cancelled)
                    return;
                held = loaded;
                draw();
            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`<div class="error-box">Where the CSRs go could not be loaded: ${errorMessage(problem)}</div>`);
            }

        }

        // An address or a key typed and not yet saved is work like any other.
        const release = unsaved.heldBy(() => anyFormTypedSinceDrawn(content));

        void load();

        return () => { cancelled = true; release(); };

    }

};
