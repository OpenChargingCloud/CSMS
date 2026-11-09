import { api, type CertificateSigning, type CertificateSigningUpdate, type StationCertificate } from '../api/client';
import { auth } from '../auth';
import type { Page } from '@node/router';
import { mayButNot, reloadButton, shell } from '@node/shell';
import { errorMessage, field, formatTimestamp, isChecked, numberField } from '@node/ui';
import { anyFormTypedSinceDrawn, unsaved } from '@node/unsaved';
import { html, nothing, render, type TemplateResult } from '@node/view';

/**
 * Where the CSRs of the charging stations go: a station's SignCertificate
 * request - its own certificate, or its SECC certificate of ISO 15118 - is
 * sent on to the EST server of a PKI, and the certificate that comes back is
 * handed to the station with CertificateSigned.
 *
 * And the certificates the stations have, as the CSMS knows of them: each is
 * renewed the days configured before it runs out - the station asked with
 * TriggerMessage for a new one - or by hand, at once.
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
            subtitle:  'Where the CSRs of the charging stations go, and the certificates they have.',
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

        function renewalCell(certificate: StationCertificate): TemplateResult | string {
            if (!certificate.renewalAsked)
                return '';
            return html`${formatTimestamp(certificate.renewalAsked)}
                        <span class="chip ${certificate.renewalAnswer === 'Accepted' ? 'ok' : 'warn'}">${certificate.renewalAnswer ?? '?'}</span>`;
        }

        function certificateRow(certificate: StationCertificate): TemplateResult {
            return html`
                <tr data-station="${certificate.station}" data-type="${certificate.certificateType}">
                    ${mayChange ? html`
                        <td><button type="button" class="btn small certificate-renew" ?disabled=${!certificate.connected}
                                    title=${certificate.connected ? nothing : 'The station is not connected'}
                                    @click=${() => void renew(certificate.station, certificate.certificateType)}>Renew now</button></td>` : nothing}
                    <td>${certificate.station}${certificate.connected ? html` <span class="chip ok">connected</span>` : nothing}</td>
                    <td>${certificate.certificateType}</td>
                    <td>${formatTimestamp(certificate.notAfter)}${certificate.due ? html` <span class="chip warn">due</span>` : nothing}</td>
                    <td>${certificate.source === 'signed' ? 'signed here' : 'signed in with'}
                        <code title=${certificate.fingerprint}>${certificate.fingerprint.slice(0, 16)}...</code></td>
                    <td>${renewalCell(certificate)}</td>
                </tr>`;
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

                            <label>Renew days before they run out
                                <input type="number" name="renewDaysBefore" min="0" max="365" step="1" required
                                       .defaultValue=${String(signing.renewDaysBefore)} ?disabled=${!mayChange} />
                            </label>
                            <span class="hint">
                                A station whose certificate runs out within these days is asked for a new one - after it
                                starts, and once a day while it stays connected. 0 for never.
                            </span>

                            ${mayChange ? html`
                                <div class="form-actions">
                                    <button type="submit" class="btn primary">Save</button>
                                    <span id="signing-note"  class="form-notice" role="status"></span>
                                    <span id="signing-error" class="form-error"  role="alert"></span>
                                </div>` : nothing}

                        </form>

                    </section>

                    <section class="card wide" id="station-certificates">

                        <h2><i class="fa-solid fa-certificate"></i> The stations' certificates</h2>

                        ${signing.certificates.length === 0 ? html`<p class="hint">
                            No certificate of a charging station is known yet: they are, once one is signed here or a station
                            signs in with its own.</p>` : html`
                            <div class="table-scroll">
                                <table class="records">
                                    <thead><tr>${mayChange ? html`<th></th>` : nothing}<th>Station</th><th>Certificate</th><th>Until</th><th>Known as</th><th>Last asked to renew</th></tr></thead>
                                    <tbody>
                                        ${signing.certificates.map(certificateRow)}
                                    </tbody>
                                </table>
                            </div>`}

                        ${mayChange ? html`
                            <form id="renew-form" class="form-row" @submit=${renewAsked}>
                                <label>Station
                                    <input type="text" name="station" placeholder="cs001" required maxlength="255" />
                                </label>
                                <label>Certificate
                                    <select name="certificateType">
                                        <option value="ChargingStationCertificate">Charging station certificate</option>
                                        <option value="V2GCertificate">V2G certificate</option>
                                    </select>
                                </label>
                                <button type="submit" class="btn">Ask for a new one</button>
                            </form>
                            <span class="hint">Any connected station, whatever is due - its first certificate, for one that signs in with a password.</span>` : nothing}

                        <p>
                            <span id="renew-note"  class="form-notice" role="status"></span>
                            <span id="renew-error" class="form-error"  role="alert"></span>
                        </p>

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
            const days    = numberField(form, 'renewDaysBefore');

            const update: CertificateSigningUpdate = {
                chargingStationCertificate:  station.length > 0 ? station : null,
                v2gCertificate:              v2g.length     > 0 ? v2g     : null,
                // Emptied: the default, as null says.
                renewDaysBefore:             Number.isNaN(days) ? null : days,
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

        async function renewAsked(event: SubmitEvent): Promise<void> {

            event.preventDefault();

            const form = event.currentTarget as HTMLFormElement;

            await renew(field(form, 'station'), field(form, 'certificateType'), form);

        }

        /**
         * Ask a station for a new certificate now, and say what it answered;
         * the page drawn again, so that the answer shows in the table too.
         */
        async function renew(station: string, certificateType: string, form?: HTMLFormElement): Promise<void> {

            const note  = content.querySelector<HTMLElement>('#renew-note');
            const error = content.querySelector<HTMLElement>('#renew-error');

            if (note)   note.textContent  = `Asking '${station}' ...`;
            if (error)  error.textContent = '';

            try
            {

                const renewal = await api.certificateSigning.renew(station, certificateType);
                if (cancelled)
                    return;

                const said = renewal.answer === 'Accepted'
                                 ? `'${station}' is about to send its CSR.`
                                 : renewal.detail ?? `'${station}' answered ${renewal.answer}.`;

                form?.reset();

                const loaded = await api.certificateSigning.get();
                if (cancelled)
                    return;

                held = loaded;
                draw();

                const done = content.querySelector<HTMLElement>('#renew-note');
                if (done)
                    done.textContent = said;

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
