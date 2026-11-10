import { api, type InstalledCertificate, type StationRoot, type StationRoots } from '../api/client';
import { auth } from '../auth';
import type { Page } from '@node/router';
import { mayButNot, reloadButton, shell } from '@node/shell';
import { errorMessage, field, formatTimestamp, isChecked } from '@node/ui';
import { anyFormTypedSinceDrawn, unsaved } from '@node/unsaved';
import { html, live, nothing, render, repeat, type TemplateResult } from '@node/view';

/**
 * The root certificates of the charging stations: those this CSMS installs -
 * the root above its own TLS certificate, the V2G root of ISO 15118, the
 * roots of mobility operators and manufacturers - on one station, on every one
 * connected, or on every one that starts without it; and what a station has,
 * asked of it, with what is there deleted.
 *
 * Read at the stations' permission, changed at the certificates': what a
 * station trusts is whom it signs in to, and whom it lets sign it.
 */
export const stationRootsPage: Page = {

    title: 'Station roots',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/ocpp-server/roots',
            title:     'Station roots',
            subtitle:  'The root certificates the charging stations are installed, and what they have.',
            actions:   reloadButton(() => load())
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        const mayChange = auth.can('certificates', 'edit');

        let cancelled  = false;
        let held:      StationRoots | null = null;
        let looked:    { station: string; installed: InstalledCertificate[] } | null = null;


        function rootRow(root: StationRoot): TemplateResult {
            return html`
                <tr data-id="${root.id}" data-type="${root.certificateType}">
                    ${mayChange ? html`
                        <td>
                            <button type="button" class="btn small root-install" ?disabled=${held!.connected.length === 0}
                                    title=${held!.connected.length === 0 ? 'No station is connected' : nothing}
                                    @click=${() => void install(root, null)}>Install on all connected</button>
                            <button type="button" class="btn small danger root-remove"
                                    @click=${() => void remove(root)}>Remove</button>
                        </td>` : nothing}
                    <td>${root.certificateType}</td>
                    <td>
                        <label class="switch small">
                            <input type="checkbox" class="root-everywhere" .checked=${live(root.everywhere)} ?disabled=${!mayChange}
                                   @change=${(event: Event) => void setEverywhere(root, (event.target as HTMLInputElement).checked)} />
                            <span>${root.everywhere ? 'every station' : 'by hand'}</span>
                        </label>
                    </td>
                    <td>${formatTimestamp(root.notAfter)}</td>
                    <td>${root.subject}</td>
                    <td><code title=${root.id}>${root.id.slice(0, 16)}...</code></td>
                </tr>`;
        }

        function installedRow(station: string, certificate: InstalledCertificate): TemplateResult {
            return html`
                <tr data-serial="${certificate.serialNumber}" data-type="${certificate.certificateType}">
                    ${mayChange ? html`
                        <td><button type="button" class="btn small danger installed-delete"
                                    @click=${() => void deleteFrom(station, certificate)}>Delete</button></td>` : nothing}
                    <td>${certificate.certificateType}</td>
                    <td>${certificate.subject ?? html`<span class="muted">none of the roots here</span>`}</td>
                    <td><code>${certificate.serialNumber}</code></td>
                    <td>${certificate.children > 0 ? `${certificate.children} below it` : ''}</td>
                </tr>`;
        }


        function draw(): void {

            const roots = held!;

            render(content, html`

                ${mayChange ? nothing : html`<div class="notice">${mayButNot('look at the roots of the stations', 'install or delete one')}</div>`}

                <div class="cards">

                    <section class="card wide" id="roots">

                        <h2><i class="fa-solid fa-anchor"></i> The roots for the stations</h2>

                        ${roots.roots.length === 0 ? html`<p class="hint">No root is kept for the stations yet.</p>` : html`
                            <div class="table-scroll">
                                <table class="records">
                                    <thead><tr>${mayChange ? html`<th></th>` : nothing}<th>Kind</th><th>Installed</th><th>Until</th><th>Subject</th><th>Fingerprint</th></tr></thead>
                                    <tbody>${repeat(roots.roots, root => `${root.certificateType}/${root.id}`, rootRow)}</tbody>
                                </table>
                            </div>`}

                        <p class="hint">
                            A root for every station is installed on a station that starts without it - the new root of a
                            rollover is on the stations before the first certificate below it is. Removed here, a root stays
                            on the stations that have it, until it is deleted there.
                            ${roots.connected.length} station(s) connected.
                        </p>

                        <p>
                            <span id="roots-note"  class="form-notice" role="status"></span>
                            <span id="roots-error" class="form-error"  role="alert"></span>
                        </p>

                    </section>

                    ${mayChange ? html`
                        <section class="card">

                            <h2><i class="fa-solid fa-plus"></i> Add a root</h2>

                            <form id="root-form" class="form-stack" @submit=${add}>

                                <label>Kind
                                    <select name="certificateType">
                                        ${roots.certificateTypes.map(type => html`<option value="${type}">${type}</option>`)}
                                    </select>
                                </label>

                                <label>The root certificate
                                    <textarea name="pem" rows="6" placeholder="-----BEGIN CERTIFICATE-----&#10;..." required></textarea>
                                </label>

                                <label class="checkbox">
                                    <input type="checkbox" name="everywhere" /> Every station is to have it
                                </label>

                                <div class="form-actions">
                                    <button type="submit" class="btn primary">Add it</button>
                                    <button type="button" class="btn" id="from-pki" @click=${() => void fromPKI()}>Take the roots of the PKI</button>
                                    <span id="add-error" class="form-error" role="alert"></span>
                                </div>

                                <span class="hint">
                                    A CA that signed itself. The roots of the PKI are those its EST servers name: the one above
                                    the V2G certificates as the V2G root, the one above this CSMS's TLS certificate as its root.
                                </span>

                            </form>

                        </section>` : nothing}

                    <section class="card wide" id="station">

                        <h2><i class="fa-solid fa-charging-station"></i> What a station has</h2>

                        <form id="look-form" class="form-row" @submit=${lookAsked}>
                            <label>Station
                                <input type="text" name="station" list="connected-stations" placeholder="cs001" required maxlength="255"
                                       .value=${live(looked?.station ?? '')} />
                                <datalist id="connected-stations">${roots.connected.map(station => html`<option value="${station}"></option>`)}</datalist>
                            </label>
                            <button type="submit" class="btn">Ask it</button>
                            ${mayChange && looked !== null && roots.roots.length > 0 ? html`
                                <label>Root
                                    <select name="root" id="install-root">
                                        ${roots.roots.map(root => html`<option value="${root.certificateType}/${root.id}">${root.certificateType}: ${root.subject}</option>`)}
                                    </select>
                                </label>
                                <button type="button" class="btn" id="install-one" @click=${installOne}>Install it there</button>` : nothing}
                        </form>

                        <p>
                            <span id="station-note"  class="form-notice" role="status"></span>
                            <span id="station-error" class="form-error"  role="alert"></span>
                        </p>

                        ${looked === null ? nothing : looked.installed.length === 0 ? html`<p class="hint">'${looked.station}' has no certificate installed.</p>` : html`
                            <div class="table-scroll">
                                <table class="records" id="installed">
                                    <thead><tr>${mayChange ? html`<th></th>` : nothing}<th>Kind</th><th>Root</th><th>Serial number</th><th></th></tr></thead>
                                    <tbody>${looked.installed.map(certificate => installedRow(looked!.station, certificate))}</tbody>
                                </table>
                            </div>`}

                    </section>

                    <section class="card wide" id="changes">

                        <h2><i class="fa-solid fa-list-check"></i> The latest changes on the stations</h2>

                        ${roots.changes.length === 0 ? html`<p class="hint">No root was installed and no certificate deleted since the start.</p>` : html`
                            <div class="table-scroll">
                                <table class="records">
                                    <thead><tr><th>When</th><th>Station</th><th>What</th><th>Answer</th><th>Kind</th><th>Certificate</th><th></th></tr></thead>
                                    <tbody>
                                        ${roots.changes.map(change => html`
                                            <tr data-station="${change.station}">
                                                <td>${formatTimestamp(change.at)}</td>
                                                <td>${change.station}</td>
                                                <td>${change.action === 'install' ? (change.automatic ? 'installed, for every station' : 'installed') : 'deleted'}</td>
                                                <td><span class="chip ${change.answer === 'Accepted' ? 'ok' : 'warn'}">${change.answer}</span></td>
                                                <td>${change.certificateType}</td>
                                                <td>${change.certificate}</td>
                                                <td>${change.detail ?? ''}</td>
                                            </tr>`)}
                                    </tbody>
                                </table>
                            </div>`}

                    </section>

                </div>

            `);

        }


        function say(note: string, problem = ''): void {
            const noted  = content.querySelector<HTMLElement>('#roots-note');
            const error  = content.querySelector<HTMLElement>('#roots-error');
            if (noted)  noted.textContent = note;
            if (error)  error.textContent = problem;
        }

        function sayAtStation(note: string, problem = ''): void {
            const noted  = content.querySelector<HTMLElement>('#station-note');
            const error  = content.querySelector<HTMLElement>('#station-error');
            if (noted)  noted.textContent = note;
            if (error)  error.textContent = problem;
        }


        async function add(event: SubmitEvent): Promise<void> {

            event.preventDefault();

            const form  = event.currentTarget as HTMLFormElement;
            const error = content.querySelector<HTMLElement>('#add-error');

            if (error)  error.textContent = '';

            try
            {
                held = await api.stationRoots.add(field(form, 'pem', false), field(form, 'certificateType'), isChecked(form, 'everywhere'));
                if (cancelled)
                    return;
                form.reset();
                draw();
                say('Added.');
            }
            catch (problem)
            {
                if (!cancelled && error)
                    error.textContent = errorMessage(problem);
            }

        }

        async function fromPKI(): Promise<void> {

            const error = content.querySelector<HTMLElement>('#add-error');
            if (error)  error.textContent = '';

            try
            {

                const taken = await api.stationRoots.fromPKI();
                if (cancelled)
                    return;

                held = taken;
                draw();

                say(taken.added.length === 0
                        ? 'The PKI names no root that is not here already.'
                        : `Taken from the PKI: ${taken.added.map(root => `${root.subject} as ${root.certificateType}`).join(', ')}.`,
                    taken.problems.join(' '));

            }
            catch (problem)
            {
                if (!cancelled && error)
                    error.textContent = errorMessage(problem);
            }

        }

        async function setEverywhere(root: StationRoot, everywhere: boolean): Promise<void> {

            try
            {
                held = await api.stationRoots.setEverywhere(root, everywhere);
                if (!cancelled)
                    draw();
            }
            catch (problem)
            {
                if (!cancelled)
                {
                    draw();
                    say('', errorMessage(problem));
                }
            }

        }

        async function remove(root: StationRoot): Promise<void> {

            if (!window.confirm(`Remove the ${root.certificateType} '${root.subject}'?\n\nIt is not installed on any station any more; the stations that have it keep it, until it is deleted there.`))
                return;

            try
            {
                held = await api.stationRoots.remove(root);
                if (!cancelled)
                {
                    draw();
                    say('Removed.');
                }
            }
            catch (problem)
            {
                if (!cancelled)
                    say('', errorMessage(problem));
            }

        }

        /**
         * Install a root on one station, or on every one connected; what each
         * answered said, and what the station has looked at again.
         */
        async function install(root: StationRoot, station: string | null): Promise<void> {

            const speak = station === null ? say : sayAtStation;

            speak(station === null ? `Installing '${root.subject}' on every connected station ...` : `Installing '${root.subject}' on '${station}' ...`);

            try
            {

                const done = await api.stationRoots.install(root, station);
                if (cancelled)
                    return;

                held = done;
                draw();

                const refused = done.results.filter(result => result.answer !== 'Accepted');

                speak(`Accepted by ${done.results.length - refused.length} of ${done.results.length}.`,
                      refused.map(result => result.detail ?? `'${result.station}' answered ${result.answer}.`).join(' '));

                if (station !== null)
                    await look(station);

            }
            catch (problem)
            {
                if (!cancelled)
                    speak('', errorMessage(problem));
            }

        }

        function installOne(): void {

            const chosen = content.querySelector<HTMLSelectElement>('#install-root')?.value ?? '';
            const root   = held?.roots.find(one => `${one.certificateType}/${one.id}` === chosen);

            if (root && looked)
                void install(root, looked.station);

        }

        function lookAsked(event: SubmitEvent): void {
            event.preventDefault();
            void look(field(event.currentTarget as HTMLFormElement, 'station'));
        }

        async function look(station: string): Promise<void> {

            sayAtStation(`Asking '${station}' ...`);

            try
            {

                const answer = await api.stationRoots.installedOn(station);
                if (cancelled)
                    return;

                looked = answer;
                draw();
                sayAtStation('');

            }
            catch (problem)
            {
                if (!cancelled)
                    sayAtStation('', errorMessage(problem));
            }

        }

        async function deleteFrom(station: string, certificate: InstalledCertificate): Promise<void> {

            if (!window.confirm(`Delete the ${certificate.certificateType} ${certificate.serialNumber}${certificate.subject ? ` (${certificate.subject})` : ''} from '${station}'?\n\n` +
                                'A station that no longer has the root of this CSMS cannot sign in to it with TLS.'))
                return;

            try
            {

                const answer = await api.stationRoots.deleteFrom(station, certificate);
                if (cancelled)
                    return;

                held = await api.stationRoots.get();
                if (cancelled)
                    return;

                await look(station);

                sayAtStation(answer.answer === 'Accepted' ? `Deleted from '${station}'.` : '', answer.detail ?? '');

            }
            catch (problem)
            {
                if (!cancelled)
                    sayAtStation('', errorMessage(problem));
            }

        }


        async function load(): Promise<void> {

            try
            {
                const loaded = await api.stationRoots.get();
                if (cancelled)
                    return;
                held = loaded;
                draw();
            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`<div class="error-box">The roots of the stations could not be loaded: ${errorMessage(problem)}</div>`);
            }

        }

        // A root pasted and not yet added is work like any other.
        const release = unsaved.heldBy(() => anyFormTypedSinceDrawn(content));

        void load();

        return () => { cancelled = true; release(); };

    }

};
