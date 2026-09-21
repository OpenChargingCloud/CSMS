import { api, type Location, type Locations, type LocationSpec } from '../api/client';
import { auth } from '../auth';
import { html, must, render, type HTMLFragment } from '../html';
import type { Page } from '../router';
import { shell } from '../shell';
import { errorMessage, field, formatTimestamp } from '../ui';

/**
 * The charging locations this operator publishes: where its stations stand,
 * as the roaming partners are shown it.
 *
 * A location lives on one OCPI version, because the partners fetch them per
 * version - an EMSP on 2.2.1 reads this operator's 2.2.1 locations. A site
 * that should be found by partners on two versions has to be published on
 * both.
 *
 * What is asked for here is the least OCPI insists on: an address, a place on
 * the map and a time zone. The EVSEs below a location are what the charging
 * stations themselves bring, over OCPP, and are not typed in.
 */
export const locationsPage: Page = {

    title: 'Locations',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/ocpi/locations',
            title:     'Locations',
            subtitle:  'Where this operator has charging stations, as its partners are shown it.',
            actions:   html`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => void load());

        const mayManage = auth.can('manageLocations');

        let cancelled = false;
        let store: Locations | null = null;


        function draw(): void {

            if (store === null)
                return;

            const locations = store;

            render(content, html`

                ${mayManage ? '' : html`
                    <div class="notice">
                        Signed in as ${auth.user?.roles.join(', ') ?? 'somebody'}, which may look at the locations but
                        not change them. That needs the CPO or the system administrator role.
                    </div>
                `}

                <div class="cards">
                    ${listCard(locations)}
                    ${mayManage ? addCard(locations) : ''}
                </div>
            `);

            wire();

        }


        function listCard(locations: Locations): HTMLFragment {

            return html`
                <section class="card wide">

                    <h2><i class="fa-solid fa-map-location-dot"></i> Published locations</h2>

                    <p class="hint">
                        Operated by ${locations.operator} (${locations.partyId}). A partner fetches these for the
                        version it is on.${locations.openData ? ' They are open data here: anybody may read them, with or without a token.' : ''}
                    </p>

                    ${locations.locations.length === 0
                          ? html`<p class="muted">No location published yet.</p>`
                          : html`
                              <div class="table-scroll">
                                  <table class="table">
                                      <thead>
                                          <tr>
                                              <th>ID</th>
                                              <th>Name</th>
                                              <th>OCPI</th>
                                              <th>Address</th>
                                              <th>Coordinates</th>
                                              <th>EVSEs</th>
                                              <th>Published</th>
                                              <th>Updated</th>
                                              <th></th>
                                          </tr>
                                      </thead>
                                      <tbody>
                                          ${locations.locations.map(location => row(location))}
                                      </tbody>
                                  </table>
                              </div>
                          `}

                </section>
            `;

        }


        function row(location: Location): HTMLFragment {

            const published = location.publish !== false;

            return html`
                <tr class="${published ? '' : 'dimmed'}">
                    <td><code>${location.id}</code></td>
                    <td>${location.name ?? '-'}</td>
                    <td>${location.version}</td>
                    <td class="small">
                        ${[location.address, location.postal_code, location.city, location.country].filter(part => part).join(', ')}
                    </td>
                    <td class="small muted">
                        ${location.coordinates ? `${location.coordinates.latitude}, ${location.coordinates.longitude}` : '-'}
                    </td>
                    <td>${Array.isArray(location.evses) ? location.evses.length : 0}</td>
                    <td>${published ? 'yes' : html`<span class="warn">no</span>`}</td>
                    <td class="small muted">${formatTimestamp(location.last_updated)}</td>
                    <td class="right">
                        <button type="button" class="btn small danger location-remove" data-version="${location.version}" data-id="${location.id}"
                                ${mayManage ? '' : html`disabled`}>
                            Withdraw
                        </button>
                    </td>
                </tr>
            `;

        }


        function addCard(locations: Locations): HTMLFragment {

            const newest = locations.versions[locations.versions.length - 1] ?? '';

            return html`
                <section class="card wide">

                    <h2><i class="fa-solid fa-plus"></i> Publish a location</h2>

                    <form id="location-form" class="form-stack">

                        <div class="form-grid">

                            <label>OCPI version
                                <select name="version">
                                    ${locations.versions.map(version => html`
                                        <option value="${version}" ${version === newest ? html`selected` : ''}>${version}</option>
                                    `)}
                                </select>
                            </label>

                            <label>ID
                                <input type="text" name="id" placeholder="LOC0001" maxlength="36" required />
                            </label>

                            <label>Name
                                <input type="text" name="name" placeholder="what the place is called" maxlength="255" required />
                            </label>

                            <label>Address
                                <input type="text" name="address" placeholder="street and number" maxlength="45" required />
                            </label>

                            <label>Postal code
                                <input type="text" name="postalCode" maxlength="10" required />
                            </label>

                            <label>City
                                <input type="text" name="city" maxlength="45" required />
                            </label>

                            <label>Country
                                <input type="text" name="country" placeholder="DEU" maxlength="3" pattern="[a-zA-Z]{3}" required />
                            </label>

                            <label>Time zone
                                <input type="text" name="timeZone" placeholder="Europe/Berlin" maxlength="255" required />
                            </label>

                            <label>Latitude
                                <input type="number" name="latitude" step="0.000001" min="-90" max="90" placeholder="50.927054" required />
                            </label>

                            <label>Longitude
                                <input type="number" name="longitude" step="0.000001" min="-180" max="180" placeholder="11.589707" required />
                            </label>

                        </div>

                        <label class="checkbox">
                            <input type="checkbox" name="publish" checked />
                            Publish
                            <span class="hint">Unticked, the location is kept but partners may show it only to a driver who is already standing there.</span>
                        </label>

                        <div class="form-actions">
                            <button type="submit" class="btn primary">Publish the location</button>
                            <span id="location-note"  class="form-notice" role="status"></span>
                            <span id="location-error" class="form-error"  role="alert"></span>
                        </div>

                    </form>

                </section>
            `;

        }


        function wire(): void {

            content.querySelectorAll<HTMLButtonElement>('.location-remove').forEach(button => {
                button.addEventListener('click', () => void remove(button.dataset.version ?? '', button.dataset.id ?? ''));
            });

            content.querySelector<HTMLFormElement>('#location-form')?.addEventListener('submit', event => {
                event.preventDefault();
                void add(event.target as HTMLFormElement);
            });

        }


        async function add(form: HTMLFormElement): Promise<void> {

            const error = must<HTMLElement>(content, '#location-error');
            error.textContent = '';

            const spec: LocationSpec = {
                version:     field(form, 'version'),
                id:          field(form, 'id'),
                name:        field(form, 'name'),
                address:     field(form, 'address'),
                postalCode:  field(form, 'postalCode'),
                city:        field(form, 'city'),
                country:     field(form, 'country').toUpperCase(),
                timeZone:    field(form, 'timeZone'),
                latitude:    Number(field(form, 'latitude')),
                longitude:   Number(field(form, 'longitude')),
                publish:     form.querySelector<HTMLInputElement>('[name="publish"]')?.checked ?? true
            };

            try
            {

                const answer = await api.ocpi.locations.add(spec);

                if (cancelled)
                    return;

                store = answer.locations;
                draw();

                must<HTMLElement>(content, '#location-note').textContent = answer.message;

            }
            catch (problem)
            {
                if (!cancelled)
                    error.textContent = errorMessage(problem);
            }

        }


        async function remove(version: string, id: string): Promise<void> {

            if (!window.confirm(`Withdraw the location '${id}' (OCPI ${version})?\n\nThe partners stop being shown it; a driver already charging there is unaffected.`))
                return;

            try
            {
                const answer = await api.ocpi.locations.remove(version, id);

                if (cancelled)
                    return;

                store = answer;
                draw();
            }
            catch (problem)
            {
                if (!cancelled)
                {
                    window.alert(errorMessage(problem));
                    void load();
                }
            }

        }


        async function load(): Promise<void> {

            try
            {
                const locations = await api.ocpi.locations.get();

                if (cancelled)
                    return;

                store = locations;
                draw();
            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`<div class="error-box">The locations could not be loaded: ${errorMessage(problem)}</div>`);
            }

        }

        void load();

        return () => { cancelled = true; };

    }

};
