import { api, type Partner, type Partners, type PartnerSpec } from '../api/client';
import { auth } from '../auth';
import { must } from '@node/html';
import type { Page } from '@node/router';
import { mayButNot, reloadButton, shell } from '@node/shell';
import { errorMessage, field, formatTimestamp, isChecked } from '@node/ui';
import { anyFormTypedSinceDrawn, unsaved } from '@node/unsaved';
import { html, nothing, render, repeat, type TemplateResult } from '@node/view';

/**
 * The roaming partners: the e-mobility service providers whose customers may
 * charge at this operator's stations, on which OCPI version, and how far the
 * peering has got.
 *
 * Two ways to add one, and they are the two halves of the OCPI registration.
 * With only a token of ours the partner is expected to come here: they fetch
 * the versions with that token and POST their credentials, and the library
 * fills in the rest. With their token and their versions URL as well, this
 * CSMS can go to them - the Register button does exactly that, and every step
 * of it is in the log.
 *
 * The token this operator made up is shown once, when the partner is added, and
 * again in the list to whoever may manage partners: it is what the operator
 * has to hand over, and it opens this operator, so it goes to nobody else.
 *
 * Drawn by view.ts: a draw changes only what differs, so that a partner half
 * typed in outlives the tokens being shown, another partner registered or
 * removed.
 */
export const partnersPage: Page = {

    title: 'Roaming partners',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/ocpi/partners',
            title:     'Roaming partners',
            subtitle:  'Who is peered with this operator over OCPI, and who is on the way.',
            actions:   reloadButton(() => load())
        });

        render(content, html`<div class="loading">Loading ...</div>`);


        const mayManage = auth.can('roaming', 'edit');

        let cancelled = false;
        let store: Partners | null = null;

        /** The token that was just made up, offered once with its instructions. */
        let justAdded: { id: string; token: string; version: string } | null = null;

        /** What the last registration said. */
        let lastRegistration: { ok: boolean; message: string } | null = null;

        /** Whether the tokens in the list are readable or dotted out. */
        let revealTokens = false;

        /** Whether the add form asks for what starting the peering from here takes. */
        let startHere = false;

        /** The partners being registered right now, by version and id. */
        const registering = new Set<string>();

        const keyOf = (partner: Partner): string => `${partner.version}/${partner.id}`;


        function draw(): void {

            if (store === null)
                return;

            const partners = store;

            render(content, html`

                ${mayManage ? nothing : html`
                    <div class="notice">
                        ${mayButNot('look at the roaming partners', 'change them')}
                    </div>
                `}

                ${justAdded === null ? nothing : html`
                    <div class="notice ok">
                        <strong>'${justAdded.id}' was added on OCPI ${justAdded.version}. The token it signs in with is</strong>
                        <code class="password">${justAdded.token}</code><br />
                        Hand it to the partner. They fetch <code>${partners.ourVersionsURL}</code> with it and POST their
                        credentials to this operator; from then on the peering is complete. The token stays readable in the
                        list below for whoever may manage partners.
                    </div>
                `}

                ${lastRegistration === null ? nothing : html`
                    <div class="notice ${lastRegistration.ok ? 'ok' : 'warn'}">${lastRegistration.message}</div>
                `}

                <div class="cards">
                    ${listCard(partners)}
                    ${mayManage ? addCard(partners) : nothing}
                </div>
            `);

        }


        function listCard(partners: Partners): TemplateResult {

            return html`
                <section class="card wide">

                    <h2>
                        <i class="fa-solid fa-handshake"></i> Partners
                        ${mayManage && partners.partners.some(partner => partner.hasOurToken) ? html`
                            <button type="button" id="reveal" class="btn small heading-action" @click=${reveal}>
                                ${revealTokens ? 'Hide the tokens' : 'Show the tokens'}
                            </button>
                        ` : nothing}
                    </h2>

                    <p class="hint">
                        A partner that is not in this list cannot call this operator, whatever token it presents. Each
                        partner is on one OCPI version - the one it was added under, which is the one it registers on.
                    </p>

                    ${partners.partners.length === 0
                          ? html`<p class="muted">No roaming partner yet.</p>`
                          : html`
                              <div class="table-scroll">
                                  <table class="table">
                                      <thead>
                                          <tr>
                                              <th>Partner</th>
                                              <th>Role</th>
                                              <th>OCPI</th>
                                              <th>Peering</th>
                                              <th>Their token, our token</th>
                                              <th>Their versions URL</th>
                                              <th>Added</th>
                                              <th></th>
                                          </tr>
                                      </thead>
                                      <tbody>
                                          ${repeat(partners.partners, keyOf, partner => row(partner))}
                                      </tbody>
                                  </table>
                              </div>
                          `}

                </section>
            `;

        }


        function row(partner: Partner): TemplateResult {

            const busy    = registering.has(keyOf(partner));
            const peering = partner.registered
                                ? html`<span class="badge ok">registered</span>`
                                : partner.canRegister
                                    ? html`<span class="badge">ready to register</span>`
                                    : html`<span class="badge warn">waiting for them</span>`;

            return html`
                <tr class="${partner.status === 'ENABLED' ? '' : 'dimmed'}">

                    <td>
                        <code>${partner.id}</code>
                        <div class="small muted">${partner.name}${partner.website ? html` &middot; <a href="${partner.website}" target="_blank" rel="noopener">${partner.website}</a>` : nothing}</div>
                    </td>

                    <td>${partner.role}</td>

                    <td>${partner.version}${partner.selectedVersion && partner.selectedVersion !== partner.version ? html`<div class="small muted">they chose ${partner.selectedVersion}</div>` : nothing}</td>

                    <td>
                        ${peering}
                        <div class="small muted">
                            ${partner.status}${partner.remoteStatus ? ` · remote ${partner.remoteStatus}` : ''}
                        </div>
                    </td>

                    <td class="small">
                        <div>${token(partner.theirToken, partner.hasTheirToken)}</div>
                        <div>${token(partner.ourToken, partner.hasOurToken)}</div>
                    </td>

                    <td class="small">${partner.theirVersionsURL ?? html`<span class="muted">-</span>`}</td>

                    <td class="small muted">${formatTimestamp(partner.created)}</td>

                    <td class="right">
                        ${mayManage && partner.canRegister ? html`
                            <button type="button" class="btn small partner-register" data-version="${partner.version}" data-id="${partner.id}"
                                    title="Fetch their versions with the token they handed out, and POST this operator's credentials to them"
                                    ?disabled=${busy} @click=${() => void register(partner.version, partner.id)}>
                                ${busy ? 'Registering ...' : partner.registered ? 'Register again' : 'Register'}
                            </button>
                        ` : nothing}
                        <button type="button" class="btn small danger partner-remove" data-version="${partner.version}" data-id="${partner.id}"
                                ?disabled=${!mayManage} @click=${() => void remove(partner.version, partner.id)}>
                            Remove
                        </button>
                    </td>

                </tr>
            `;

        }


        /** A token as a cell: dotted out until revealed, "none" when there is none. */
        function token(value: string | null, present: boolean): TemplateResult {

            if (!present)
                return html`<span class="muted">none</span>`;

            if (value === null)
                return html`<span class="muted" title="Only whoever may manage partners sees the tokens">set</span>`;

            return revealTokens
                       ? html`<code class="token">${value}</code>`
                       : html`<code class="token muted">${'•'.repeat(Math.min(value.length, 24))}</code>`;

        }


        function addCard(partners: Partners): TemplateResult {

            const newest = partners.versions[partners.versions.length - 1] ?? '';

            return html`
                <section class="card wide">

                    <h2><i class="fa-solid fa-plus"></i> Add a roaming partner</h2>

                    <form id="partner-form" class="form-stack" @submit=${add}>

                        <div class="form-grid">

                            <label>OCPI version
                                <select name="version">
                                    ${partners.versions.map(version => html`
                                        <option value="${version}" ?selected=${version === newest}>${version}</option>
                                    `)}
                                </select>
                            </label>

                            <label>Role
                                <select name="role">
                                    ${partners.roles.map(role => html`
                                        <option value="${role}" ?selected=${role === 'EMSP'}>${role}</option>
                                    `)}
                                </select>
                            </label>

                            <label>Country code
                                <input type="text" name="countryCode" placeholder="DE" maxlength="2" minlength="2" required
                                       pattern="[A-Za-z]{2}" class="capitals" />
                            </label>

                            <label>Party ID
                                <input type="text" name="partyId" placeholder="GEF" maxlength="3" minlength="3" required
                                       pattern="[A-Za-z0-9]{3}" class="capitals" />
                            </label>

                            <label>Name
                                <input type="text" name="name" placeholder="Example Charging GmbH" maxlength="100" required />
                            </label>

                            <label>Website
                                <input type="url" name="website" placeholder="https://example.org" maxlength="255" />
                            </label>

                            <label>The token they will use with this operator
                                <input type="text" name="ourToken" placeholder="leave empty to make one up" maxlength="255" autocomplete="off" />
                            </label>

                        </div>

                        <label class="checkbox">
                            <input type="checkbox" name="startHere" @change=${toggleStartHere} />
                            This operator starts the peering
                            <span class="hint">
                                Tick this when the partner has already handed out a token and a versions URL. Without
                                it, the partner is expected to register here with the token above.
                            </span>
                        </label>

                        <div class="form-grid" id="start-here" ?hidden=${!startHere}>
                            <label>The token they handed out
                                <input type="text" name="theirToken" maxlength="255" autocomplete="off" required ?disabled=${!startHere} />
                            </label>
                            <label>Their versions URL
                                <input type="url" name="versionsURL" placeholder="https://emsp.example.org/ocpi/versions" maxlength="255" required ?disabled=${!startHere} />
                            </label>
                        </div>

                        <div class="form-actions">
                            <button type="submit" class="btn primary">Add the partner</button>
                            <span id="partner-error" class="form-error" role="alert"></span>
                        </div>

                    </form>

                </section>
            `;

        }


        function reveal(): void {
            revealTokens = !revealTokens;
            draw();
        }


        /**
         * The fields for starting the peering from here, shown and enabled
         * while their box is ticked - drawn so, the rest of the form left as it
         * is typed into. Hidden, they are disabled too, so that they neither
         * hold up the form nor are sent.
         */
        function toggleStartHere(event: Event): void {

            startHere = (event.target as HTMLInputElement).checked;
            draw();

            if (startHere)
                content.querySelector<HTMLInputElement>('#partner-form [name="theirToken"]')?.focus();

        }


        function add(event: SubmitEvent): void {

            event.preventDefault();

            void addPartner(event.currentTarget as HTMLFormElement);

        }


        async function addPartner(form: HTMLFormElement): Promise<void> {

            const error = must<HTMLElement>(content, '#partner-error');
            error.textContent = '';

            const spec: PartnerSpec = {
                version:      field(form, 'version'),
                role:         field(form, 'role'),
                countryCode:  field(form, 'countryCode').toUpperCase(),
                partyId:      field(form, 'partyId').toUpperCase(),
                name:         field(form, 'name'),
                website:      field(form, 'website') || undefined,
                ourToken:     field(form, 'ourToken') || undefined
            };

            if (isChecked(form, 'startHere')) {
                spec.theirToken   = field(form, 'theirToken');
                spec.versionsURL  = field(form, 'versionsURL');
            }

            try
            {

                const answer = await api.ocpi.partners.add(spec);

                if (cancelled)
                    return;

                store             = answer.partners;
                justAdded         = { id: answer.id, token: answer.ourToken, version: answer.version };
                lastRegistration  = null;

                // A draw leaves a form as it is typed into; this one was
                // taken in, so it is emptied, the box for starting here too.
                form.reset();
                startHere = false;

                draw();

            }
            catch (problem)
            {
                if (!cancelled)
                    error.textContent = errorMessage(problem);
            }

        }


        async function register(version: string, id: string): Promise<void> {

            const key = `${version}/${id}`;

            registering.add(key);
            draw();

            try
            {

                const answer = await api.ocpi.partners.register(version, id);

                if (cancelled)
                    return;

                registering.delete(key);

                store             = answer.partners;
                lastRegistration  = { ok: answer.ok, message: answer.message };
                justAdded         = null;

                draw();

            }
            catch (problem)
            {

                if (cancelled)
                    return;

                registering.delete(key);

                // A failed handshake answers 502 with the same shape; anything
                // else is a fault of this operator.
                const body = (problem as { body?: { ok?: boolean; message?: string; partners?: Partners } }).body;

                if (body && typeof body.message === 'string') {
                    if (body.partners)
                        store = body.partners;
                    lastRegistration = { ok: false, message: body.message };
                    draw();
                }
                else
                {
                    draw();
                    window.alert(errorMessage(problem));
                }

            }

        }


        async function remove(version: string, id: string): Promise<void> {

            if (!window.confirm(`Remove the roaming partner '${id}' (OCPI ${version})?\n\nIts token stops opening this operator the moment it is gone.`))
                return;

            try
            {

                const answer = await api.ocpi.partners.remove(version, id);

                if (cancelled)
                    return;

                store             = answer;
                justAdded         = null;
                lastRegistration  = null;

                draw();

            }
            catch (problem)
            {
                if (!cancelled)
                {
                    window.alert(errorMessage(problem));
                    void load(false);
                }
            }

        }


        /**
         * The partners as the CSMS has them now, drawn over the page as it is
         * - what is typed into its form kept, as a draw keeps it - or from
         * nothing, with Loading first, as Reload and the start have it.
         */
        async function load(showLoading = true): Promise<void> {

            if (showLoading)
            {
                render(content, html`<div class="loading">Loading ...</div>`);
                startHere = false;
            }

            try
            {
                const partners = await api.ocpi.partners.get();

                if (cancelled)
                    return;

                store = partners;
                draw();
            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`<div class="error-box">The roaming partners could not be loaded: ${errorMessage(problem)}</div>`);
            }

        }

        // A partner being added is a draft until it is added. Register and
        // Remove in the list are in no form: they act when they are clicked.
        const release = unsaved.heldBy(() => anyFormTypedSinceDrawn(content));

        void load();

        return () => { cancelled = true; release(); };

    }

};
