import { api, type RoamingDataKind, type RoamingItem } from '../api/client';
import { html as stringHTML, must } from '@node/html';
import type { Page } from '@node/router';
import { shell } from '@node/shell';
import { errorMessage, formatTimestamp, formatValue } from '@node/ui';
import { html, render, repeat, type TemplateResult } from '@node/view';

/**
 * What travels between this operator and its roaming partners, other than the
 * locations it publishes: the tokens the partners pushed in, and the tariffs,
 * charging sessions and charge detail records this operator holds.
 *
 * Read-only, and for two different reasons. The tokens are the partners': an
 * EMSP issues a card and an EMSP takes it away, and an operator that edited a
 * copy would be an operator authorising a card nobody is billed for. The rest
 * is written by the charging stations below and by whatever settles them, and
 * a record changed by hand in a web interface is not a record any more.
 *
 * The columns are the handful of fields worth a glance; the whole object, as
 * OCPI wrote it, is behind every row. Drawn by view.ts, rows by their key: a
 * row opened to its JSON stays open when Reload draws the list again.
 */

interface Column {
    label:   string;
    /** The value of the cell, out of the object as OCPI writes it. */
    value:   (item: RoamingItem) => unknown;
    /** Whether the value is a moment to be written as one. */
    time?:   boolean;
}

interface KindPage {
    kind:       RoamingDataKind;
    /** What names one of them within its version: a token its uid, the rest their id. */
    key:        string;
    path:       string;
    title:      string;
    subtitle:   string;
    icon:       string;
    /** What the page says when there is nothing, which differs per kind. */
    emptyText:  string;
    columns:    Column[];
}

const string = (item: RoamingItem, key: string): unknown => item[key];

const kinds: KindPage[] = [
    {
        kind:       'tokens',
        key:        'uid',
        path:       '/roaming/tokens',
        title:      'Tokens',
        subtitle:   'The cards and app identities the partners let charge here.',
        icon:       'fa-id-card',
        emptyText:  'No partner has pushed a token yet. An EMSP sends these once the peering is complete.',
        columns:    [
            { label: 'UID',        value: item => string(item, 'uid') },
            { label: 'Issuer',     value: item => `${string(item, 'country_code') ?? ''}-${string(item, 'party_id') ?? ''}` },
            { label: 'Type',       value: item => string(item, 'type') },
            { label: 'Contract',   value: item => string(item, 'contract_id') ?? string(item, 'auth_id') },
            { label: 'Valid',      value: item => string(item, 'valid') },
            { label: 'Whitelist',  value: item => string(item, 'whitelist') },
            { label: 'Status',     value: item => string(item, 'status') },
            { label: 'Updated',    value: item => string(item, 'last_updated'), time: true }
        ]
    },
    {
        kind:       'tariffs',
        key:        'id',
        path:       '/roaming/tariffs',
        title:      'Tariffs',
        subtitle:   'What this operator charges, as its partners are told.',
        icon:       'fa-tags',
        emptyText:  'No tariff yet.',
        columns:    [
            { label: 'ID',        value: item => string(item, 'id') },
            { label: 'Operator',  value: item => `${string(item, 'country_code') ?? ''}-${string(item, 'party_id') ?? ''}` },
            { label: 'Currency',  value: item => string(item, 'currency') },
            { label: 'Type',      value: item => string(item, 'type') },
            { label: 'Elements',  value: item => Array.isArray(item['elements']) ? (item['elements'] as unknown[]).length : 0 },
            { label: 'Updated',   value: item => string(item, 'last_updated'), time: true }
        ]
    },
    {
        kind:       'sessions',
        key:        'id',
        path:       '/roaming/sessions',
        title:      'Charging sessions',
        subtitle:   'What is charging at this operator\'s stations, as its partners see it.',
        icon:       'fa-bolt',
        emptyText:  'No charging session yet.',
        columns:    [
            { label: 'ID',        value: item => string(item, 'id') },
            { label: 'Operator',  value: item => `${string(item, 'country_code') ?? ''}-${string(item, 'party_id') ?? ''}` },
            { label: 'Started',   value: item => string(item, 'start_date_time') ?? string(item, 'start_datetime'), time: true },
            { label: 'Ended',     value: item => string(item, 'end_date_time')   ?? string(item, 'end_datetime'),   time: true },
            { label: 'kWh',       value: item => string(item, 'kwh') },
            { label: 'Status',    value: item => string(item, 'status') },
            { label: 'Cost',      value: item => cost(item['total_cost']) },
            { label: 'Updated',   value: item => string(item, 'last_updated'), time: true }
        ]
    },
    {
        kind:       'cdrs',
        key:        'id',
        path:       '/roaming/cdrs',
        title:      'Charge detail records',
        subtitle:   'What this operator will invoice its partners for.',
        icon:       'fa-file-invoice',
        emptyText:  'No charge detail record yet.',
        columns:    [
            { label: 'ID',        value: item => string(item, 'id') },
            { label: 'Operator',  value: item => `${string(item, 'country_code') ?? ''}-${string(item, 'party_id') ?? ''}` },
            { label: 'Started',   value: item => string(item, 'start_date_time') ?? string(item, 'start_datetime'), time: true },
            { label: 'Ended',     value: item => string(item, 'end_date_time')   ?? string(item, 'stop_datetime'),  time: true },
            { label: 'Energy',    value: item => string(item, 'total_energy') },
            { label: 'Cost',      value: item => cost(item['total_cost']) },
            { label: 'Updated',   value: item => string(item, 'last_updated'), time: true }
        ]
    }
];

/** A price as OCPI writes it: a number in 2.1.1, an object with excl_vat/incl_vat later. */
function cost(value: unknown): unknown {

    if (value === null || value === undefined)
        return null;

    if (typeof value === 'object' && 'excl_vat' in value)
        return `${formatValue((value as { excl_vat: unknown }).excl_vat)}${'incl_vat' in value ? ` (${formatValue((value as { incl_vat: unknown }).incl_vat)} incl. VAT)` : ''}`;

    return value;

}


function page(definition: KindPage): Page {

    return {

        title: definition.title,

        render({ root }) {

            const content = shell(root, {
                active:    definition.path,
                title:     definition.title,
                subtitle:  definition.subtitle,
                actions:   stringHTML`<button type="button" id="reload" class="btn small">Reload</button>`
            });

            render(content, html`<div class="loading">Loading ...</div>`);

            must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => void load());

            let cancelled = false;
            let items: RoamingItem[] = [];

            /** The rows opened to their JSON, by their key. */
            const opened = new Set<string>();

            /**
             * What names an object here: its version, its operator and its id -
             * a partner's token and another partner's may share a uid.
             */
            const keyOf = (item: RoamingItem): string =>
                `${item.version}/${String(item['country_code'] ?? '')}-${String(item['party_id'] ?? '')}/${String(item[definition.key] ?? '')}`;

            function draw(): void {

                render(content, html`
                    <section class="card wide">

                        <h2><i class="fa-solid ${definition.icon}"></i> ${definition.title} <span class="chip">${items.length}</span></h2>

                        ${items.length === 0
                              ? html`<p class="muted">${definition.emptyText}</p>`
                              : html`
                                  <div class="table-scroll">
                                      <table class="table">
                                          <thead>
                                              <tr>
                                                  ${definition.columns.map(column => html`<th>${column.label}</th>`)}
                                                  <th>OCPI</th>
                                                  <th></th>
                                              </tr>
                                          </thead>
                                          <tbody>
                                              ${repeat(items, keyOf, item => row(item))}
                                          </tbody>
                                      </table>
                                  </div>
                              `}

                    </section>
                `);

            }

            function toggle(key: string): void {

                if (!opened.delete(key))
                    opened.add(key);

                draw();

            }

            function row(item: RoamingItem): TemplateResult {

                const { version, ...rest } = item;
                const key  = keyOf(item);
                const open = opened.has(key);

                return html`
                    <tr>
                        ${definition.columns.map(column => {
                            const value = column.value(item);
                            return html`<td class="small">${column.time && typeof value === 'string' ? formatTimestamp(value) : formatValue(value)}</td>`;
                        })}
                        <td class="small">${version}</td>
                        <td class="right">
                            <button type="button" class="btn small show-raw" data-key="${key}"
                                    @click=${() => toggle(key)}>${open ? 'Hide' : 'JSON'}</button>
                        </td>
                    </tr>
                    <tr class="raw" data-key="${key}" ?hidden=${!open}>
                        <td colspan="${definition.columns.length + 2}">
                            <pre class="pem">${JSON.stringify(rest, null, 2)}</pre>
                        </td>
                    </tr>
                `;

            }

            async function load(): Promise<void> {

                try
                {
                    const data = await api.ocpi.data(definition.kind);

                    if (cancelled)
                        return;

                    items = data.items;
                    draw();
                }
                catch (problem)
                {
                    if (!cancelled)
                        render(content, html`<div class="error-box">The ${definition.title.toLowerCase()} could not be loaded: ${errorMessage(problem)}</div>`);
                }

            }

            void load();

            return () => { cancelled = true; };

        }

    };

}


/** One page per kind, by the name of the kind. */
export const roamingDataPages: Record<RoamingDataKind, Page> = {
    tokens:     page(kinds[0]),
    tariffs:    page(kinds[1]),
    sessions:   page(kinds[2]),
    cdrs:       page(kinds[3])
};
