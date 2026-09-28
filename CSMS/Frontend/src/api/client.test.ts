/**
 * Where the client asks for what every node answers, asked of its source.
 *
 * Run with `npm test`. Node's runner could call the client with a fetch of its
 * own, as the local controller's tests do; what is pinned here is one path,
 * and the source says it plainly enough.
 */

import { strict as assert }  from 'node:assert';
import { readFileSync }      from 'node:fs';
import { describe, it }      from 'node:test';


const client = readFileSync(new URL('./client.ts', import.meta.url), 'utf-8');


describe('the clock', () => {

    it('is asked at /v1/clock, where every node has it now', () => {

        // At /v1/configuration/time it was this CSMS's alone; the node's JSON
        // API answers that path with its 404 now, which a page would show as
        // a clock nobody can read.
        assert.match(client, /clock:\s+\(\) => request<Clock>\s*\('GET', '\/clock'\)/,
                     'the client asks for the clock somewhere else than every node has it');

    });

});
