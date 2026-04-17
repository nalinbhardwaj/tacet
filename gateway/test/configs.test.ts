import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ConfigRegistry, loadConfigsFromFile } from '../src/configs.js';

const UUID = '00000000-0000-4000-8000-000000000001';
const UUID2 = '00000000-0000-4000-8000-000000000002';

describe('ConfigRegistry', () => {
  it('indexes configs by id and exposes a public listing', () => {
    const reg = new ConfigRegistry([
      { id: UUID, name: 'a', tee_url: 'http://t/', model_name: 'm' },
      { id: UUID2, name: 'b', tee_url: 'http://t2/', model_name: 'm2' },
    ]);
    expect(reg.size()).toBe(2);
    expect(reg.get(UUID)?.name).toBe('a');
    expect(reg.list()).toEqual([
      { id: UUID, name: 'a', model_name: 'm' },
      { id: UUID2, name: 'b', model_name: 'm2' },
    ]);
  });

  it('rejects duplicate config ids', () => {
    expect(
      () =>
        new ConfigRegistry([
          { id: UUID, name: 'a', tee_url: 'http://t/', model_name: 'm' },
          { id: UUID, name: 'b', tee_url: 'http://t2/', model_name: 'm2' },
        ]),
    ).toThrow(/Duplicate config id/);
  });
});

describe('loadConfigsFromFile', () => {
  it('parses a valid JSON file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tacet-gw-'));
    const path = join(dir, 'configs.json');
    writeFileSync(
      path,
      JSON.stringify({
        configs: [{ id: UUID, name: 'a', tee_url: 'http://t:1/', model_name: 'm' }],
      }),
    );
    const reg = loadConfigsFromFile(path);
    expect(reg.size()).toBe(1);
  });

  it('throws on invalid JSON', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tacet-gw-'));
    const path = join(dir, 'configs.json');
    writeFileSync(path, 'not json');
    expect(() => loadConfigsFromFile(path)).toThrow(/not valid JSON/);
  });

  it('throws on schema violation', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tacet-gw-'));
    const path = join(dir, 'configs.json');
    writeFileSync(path, JSON.stringify({ configs: [{ id: 'nope' }] }));
    expect(() => loadConfigsFromFile(path)).toThrow();
  });
});
