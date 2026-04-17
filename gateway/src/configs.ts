/**
 * Config registry.
 *
 * In Step 5, configs live in a JSON file loaded at gateway boot. The schema
 * foreshadows the Postgres `configs` table that lands in Step 8:
 *
 *   { id: UUID, name: string, tee_url: string, model_name: string }
 *
 * The gateway never stores or inspects developer secrets — `tee_url` is
 * enough to route WS traffic to the right backend.
 */

import { readFileSync } from 'node:fs';
import { z } from 'zod';

export const ConfigSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1),
  tee_url: z.string().url(),
  model_name: z.string().min(1),
});
export type Config = z.infer<typeof ConfigSchema>;

const ConfigFileSchema = z.object({
  configs: z.array(ConfigSchema),
});

export class ConfigRegistry {
  private readonly byId: Map<string, Config>;

  constructor(configs: Config[]) {
    this.byId = new Map();
    for (const cfg of configs) {
      if (this.byId.has(cfg.id)) {
        throw new Error(`Duplicate config id: ${cfg.id}`);
      }
      this.byId.set(cfg.id, cfg);
    }
  }

  get(id: string): Config | undefined {
    return this.byId.get(id);
  }

  /** Public listing — no secrets; safe for `GET /v1/configs`. */
  list(): Array<Pick<Config, 'id' | 'name' | 'model_name'>> {
    return [...this.byId.values()].map(({ id, name, model_name }) => ({
      id,
      name,
      model_name,
    }));
  }

  size(): number {
    return this.byId.size;
  }
}

export function loadConfigsFromFile(path: string): ConfigRegistry {
  const raw = readFileSync(path, 'utf8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Config file ${path} is not valid JSON: ${(err as Error).message}`);
  }
  const { configs } = ConfigFileSchema.parse(parsed);
  return new ConfigRegistry(configs);
}
