import type { Hono } from 'hono';
import {
  onRequestPost as tokenizePost,
  type DataByokEnv
} from '../functions/api/data-byok/tokenize';
import type { KVNamespace } from './kvAdapter';
import { createBaseLabApp, type BaseCloudRunEnv } from './runtime';

export { verifyRouterSecret } from './runtime';

export interface CloudRunEnv extends DataByokEnv, BaseCloudRunEnv {}

export function createCloudRunApp(options?: {
  env?: CloudRunEnv;
  kv?: KVNamespace;
}): Hono {
  return createBaseLabApp<CloudRunEnv>({
    labSlug: 'data-byok',
    env: options?.env,
    kv: options?.kv,
    registerRoutes: (app, wrap) => {
      app.post('/api/data-byok/tokenize', wrap(tokenizePost));
    }
  });
}
