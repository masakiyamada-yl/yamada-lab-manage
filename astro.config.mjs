import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import node from '@astrojs/node';
import auth from 'auth-astro';

export default defineConfig({
  output: 'server',
  adapter: node({ mode: 'standalone' }),
  site: 'https://manage.yamada-lab.co.jp',
  integrations: [tailwind(), auth()],
});
