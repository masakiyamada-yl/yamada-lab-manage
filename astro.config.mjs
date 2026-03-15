import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';

export default defineConfig({
  site: 'https://manage.yamada-lab.co.jp',
  integrations: [tailwind()],
});
