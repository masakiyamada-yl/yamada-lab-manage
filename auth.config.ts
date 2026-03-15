import Google from '@auth/core/providers/google';
import type { AuthConfig } from '@auth/core';

export default {
  providers: [
    Google({
      clientId: import.meta.env.GOOGLE_CLIENT_ID,
      clientSecret: import.meta.env.GOOGLE_CLIENT_SECRET,
    }),
  ],
  callbacks: {
    async signIn({ account, profile }) {
      // yamada-lab.co.jp ドメインのみ許可
      if (account?.provider === 'google' && profile?.email) {
        return profile.email.endsWith('@yamada-lab.co.jp');
      }
      return false;
    },
  },
} satisfies AuthConfig;
