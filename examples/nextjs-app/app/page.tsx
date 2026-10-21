import { cookies } from 'next/headers';
import { SignInWithIdentvia } from '@identvia/react';
import { identvia } from '../lib/identvia';

export default async function Home() {
  const session = await identvia.getSession(await cookies());
  if (!session) return <main><SignInWithIdentvia href="/auth/login?returnTo=/dashboard" theme="dark" /></main>;
  return (
    <main>
      <p>Signed in as {session.user.email ?? session.user.sub}</p>
      <form method="post" action="/auth/logout"><button>Sign out</button></form>
    </main>
  );
}
