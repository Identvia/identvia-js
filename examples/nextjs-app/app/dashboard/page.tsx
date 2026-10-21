import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { identvia } from '../../lib/identvia';

export default async function Dashboard() {
  const session = await identvia.getSession(await cookies());
  if (!session) redirect('/auth/login?returnTo=/dashboard');
  return <main><h1>Dashboard</h1><p>Pairwise user ID: <code>{session.user.sub}</code></p></main>;
}
