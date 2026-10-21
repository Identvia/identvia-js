import { createRoot } from 'react-dom/client';
import { IdentviaProvider, SignInWithIdentvia, SignedIn, SignedOut, useIdentvia } from '@identvia/react';

function Profile() {
  const { user, signOut, getAccessToken } = useIdentvia();
  const callApi = async () => {
    const token = await getAccessToken(); // refreshes (with rotation) when needed
    await fetch('/api/me', { headers: { Authorization: `Bearer ${token}` } });
  };
  return (
    <div>
      <p>Hi {user?.name ?? user?.email}</p>
      <button onClick={callApi}>Call my API</button>
      <button onClick={() => signOut()}>Sign out</button>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <IdentviaProvider
    clientId={import.meta.env.VITE_IDENTVIA_CLIENT_ID /* public client id, no secret */}
    redirectUri={`${window.location.origin}/callback`}
    scopes={['email', 'profile', 'offline_access']}
    storage="session"
  >
    <SignedOut><SignInWithIdentvia theme="auto" mode="popup" /></SignedOut>
    <SignedIn><Profile /></SignedIn>
  </IdentviaProvider>,
);
