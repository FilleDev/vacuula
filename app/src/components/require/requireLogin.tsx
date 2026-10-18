import { useEffect, useState, type ReactNode } from 'react'
import { Http } from '../../http'
import Loading from '../../pages/loading/loading'
import Login from '../../pages/login/login'

// Asks the server if a panel password is set before anything else loads.
// If the check itself fails, the app is let through and shows its own
// "server unreachable" state.
export function RequireLogin({ children }: { children: ReactNode }) {
    const [state, setState] = useState<'checking' | 'login' | 'ok'>('checking')

    useEffect(() => {
        Http.getAuth()
            .then(res => setState(res.data.required && !res.data.authenticated ? 'login' : 'ok'))
            .catch(() => setState('ok'))
    }, [])

    if (state === 'checking') return <Loading />
    if (state === 'login') return <Login onLoggedIn={() => setState('ok')} />
    return <>{children}</>
}
