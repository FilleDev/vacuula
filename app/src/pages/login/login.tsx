import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMascot } from '../../mascot'
import Button from '../../components/button/button'
import Input from '../../components/input/input'
import { Http } from '../../http'
import styles from './login.module.scss'

// Shown instead of the app when the server has a panel password and this
// browser has no valid login cookie yet. The server sets the cookie (1 year).
export default function Login({ onLoggedIn }: { onLoggedIn: () => void }) {
    const { t } = useTranslation()
    const { mascot } = useMascot()
    const [password, setPassword] = useState('')
    const [error, setError] = useState<'wrongPassword' | 'httpsRequired' | null>(null)
    const [busy, setBusy] = useState(false)

    const submit = () => {
        if (!password || busy) return
        setBusy(true)
        setError(null)
        Http.login(password)
            .then(onLoggedIn)
            .catch(err => setError(err.response?.status === 400 ? 'httpsRequired' : 'wrongPassword'))
            .finally(() => setBusy(false))
    }

    return (
        <form className={styles.wrap} onSubmit={e => { e.preventDefault(); submit() }}>
            <img src={mascot.src} alt="" className={styles.mascot} />
            <span className={styles.title}>{t('login.title')}</span>
            <div className={styles.fields}>
                <Input
                    type='password'
                    label={t('login.password')}
                    value={password}
                    onChange={setPassword}
                    autoFocus
                />
                {error && <span className={styles.error} role="alert">{t(`login.${error}`)}</span>}
                <Button text={t('login.submit')} style='primary' disabled={busy || !password} onClick={submit} />
            </div>
        </form>
    )
}
