import { createRoot } from 'react-dom/client'
import { BrowserRouter } from "react-router";
import { AppProvider } from './context/AppContext'
import { RequireLogin } from './components/require/requireLogin'
import './i18n'
import './theme/theme.css'
import './theme'
import './mascot'
import './index.css'
import App from './app.tsx'

createRoot(document.getElementById('root')!).render(
  <RequireLogin>
    <AppProvider>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </AppProvider>
  </RequireLogin>,
)
