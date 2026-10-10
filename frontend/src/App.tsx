import { Navigate, Route, Routes } from 'react-router-dom'
import { AppLayout } from '@/components/layout/app-layout'
import { AboutPage } from '@/pages/about'
import { HistoryPage } from '@/pages/history'
import { NotFoundPage } from '@/pages/not-found'
import { ResearchPage } from '@/pages/research'
import { RulesPage } from '@/pages/rules'
import { ScanPage } from '@/pages/scan'
import { SettingsPage } from '@/pages/settings'

export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<Navigate to="/scan" replace />} />
        <Route path="scan" element={<ScanPage />} />
        <Route path="history" element={<HistoryPage />} />
        <Route path="rules" element={<RulesPage />} />
        <Route path="research" element={<ResearchPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="about" element={<AboutPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
