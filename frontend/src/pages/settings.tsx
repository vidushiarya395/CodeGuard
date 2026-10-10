import { Settings } from 'lucide-react'
import { EmptyState, PageHeader } from '@/components/page'

export function SettingsPage() {
  return (
    <>
      <PageHeader title="Settings" description="AI provider, scanner and display options." />
      <EmptyState icon={Settings} title="No settings yet">
        Settings will be added in a later phase. The theme can be changed with the button in the top bar.
      </EmptyState>
    </>
  )
}
