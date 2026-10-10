import { History } from 'lucide-react'
import { EmptyState, PageHeader } from '@/components/page'

export function HistoryPage() {
  return (
    <>
      <PageHeader title="History" description="Your past scans and their reports." />
      <EmptyState icon={History} title="No scans yet">
        Saved scan history will be added in a later phase.
      </EmptyState>
    </>
  )
}
