import { BookOpen } from 'lucide-react'
import { EmptyState, PageHeader } from '@/components/page'

export function RulesPage() {
  return (
    <>
      <PageHeader title="Rules" description="The checks CodeGuard runs, with their CWE IDs and sources." />
      <EmptyState icon={BookOpen} title="Rule browser not available yet">
        The rule list will be shown here in a later phase.
      </EmptyState>
    </>
  )
}
