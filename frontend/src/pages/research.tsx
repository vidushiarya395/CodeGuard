import { FlaskConical } from 'lucide-react'
import { EmptyState, PageHeader } from '@/components/page'

export function ResearchPage() {
  return (
    <>
      <PageHeader
        title="Research"
        description="Benchmark results comparing CodeGuard with Semgrep, Bandit and an LLM on public datasets."
      />
      <EmptyState icon={FlaskConical} title="Not yet measured">
        Results appear here only after the benchmark scripts have been run.
      </EmptyState>
    </>
  )
}
