import { FileQuestion } from 'lucide-react'
import { Link } from 'react-router-dom'
import { EmptyState } from '@/components/page'

export function NotFoundPage() {
  return (
    <EmptyState icon={FileQuestion} title="Page not found">
      <Link to="/scan" className="text-foreground underline underline-offset-4">
        Go to Scan
      </Link>
    </EmptyState>
  )
}
