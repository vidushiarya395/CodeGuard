import { ScanSearch, ShieldAlert } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { EmptyState, PageHeader } from '@/components/page'

export function ScanPage() {
  return (
    <>
      <PageHeader title="Scan" description="Check Python code for security problems." />
      <Alert className="mb-6">
        <ShieldAlert aria-hidden />
        <AlertTitle>Privacy note</AlertTitle>
        <AlertDescription>
          Code you scan may be sent to a free AI service for review. Do not paste private code or real secrets.
        </AlertDescription>
      </Alert>
      <EmptyState icon={ScanSearch} title="Scanning from the browser is not available yet">
        It will be added in a later phase. For now, use the command line:{' '}
        <code className="bg-muted rounded px-1 py-0.5 text-xs">codeguard scan &lt;path&gt;</code>
      </EmptyState>
    </>
  )
}
