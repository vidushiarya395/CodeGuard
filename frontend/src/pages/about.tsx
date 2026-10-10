import { PageHeader } from '@/components/page'

export function AboutPage() {
  return (
    <>
      <PageHeader title="About" description="What CodeGuard is and how it works." />
      <div className="text-muted-foreground max-w-2xl space-y-4 text-sm leading-relaxed">
        <p>
          CodeGuard checks AI-written Python code for security holes. Several checkers look at the code, only
          findings backed by evidence are kept, and each one is explained in plain English.
        </p>
        <p>
          CodeGuard only reads code. It never runs the code it scans.
        </p>
        <p>
          It is a final-year major project and research paper by Vidushi Arya, built only with free tools.
        </p>
      </div>
    </>
  )
}
