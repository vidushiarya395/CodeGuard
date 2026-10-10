import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'

export function PageHeader({ title, description }: { title: string; description: string }) {
  return (
    <div className="mb-6 space-y-1">
      <h2 className="text-2xl font-semibold tracking-tight">{title}</h2>
      <p className="text-muted-foreground text-sm">{description}</p>
    </div>
  )
}

export function EmptyState({
  icon: Icon,
  title,
  children,
}: {
  icon: LucideIcon
  title: string
  children?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed px-6 py-16 text-center">
      <Icon className="text-muted-foreground mb-3 size-8" aria-hidden />
      <p className="font-medium">{title}</p>
      {children ? <div className="text-muted-foreground mt-1 max-w-md text-sm">{children}</div> : null}
    </div>
  )
}
