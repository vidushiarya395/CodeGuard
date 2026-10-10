import { useState } from 'react'
import { Loader2, Menu, Moon, RotateCw, Sun } from 'lucide-react'
import { useLocation } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Sheet, SheetContent, SheetDescription, SheetTitle, SheetTrigger } from '@/components/ui/sheet'
import { useApiHealth } from '@/hooks/use-api-health'
import { useTheme } from '@/hooks/use-theme'
import { NAV_ITEMS } from './nav'
import { Brand, SidebarNav } from './sidebar'

function ApiStatus() {
  const { health, retry } = useApiHealth()

  if (health.state === 'loading') {
    return (
      <span className="text-muted-foreground flex items-center gap-2 text-xs" role="status">
        <Loader2 className="size-3.5 animate-spin" aria-hidden />
        <span className="hidden sm:inline">Checking API</span>
      </span>
    )
  }
  if (health.state === 'online') {
    return (
      <span className="text-muted-foreground flex items-center gap-2 text-xs" role="status">
        <span className="bg-foreground/70 size-2 rounded-full" aria-hidden />
        <span className="hidden sm:inline">API online{health.version ? ` · v${health.version}` : ''}</span>
        <span className="sr-only sm:hidden">API online</span>
      </span>
    )
  }
  return (
    <span className="flex items-center gap-1 text-xs" role="status" title={health.error}>
      <span className="text-destructive">API offline</span>
      <Button variant="ghost" size="icon-sm" onClick={retry} aria-label="Check API again">
        <RotateCw className="size-3.5" aria-hidden />
      </Button>
    </span>
  )
}

export function TopBar() {
  const { theme, toggleTheme } = useTheme()
  const [menuOpen, setMenuOpen] = useState(false)
  const { pathname } = useLocation()
  const title = NAV_ITEMS.find((item) => pathname.startsWith(item.to))?.label ?? 'CodeGuard'

  return (
    <header className="bg-background/95 sticky top-0 z-10 flex h-14 items-center gap-2 border-b px-4">
      <Sheet open={menuOpen} onOpenChange={setMenuOpen}>
        <SheetTrigger asChild>
          <Button variant="ghost" size="icon" className="md:hidden" aria-label="Open menu">
            <Menu className="size-5" aria-hidden />
          </Button>
        </SheetTrigger>
        <SheetContent side="left" className="bg-sidebar w-64 p-0">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <SheetDescription className="sr-only">Go to a CodeGuard page</SheetDescription>
          <Brand />
          <SidebarNav onNavigate={() => setMenuOpen(false)} />
        </SheetContent>
      </Sheet>

      <h1 className="truncate text-sm font-medium">{title}</h1>

      <div className="ml-auto flex items-center gap-2">
        <ApiStatus />
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleTheme}
          aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          title={theme === 'dark' ? 'Light mode' : 'Dark mode'}
        >
          {theme === 'dark' ? <Sun className="size-4" aria-hidden /> : <Moon className="size-4" aria-hidden />}
        </Button>
      </div>
    </header>
  )
}
