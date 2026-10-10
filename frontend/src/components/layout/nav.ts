import { BookOpen, FlaskConical, History, Info, ScanSearch, Settings, type LucideIcon } from 'lucide-react'

export type NavItem = {
  to: string
  label: string
  icon: LucideIcon
}

export const NAV_ITEMS: NavItem[] = [
  { to: '/scan', label: 'Scan', icon: ScanSearch },
  { to: '/history', label: 'History', icon: History },
  { to: '/rules', label: 'Rules', icon: BookOpen },
  { to: '/research', label: 'Research', icon: FlaskConical },
  { to: '/settings', label: 'Settings', icon: Settings },
  { to: '/about', label: 'About', icon: Info },
]
