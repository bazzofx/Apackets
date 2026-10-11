import { useCallback, useEffect, useRef, useState } from 'react'
import clsx from 'clsx'
import { Check, Copy } from 'lucide-react'

export interface CopyButtonProps {
  value: string | null | undefined
  /** Accessible label / tooltip; defaults to the value itself. */
  label?: string
  className?: string
  disabled?: boolean
}

/** Copies a value to the clipboard and briefly shows a check mark. */
export function CopyButton({ value, label, className, disabled = false }: CopyButtonProps) {
  const [copied, setCopied] = useState(false)
  const timer = useRef<number | null>(null)

  useEffect(
    () => () => {
      if (timer.current !== null) window.clearTimeout(timer.current)
    },
    [],
  )

  const copy = useCallback(() => {
    if (value === null || value === undefined || value === '') return
    void (async () => {
      try {
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(value)
        } else {
          // Fallback for non-secure contexts (http://127.0.0.1 without clipboard API).
          const area = document.createElement('textarea')
          area.value = value
          area.setAttribute('readonly', '')
          area.style.position = 'fixed'
          area.style.opacity = '0'
          document.body.appendChild(area)
          area.select()
          document.execCommand('copy')
          document.body.removeChild(area)
        }
        setCopied(true)
        if (timer.current !== null) window.clearTimeout(timer.current)
        timer.current = window.setTimeout(() => setCopied(false), 1200)
      } catch {
        setCopied(false)
      }
    })()
  }, [value])

  const unavailable = disabled || value === null || value === undefined || value === ''

  return (
    <button
      type="button"
      className={clsx('btn px-1.5 py-1', className)}
      onClick={copy}
      disabled={unavailable}
      title={label ?? (value ? `Copy ${value}` : 'Nothing to copy')}
      aria-label={label ?? 'Copy value'}
    >
      {copied ? <Check size={13} className="text-ok" aria-hidden /> : <Copy size={13} aria-hidden />}
    </button>
  )
}

export default CopyButton
