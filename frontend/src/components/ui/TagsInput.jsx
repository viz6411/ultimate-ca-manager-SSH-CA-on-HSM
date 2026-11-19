import { useState, useRef, useId } from 'react'
import { useTranslation } from 'react-i18next'
import { X } from '@phosphor-icons/react'

/**
 * TagsInput - Modern tag/chip input for multiple values (emails, etc.)
 * Type a value and press Enter/Tab/comma to add it as a tag.
 * Click the × on a tag to remove it.
 */
export default function TagsInput({ value = [], onChange, label, placeholder, helperText, error, validate, className = '', id }) {
  const { t } = useTranslation()
  const [input, setInput] = useState('')
  const inputRef = useRef(null)
  // The label names the field for assistive technologies (WCAG 1.3.1 / 4.1.2)
  const autoId = useId()
  const fieldId = id ?? autoId

  const addTag = (raw) => {
    const tag = raw.trim()
    if (!tag) return
    if (value.includes(tag)) { setInput(''); return }
    if (validate && !validate(tag)) return
    onChange([...value, tag])
    setInput('')
  }

  const removeTag = (idx) => {
    onChange(value.filter((_, i) => i !== idx))
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === 'Tab' || e.key === ',') {
      e.preventDefault()
      addTag(input)
    }
    if (e.key === 'Backspace' && !input && value.length > 0) {
      removeTag(value.length - 1)
    }
  }

  const handlePaste = (e) => {
    e.preventDefault()
    const text = e.clipboardData.getData('text')
    const items = text.split(/[,;\s]+/).filter(Boolean)
    const newTags = items.filter(item => !value.includes(item) && (!validate || validate(item)))
    if (newTags.length) onChange([...value, ...newTags])
  }

  return (
    <div className={className}>
      {label && (
        <label htmlFor={fieldId} className="block text-xs font-medium text-text-secondary mb-1">{label}</label>
      )}
      <div
        className={`flex flex-wrap items-center gap-2 min-h-[38px] px-2.5 py-1.5 rounded-lg border ${error ? 'border-accent-danger' : 'border-border'} bg-bg-secondary cursor-text transition-colors focus-within:border-accent-primary focus-within:ring-1 focus-within:ring-accent-primary`}
        onClick={() => inputRef.current?.focus()}
      >
        {value.map((tag, i) => (
          // The × alone is a glyph: without a name the button is an unnamed
          // control and nothing says which chip it removes
          <span
            key={i}
            className="inline-flex items-center gap-1.5 pl-2.5 pr-1.5 py-1 rounded-md bg-bg-secondary text-accent-primary text-sm font-medium border border-border"
          >
            {tag}
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); removeTag(i) }}
              aria-label={`${t('common.remove')}: ${tag}`}
              className="p-0.5 rounded hover:bg-bg-tertiary hover:text-status-danger transition-colors"
            >
              <X size={12} weight="bold" />
            </button>
          </span>
        ))}
        <input
          ref={inputRef}
          id={fieldId}
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          onPaste={handlePaste}
          onBlur={() => addTag(input)}
          placeholder={value.length === 0 ? placeholder : ''}
          aria-describedby={error ? `${fieldId}-error` : helperText ? `${fieldId}-helper` : undefined}
          className={`flex-1 min-w-[120px] bg-transparent border-none outline-none text-sm text-text-primary placeholder:text-text-tertiary${error ? ' text-status-danger' : ''}`}
        />
      </div>
      {helperText && !error && (
        <p id={`${fieldId}-helper`} className="text-xs text-text-tertiary mt-1">{helperText}</p>
      )}
      {error && (
        <p id={`${fieldId}-error`} role="status" className="text-xs status-danger-text mt-1">{error}</p>
      )}
    </div>
  )
}
