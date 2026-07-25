import { forwardRef, type ButtonHTMLAttributes, type HTMLAttributes, type ReactNode } from 'react';
import { assets, type AssetName } from '../assets';

export function Icon({
  name,
  size = 20,
  label,
  className = '',
}: {
  name: AssetName;
  size?: number;
  label?: string;
  className?: string;
}) {
  const preserveColor = ['appLogo', 'phoneRender', 'magisk', 'apatch', 'kernelSu', 'sukiSu', 'wildKsu'].includes(name);
  return (
    <img
      className={`icon ${preserveColor ? '' : 'icon--monochrome'} ${className}`}
      src={assets[name]}
      width={size}
      height={size}
      alt={label ?? ''}
      aria-hidden={label ? undefined : true}
      draggable={false}
    />
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle: string; actions?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <h1 tabIndex={-1}>{title}</h1>
        <p>{subtitle}</p>
      </div>
      {actions ? <div className="page-header__actions">{actions}</div> : null}
    </header>
  );
}

export function Card({ className = '', children, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={`card ${className}`} {...props}>
      {children}
    </div>
  );
}

export function CardTitle({ icon, children, after }: { icon?: AssetName; children: ReactNode; after?: ReactNode }) {
  return (
    <div className="card-title">
      <span className="card-title__label">
        {icon ? <Icon name={icon} size={20} /> : null}
        <span>{children}</span>
      </span>
      {after}
    </div>
  );
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  icon?: AssetName;
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button({
  variant = 'secondary',
  icon,
  children,
  className = '',
  ...props
}, ref) {
  return (
    <button ref={ref} className={`button button--${variant} ${className}`} {...props}>
      {icon ? <Icon name={icon} size={18} /> : null}
      <span>{children}</span>
    </button>
  );
});

export function Badge({ tone = 'neutral', children }: { tone?: 'neutral' | 'success' | 'warning' | 'accent' | 'danger'; children: ReactNode }) {
  return <span className={`badge badge--${tone}`}>{children}</span>;
}

export function Toggle({
  checked,
  onChange,
  label,
  description,
  disabled,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  description?: string;
  disabled?: boolean;
}) {
  return (
    <label className={`toggle-row ${disabled ? 'is-disabled' : ''}`}>
      <span className="toggle-row__copy">
        <span className="toggle-row__label">{label}</span>
        {description ? <span className="toggle-row__description">{description}</span> : null}
      </span>
      <span className="switch">
        <input
          type="checkbox"
          checked={checked}
          onChange={(event) => onChange(event.currentTarget.checked)}
          disabled={disabled}
        />
        <span className="switch__track" aria-hidden="true">
          <span className="switch__thumb" />
        </span>
      </span>
    </label>
  );
}

export function Meter({ value, label }: { value: number; label: string }) {
  const safeValue = Math.max(0, Math.min(100, value));
  return (
    <div className="meter">
      <div className="meter__header">
        <span>{label}</span>
        <strong>{safeValue}%</strong>
      </div>
      <div
        className="meter__track"
        role="progressbar"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={safeValue}
      >
        <span className="meter__value" style={{ width: `${safeValue}%` }} />
      </div>
    </div>
  );
}

export function EmptyState({ icon, title, detail }: { icon: AssetName; title: string; detail: string }) {
  return (
    <div className="empty-state">
      <Icon name={icon} size={38} />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}
