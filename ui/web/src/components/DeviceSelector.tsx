import { useId } from 'react';
import type { Device } from '../types';
import { Badge, Icon } from './ui';

export function DeviceSelector({
  devices,
  selected,
  onChange,
  compact = false,
  selectionMode = 'multiple',
  ariaLabel = 'Connected devices',
}: {
  devices: Device[];
  selected: string[];
  onChange: (serials: string[]) => void | Promise<void>;
  compact?: boolean;
  selectionMode?: 'single' | 'multiple';
  ariaLabel?: string;
}) {
  const groupId = useId();

  const toggle = (serial: string) => {
    if (selectionMode === 'single') {
      onChange([serial]);
      return;
    }
    onChange(selected.includes(serial) ? selected.filter((value) => value !== serial) : [...selected, serial]);
  };

  return (
    <div className={`device-selector ${compact ? 'device-selector--compact' : ''}`} role="group" aria-label={ariaLabel}>
      {devices.map((device) => (
        <DeviceOption
          key={device.serial}
          device={device}
          checked={selected.includes(device.serial)}
          compact={compact}
          inputType={selectionMode === 'single' ? 'radio' : 'checkbox'}
          name={selectionMode === 'single' ? `${groupId}-selection` : undefined}
          onToggle={toggle}
        />
      ))}
    </div>
  );
}

function DeviceOption({
  device,
  checked,
  compact,
  inputType,
  name,
  onToggle,
}: {
  device: Device;
  checked: boolean;
  compact: boolean;
  inputType: 'radio' | 'checkbox';
  name?: string;
  onToggle: (serial: string) => void;
}) {
  // A keyed child owns the ID, so it remains collision-free even when serials
  // differ only by punctuation and stable when the inventory is reordered.
  const inputId = useId();
  return (
    <label className={`device-option ${checked ? 'is-selected' : ''}`} htmlFor={inputId}>
      <input
        id={inputId}
        type={inputType}
        name={name}
        checked={checked}
        onChange={() => onToggle(device.serial)}
      />
      <span className="device-option__check" aria-hidden="true">
        {checked ? <Icon name="check" size={14} /> : null}
      </span>
      <span className="device-option__icon">
        <Icon name="devices" size={compact ? 22 : 26} />
      </span>
      <span className="device-option__copy">
        <span className="device-option__title-row">
          <strong>{device.name}</strong>
          <Badge tone={device.mode === 'offline' ? 'danger' : device.mode.startsWith('fastboot') ? 'warning' : 'success'}>
            {device.mode.toUpperCase()}
          </Badge>
        </span>
        <span>{device.serial}</span>
        {!compact ? <small>{device.codename} · Android {device.androidVersion} · {device.connection}</small> : null}
      </span>
    </label>
  );
}
