import { fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { DeviceSelector } from '../components/DeviceSelector';
import { Badge, Button, Card, CardTitle, EmptyState, Icon, Meter, PageHeader, Toggle } from '../components/ui';
import type { Device } from '../types';

const devices: Device[] = [
  {
    serial: 'ADB:1', name: 'ADB device', model: 'Pixel', codename: 'akita', mode: 'adb',
    androidVersion: '16', build: 'BUILD', securityPatch: '2026-01-01', bootloader: 'unlocked',
    slot: 'a', battery: 50, connection: 'USB', architecture: 'arm64', kernelRelease: '5.15.1-android14-1-gtest', kmi: 'android14-5.15', rooted: true,
  },
  {
    serial: 'FAST-2', name: 'Fastboot device', model: 'Pixel', codename: 'husky', mode: 'fastbootd',
    androidVersion: '16', build: 'BUILD', securityPatch: '2026-01-01', bootloader: 'locked',
    slot: 'b', battery: 60, connection: 'Wi-Fi', architecture: '', kernelRelease: '', kmi: '', rooted: false,
  },
  {
    serial: 'OFFLINE', name: 'Offline device', model: 'Pixel', codename: 'panther', mode: 'offline',
    androidVersion: '15', build: 'OLD', securityPatch: '2025-01-01', bootloader: 'unknown',
    slot: 'unknown', battery: 0, connection: 'USB', architecture: '', kernelRelease: '', kmi: '', rooted: false,
  },
];

describe('shared accessible UI primitives', () => {
  it('renders semantic optional content and image accessibility correctly', async () => {
    const user = userEvent.setup();
    const onClick = vi.fn();
    const { rerender } = render(
      <>
        <PageHeader title="Title" subtitle="Subtitle" actions={<button type="button">Header action</button>} />
        <Card className="extra" data-testid="card">
          <CardTitle icon="settings" after={<Badge tone="danger">Blocked</Badge>}>Preferences</CardTitle>
          <Button icon="check" onClick={onClick}>Save</Button>
          <Icon name="magisk" label="Magisk logo" className="brand" />
          <EmptyState icon="folder" title="Empty" detail="Choose a file" />
        </Card>
      </>,
    );
    expect(screen.getByTestId('card')).toHaveClass('card', 'extra');
    expect(screen.getByRole('img', { name: 'Magisk logo' })).not.toHaveClass('icon--monochrome');
    expect(screen.getByText('Blocked')).toHaveClass('badge--danger');
    expect(screen.getByText('Empty')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(onClick).toHaveBeenCalledOnce();

    rerender(
      <>
        <PageHeader title="No actions" subtitle="Simple" />
        <CardTitle>Without icon</CardTitle>
        <Button>Plain</Button>
        <Icon name="settings" />
      </>,
    );
    const decorative = document.querySelector('img.icon--monochrome') as HTMLImageElement;
    expect(decorative).toHaveAttribute('aria-hidden', 'true');
    expect(decorative).toHaveAttribute('alt', '');
    expect(screen.queryByRole('button', { name: 'Header action' })).not.toBeInTheDocument();
  });

  it('propagates toggle changes, disabled state and clamps meter bounds', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    const { rerender } = render(
      <>
        <Toggle checked={false} onChange={onChange} label="Contrast" description="Stronger borders" />
        <Meter value={-20} label="Battery" />
      </>,
    );
    await user.click(screen.getByRole('checkbox', { name: /Contrast/ }));
    expect(onChange).toHaveBeenCalledWith(true);
    expect(screen.getByRole('progressbar', { name: 'Battery' })).toHaveAttribute('aria-valuenow', '0');

    rerender(
      <>
        <Toggle checked disabled onChange={onChange} label="Motion" />
        <Meter value={150} label="Charge" />
      </>,
    );
    expect(screen.getByRole('checkbox', { name: 'Motion' })).toBeDisabled();
    expect(screen.getByText('Motion').closest('label')).toHaveClass('is-disabled');
    expect(screen.getByRole('progressbar', { name: 'Charge' })).toHaveAttribute('aria-valuenow', '100');
  });
});

describe('device selector behavior', () => {
  it('adds and removes multiple devices while exposing all mode treatments', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    const { rerender } = render(
      <DeviceSelector devices={devices} selected={['ADB:1']} onChange={onChange} ariaLabel="Targets" />,
    );
    const group = screen.getByRole('group', { name: 'Targets' });
    expect(within(group).getByText('ADB')).toBeVisible();
    expect(within(group).getByText('FASTBOOTD')).toBeVisible();
    expect(within(group).getAllByText('OFFLINE')).toHaveLength(2);
    expect(within(group).getAllByText(/Android 16/)).toHaveLength(2);

    await user.click(screen.getByRole('checkbox', { name: /Fastboot device/ }));
    expect(onChange).toHaveBeenLastCalledWith(['ADB:1', 'FAST-2']);
    await user.click(screen.getByRole('checkbox', { name: /ADB device/ }));
    expect(onChange).toHaveBeenLastCalledWith([]);

    rerender(<DeviceSelector devices={devices} selected={[]} onChange={onChange} compact ariaLabel="Compact targets" />);
    expect(screen.queryByText(/Android 16/)).not.toBeInTheDocument();
    expect(screen.getByRole('group', { name: 'Compact targets' })).toHaveClass('device-selector--compact');
  });

  it('uses radio semantics and replaces selection in single-device mode', () => {
    const onChange = vi.fn();
    render(
      <DeviceSelector
        devices={devices.slice(0, 2)}
        selected={['ADB:1']}
        onChange={onChange}
        selectionMode="single"
        ariaLabel="One target"
      />,
    );
    const target = screen.getByRole('radio', { name: /Fastboot device/ });
    fireEvent.click(target);
    expect(onChange).toHaveBeenCalledWith(['FAST-2']);
    expect(screen.getAllByRole('radio')[0]).toHaveAttribute('name');
  });

  it('keeps unique stable input IDs for serials that sanitize to the same text', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    const colliding = [
      { ...devices[0], serial: 'A:B', name: 'Colon target' },
      { ...devices[0], serial: 'AB', name: 'Plain target' },
    ];
    const { rerender } = render(
      <DeviceSelector devices={colliding} selected={[]} onChange={onChange} ariaLabel="Collision targets" />,
    );
    const inputs = screen.getAllByRole('checkbox');
    expect(inputs[0]).not.toHaveAttribute('id', inputs[1].id);

    const plainId = screen.getByRole('checkbox', { name: /Plain target/ }).id;
    await user.click(screen.getByRole('checkbox', { name: /Plain target/ }));
    expect(onChange).toHaveBeenCalledWith(['AB']);
    rerender(<DeviceSelector devices={[colliding[1], colliding[0]]} selected={[]} onChange={onChange} ariaLabel="Collision targets" />);
    expect(screen.getByRole('checkbox', { name: /Plain target/ })).toHaveAttribute('id', plainId);
  });
});
