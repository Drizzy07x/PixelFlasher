import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { commands } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import type { SharedPageProps } from '../pages/shared';
import { ToolsPage } from '../pages/tooling/ToolsPage';
import type { HostSnapshot } from '../types';

function renderTools(onCommand: SharedPageProps['onCommand']) {
  const snapshot = structuredClone(demoSnapshot) as HostSnapshot;
  return render(
    <I18nProvider locale="en">
      <ToolsPage
        snapshot={snapshot}
        selectedSerials={snapshot.selectedSerials ?? []}
        onSelectionChange={vi.fn()}
        onCommand={onCommand}
        expertMode
      />
    </I18nProvider>,
  );
}

describe('keybox Expert workspace', () => {
  it('uses bounded native grants and distinguishes unverified from valid', async () => {
    const user = userEvent.setup();
    const calls: Parameters<SharedPageProps['onCommand']>[] = [];
    const onCommand: SharedPageProps['onCommand'] = vi.fn(async (command, payload = {}, options) => {
      calls.push([command, payload, options]);
      if (command === commands.nativePickFiles) {
        return {
          result: {
            status: 'SUCCESS',
            data: { grants: [{ grant: 'opaque-keybox-grant' }] },
          },
          revision: 41,
        };
      }
      return {
        result: {
          status: 'SUCCESS',
          code: 'keybox_analyzed',
          message: 'Keybox analysis completed.',
          value: {
            reports: [{
              displayName: 'attestation.xml',
              sha256: 'c'.repeat(64),
              sizeBytes: 4096,
              status: 'unverified',
              structureValid: true,
              cryptographicValid: true,
              keyboxCount: 1,
              algorithms: ['ecdsa', 'rsa'],
              certificateCount: 4,
              expired: false,
              expiringSoon: false,
              softwareAttestation: false,
              revocationStatus: 'unverified',
              issues: ['revocation_evidence_unavailable'],
            }],
            count: 1,
            summary: {
              valid: 0,
              unverified: 1,
              revoked: 0,
              expired: 0,
              softwareAttestation: 0,
              invalid: 0,
            },
            revocationEvidence: null,
            bounded: true,
          },
        },
        revision: 43,
      };
    });
    renderTools(onCommand);

    await user.click(screen.getByRole('button', { name: /Validate keyboxes/i }));
    const workspace = document.querySelector('.tool-workspace') as HTMLElement;
    await user.click(within(workspace).getByRole('button', { name: 'Choose keybox files' }));

    expect(calls).toEqual([
      [commands.nativePickFiles, {
        purpose: 'tools.keybox.sources',
        title: 'Choose keybox files',
        filters: [{ label: 'Keybox XML files', extensions: ['xml'] }],
      }, undefined],
      [commands.toolsKeybox, {
        action: 'analyze',
        grants: ['opaque-keybox-grant'],
      }, {
        expectedRevision: 41,
        returnCancelled: true,
        returnFailed: true,
      }],
    ]);
    expect(JSON.stringify(calls)).not.toMatch(/privateKey|certificate|[A-Z]:\\|\/home\/|\/Users\//i);
    expect(await within(workspace).findByText('attestation.xml')).toBeVisible();
    expect(within(workspace).getByText('Authenticated revocation evidence is unavailable. Cryptographically valid keyboxes remain unverified.')).toBeVisible();
    expect(within(workspace).getByText('c'.repeat(64))).toBeVisible();
    expect(within(workspace).queryByText('Valid', { selector: '.badge' })).not.toBeInTheDocument();
    expect(within(workspace).getByText('Unverified', { selector: '.badge' })).toBeVisible();
  });
});
