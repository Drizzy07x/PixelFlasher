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

describe('binary XML Expert workspace', () => {
  it('uses a native read grant and renders only the bounded decoded receipt', async () => {
    const user = userEvent.setup();
    const calls: Parameters<SharedPageProps['onCommand']>[] = [];
    const xml = '<?xml version="1.0" encoding="utf-8"?>\n<manifest package="com.example.test">\n</manifest>\n';
    const onCommand: SharedPageProps['onCommand'] = vi.fn(async (command, payload = {}, options) => {
      calls.push([command, payload, options]);
      if (command === commands.nativePickFile) {
        return {
          result: { status: 'SUCCESS', data: { grant: 'opaque-binary-xml-grant' } },
          revision: 31,
        };
      }
      return {
        result: {
          status: 'SUCCESS',
          code: 'binary_xml_decoded',
          message: 'Android binary XML decoded successfully.',
          value: {
            format: 'android-binary-xml',
            xml,
            sha256: 'b'.repeat(64),
            sizeBytes: 256,
            elementCount: 1,
            attributeCount: 1,
            bounded: true,
          },
        },
        revision: 33,
      };
    });
    renderTools(onCommand);

    await user.click(screen.getByRole('button', { name: /Decode binary XML/i }));
    const workspace = document.querySelector('.tool-workspace') as HTMLElement;
    await user.click(within(workspace).getByRole('button', { name: 'Choose binary XML' }));

    expect(calls).toEqual([
      [commands.nativePickFile, {
        purpose: 'tools.xml.source',
        title: 'Choose binary XML',
        filters: [{ label: 'Binary XML files', extensions: ['xml', 'axml'] }],
      }, undefined],
      [commands.toolsXml, {
        action: 'decodeBinary',
        grant: 'opaque-binary-xml-grant',
      }, {
        expectedRevision: 31,
        returnCancelled: true,
        returnFailed: true,
      }],
    ]);
    expect(JSON.stringify(calls)).not.toMatch(/[A-Z]:\\|\/home\/|\/Users\/|path/i);
    expect(await within(workspace).findByLabelText('Decoded XML')).toHaveTextContent('com.example.test');
    expect(within(workspace).getByText('b'.repeat(64))).toBeVisible();
    expect(within(workspace).getAllByText('1')).toHaveLength(2);
  });
});
