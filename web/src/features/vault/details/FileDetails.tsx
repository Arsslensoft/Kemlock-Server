// The detail of a File item (name, type, size and Download) and the attachments of a secure note.
// A file is fetched from the server as ciphertext and opened in the browser (fileDownload.ts), so
// Download only does what the caller's `download` does and shows when it fails.
import { useState } from 'react';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import type { ItemData } from '../vault';
import { type AttachedFile, type DownloadFile, fileOf, filesOf, formatSize, typeLabel } from './files';
import { Card, Row } from './rows';

/** Download one file: idle, working, or failed (with a message under the button). */
function DownloadButton({
  file,
  download,
  label,
}: {
  file: AttachedFile;
  download: DownloadFile | undefined;
  label: string;
}) {
  const t = useT();
  const [state, setState] = useState<'idle' | 'busy' | 'failed'>('idle');
  return (
    <>
      <Button
        size="small"
        isDisabled={!download || state === 'busy' || !file.serverId}
        aria-label={label}
        onPress={() => {
          if (!download) return;
          setState('busy');
          download(file).then(
            () => setState('idle'),
            () => setState('failed'),
          );
        }}
      >
        <Icon name="download" />
        {t(state === 'busy' ? 'detail.file.working' : 'detail.file.download')}
      </Button>
      {state === 'failed' ? (
        <Notice tone="error" live>
          <p>{t('detail.file.failed')}</p>
        </Notice>
      ) : null}
    </>
  );
}

function summary(file: AttachedFile): string {
  return [typeLabel(file), formatSize(file.size)].filter((part) => part !== '').join(' · ');
}

/** A File item: the file, with its name, type, size and a Download button. */
export function FileDetail({ data, download }: { data: ItemData | null; download: DownloadFile | undefined }) {
  const t = useT();
  const file = fileOf(data);
  return (
    <Card id="h-file" title={t('detail.file.title')}>
      {file ? (
        <>
          <Row label={t('detail.file.name')} copy={file.name} copyLabel={t('detail.copy', { field: t('detail.file.name').toLowerCase() })}>
            <div className="wrap">{file.name || '—'}</div>
          </Row>
          {typeLabel(file) ? (
            <Row label={t('detail.file.type')}>
              <div>{typeLabel(file)}</div>
            </Row>
          ) : null}
          <Row label={t('detail.file.size')}>
            <div>{formatSize(file.size)}</div>
          </Row>
          <div className="row">
            <DownloadButton file={file} download={download} label={t('detail.file.downloadNamed', { name: file.name })} />
            {file.serverId ? null : <p className="grow muted">{t('detail.file.notUploaded')}</p>}
          </div>
        </>
      ) : (
        <div className="row">
          <p className="grow muted">{t('detail.file.none')}</p>
        </div>
      )}
    </Card>
  );
}

/** The files attached to a secure note, each with a Download button; nothing when it has none. */
export function AttachmentsCard({ data, download }: { data: ItemData | null; download: DownloadFile | undefined }) {
  const t = useT();
  const files = filesOf(data);
  if (files.length === 0) return null;
  return (
    <Card id="h-attachments" title={t('detail.attachments.title')} custom={false}>
      {files.map((file, i) => (
        <div className="row" key={`${file.id}-${i}`}>
          <div className="grow">
            <div className="wrap">{file.name || '—'}</div>
            <div className="muted">{summary(file)}</div>
          </div>
          <DownloadButton file={file} download={download} label={t('detail.file.downloadNamed', { name: file.name })} />
        </div>
      ))}
    </Card>
  );
}
