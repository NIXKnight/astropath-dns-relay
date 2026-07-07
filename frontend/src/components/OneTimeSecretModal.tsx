// SPDX-License-Identifier: GPL-3.0-or-later
// astropath-dns-relay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import { useState } from 'react'

import { ONE_TIME_SECRET_NOTICE } from '../lib/notice.ts'
import { Modal } from './Modal.tsx'

interface OneTimeSecretModalProps {
  title: string
  label: string
  /** The plaintext secret — held only in component memory, never persisted. */
  value: string
  onClose: () => void
}

// Renders a generated TSIG secret / API token exactly once (SPEC §9.2, §16). The
// value lives only in this component's props/state; it is never written to
// localStorage, sessionStorage, or any log. Closing discards it — recovery is
// revoke + recreate (the notice makes that explicit).
export function OneTimeSecretModal({
  title,
  label,
  value,
  onClose,
}: OneTimeSecretModalProps): React.JSX.Element {
  const [copied, setCopied] = useState(false)

  async function copy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  return (
    <Modal title={title} onClose={onClose} dismissible={false}>
      <p className="notice notice-warn">{ONE_TIME_SECRET_NOTICE}</p>
      <label className="field">
        <span>{label}</span>
        <div className="reveal-row">
          <input
            className="mono"
            readOnly
            value={value}
            aria-label={label}
            onFocus={(event) => event.currentTarget.select()}
          />
          <button type="button" onClick={() => void copy()}>
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
      </label>
      <p className="muted small">
        You will not see this value again. Store it now (for a TSIG key, this is
        the base64 secret that goes verbatim into the cert-manager Secret).
      </p>
      <div className="modal-actions">
        <button type="button" className="primary" onClick={onClose}>
          I have saved it — close
        </button>
      </div>
    </Modal>
  )
}
