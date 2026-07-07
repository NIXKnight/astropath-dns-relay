// SPDX-License-Identifier: GPL-3.0-or-later
// astropath-dns-relay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import type { ReactNode } from 'react'

interface ModalProps {
  title: string
  onClose: () => void
  children: ReactNode
  /** When false the backdrop and the × button do not dismiss (reveal flow). */
  dismissible?: boolean
}

export function Modal({
  title,
  onClose,
  children,
  dismissible = true,
}: ModalProps): React.JSX.Element {
  return (
    <div
      className="modal-backdrop"
      onClick={dismissible ? onClose : undefined}
      role="presentation"
    >
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="modal-head">
          <h2>{title}</h2>
          {dismissible && (
            <button
              type="button"
              className="icon-btn"
              aria-label="Close"
              onClick={onClose}
            >
              ×
            </button>
          )}
        </header>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  )
}
