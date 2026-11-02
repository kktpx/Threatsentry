import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi } from 'vitest'

import { ForgotPasswordPage } from './ForgotPasswordPage'

const { resetPasswordForEmail } = vi.hoisted(() => ({ resetPasswordForEmail: vi.fn() }))

vi.mock('../../lib/supabase', () => ({
  supabase: {
    auth: { resetPasswordForEmail },
  },
}))

it('requests a reset email redirecting to /reset-password', async () => {
  resetPasswordForEmail.mockResolvedValue({ data: {}, error: null })
  const user = userEvent.setup()
  render(<MemoryRouter><ForgotPasswordPage /></MemoryRouter>)

  await user.type(screen.getByLabelText('Email'), 'analyst@example.com')
  await user.click(screen.getByRole('button', { name: /Send reset link/i }))

  expect(resetPasswordForEmail).toHaveBeenCalledWith('analyst@example.com', {
    redirectTo: `${window.location.origin}/reset-password`,
  })
  expect(await screen.findByRole('status')).toHaveTextContent('analyst@example.com')
})

it('shows the error returned by Supabase', async () => {
  resetPasswordForEmail.mockResolvedValue({ data: null, error: new Error('rate limit exceeded') })
  const user = userEvent.setup()
  render(<MemoryRouter><ForgotPasswordPage /></MemoryRouter>)

  await user.type(screen.getByLabelText('Email'), 'analyst@example.com')
  await user.click(screen.getByRole('button', { name: /Send reset link/i }))

  expect(await screen.findByRole('alert')).toHaveTextContent('rate limit exceeded')
})
