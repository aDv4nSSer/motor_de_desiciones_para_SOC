export const TIER_LABEL = ['T0 benigno', 'T1 bajo', 'T2 medio', 'T3 crítico'] as const

/** Nombres legibles de los access_event que audita motor/auth.py y user_admin.py. */
export const ACCESS_LABEL: Record<string, string> = {
  login_success: 'Inicio de sesión',
  login_failed: 'Inicio de sesión fallido',
  logout: 'Cierre de sesión',
  action_denied_role: 'Acción denegada por rol',
  approval_denied_role: 'Aprobación denegada por rol',
  approval_denied_safelist: 'Aprobación rechazada (safelist)',
  approval_granted: 'Aprobación otorgada',
  approval_rejected: 'Aprobación rechazada',
  token_rejected_user_state: 'Token rechazado (usuario cambiado)',
  token_rejected_session_revoked: 'Token rechazado (sesión revocada)',
  user_created: 'Usuario creado',
  user_role_changed: 'Rol cambiado',
  user_disabled: 'Usuario dado de baja',
  user_enabled: 'Usuario reactivado',
  user_password_reset: 'Contraseña restablecida', // pragma: allowlist secret (etiqueta de UI, no es un secreto)
  user_admin_denied: 'Gestión de usuarios denegada',
  session_revoked: 'Sesión revocada',
  sessions_revoked_all: 'Todas las sesiones revocadas',
  audit_trace_viewed: 'Consulta de historial',
}
