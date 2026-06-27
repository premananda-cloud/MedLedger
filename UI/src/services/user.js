/**
 * user.js — User profile service.
 */

import { http } from './http.js';
import authStore from '../state/authStore.js';

/**
 * getProfile()
 * @returns {UserProfile}
 */
export async function getProfile() {
  const data = await http('/api/users/me');
  authStore.setState({ user: data });
  return data;
}

/**
 * updateProfile({ full_name })
 * @returns {UserProfile}
 */
export async function updateProfile(fields) {
  const data = await http('/api/users/me', {
    method: 'PUT',
    body: fields,
  });
  authStore.setState({ user: data });
  return data;
}

/**
 * deleteAccount(password)
 * Permanent. Caller must log out and clear crypto state afterward.
 */
export async function deleteAccount(password) {
  return http('/api/users/me', {
    method: 'DELETE',
    body: { password },
  });
}
