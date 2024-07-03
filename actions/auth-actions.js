'use server';

import {createAuthSession} from '@/lib/auth';
import {hashUserPassword, verifyPassword} from '@/lib/hash';
import {createUser, getUserByEmail} from '@/lib/user';
import {redirect} from 'next/navigation';

export async function signup(_, formData) {
  const email = formData.get('email');
  const password = formData.get('password');

  let errors = {};

  if (!email.includes('@')) {
    errors.email = 'Please enter a valid email';
  }

  if (password.trim().length < 8) {
    errors.password = 'Password must be at least 8 characters long';
  }

  if (Object.keys(errors).length > 0) {
    return {
      errors,
    };
  }

  const hashedPassword = hashUserPassword(password);
  try {
    const userId = createUser(email, hashedPassword);
    await createAuthSession(userId);
    redirect('/training');
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return {
        errors: {
          email: 'Email already exist',
        },
      };
    }
    throw error;
  }
}

export async function login(_, formData) {
  const email = formData.get('email');
  const password = formData.get('password');

  const existingUser = await getUserByEmail(email);

  if (!existingUser) {
    return {
      errors: {
        email: 'Please check your credentials',
      },
    };
  }

  const isValidPassword = verifyPassword(existingUser.password, password);

  if (!isValidPassword) {
    return {
      errors: {
        password: 'Please check your credentials',
      },
    };
  }

  await createAuthSession(existingUser.id);
  redirect('/training');
}

export async function auth(mode, prevState, formData) {
  if (mode === 'login') {
    return login(prevState, formData);
  }
  return signup(prevState, formData);
}
