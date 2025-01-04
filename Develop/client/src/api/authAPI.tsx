import { UserLogin } from "../interfaces/UserLogin";

const login = async (userInfo: UserLogin) => {
  const response = await fetch('/api/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(userInfo),
  });

  if (!response.ok) {
    throw new Error('Login failed');
  }

  return await response.json();
}



export { login };
