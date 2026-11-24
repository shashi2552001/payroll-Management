export class ApiError extends Error {
  status: number;
  code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

let refreshPromise: Promise<boolean> | null = null;

async function tryRefreshSession(): Promise<boolean> {
  if (!refreshPromise) {
    refreshPromise = fetch('/api/auth/refresh', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'X-Requested-With': '9HR-Client',
      },
    })
      .then((r) => r.ok)
      .catch(() => false)
      .finally(() => {
        refreshPromise = null;
      });
  }
  return refreshPromise;
}

export async function apiFetch<T>(
  path: string,
  options: RequestInit & { skipAutoRefresh?: boolean } = {},
): Promise<T> {
  const { skipAutoRefresh, headers, body, ...rest } = options;
  const isFormData = typeof FormData !== 'undefined' && body instanceof FormData;

  const mergedHeaders: Record<string, string> = {
    'X-Requested-With': '9HR-Client',
    ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
    ...((headers as Record<string, string>) || {}),
  };

  let res = await fetch(path, {
    ...rest,
    body,
    credentials: 'include',
    headers: mergedHeaders,
  });

  if (
    res.status === 401 &&
    !skipAutoRefresh &&
    !path.startsWith('/api/auth/login') &&
    !path.startsWith('/api/auth/refresh') &&
    !path.startsWith('/api/candidate-portal/')
  ) {
    const refreshed = await tryRefreshSession();
    if (refreshed) {
      res = await fetch(path, {
        ...rest,
        body,
        credentials: 'include',
        headers: mergedHeaders,
      });
    }
  }

  const text = await res.text();
  let data: Record<string, unknown> = {};
  if (text) {
    try {
      data = JSON.parse(text) as Record<string, unknown>;
    } catch {
      data = { error: text };
    }
  }

  if (!res.ok) {
    throw new ApiError(
      String(data.error || `Request failed (${res.status})`),
      res.status,
      typeof data.code === 'string' ? data.code : undefined,
    );
  }

  return data as T;
}
