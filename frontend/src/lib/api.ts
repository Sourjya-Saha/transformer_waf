/**
 * MedCore Health Standard API Client.
 * Routes all HTTP requests through the Layer-7 Gateway.
 */

export const WAF_BASE_URL = process.env.NEXT_PUBLIC_WAF_URL || "http://localhost:8000";

export async function wafFetch<T = any>(
  path: string,
  options: RequestInit = {}
): Promise<{ status: number; data: T; isBlocked: boolean; rawResponse: Response }> {
  const url = `${WAF_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`;

  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        "Accept": "application/json, text/plain, */*",
        ...(options.headers || {}),
      },
    });

    let data: any = null;
    const contentType = res.headers.get("content-type") || "";

    if (contentType.includes("application/json")) {
      try {
        data = await res.json();
      } catch {
        data = {};
      }
    } else {
      data = { text: await res.text() };
    }

    const isBlocked = res.status === 403 || res.status === 429;

    return {
      status: res.status,
      data,
      isBlocked,
      rawResponse: res,
    };
  } catch (err: any) {
    return {
      status: 502,
      data: { error: err.message } as any,
      isBlocked: true,
      rawResponse: new Response(JSON.stringify({ error: err.message }), { status: 502 }),
    };
  }
}
