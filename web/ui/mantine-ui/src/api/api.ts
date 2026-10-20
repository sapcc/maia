import {
  keepPreviousData,
  QueryKey,
  useQuery,
  UseQueryResult,
  useSuspenseQuery,
} from "@tanstack/react-query";
// MAIA: replaced fetch with maiaFetch for X-Auth-Token injection
import { maiaFetch } from "../lib/maiaFetch";
// MAIA: inject project_id into every API call
import { useMaiaProject } from "../context/useMaiaProject";
// MAIA: resolve the API base from the served path (supports reverse-proxy sub-paths)
import { apiBase, API_PATH } from "./apiBase";
import { useSettings } from "../state/settingsSlice";

// Re-exported for callers that imported API_PATH from here historically.
export { API_PATH };

export type SuccessAPIResponse<T> = {
  status: "success";
  data: T;
  warnings?: string[];
  infos?: string[];
};

export type ErrorAPIResponse = {
  status: "error";
  errorType: string;
  error: string;
};

export type APIResponse<T> = SuccessAPIResponse<T> | ErrorAPIResponse;

/** APIQueryMetadata describes the request that produced a successful response. */
export type APIQueryMetadata = {
  params: Readonly<Record<string, string>>;
  responseTimeMs: number;
  receivedAtMs: number;
};

type QueryResult<T> = {
  response: SuccessAPIResponse<T>;
  metadata: APIQueryMetadata;
};

type QueryParams =
  Record<string, string> | ((requestTimeMs: number) => Record<string, string>);

const createQueryFn =
  <T>({
    apiBasePath,
    path,
    params,
    recordResponseTime,
  }: {
    apiBasePath: string;
    path: string;
    params?: QueryParams;
    recordResponseTime?: (time: number) => void;
  }) =>
  async ({ signal }: { signal: AbortSignal }) => {
    try {
      const startTime = Date.now();
      const resolvedParams =
        typeof params === "function" ? params(startTime) : params;
      const requestParams = { ...resolvedParams };
      const queryString = resolvedParams
        ? `?${new URLSearchParams(requestParams).toString()}`
        : "";

      // MAIA: apiBasePath is derived from the served path (apiBase()), so the
      // same bundle works served at Maia's own root (/api/v1) or behind a
      // reverse proxy under a sub-path (<prefix>/api/v1).
      const res = await maiaFetch(
        `${apiBasePath}${path}${queryString}`,
        {
          cache: "no-store",
          signal,
        }
      );

      if (
        !res.ok &&
        !res.headers.get("content-type")?.startsWith("application/json")
      ) {
        // For example, Prometheus may send a 503 Service Unavailable response
        // with a "text/plain" content type when it's starting up. But the API
        // may also respond with a JSON error message and the same error code.
        throw new Error(res.statusText);
      }

      const apiRes = (await res.json()) as APIResponse<T>;
      const receivedAtMs = Date.now();
      const responseTimeMs = receivedAtMs - startTime;

      if (recordResponseTime) {
        recordResponseTime(responseTimeMs);
      }

      if (apiRes.status === "error") {
        throw new Error(
          apiRes.error !== undefined
            ? apiRes.error
            : 'missing "error" field in response JSON'
        );
      }

      return {
        response: apiRes,
        metadata: { params: requestParams, responseTimeMs, receivedAtMs },
      };
    } catch (error) {
      if (!(error instanceof Error)) {
        throw new Error("Unknown error", { cause: error });
      }

      switch (error.name) {
        case "TypeError":
          throw new Error("Network error or unable to reach the server", {
            cause: error,
          });
        case "SyntaxError":
          throw new Error("Invalid JSON response", { cause: error });
        default:
          throw error;
      }
    }
  };

type QueryOptions = {
  path: string;
  enabled?: boolean;
  refetchInterval?: false | number;
  recordResponseTime?: (time: number) => void;
  keepPreviousData?: boolean;
} & (
  | { key?: QueryKey; params?: Record<string, string> }
  | { key: QueryKey; params: (requestTimeMs: number) => Record<string, string> }
);

// MAIA: add project_id to the request params, including deferred params that
// are only resolved when the fetch starts.
const withProjectID = (
  params: QueryParams | undefined,
  projectID: string | undefined,
): QueryParams | undefined => {
  if (projectID === undefined) {
    return params;
  }
  if (typeof params === "function") {
    return (requestTimeMs: number) => ({
      ...params(requestTimeMs),
      project_id: projectID,
    });
  }
  return { ...params, project_id: projectID };
};

/**
 * Queries the API, optionally selecting a response with its request metadata.
 * Deferred params receive the fetch start time in milliseconds and require an explicit key.
 */
export function useAPIQuery<T>(
  options: QueryOptions,
): UseQueryResult<SuccessAPIResponse<T>>;
export function useAPIQuery<T, D>(
  options: QueryOptions & {
    select: (response: SuccessAPIResponse<T>, metadata: APIQueryMetadata) => D;
  },
): UseQueryResult<D>;
export function useAPIQuery<T, D>({
  key,
  path,
  params,
  enabled,
  recordResponseTime,
  refetchInterval,
  keepPreviousData: retainPreviousData,
  select,
}: QueryOptions & {
  select?: (response: SuccessAPIResponse<T>, metadata: APIQueryMetadata) => D;
}): UseQueryResult<SuccessAPIResponse<T> | D> {
  // MAIA: inject project_id into every API call
  const { currentProject } = useMaiaProject();
  // MAIA: resolve API base from the served path
  const { pathPrefix } = useSettings();
  const maiaParams = withProjectID(params, currentProject?.id);

  return useQuery<QueryResult<T>, Error, SuccessAPIResponse<T> | D>({
    // MAIA: explicit keys get the project appended so a project switch refetches.
    queryKey:
      key !== undefined ? [...key, currentProject?.id] : [path, maiaParams],
    retry: false,
    refetchOnWindowFocus: false,
    refetchInterval: refetchInterval,
    gcTime: 0,
    // MAIA: don't fire until project is loaded — avoids scope-less queries
    // that would silently fall back to the Keystone token scope instead of
    // the project the user selected in the switcher.
    enabled: enabled !== false && currentProject !== null,
    queryFn: createQueryFn<T>({
      apiBasePath: apiBase(pathPrefix),
      path,
      params: maiaParams,
      recordResponseTime,
    }),
    placeholderData: retainPreviousData ? keepPreviousData : undefined,
    select: (result) =>
      select ? select(result.response, result.metadata) : result.response,
  });
}

export const useSuspenseAPIQuery = <T>({ key, path, params }: QueryOptions) => {
  // MAIA: inject project_id into every API call
  const { currentProject } = useMaiaProject();
  // MAIA: resolve API base from the served path
  const { pathPrefix } = useSettings();
  const maiaParams = withProjectID(params, currentProject?.id);

  return useSuspenseQuery<QueryResult<T>, Error, SuccessAPIResponse<T>>({
    // MAIA: explicit keys get the project appended so a project switch refetches.
    queryKey:
      key !== undefined ? [...key, currentProject?.id] : [path, maiaParams],
    retry: false,
    refetchOnWindowFocus: false,
    staleTime: Infinity,
    gcTime: 0,
    queryFn: createQueryFn<T>({ apiBasePath: apiBase(pathPrefix), path, params: maiaParams }),
    select: (result) => result.response,
  });
};
