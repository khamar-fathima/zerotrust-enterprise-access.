import { useCallback, useEffect, useState } from "react";
import { errorMessage } from "../lib/identity.js";

export default function usePaginatedRemote(load, collection, scope = "", initialFilters = {}) {
  const [params, setParams] = useState({ page: 1, limit: 25, q: "", ...initialFilters });
  const [revision, setRevision] = useState(0);
  const [result, setResult] = useState(null);
  const key = JSON.stringify([params, scope, revision]);
  const refresh = useCallback(() => setRevision((value) => value + 1), []);
  const setFilter = (name, value) => setParams((current) => ({ ...current, [name]: value, page: 1 }));
  const setPage = (page) => setParams((current) => ({ ...current, page }));
  const setError = (error) => setResult((current) => ({ ...current, key, error }));

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    // Debounce typing and cancel superseded requests, including scope changes.
    const timer = setTimeout(async () => {
      try {
        const data = await load(params, { signal: controller.signal });
        if (!active) return;
        // A mutation or concurrent removal may have emptied the last page.
        if (data.page !== params.page) {
          setParams((current) => ({ ...current, page: data.page }));
          return;
        }
        setResult({ ...data, key, error: "" });
      } catch (err) {
        if (active) setResult({ key, error: errorMessage(err, "The requested records could not be loaded.") });
      }
    }, 250);
    return () => { active = false; clearTimeout(timer); controller.abort(); };
  // The serialized key includes every parameter and the signed-in scope.
  }, [key, load]);

  const current = result?.key === key ? result : null;
  return {
    params, setFilter, setPage, refresh, setError,
    rows: current?.[collection] || [],
    total: current?.total || 0,
    totalPages: current?.totalPages || 0,
    loading: !current,
    error: current?.error || "",
  };
}
